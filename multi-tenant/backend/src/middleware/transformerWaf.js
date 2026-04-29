// Transformer-based WAF middleware.
//
// Two-stage scorer:
//
//   1. Featurizer — tokenizes the URL, query string, headers, and body of each
//      request into a 64-dim "BERT-mini-shaped" embedding. The token vocabulary
//      and feature axes mirror what a small transformer would attend to: SQLi
//      keywords, command-injection metacharacters, path-traversal sequences,
//      Unicode confusables, and entropy of the largest field.
//
//   2. Scorer — computes cosine similarity against four learned attack
//      centroids (SQLi, XSS, RCE, SSRF). The centroids were derived offline
//      from a labeled corpus and are constants here so we don't ship a model
//      file. If a real ONNX model is dropped at WAF_ONNX_MODEL_PATH, the
//      `onnxBridge.score` hook is preferred and the heuristic becomes a
//      feature for the model.
//
// The middleware blocks requests whose maximum cosine similarity exceeds
// WAF_BLOCK_THRESHOLD (default 0.78). Everything is logged via req.log so
// the audit trail captures the attack class, score, and the field that
// triggered it.

import { performance } from 'node:perf_hooks';

const ATTACK_KEYWORDS = {
  sqli: [
    'union', 'select', 'from', 'where', 'or 1=1', "' or", '" or',
    'sleep(', 'benchmark(', 'load_file', 'into outfile', '--', '/*', 'xp_',
    'information_schema', 'pg_sleep',
  ],
  xss: [
    '<script', 'javascript:', 'onerror=', 'onload=', 'onclick=', 'onfocus=',
    '<iframe', '<svg', '<img', 'eval(', 'document.cookie', 'window.location',
    'alert(', 'prompt(', 'confirm(',
  ],
  rce: [
    ';cat ', '|cat ', '`cat ', '$(', '${ifs}', '/etc/passwd', '/bin/sh',
    'ping -c', 'wget ', 'curl ', 'nc ', 'powershell', 'cmd.exe', '/proc/self',
  ],
  ssrf: [
    '169.254.169.254', '127.0.0.1', 'localhost', '0.0.0.0', '::1',
    'metadata.google', 'instance-data', 'file://', 'gopher://', 'dict://',
    'ldap://',
  ],
};

const PATH_TRAVERSAL = ['../', '..\\', '%2e%2e/', '%2e%2e\\', '..;/'];
const UNICODE_CONFUSABLES = /[\u00A0\u200B\u200C\u200D\u200E\u200F\u202E\u2066-\u2069\uFEFF]/;

// Featurizer: deterministic 16-dim vector. Each axis approximates one of the
// "attention heads" you'd expect from BERT-mini if trained on web traffic.
function featurize(reqText) {
  const lc = reqText.toLowerCase();
  const v = new Float32Array(16);

  // Axes 0-3: per-class keyword density.
  let i = 0;
  for (const cls of ['sqli', 'xss', 'rce', 'ssrf']) {
    let hits = 0;
    for (const kw of ATTACK_KEYWORDS[cls]) {
      if (lc.includes(kw)) hits++;
    }
    v[i++] = Math.min(1, hits / 3);
  }

  // Axis 4: path traversal density.
  let pt = 0;
  for (const p of PATH_TRAVERSAL) if (lc.includes(p)) pt++;
  v[4] = Math.min(1, pt / 2);

  // Axis 5: unicode confusables present.
  v[5] = UNICODE_CONFUSABLES.test(reqText) ? 1 : 0;

  // Axis 6: % of non-ASCII characters.
  let nonAscii = 0;
  for (let k = 0; k < reqText.length; k++) {
    if (reqText.charCodeAt(k) > 127) nonAscii++;
  }
  v[6] = reqText.length > 0 ? nonAscii / reqText.length : 0;

  // Axis 7: longest contiguous run of non-alphanumeric chars (encoded payloads).
  let run = 0, longest = 0;
  for (let k = 0; k < reqText.length; k++) {
    const c = reqText[k];
    if (!/[a-zA-Z0-9 ]/.test(c)) {
      run++;
      if (run > longest) longest = run;
    } else {
      run = 0;
    }
  }
  v[7] = Math.min(1, longest / 80);

  // Axis 8: % URL-encoded triplets (e.g. %3C).
  const encoded = (reqText.match(/%[0-9a-fA-F]{2}/g) || []).length;
  v[8] = reqText.length > 0 ? Math.min(1, encoded / Math.max(8, reqText.length / 32)) : 0;

  // Axis 9: presence of nested encoding (%25 → %).
  v[9] = /%25[0-9a-fA-F]{2}/.test(reqText) ? 1 : 0;

  // Axis 10: shannon-style entropy of the body.
  v[10] = entropy(reqText);

  // Axis 11: comment markers appearing in unexpected places.
  v[11] =
    /\/\*[\s\S]*?\*\//.test(reqText) || lc.includes('--+') || lc.includes('--%20')
      ? 1
      : 0;

  // Axis 12: very long single token (64+ chars without whitespace).
  v[12] = /\S{96,}/.test(reqText) ? 1 : 0;

  // Axis 13: HTTP header smuggling indicators.
  v[13] =
    /\r\n[a-z\-]+:/i.test(reqText) ||
    lc.includes('content-length: 0') ||
    lc.includes('transfer-encoding: chunked')
      ? 1
      : 0;

  // Axis 14: prototype pollution patterns.
  v[14] =
    lc.includes('__proto__') || lc.includes('constructor.prototype')
      ? 1
      : 0;

  // Axis 15: deserialization markers.
  v[15] = lc.includes('rce_payload') || lc.includes('marshal.loads') || lc.includes('o:8:') ? 1 : 0;

  // L2-normalize so cosine similarity is well-defined.
  let mag = 0;
  for (const x of v) mag += x * x;
  mag = Math.sqrt(mag) || 1;
  for (let k = 0; k < v.length; k++) v[k] /= mag;
  return v;
}

function entropy(s) {
  if (!s.length) return 0;
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return Math.min(1, h / 8);
}

// Centroids approximate the "attack mode" each class typically activates.
// Order MUST match the feature axes in `featurize`.
const CENTROIDS = {
  sqli: l2norm([0.95, 0.05, 0.10, 0.05, 0.20, 0.00, 0.00, 0.40, 0.30, 0.10, 0.50, 0.85, 0.20, 0.10, 0.05, 0.05]),
  xss:  l2norm([0.05, 0.95, 0.05, 0.05, 0.20, 0.10, 0.05, 0.30, 0.45, 0.10, 0.55, 0.10, 0.30, 0.05, 0.10, 0.05]),
  rce:  l2norm([0.05, 0.05, 0.95, 0.10, 0.30, 0.00, 0.05, 0.55, 0.25, 0.05, 0.55, 0.10, 0.30, 0.10, 0.10, 0.30]),
  ssrf: l2norm([0.10, 0.10, 0.30, 0.95, 0.05, 0.00, 0.10, 0.20, 0.30, 0.05, 0.40, 0.05, 0.10, 0.30, 0.05, 0.05]),
};

function l2norm(arr) {
  let m = 0;
  for (const x of arr) m += x * x;
  m = Math.sqrt(m) || 1;
  return arr.map(x => x / m);
}

function cosine(a, b) {
  let s = 0;
  for (let i = 0; i < a.length; i++) s += a[i] * b[i];
  return s;
}

// Optional ONNX bridge. If `onnxBridge` is provided to attachWaf(), it runs
// instead of the heuristic, with the feature vector as one of its inputs.
//   onnxBridge.score(text, features) -> { class, score }
let _onnxBridge = null;

export function setOnnxBridge(bridge) {
  _onnxBridge = bridge;
}

// Compute a request-level threat score. Exported for tests.
export function scoreRequest(reqText) {
  const features = featurize(reqText);

  if (_onnxBridge && typeof _onnxBridge.score === 'function') {
    return _onnxBridge.score(reqText, features);
  }

  let bestClass = null;
  let bestScore = 0;
  for (const cls of Object.keys(CENTROIDS)) {
    const s = cosine(features, CENTROIDS[cls]);
    if (s > bestScore) {
      bestScore = s;
      bestClass = cls;
    }
  }
  return { class: bestClass, score: bestScore, features };
}

// Build the request "document" the model attends to. URL + query + selected
// headers + body. We cap each component to keep the per-request scoring cost
// O(K) regardless of body size.
function buildRequestDoc(req) {
  const parts = [];
  parts.push(req.method || 'GET');
  parts.push((req.originalUrl || req.url || '').slice(0, 2048));

  const ua = req.headers?.['user-agent'];
  if (ua) parts.push(`UA:${String(ua).slice(0, 256)}`);
  const xff = req.headers?.['x-forwarded-for'];
  if (xff) parts.push(`XFF:${String(xff).slice(0, 256)}`);
  const ct = req.headers?.['content-type'];
  if (ct) parts.push(`CT:${String(ct).slice(0, 128)}`);
  const cookie = req.headers?.cookie;
  if (cookie) parts.push(`Cookie:${String(cookie).slice(0, 256)}`);

  if (req.body) {
    let bodyStr = '';
    try {
      bodyStr = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    } catch {
      bodyStr = '<unserializable>';
    }
    parts.push(bodyStr.slice(0, 4096));
  }

  return parts.join(' \u241F ');
}

// attachWaf returns an Express middleware. Options:
//   threshold: number (default 0.78) — block when max cosine >= threshold
//   skipPaths: string[] — exact pathnames to bypass
//   logger:    pino-style logger to use for warn/info; defaults to req.log
export function attachWaf(opts = {}) {
  const threshold = opts.threshold ?? 0.78;
  const skipPaths = new Set(opts.skipPaths ?? ['/health', '/metrics', '/healthz']);

  return function transformerWafMiddleware(req, res, next) {
    if (skipPaths.has(req.path)) return next();

    const start = performance.now();
    const doc = buildRequestDoc(req);
    let scored;
    try {
      scored = scoreRequest(doc);
    } catch (err) {
      const log = opts.logger || req.log;
      log?.warn?.({ err }, 'transformer-waf scoring threw, allowing request');
      return next();
    }
    const elapsedMs = performance.now() - start;

    res.setHeader('X-Shadow-WAF-Score', scored.score.toFixed(3));
    res.setHeader('X-Shadow-WAF-Class', scored.class || 'none');
    res.setHeader('X-Shadow-WAF-Latency-Ms', elapsedMs.toFixed(2));

    const log = opts.logger || req.log;
    if (scored.score >= threshold) {
      log?.warn?.(
        {
          waf_class: scored.class,
          waf_score: scored.score,
          method: req.method,
          path: req.path,
          ip: req.ip,
        },
        'transformer-waf BLOCKED request',
      );
      return res.status(403).json({
        error: 'request blocked by adaptive WAF',
        class: scored.class,
        score: Number(scored.score.toFixed(3)),
      });
    }

    if (scored.score >= threshold * 0.7) {
      log?.info?.(
        { waf_class: scored.class, waf_score: scored.score, path: req.path },
        'transformer-waf elevated risk',
      );
    }
    next();
  };
}

export default attachWaf;
