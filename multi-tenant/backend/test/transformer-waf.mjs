// Transformer WAF unit tests. Run with `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scoreRequest, attachWaf } from '../src/middleware/transformerWaf.js';

test('benign GET request scores low', () => {
  const r = scoreRequest('GET /api/threats?limit=20 UA:Mozilla/5.0');
  assert.ok(r.score < 0.6, `benign score should be < 0.6, got ${r.score}`);
});

test('SQLi payload classified as sqli with high score', () => {
  const r = scoreRequest("POST /login {\"u\":\"admin' OR 1=1 --\",\"p\":\"x\"}");
  assert.equal(r.class, 'sqli');
  assert.ok(r.score >= 0.65, `SQLi score should be >= 0.65, got ${r.score}`);
});

test('XSS payload classified as xss', () => {
  const r = scoreRequest('GET /search?q=<script>alert(1)</script>');
  assert.equal(r.class, 'xss');
  assert.ok(r.score >= 0.6, `XSS score should be >= 0.6, got ${r.score}`);
});

test('SSRF payload classified as ssrf', () => {
  const r = scoreRequest('GET /fetch?url=http://169.254.169.254/latest/meta-data/');
  assert.equal(r.class, 'ssrf');
  assert.ok(r.score >= 0.6, `SSRF score should be >= 0.6, got ${r.score}`);
});

test('middleware blocks request above threshold', async () => {
  const mw = attachWaf({ threshold: 0.6 });
  const req = {
    method: 'POST',
    originalUrl: "/login?u=admin' OR 1=1 --",
    path: '/login',
    body: { u: "admin' OR 1=1 --", p: 'x' },
    headers: { 'user-agent': 'curl/7' },
    ip: '10.0.0.1',
    log: { warn: () => {}, info: () => {} },
  };
  let blocked = false;
  let nextCalled = false;
  const res = {
    headers: {},
    setHeader(k, v) { this.headers[k] = v; },
    status(code) {
      assert.equal(code, 403);
      blocked = true;
      return this;
    },
    json() { return this; },
  };
  await new Promise(resolve => {
    mw(req, res, () => {
      nextCalled = true;
      resolve();
    });
    // give synchronous middleware a tick
    setImmediate(resolve);
  });
  assert.equal(blocked, true, 'middleware should have called res.status(403)');
  assert.equal(nextCalled, false, 'middleware should not have called next() on a block');
});

test('skipPaths bypass scoring', () => {
  const mw = attachWaf({ threshold: 0.0, skipPaths: ['/health'] });
  const req = { path: '/health', headers: {} };
  const res = { setHeader: () => {}, status: () => res, json: () => res };
  let nextCalled = false;
  mw(req, res, () => { nextCalled = true; });
  assert.equal(nextCalled, true, 'health endpoint must bypass WAF');
});
