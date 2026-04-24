import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";

/**
 * Hardened security middleware stack for Shadow NDR Aviation backend.
 *
 * The frontend (Vite dev / prod build) is the only origin we expect to receive
 * browser traffic from. Sensor traffic hits /api/sensor/data without a browser
 * so it is not subject to CORS (it carries its own JWT).
 */

const DEFAULT_FRONTENDS = [
  "http://localhost:3000",
  "http://localhost:3100",
  "http://127.0.0.1:3000",
  "http://127.0.0.1:3100",
];

const allowedOrigins = (process.env.FRONTEND_URL || DEFAULT_FRONTENDS.join(","))
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

export const securityMiddleware = [
  helmet({
    // CSP: block inline-script injection, limit where JS/fonts/images can load
    // from. Aviation dashboards are sensitive — lock this down hard.
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        // Our React bundle is served by Vite — dev mode injects inline runtime,
        // prod bundle is static. 'unsafe-eval' is needed for Vite HMR only.
        scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com", "data:"],
        imgSrc: ["'self'", "data:", "blob:", "https:", "http://*.tile.openstreetmap.org", "http://*.basemaps.cartocdn.com"],
        connectSrc: [
          "'self'",
          "ws:", "wss:",              // Socket.IO
          "http://localhost:3001",     // backend API when frontend is on :3100
          "http://localhost:11434",    // Ollama (direct; proxy is preferred)
        ],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],   // clickjacking protection
        baseUri: ["'self'"],
        formAction: ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,       // allow OSM tiles
    crossOriginResourcePolicy: { policy: "cross-origin" },
    // HSTS only when terminating TLS (reverse proxy typically does this)
    hsts: process.env.NODE_ENV === "production"
      ? { maxAge: 63072000, includeSubDomains: true, preload: true }
      : false,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  }),

  cors({
    origin: (origin, cb) => {
      // Allow same-origin / curl / server-to-server (no Origin header).
      if (!origin) return cb(null, true);
      if (allowedOrigins.includes(origin)) return cb(null, true);
      return cb(new Error(`CORS: origin ${origin} not allowed`));
    },
    credentials: true,
    methods: ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
    maxAge: 600,
  }),
];

// Brute-force guard for auth endpoints. 10 tries / minute / IP.
// Login failures only — successes do not count.
export const authRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: "Too many authentication attempts, slow down" },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
});

// Generic API rate limit: 300 req / minute / IP. Prevents scraping/abuse.
export const apiRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  message: { error: "Rate limit exceeded" },
  standardHeaders: true,
  legacyHeaders: false,
});

export const sensorRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100000,
  message: { error: "Too many sensor requests" },
  skipSuccessfulRequests: true,
});

export const errorHandler = (err, req, res, next) => {
  // CORS errors should be 403 with no stack leak
  if (err?.message?.startsWith("CORS:")) {
    return res.status(403).json({ error: "Forbidden" });
  }
  console.error(err.stack);
  const status = err.status || 500;
  const body = process.env.NODE_ENV === "production"
    ? { error: status === 500 ? "Internal server error" : err.message }
    : { error: err.message || "Internal server error", stack: err.stack };
  res.status(status).json(body);
};
