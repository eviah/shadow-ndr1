"""
SHADOW-ML v10.0 — Main Entry Point
Hardened FastAPI application.

Middleware order (outer → inner):
  1. TrustedHost    (allowlist)
  2. CORS           (allowlist)
  3. SecurityHeaders (nosniff/DENY/CSP/HSTS)
  4. AuditMiddleware (logs + IP blocklist + rate limit + size limit + auth gate)
  5. Router (public + canary)
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("shadow.main")


# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------

def _csv(name: str, default: str = "") -> list[str]:
    raw = os.environ.get(name, default).strip()
    return [p.strip() for p in raw.split(",") if p.strip()]


SHADOW_ENV = os.environ.get("SHADOW_ENV", "development").lower()
IS_PROD = SHADOW_ENV == "production"
CORS_ORIGINS = _csv("SHADOW_ML_CORS_ORIGINS", "http://localhost:3000,http://localhost:3002")
TRUSTED_HOSTS = _csv("SHADOW_ML_TRUSTED_HOSTS", "localhost,127.0.0.1,shadow-ml")
DISABLE_DOCS = os.environ.get("SHADOW_DISABLE_DOCS", "1" if IS_PROD else "0") == "1"
MAX_BODY_BYTES = int(os.environ.get("SHADOW_MAX_BODY_BYTES", str(1 * 1024 * 1024)))  # 1 MiB
ENABLE_HSTS = os.environ.get("SHADOW_HSTS", "0") == "1"


# ---------------------------------------------------------------------------
# Startup / shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    logger.info("=" * 70)
    logger.info("  SHADOW-ML v10.0 — env=%s | docs=%s", SHADOW_ENV, "off" if DISABLE_DOCS else "on")
    logger.info("=" * 70)

    try:
        from core.neural_engine import get_engine
        engine = get_engine()
        logger.info("Neural engine ready: v%s | %d layers", engine.VERSION, engine.TOTAL_LAYERS)
    except Exception as exc:
        logger.warning("Neural engine warm-up failed (non-fatal): %s", exc)

    try:
        from defense.canary_tokens import CanaryTokens
        canaries = CanaryTokens()
        batch = canaries.create_batch(count=24)
        logger.info("Canary arsenal: %d tokens across %d types", len(batch), len({t.token_type for t in batch}))
    except Exception as exc:
        logger.warning("Canary init failed (non-fatal): %s", exc)

    try:
        from monitoring.metrics import get_registry
        reg = get_registry()
        reg.knowledge_base_size.set(0)
        logger.info("Metrics registry initialised")
    except Exception as exc:
        logger.warning("Metrics init failed (non-fatal): %s", exc)

    try:
        from orchestrator.threat_consumer import get_threat_consumer
        threat_consumer = get_threat_consumer()
        asyncio.create_task(threat_consumer.start())
        logger.info("Threat consumer task created")
    except Exception as exc:
        logger.warning("Threat consumer init failed (non-fatal): %s", exc)

    logger.info("SHADOW-ML — ONLINE")
    logger.info("=" * 70)
    yield

    logger.info("SHADOW-ML shutting down gracefully...")
    try:
        from orchestrator.threat_consumer import get_threat_consumer
        get_threat_consumer().shutdown()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SHADOW-ML",
    version="10.0.0",
    description="Network Detection & Response ML platform.",
    docs_url=None if DISABLE_DOCS else "/docs",
    redoc_url=None if DISABLE_DOCS else "/redoc",
    openapi_url=None if DISABLE_DOCS else "/openapi.json",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Middleware — registered outer→inner in add order
# ---------------------------------------------------------------------------

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=TRUSTED_HOSTS or ["*"],  # keep permissive if user forgets env
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS or ["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
    max_age=600,
)

from core.security_headers import SecurityHeadersMiddleware  # noqa: E402

app.add_middleware(SecurityHeadersMiddleware, enable_hsts=ENABLE_HSTS)


# ---------------------------------------------------------------------------
# Audit + auth + rate-limit + size-limit middleware (one pass)
# ---------------------------------------------------------------------------

PUBLIC_PATHS = {
    "/",
    "/health",
    "/metrics",
    "/auth/login",
    "/openapi.json",
    "/docs",
    "/redoc",
    "/docs/oauth2-redirect",
    "/favicon.ico",
}
PUBLIC_PREFIXES = ("/static/",)

# Canary paths bypass auth so the tripwire fires and the attacker gets
# the 404 they're probing for (not a 401 that tells them the path exists).
try:
    from api.canary_routes import _CANARY_PATHS as _CANARY_PUBLIC
    PUBLIC_PATHS.update(_CANARY_PUBLIC)
except Exception:
    pass


def _is_public(path: str) -> bool:
    if path in PUBLIC_PATHS:
        return True
    for p in PUBLIC_PREFIXES:
        if path.startswith(p):
            return True
    return False


@app.middleware("http")
async def audit_middleware(request: Request, call_next) -> Response:
    from core.audit_log import record, critical as audit_critical
    from core.ip_blocklist import get_blocklist
    from core.rate_limiter import get_limiter

    t0 = time.perf_counter()
    ip = request.client.host if request.client else "unknown"
    path = request.url.path
    method = request.method
    blocklist = get_blocklist()

    # 1. Blocklist check
    if blocklist.is_blocked(ip):
        record({
            "ts": time.time(), "level": "warning", "event": "blocked_ip_hit",
            "ip": ip, "path": path, "method": method, "status": 403,
        })
        return JSONResponse(status_code=403, content={"error": "forbidden"})

    # 2. Rate limit
    allowed, retry = get_limiter().allow(ip, path)
    if not allowed:
        tripped = blocklist.record_failure(ip, threshold=200, window_seconds=60, block_seconds=900)
        headers = {"Retry-After": str(retry)}
        record({
            "ts": time.time(), "level": "warning", "event": "rate_limited",
            "ip": ip, "path": path, "method": method, "status": 429, "block_triggered": tripped,
        })
        return JSONResponse(status_code=429, content={"error": "rate_limited", "retry_after": retry}, headers=headers)

    # 3. Body size limit (via Content-Length; streaming bodies will be caught by uvicorn limits)
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_BODY_BYTES:
        record({
            "ts": time.time(), "level": "warning", "event": "oversize_body",
            "ip": ip, "path": path, "method": method, "status": 413, "content_length": int(cl),
        })
        return JSONResponse(status_code=413, content={"error": "payload_too_large"})

    # 4. Auth (except public paths)
    user_sub = "anonymous"
    if not _is_public(path):
        from api.auth import verify_auth_header
        payload = verify_auth_header(request)
        if payload is None:
            tripped = blocklist.record_failure(ip, threshold=30, window_seconds=60, block_seconds=900)
            record({
                "ts": time.time(), "level": "warning", "event": "auth_failed",
                "ip": ip, "path": path, "method": method, "status": 401, "block_triggered": tripped,
            })
            return JSONResponse(
                status_code=401,
                content={"error": "unauthorized"},
                headers={"WWW-Authenticate": 'Bearer realm="shadow-ml"'},
            )
        user_sub = str(payload.get("sub", "unknown"))
        request.state.auth = payload

    # 5. Downstream call
    try:
        response = await call_next(request)
    except Exception as exc:
        logger.exception("Unhandled error on %s %s", method, path)
        record({
            "ts": time.time(), "level": "error", "event": "unhandled_exception",
            "ip": ip, "path": path, "method": method, "status": 500, "error": str(exc),
        })
        return JSONResponse(status_code=500, content={"error": "internal_server_error"})

    elapsed_ms = (time.perf_counter() - t0) * 1000
    response.headers["X-Shadow-Version"] = "10.0.0"
    response.headers["X-Processing-Ms"] = str(round(elapsed_ms, 2))

    # Metrics (best-effort)
    try:
        from monitoring.metrics import get_registry
        reg = get_registry()
        reg.api_requests.inc()
        reg.api_latency_ms.observe(elapsed_ms)
        if response.status_code >= 400:
            reg.api_errors.inc()
    except Exception:
        pass

    # Audit log (single line per request)
    record({
        "ts": time.time(), "event": "http_request",
        "ip": ip, "path": path, "method": method, "status": response.status_code,
        "latency_ms": round(elapsed_ms, 2), "user": user_sub,
        "user_agent": request.headers.get("user-agent", "")[:200],
    })

    return response


# ---------------------------------------------------------------------------
# Routers — canaries FIRST so real routes can't shadow them
# ---------------------------------------------------------------------------

from api.canary_routes import canary_router  # noqa: E402
app.include_router(canary_router, prefix="")

from api.routes import router as api_router  # noqa: E402
app.include_router(api_router, prefix="")

try:
    from apex.routes import router as apex_router  # noqa: E402
    app.include_router(apex_router, prefix="")
    logger.info("APEX router loaded: /apex/proof, /apex/ghost, /apex/vault, /apex/swarm")
except Exception as exc:
    logger.warning("APEX router not loaded (non-fatal): %s", exc)


# ---------------------------------------------------------------------------
# Exception handlers
# ---------------------------------------------------------------------------

@app.exception_handler(404)
async def not_found(_request: Request, _exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=404, content={"error": "not_found"})


@app.exception_handler(500)
async def server_error(_request: Request, _exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=500, content={"error": "internal_server_error"})


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("SHADOW_ML_PORT", "8001"))
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        workers=int(os.environ.get("SHADOW_ML_WORKERS", "1")),
        reload=False,
        log_level="info",
        access_log=False,  # replaced by audit middleware
        timeout_keep_alive=5,
        limit_concurrency=int(os.environ.get("SHADOW_ML_CONCURRENCY", "100")),
        limit_max_requests=int(os.environ.get("SHADOW_ML_MAX_REQUESTS", "10000")),
    )
