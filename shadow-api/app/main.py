# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  Shadow NDR – Ultimate FastAPI Application                               ║
║  Production‑grade, AI‑ready, high‑performance aviation NDR API           ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import time
import uuid
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from loguru import logger
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from .config import get_settings
from .db import db
from .routes import health, threats, assets, ml, auth, sensor_integration, breach_horizon

# =============================================================================
# Settings
# =============================================================================
settings = get_settings()

# =============================================================================
# Rate limiter (global)
# =============================================================================
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

# =============================================================================
# Prometheus metrics
# =============================================================================
http_requests_total = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)
http_request_duration_seconds = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration",
    ["method", "path"],
)

# =============================================================================
# Middleware: Request ID
# =============================================================================
async def request_id_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response

# =============================================================================
# Middleware: Logging & Metrics
# =============================================================================
async def logging_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    http_requests_total.labels(
        method=request.method,
        path=request.url.path,
        status=response.status_code,
    ).inc()
    http_request_duration_seconds.labels(
        method=request.method,
        path=request.url.path,
    ).observe(duration)
    logger.info(
        f"{request.method} {request.url.path} - {response.status_code} - {duration:.3f}s",
        extra={
            "request_id": getattr(request.state, "request_id", None),
            "client_ip": request.client.host,
            "user_agent": request.headers.get("user-agent", ""),
        },
    )
    return response

# =============================================================================
# Middleware: Security Headers
# =============================================================================
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# =============================================================================
# Global exception handlers
# =============================================================================
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "status_code": exc.status_code,
            "request_id": getattr(request.state, "request_id", None),
        },
    )

async def validation_exception_handler(request: Request, exc):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": exc.errors(),
            "request_id": getattr(request.state, "request_id", None),
        },
    )

async def generic_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error",
            "request_id": getattr(request.state, "request_id", None),
        },
    )

# =============================================================================
# Lifespan (startup/shutdown)
# =============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("🚀 Starting Shadow NDR API v{}", settings.VERSION if hasattr(settings, "VERSION") else "1.0.0")
    try:
        await db.connect()
        logger.info("✅ Database connections established")
        db_connected = True
    except Exception as e:
        logger.warning(f"⚠️  Database connection failed (continuing without DB): {e}")
        db_connected = False
        app.state.db_connected = False

    if db_connected:
        app.state.db_connected = True

    yield

    # Shutdown
    logger.info("🛑 Shutting down...")
    if db_connected:
        await db.close()
    logger.info("✅ Graceful shutdown complete")

# =============================================================================
# FastAPI app
# =============================================================================
app = FastAPI(
    title="Shadow NDR – Aviation Cybersecurity API",
    description="Aviation Network Detection & Response – AI-powered cyber defense for airlines, aircraft, and airports. Monitors ADS-B, ACARS, SATCOM, Mode-S and ground IT networks in real time.",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
    openapi_tags=[
        {"name": "System", "description": "Health, metrics, and system information"},
        {"name": "Authentication", "description": "User login, registration, token refresh"},
        {"name": "Threats", "description": "Threat detection, statistics, and predictions"},
        {"name": "Assets", "description": "Asset inventory and risk assessment"},
        {"name": "Machine Learning", "description": "ML service proxy and model information"},
    ],
)

# =============================================================================
# Add middleware
# =============================================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.security.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])  # restrict in production
app.middleware("http")(request_id_middleware)
app.middleware("http")(logging_middleware)
app.middleware("http")(security_headers_middleware)

# =============================================================================
# Exception handlers
# =============================================================================
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_exception_handler(Exception, generic_exception_handler)

# =============================================================================
# Include routers (with version prefix)
# =============================================================================
api_v1 = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
api_v1.include_router(health.router)
api_v1.include_router(threats.router)
api_v1.include_router(assets.router)
api_v1.include_router(ml.router)
api_v1.include_router(auth.router)
api_v1.include_router(sensor_integration.router)
api_v1.include_router(breach_horizon.router)

app.mount("/api/v1", api_v1)

# Also keep root routes for backward compatibility (optional)
app.include_router(health.router)
app.include_router(threats.router)
app.include_router(assets.router)
app.include_router(ml.router)
app.include_router(auth.router)
app.include_router(sensor_integration.router)
app.include_router(breach_horizon.router)

# =============================================================================
# Root endpoint
# =============================================================================
@app.get("/", include_in_schema=False)
async def root() -> Dict[str, Any]:
    return {
        "name": "Shadow NDR API",
        "version": "2.0.0",
        "docs": "/docs",
        "api_v1": "/api/v1",
        "status": "operational",
        "environment": settings.environment.value,
        "instance": getattr(settings, "instance_id", "unknown"),
    }

# =============================================================================
# Prometheus metrics endpoint
# =============================================================================
@app.get("/metrics", include_in_schema=False)
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

# =============================================================================
# Live/Ready probes (for Kubernetes)
# =============================================================================
@app.get("/live", include_in_schema=False)
async def liveness():
    return {"status": "alive"}

@app.get("/ready", include_in_schema=False)
async def readiness():
    # Basic readiness: check database connection quickly
    try:
        await db.pg.fetchval("SELECT 1")
        return {"status": "ready"}
    except Exception:
        return Response(status_code=503, content={"status": "not ready"})

# =============================================================================
# Optional: run with uvicorn (if __name__ == "__main__")
# =============================================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.server.host,
        port=settings.server.port,
        reload=settings.server.reload,
        workers=settings.server.workers,
        log_level=settings.logging.level.value.lower(),
    )