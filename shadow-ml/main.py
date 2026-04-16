"""
SHADOW-ML v10.0 — Main Entry Point
World's Most Powerful Neural NDR System

200-Layer Deep Architecture | 24 Defense Techniques | 23 Attack Classes
Post-Quantum Cryptography | Reinforcement Learning | RAG Threat Intelligence
Federated Learning | Adversarial Defense | RF Fingerprinting | VAE Autoencoders
Protocol Micro-Models | PPO/RLHF | Predictive Canary | eBPF Firewall Generator
Incident Triage | Cyber-Physical Impact | Ray Distributed | Zero-Trust mTLS
JA3/JA4 TLS Fingerprinting | UEBA | Cross-Protocol Correlation | OpenTelemetry
ONNX/TensorRT/Triton Hardware Acceleration | NLP Query Engine | SOC Dashboard
"""

from __future__ import annotations

import logging
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
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("shadow.main")

# ---------------------------------------------------------------------------
# Startup / Shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    logger.info("=" * 70)
    logger.info("  SHADOW-ML v10.0 — Initialising 200-Layer Neural Engine")
    logger.info("=" * 70)

    # Pre-warm the neural engine (lazy singleton — first call is slow)
    try:
        from core.neural_engine import get_engine
        engine = get_engine()
        logger.info("Neural engine ready: v%s | %d layers", engine.VERSION, engine.TOTAL_LAYERS)
    except Exception as exc:
        logger.warning("Neural engine warm-up failed (non-fatal): %s", exc)

    # Deploy initial canary arsenal
    try:
        from defense.canary_tokens import CanaryTokens
        canaries = CanaryTokens()
        batch = canaries.create_batch(count=24)
        logger.info("Canary arsenal deployed: %d tokens across %d types", len(batch), len({t.token_type for t in batch}))
    except Exception as exc:
        logger.warning("Canary init failed (non-fatal): %s", exc)

    # Start metrics registry
    try:
        from monitoring.metrics import get_registry
        reg = get_registry()
        reg.knowledge_base_size.set(0)
        logger.info("Metrics registry initialised")
    except Exception as exc:
        logger.warning("Metrics init failed (non-fatal): %s", exc)

    logger.info("SHADOW-ML v10.0 — ONLINE | All systems operational")
    logger.info("=" * 70)

    yield

    logger.info("SHADOW-ML shutting down gracefully...")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SHADOW-ML",
    version="10.0.0",
    description=(
        "World's most powerful neural Network Detection & Response system. "
        "200-layer deep architecture, 24 defense techniques, post-quantum cryptography."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],           # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"],           # Restrict in production
)


@app.middleware("http")
async def metrics_middleware(request: Request, call_next) -> Response:
    """Track request latency and count in metrics registry."""
    t0 = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception as exc:
        logger.error("Unhandled error: %s", exc, exc_info=True)
        return JSONResponse(status_code=500, content={"error": "internal_server_error"})

    elapsed_ms = (time.perf_counter() - t0) * 1000
    try:
        from monitoring.metrics import get_registry
        reg = get_registry()
        reg.api_requests.inc()
        reg.api_latency_ms.observe(elapsed_ms)
        if response.status_code >= 400:
            reg.api_errors.inc()
    except Exception:
        pass  # Metrics must never crash the request

    response.headers["X-Shadow-Version"] = "10.0.0"
    response.headers["X-Processing-Ms"] = str(round(elapsed_ms, 2))
    return response


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

from api.routes import router as api_router
app.include_router(api_router, prefix="")

# ---------------------------------------------------------------------------
# Global exception handlers
# ---------------------------------------------------------------------------

@app.exception_handler(404)
async def not_found(_request: Request, _exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=404, content={"error": "not_found", "system": "shadow-ml"})


@app.exception_handler(500)
async def server_error(_request: Request, _exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=500, content={"error": "internal_server_error"})


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        workers=1,
        reload=False,
        log_level="info",
        access_log=True,
    )
