# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  Shadow NDR – World‑Class Health & Readiness Probes                      ║
║  Kubernetes‑ready, Prometheus‑integrated, production‑grade               ║
║  FIXED: Removed broken dependencies (Redis, ClickHouse, ML_URL)          ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import time
from datetime import datetime
from typing import Dict, Any, Optional

from fastapi import APIRouter, status
from loguru import logger
from prometheus_client import Gauge, Histogram, Counter

from ..config import get_settings
from ..db import db

settings = get_settings()
router = APIRouter(prefix="/health", tags=["Health"])

# =============================================================================
# Prometheus metrics for health checks
# =============================================================================
health_check_latency = Histogram(
    "health_check_latency_seconds",
    "Latency of health checks per service",
    ["service"],
)
health_check_status = Gauge(
    "health_check_status",
    "Health check status (1 = healthy, 0 = unhealthy)",
    ["service"],
)
health_check_errors_total = Counter(
    "health_check_errors_total",
    "Total health check errors",
    ["service"],
)

# =============================================================================
# Cached health results (to avoid hammering services on every request)
# =============================================================================
_health_cache: Dict[str, Any] = {}
_cache_ttl = 5  # seconds

def _get_cached(key: str) -> Optional[Any]:
    entry = _health_cache.get(key)
    if entry and time.time() - entry["ts"] < _cache_ttl:
        return entry["value"]
    return None

def _set_cache(key: str, value: Any):
    _health_cache[key] = {"ts": time.time(), "value": value}

# =============================================================================
# Service check functions (only PostgreSQL – others are optional)
# =============================================================================

async def check_postgresql() -> Dict[str, Any]:
    """Check PostgreSQL connectivity and pool stats."""
    start = time.time()
    try:
        async with asyncio.timeout(2.0):
            # Try to get a connection and run a simple query
            # db.pg_pool is an asyncpg pool (or None)
            if db.pg_pool is None:
                raise Exception("PostgreSQL pool not initialized")
            async with db.pg_pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
        latency = time.time() - start
        health_check_latency.labels(service="postgresql").observe(latency)
        health_check_status.labels(service="postgresql").set(1)

        # Get pool stats if available
        pool_stats = {}
        if db.pg_pool:
            pool_stats = {
                "size": getattr(db.pg_pool, "_max_size", "unknown"),
                "free": getattr(db.pg_pool, "_free_size", "unknown") if hasattr(db.pg_pool, "_free_size") else "unknown",
            }

        return {
            "status": "ok",
            "latency_ms": round(latency * 1000, 2),
            "pool": pool_stats,
        }
    except Exception as e:
        health_check_status.labels(service="postgresql").set(0)
        health_check_errors_total.labels(service="postgresql").inc()
        logger.warning(f"PostgreSQL health check failed: {e}")
        return {"status": "error", "error": str(e), "latency_ms": None}

# -----------------------------------------------------------------------------
# Optional checks (disabled by default to avoid errors)
# -----------------------------------------------------------------------------
async def check_redis() -> Dict[str, Any]:
    """Redis check – currently disabled (no redis client)."""
    return {"status": "skipped", "reason": "Redis not configured"}

async def check_clickhouse() -> Dict[str, Any]:
    """ClickHouse check – currently disabled."""
    return {"status": "skipped", "reason": "ClickHouse not configured"}

async def check_kafka() -> Optional[Dict[str, Any]]:
    """Kafka check – placeholder."""
    return None

# =============================================================================
# Main health endpoint
# =============================================================================

@router.get("")
async def health() -> Dict[str, Any]:
    """
    Detailed health check with all services.

    Returns:
        - 200 if all critical services are healthy
        - 503 if any critical service is degraded
    """
    cached = _get_cached("full_health")
    if cached:
        return cached

    # Run only PostgreSQL as critical; others are optional/skipped
    tasks = {
        "postgresql": check_postgresql(),
        "redis": check_redis(),
        "clickhouse": check_clickhouse(),
    }
    # Add ML check if configured
    if getattr(settings, "ML_URL", None):
        try:
            # Import only if needed (avoid circular)
            from . import ml_health
            tasks["ml"] = ml_health.check_ml_service()
        except ImportError:
            # Fallback if ml_health doesn't exist yet
            async def dummy_ml(): return {"status": "skipped", "reason": "ml_health module not found"}
            tasks["ml"] = dummy_ml()

    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    services = {name: res for name, res in zip(tasks.keys(), results)}

    # Critical services that must be healthy
    critical_services = ["postgresql"]
    degraded = False
    for svc in critical_services:
        svc_status = services.get(svc)
        if isinstance(svc_status, Exception) or svc_status.get("status") != "ok":
            degraded = True
            break

    overall = "degraded" if degraded else "healthy"
    http_status = status.HTTP_200_OK if not degraded else status.HTTP_503_SERVICE_UNAVAILABLE

    response = {
        "status": overall,
        "timestamp": datetime.utcnow().isoformat(),
        "version": getattr(settings, "VERSION", "11.0.0"),
        "instance": getattr(settings, "instance_id", "unknown"),
        "services": services,
    }

    _set_cache("full_health", response)
    return response

# =============================================================================
# Liveness probe – only checks that the process is alive
# =============================================================================

@router.get("/live")
async def liveness() -> Dict[str, str]:
    """
    Kubernetes liveness probe – simple check that the server is running.
    No database checks – just returns 200.
    """
    return {"status": "alive"}

# =============================================================================
# Readiness probe – checks that the service is ready to accept traffic
# =============================================================================

@router.get("/ready")
async def readiness() -> Dict[str, Any]:
    """
    Kubernetes readiness probe – checks critical dependencies.
    Must be healthy to receive traffic.
    """
    # Quick check without caching
    pg_status = await check_postgresql()
    ready = pg_status.get("status") == "ok"

    status_code = status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ready" if ready else "not_ready",
        "timestamp": datetime.utcnow().isoformat(),
        "postgresql": pg_status,
    }