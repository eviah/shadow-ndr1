# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  Shadow NDR – World‑Class Health & Readiness Probes                      ║
║  Kubernetes‑ready, Prometheus‑integrated, production‑grade               ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import time
from datetime import datetime
from typing import Dict, Any, Optional, List

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from loguru import logger
from prometheus_client import Gauge, Histogram, Counter

from ..config import get_settings
from ..db import db
from .auth import get_current_user  # Optional, we will not use it for public health

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
    """Get cached value if still fresh."""
    entry = _health_cache.get(key)
    if entry and time.time() - entry["ts"] < _cache_ttl:
        return entry["value"]
    return None

def _set_cache(key: str, value: Any):
    _health_cache[key] = {"ts": time.time(), "value": value}

# =============================================================================
# Service check functions
# =============================================================================

async def check_postgresql() -> Dict[str, Any]:
    """Check PostgreSQL connectivity and pool stats."""
    start = time.time()
    try:
        # Use a timeout to avoid hanging
        async with asyncio.timeout(2.0):
            async with db.pg.acquire() as conn:
                await conn.fetchval("SELECT 1")
        latency = time.time() - start
        health_check_latency.labels(service="postgresql").observe(latency)
        health_check_status.labels(service="postgresql").set(1)

        # Get pool stats if available
        pool_stats = {}
        if hasattr(db.pg, "_pool") and db.pg._pool:
            pool_stats = {
                "size": db.pg._pool._max_size,
                "used": len(db.pg._pool._holders) - db.pg._pool._queue.qsize(),
                "free": db.pg._pool._queue.qsize(),
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

async def check_redis() -> Dict[str, Any]:
    """Check Redis connectivity."""
    start = time.time()
    try:
        async with asyncio.timeout(1.0):
            await db.redis.ping()
        latency = time.time() - start
        health_check_latency.labels(service="redis").observe(latency)
        health_check_status.labels(service="redis").set(1)
        return {"status": "ok", "latency_ms": round(latency * 1000, 2)}
    except Exception as e:
        health_check_status.labels(service="redis").set(0)
        health_check_errors_total.labels(service="redis").inc()
        logger.warning(f"Redis health check failed: {e}")
        return {"status": "error", "error": str(e), "latency_ms": None}

async def check_clickhouse() -> Dict[str, Any]:
    """Check ClickHouse connectivity."""
    start = time.time()
    try:
        async with asyncio.timeout(2.0):
            async with db.clickhouse_client.acquire() as conn:
                async with conn.cursor() as cursor:
                    await cursor.execute("SELECT 1")
        latency = time.time() - start
        health_check_latency.labels(service="clickhouse").observe(latency)
        health_check_status.labels(service="clickhouse").set(1)
        return {"status": "ok", "latency_ms": round(latency * 1000, 2)}
    except Exception as e:
        health_check_status.labels(service="clickhouse").set(0)
        health_check_errors_total.labels(service="clickhouse").inc()
        logger.warning(f"ClickHouse health check failed: {e}")
        return {"status": "error", "error": str(e), "latency_ms": None}

async def check_ml_service() -> Optional[Dict[str, Any]]:
    """Check ML service health via HTTP."""
    if not settings.ML_URL:
        return None
    start = time.time()
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"{settings.ML_URL}/health")
        latency = time.time() - start
        if resp.status_code == 200:
            health_check_status.labels(service="ml").set(1)
            return {"status": "ok", "latency_ms": round(latency * 1000, 2)}
        else:
            health_check_status.labels(service="ml").set(0)
            return {"status": "error", "http_code": resp.status_code, "latency_ms": round(latency * 1000, 2)}
    except Exception as e:
        health_check_status.labels(service="ml").set(0)
        health_check_errors_total.labels(service="ml").inc()
        return {"status": "error", "error": str(e), "latency_ms": None}

async def check_kafka() -> Optional[Dict[str, Any]]:
    """Check Kafka connectivity (optional)."""
    # Placeholder – implement if Kafka client is available
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
    # Try to get cached result
    cached = _get_cached("full_health")
    if cached:
        return cached

    # Run all checks concurrently
    tasks = {
        "postgresql": check_postgresql(),
        "redis": check_redis(),
        "clickhouse": check_clickhouse(),
    }
    # Optional services
    if settings.ML_URL:
        tasks["ml"] = check_ml_service()
    # Add Kafka if configured
    # tasks["kafka"] = check_kafka()

    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    services = {name: res for name, res in zip(tasks.keys(), results)}

    # Determine overall status
    critical_services = ["postgresql", "clickhouse"]  # Redis is not critical for API
    degraded = False
    for svc in critical_services:
        if svc not in services:
            continue
        svc_status = services[svc]
        if isinstance(svc_status, Exception) or svc_status.get("status") != "ok":
            degraded = True
            break

    overall = "degraded" if degraded else "healthy"
    http_status = status.HTTP_200_OK if not degraded else status.HTTP_503_SERVICE_UNAVAILABLE

    # Build response
    response = {
        "status": overall,
        "timestamp": datetime.utcnow().isoformat(),
        "version": getattr(settings, "VERSION", "1.0.0"),
        "instance": getattr(settings, "instance_id", "unknown"),
        "services": services,
    }

    # Cache for a few seconds
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
    # We'll run quick checks without caching
    tasks = {
        "postgresql": check_postgresql(),
        "clickhouse": check_clickhouse(),
    }
    # Optional: ML service not required for readiness
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    services = {name: res for name, res in zip(tasks.keys(), results)}

    critical_services = ["postgresql", "clickhouse"]
    ready = True
    for svc in critical_services:
        svc_status = services.get(svc)
        if isinstance(svc_status, Exception) or svc_status.get("status") != "ok":
            ready = False
            break

    status_code = status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ready" if ready else "not_ready",
        "timestamp": datetime.utcnow().isoformat(),
        "services": services,
    }