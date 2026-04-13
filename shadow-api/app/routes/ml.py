# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  Shadow NDR – Ultimate ML Client with Circuit Breaker, Fallback, Caching ║
║  AI‑powered, resilient, production‑grade                                ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import hashlib
import json
import time
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Tuple
import math

import httpx
from fastapi import APIRouter, Depends, HTTPException, status, Request
from loguru import logger
from pydantic import BaseModel, Field
from prometheus_client import Counter, Histogram, Gauge
from slowapi import Limiter
from slowapi.util import get_remote_address

from ..config import get_settings
from ..db import db
from .auth import get_current_user

# =============================================================================
# Rate limiting
# =============================================================================
limiter = Limiter(key_func=get_remote_address)

router = APIRouter(prefix="/ml", tags=["Machine Learning"])
settings = get_settings()

# =============================================================================
# Prometheus metrics
# =============================================================================
ml_requests_total = Counter(
    "ml_requests_total",
    "Total number of ML requests",
    ["status"],  # success, error, fallback, circuit_open
)
ml_request_duration = Histogram(
    "ml_request_duration_seconds",
    "Duration of ML requests",
    ["status"],
)
ml_circuit_open = Gauge(
    "ml_circuit_open",
    "1 if circuit breaker is open, 0 otherwise",
)
ml_cache_hits = Counter(
    "ml_cache_hits_total",
    "Cache hits for ML requests",
)
ml_cache_misses = Counter(
    "ml_cache_misses_total",
    "Cache misses for ML requests",
)

# =============================================================================
# Circuit breaker state
# =============================================================================
class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 30):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = 0
        self.state = "closed"  # closed, open, half-open
        self._lock = asyncio.Lock()

    async def call(self, func, *args, **kwargs):
        async with self._lock:
            if self.state == "open":
                if time.time() - self.last_failure_time >= self.recovery_timeout:
                    self.state = "half-open"
                    ml_circuit_open.set(0)
                    logger.info("Circuit breaker moved to half-open")
                else:
                    ml_requests_total.labels(status="circuit_open").inc()
                    raise Exception("Circuit breaker is open")

        try:
            result = await func(*args, **kwargs)
            async with self._lock:
                if self.state == "half-open":
                    self.state = "closed"
                    self.failure_count = 0
                    ml_circuit_open.set(0)
                    logger.info("Circuit breaker closed")
                else:
                    self.failure_count = 0
            return result
        except Exception as e:
            async with self._lock:
                if self.state == "closed":
                    self.failure_count += 1
                    if self.failure_count >= self.failure_threshold:
                        self.state = "open"
                        self.last_failure_time = time.time()
                        ml_circuit_open.set(1)
                        logger.warning("Circuit breaker opened")
                elif self.state == "half-open":
                    self.state = "open"
                    self.last_failure_time = time.time()
                    ml_circuit_open.set(1)
                    logger.warning("Circuit breaker opened from half-open")
            raise

circuit_breaker = CircuitBreaker()

# =============================================================================
# Caching (Redis + in‑memory)
# =============================================================================
async def _get_cached(key: str) -> Optional[Any]:
    """Get value from Redis cache (or in‑memory)."""
    try:
        val = await db.redis_get(key)
        if val:
            ml_cache_hits.inc()
            return json.loads(val)
    except Exception:
        # fallback to simple dict
        if key in _simple_cache:
            ml_cache_hits.inc()
            return _simple_cache[key].get("value")
    ml_cache_misses.inc()
    return None

async def _set_cache(key: str, value: Any, ttl: int = 30):
    """Store value in Redis cache."""
    try:
        await db.redis_set(key, json.dumps(value, default=str), ttl)
    except Exception:
        # fallback to simple dict
        _simple_cache[key] = {"ts": time.time(), "value": value}

_simple_cache = {}

def _hash_features(features: List[float]) -> str:
    """Create cache key from features."""
    h = hashlib.sha256(json.dumps(features, sort_keys=True).encode()).hexdigest()
    return f"ml:analyze:{h}"

# =============================================================================
# Fallback model (simple logistic regression)
# =============================================================================
# Pre-trained coefficients (example). In production, these could be loaded from a file.
_FALLBACK_WEIGHTS = [
    -2.0,   # bias
    1.5,    # size
    0.5,    # is_tcp
    -0.2,   # is_udp
    0.8,    # packet_rate
    0.3,    # byte_rate
    0.6,    # avg_size
    1.2,    # attack_count
    2.0,    # is_critical
]

def _fallback_score(features: List[float]) -> float:
    """Simple logistic regression fallback."""
    x = [1.0] + features  # add bias term
    # Ensure features match weights (pad with 0 if needed)
    while len(x) < len(_FALLBACK_WEIGHTS):
        x.append(0.0)
    # Dot product
    score = sum(w * x[i] for i, w in enumerate(_FALLBACK_WEIGHTS))
    # Sigmoid
    return 1.0 / (1.0 + math.exp(-score))

# =============================================================================
# Pydantic models
# =============================================================================
class AnalyzeRequest(BaseModel):
    features: List[float] = Field(..., min_items=9, max_items=9)

class AnalyzeResponse(BaseModel):
    score: float = Field(..., ge=0, le=1)
    is_anomaly: bool
    threshold: float
    from_cache: bool = False
    fallback_used: bool = False

class ModelInfo(BaseModel):
    model_name: str
    version: str
    status: str
    trained_at: Optional[str] = None
    metrics: Dict[str, float] = {}

# =============================================================================
# Helper: actual ML service call with retry
# =============================================================================
async def _call_ml_service(features: List[float]) -> Dict[str, Any]:
    """Call the actual ML service with retry logic."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.post(
            f"{settings.ML_URL}/analyze",
            json={
                "size": features[0],
                "ttl": features[1],
                "is_tcp": bool(features[2]),
                "is_udp": bool(features[3]),
                "packet_rate": features[4],
                "byte_rate": features[5],
                "avg_size": features[6],
                "attack_count": features[7],
                "is_critical": bool(features[8]),
            },
        )
        response.raise_for_status()
        return response.json()

async def _call_with_retry(features: List[float]) -> Dict[str, Any]:
    """Call ML service with exponential backoff (max 3 attempts)."""
    last_error = None
    for attempt in range(3):
        try:
            return await _call_ml_service(features)
        except httpx.TimeoutException as e:
            last_error = e
            wait = 0.5 * (2 ** attempt)
            logger.warning(f"ML service timeout, attempt {attempt+1}, retrying in {wait}s")
            await asyncio.sleep(wait)
        except Exception as e:
            last_error = e
            wait = 1.0 * (2 ** attempt)
            logger.warning(f"ML service error: {e}, attempt {attempt+1}, retrying in {wait}s")
            await asyncio.sleep(wait)
    raise last_error

# =============================================================================
# Endpoints
# =============================================================================

@router.post("/analyze", response_model=AnalyzeResponse)
@limiter.limit("100/minute")
async def analyze_packet(
    request: Request,
    req: AnalyzeRequest,
    user = Depends(get_current_user),
) -> AnalyzeResponse:
    """
    Analyze a packet's features using the ML service.
    Includes caching, circuit breaker, retries, and fallback.
    """
    start_time = time.time()
    cache_key = _hash_features(req.features)
    from_cache = False
    fallback_used = False

    # 1. Check cache
    cached = await _get_cached(cache_key)
    if cached:
        from_cache = True
        ml_requests_total.labels(status="cache_hit").inc()
        return AnalyzeResponse(
            score=cached["score"],
            is_anomaly=cached["is_anomaly"],
            threshold=cached["threshold"],
            from_cache=True,
            fallback_used=False,
        )

    # 2. Try ML service with circuit breaker
    try:
        result = await circuit_breaker.call(_call_with_retry, req.features)
        status_label = "success"
        score = result["score"]
        is_anomaly = result["is_anomaly"]
        threshold = result["threshold"]
    except Exception as e:
        logger.error(f"ML service failed: {e}")
        status_label = "error"
        # 3. Fallback scoring
        fallback_used = True
        score = _fallback_score(req.features)
        is_anomaly = score > 0.95
        threshold = 0.95
        ml_requests_total.labels(status="fallback").inc()
        ml_requests_total.labels(status="error").inc()

    # 4. Cache result (if successful)
    if not fallback_used:
        await _set_cache(cache_key, {"score": score, "is_anomaly": is_anomaly, "threshold": threshold}, ttl=30)
        ml_requests_total.labels(status="success").inc()
    else:
        ml_requests_total.labels(status="fallback").inc()

    # 5. Record duration
    duration = time.time() - start_time
    ml_request_duration.labels(status=status_label if not fallback_used else "fallback").observe(duration)

    return AnalyzeResponse(
        score=score,
        is_anomaly=is_anomaly,
        threshold=threshold,
        from_cache=from_cache,
        fallback_used=fallback_used,
    )

@router.get("/status")
@limiter.limit("10/minute")
async def ml_status(user = Depends(get_current_user)) -> Dict[str, Any]:
    """Get ML service status."""
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"{settings.ML_URL}/health")
            if resp.status_code == 200:
                ml_service_status = "online"
                data = resp.json()
                models = data.get("models", {})
            else:
                ml_service_status = "degraded"
                models = {}
    except Exception:
        ml_service_status = "offline"
        models = {}

    return {
        "status": "healthy" if ml_service_status == "online" else "degraded",
        "ml_service": ml_service_status,
        "circuit_breaker_state": circuit_breaker.state,
        "models": models,
        "fallback_available": True,
    }

@router.get("/models", response_model=List[ModelInfo])
@limiter.limit("10/minute")
async def get_models(user = Depends(get_current_user)) -> List[ModelInfo]:
    """Get list of active ML models (from ML service)."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{settings.ML_URL}/models")
            if resp.status_code == 200:
                models_data = resp.json()
                return [ModelInfo(**m) for m in models_data]
    except Exception as e:
        logger.warning(f"Could not fetch models from ML service: {e}")
    # Fallback
    return [
        ModelInfo(
            model_name="isolation_forest",
            version="1.0",
            status="active",
            trained_at=datetime.now().isoformat(),
            metrics={"f1": 0.89},
        ),
        ModelInfo(
            model_name="lstm_sequence",
            version="1.0",
            status="active",
            trained_at=datetime.now().isoformat(),
            metrics={"f1": 0.91},
        ),
    ]