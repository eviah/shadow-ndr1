#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║   shadow-ml – Machine Learning Service for Shadow NDR                     ║
║   Production‑grade API with authentication, rate limiting, metrics       ║
╚═══════════════════════════════════════════════════════════════════════════╝

Real‑time anomaly detection and attack prediction for railway networks.
"""

import asyncio
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated, Any, Dict, List, Optional

import numpy as np
from fastapi import (
    FastAPI,
    HTTPException,
    BackgroundTasks,
    Depends,
    Request,
    Response,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from loguru import logger
from prometheus_client import generate_latest, REGISTRY, Counter, Histogram
from pydantic import BaseModel, Field, ConfigDict
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import uvicorn

from .config import get_settings
from .database import db
from .features import feature_extractor
from .models.anomaly import anomaly_detector
from .models.predictor import predictor
from .models.trainer import trainer

settings = get_settings()

# =============================================================================
# Prometheus metrics (additional)
# =============================================================================

http_requests_total = Counter(
    "http_requests_total", "Total HTTP requests", ["method", "endpoint", "status"]
)
http_request_duration_seconds = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration",
    ["method", "endpoint"],
)

# =============================================================================
# Rate limiting
# =============================================================================

limiter = Limiter(key_func=get_remote_address)

# =============================================================================
# Authentication (simple API key)
# =============================================================================

security = HTTPBearer(auto_error=False)

async def verify_api_key(credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(security)]):
    if settings.environment == "development":
        # In development, allow all requests without token
        return {"user": "dev", "org": "dev"}
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    api_key = credentials.credentials
    # Here you would validate against a secure store (e.g., database or env)
    # For simplicity, we compare with a single key from settings
    if api_key != settings.secret_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    # Optionally return user info
    return {"user": "ml_client", "org": "shadow"}

# =============================================================================
# Pydantic models (v2)
# =============================================================================

class PacketFeatures(BaseModel):
    """Features extracted from a network packet."""
    size: float = Field(..., ge=0, le=1500, description="Packet size (normalized)")
    ttl: float = Field(..., ge=0, le=1, description="TTL normalized to 0-1")
    is_tcp: bool = Field(..., description="True if TCP")
    is_udp: bool = Field(..., description="True if UDP")
    packet_rate: float = Field(..., ge=0, le=1, description="Packet rate (normalized)")
    byte_rate: float = Field(..., ge=0, le=1, description="Byte rate (normalized)")
    avg_size: float = Field(..., ge=0, le=1, description="Average packet size (normalized)")
    attack_count: float = Field(..., ge=0, le=1, description="Recent attack count (normalized)")
    is_critical: bool = Field(..., description="Whether packet contains critical command")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "size": 0.5,
                "ttl": 0.25,
                "is_tcp": True,
                "is_udp": False,
                "packet_rate": 0.3,
                "byte_rate": 0.1,
                "avg_size": 0.4,
                "attack_count": 0.0,
                "is_critical": False,
            }
        }
    )


class AnomalyResponse(BaseModel):
    """Response from anomaly detection."""
    score: float = Field(..., ge=0, le=1, description="Anomaly score (0=normal, 1=anomalous)")
    is_anomaly: bool = Field(..., description="True if the packet is anomalous")
    threshold: float = Field(..., description="Current threshold used")
    timestamp: datetime = Field(..., description="Timestamp of analysis")


class PredictionResponse(BaseModel):
    """Response from attack prediction."""
    predictions: List[float] = Field(..., description="Forecasted attack probabilities")
    horizon_minutes: int = Field(..., description="Forecast horizon in minutes")
    confidence: float = Field(..., ge=0, le=1, description="Confidence in prediction")
    change_point_detected: bool = Field(..., description="Whether a change point was detected")
    generated_at: datetime = Field(..., description="Timestamp when prediction was generated")


class ModelStatus(BaseModel):
    """Status of ML models."""
    anomaly_model_trained: bool = Field(..., description="Anomaly detector is trained")
    predictor_model_trained: bool = Field(..., description="Predictor is trained")
    last_training: Optional[datetime] = Field(None, description="Last successful training time")
    total_packets_processed: int = Field(..., description="Packets processed since last restart")


class TrainingResponse(BaseModel):
    """Response from triggering training."""
    message: str = Field(..., description="Status message")
    timestamp: datetime = Field(..., description="Request timestamp")
    run_id: Optional[str] = Field(None, description="Unique identifier for this training run")


class HealthResponse(BaseModel):
    """Detailed health status."""
    status: str = Field(..., description="Overall health (healthy/degraded/unhealthy)")
    version: str = Field(..., description="Service version")
    timestamp: datetime = Field(..., description="Current server time")
    models: Dict[str, bool] = Field(..., description="Model readiness")
    database: Dict[str, str] = Field(..., description="Database connectivity status")
    uptime_seconds: float = Field(..., description="Seconds since service started")


# =============================================================================
# Startup / shutdown
# =============================================================================

_start_time = datetime.utcnow()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage startup and shutdown events."""
    # Startup
    logger.info("🚀 Starting shadow-ml service...")
    try:
        await db.connect()
        logger.info("✅ Database connected")
    except Exception as e:
        logger.critical(f"❌ Database connection failed: {e}")
        # Depending on policy, we might want to crash or continue
        # We'll continue but mark as degraded in health checks

    # Start background training loop
    trainer_task = asyncio.create_task(trainer.training_loop())
    logger.info("✅ Background trainer started")

    yield

    # Shutdown
    logger.info("🛑 Shutting down shadow-ml service...")
    trainer_task.cancel()
    try:
        await trainer_task
    except asyncio.CancelledError:
        pass
    await db.close()
    logger.info("✅ Shutdown complete")


app = FastAPI(
    title="Shadow NDR ML Service",
    description="Machine Learning service for railway network security",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {
            "name": "System",
            "description": "Health, metrics, and status endpoints",
        },
        {
            "name": "Detection",
            "description": "Real‑time anomaly detection",
        },
        {
            "name": "Prediction",
            "description": "Attack forecasting",
        },
        {
            "name": "Management",
            "description": "Model training and status management",
        },
    ],
)

# =============================================================================
# CORS (allow any for simplicity; restrict in production)
# =============================================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# Rate limiting exception handler
# =============================================================================
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# =============================================================================
# Middleware: Request ID, Logging, Timing, Metrics
# =============================================================================

@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Add a unique request ID for tracing."""
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log each request with timing."""
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    logger.info(
        f"Request completed",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        duration_ms=round(duration * 1000, 2),
        request_id=request.state.request_id,
    )
    return response


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """Collect Prometheus metrics for requests."""
    method = request.method
    path = request.url.path
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    http_requests_total.labels(method=method, endpoint=path, status=response.status_code).inc()
    http_request_duration_seconds.labels(method=method, endpoint=path).observe(duration)
    return response


# =============================================================================
# Exception handlers
# =============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Return RFC 7807 problem details for HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "type": "about:blank",
            "title": "HTTP Exception",
            "status": exc.status_code,
            "detail": exc.detail,
            "instance": request.url.path,
            "request_id": request.state.request_id,
        },
        headers=exc.headers,
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions."""
    logger.exception("Unhandled exception", request_id=request.state.request_id)
    return JSONResponse(
        status_code=500,
        content={
            "type": "about:blank",
            "title": "Internal Server Error",
            "status": 500,
            "detail": "An unexpected error occurred",
            "instance": request.url.path,
            "request_id": request.state.request_id,
        },
    )


# =============================================================================
# Dependency for getting feature vector (with validation)
# =============================================================================

def feature_vector_from_packet(features: PacketFeatures) -> np.ndarray:
    """Convert PacketFeatures to numpy array for model input."""
    return np.array([
        features.size,
        features.ttl,
        float(features.is_tcp),
        float(features.is_udp),
        features.packet_rate,
        features.byte_rate,
        features.avg_size,
        features.attack_count,
        float(features.is_critical),
    ], dtype=np.float32)


# =============================================================================
# Routes
# =============================================================================

@app.get("/health", response_model=HealthResponse, tags=["System"])
@limiter.limit("10/minute")  # rate limit for health checks
async def health(request: Request):
    """
    Detailed health check.

    Returns status of the service, models, and databases.
    """
    # Check database connectivity
    db_status = await db.health_check() if hasattr(db, 'health_check') else {"clickhouse": "unknown", "redis": "unknown"}

    uptime = (datetime.utcnow() - _start_time).total_seconds()

    return HealthResponse(
        status="healthy" if all(db_status.values()) else "degraded",
        version=app.version,
        timestamp=datetime.utcnow(),
        models={
            "anomaly": anomaly_detector.model is not None,
            "predictor": predictor.model is not None,
        },
        database=db_status,
        uptime_seconds=uptime,
    )


@app.get("/metrics", tags=["System"])
async def metrics():
    """Prometheus metrics endpoint."""
    return PlainTextResponse(generate_latest(REGISTRY).decode("utf-8"))


@app.post("/analyze",
          response_model=AnomalyResponse,
          tags=["Detection"],
          dependencies=[Depends(verify_api_key)])
@limiter.limit("100/minute")
async def analyze_packet(
    request: Request,
    features: PacketFeatures,
):
    """
    Analyze a single packet for anomalies.

    Returns an anomaly score (0-1) and whether it's considered anomalous.
    """
    # Convert to feature vector
    feature_array = feature_vector_from_packet(features)

    # Get prediction
    score, is_anomaly = anomaly_detector.predict_single(feature_array)

    return AnomalyResponse(
        score=score,
        is_anomaly=is_anomaly,
        threshold=anomaly_detector.threshold,
        timestamp=datetime.utcnow(),
    )


@app.get("/predict",
         response_model=PredictionResponse,
         tags=["Prediction"],
         dependencies=[Depends(verify_api_key)])
@limiter.limit("30/minute")
async def predict_attacks(
    request: Request,
    hours: int = 1,
):
    """
    Predict attack rates for the next N hours.

    Returns a time series of predicted attack probabilities (0-1).
    """
    if hours < 1 or hours > 24:
        raise HTTPException(
            status_code=400,
            detail="hours must be between 1 and 24"
        )

    predictions = predictor.predict(hours)

    # Get recent history for change detection
    recent = await db.get_recent_packets(minutes=30)
    attack_rates = [p.get('score', 0) for p in recent if p.get('score')]
    change_detected = predictor.detect_change_point(attack_rates)

    # Calculate confidence (simplified)
    confidence = 0.7 if predictor.model else 0.3

    return PredictionResponse(
        predictions=predictions,
        horizon_minutes=hours * 60,
        confidence=confidence,
        change_point_detected=change_detected,
        generated_at=datetime.utcnow(),
    )


@app.post("/train",
          response_model=TrainingResponse,
          tags=["Management"],
          dependencies=[Depends(verify_api_key)])
@limiter.limit("5/minute")
async def train_models(
    request: Request,
    background_tasks: BackgroundTasks,
):
    """
    Trigger model training manually.

    This will retrain both anomaly detection and prediction models
    with the most recent data. Training runs in the background.
    """
    run_id = str(uuid.uuid4())
    background_tasks.add_task(trainer.train_models, trigger="manual", run_id=run_id)
    return TrainingResponse(
        message="Training started",
        timestamp=datetime.utcnow(),
        run_id=run_id,
    )


@app.get("/status", response_model=ModelStatus, tags=["Management"])
@limiter.limit("20/minute")
async def get_status(request: Request):
    """Get current status of ML models and packet count."""
    recent = await db.get_recent_packets(minutes=5)

    return ModelStatus(
        anomaly_model_trained=anomaly_detector.model is not None,
        predictor_model_trained=predictor.model is not None,
        last_training=trainer.last_train if trainer.last_train > datetime.min else None,
        total_packets_processed=len(recent),
    )


# =============================================================================
# Run (for development only)
# =============================================================================

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.server.host,
        port=settings.server.port,
        reload=settings.server.reload,
        workers=settings.server.workers,
        log_level=settings.server.log_level.value.lower(),
    )