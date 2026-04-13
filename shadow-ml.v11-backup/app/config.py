#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║   Shadow NDR – ML Service Configuration                                   ║
║   Centralized settings with validation, caching, and hot‑reload          ║
╚═══════════════════════════════════════════════════════════════════════════╝

All settings are read from environment variables with the prefix `SHADOW_`
(or from a `.env` file). Default values are provided for local development.
"""

import json
import os
import warnings
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    Field,
    FilePath,
    PositiveFloat,
    PositiveInt,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing_extensions import Self

# =============================================================================
# Enums and simple types
# =============================================================================


class LogLevel(str, Enum):
    """Logging levels supported by the application."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ModelProvider(str, Enum):
    """Machine learning framework provider."""

    SKLEARN = "sklearn"
    XGBOOST = "xgboost"
    PROPHET = "prophet"
    TORCH = "torch"


# =============================================================================
# Sub‑configurations (nested)
# =============================================================================


class DatabaseSettings(BaseModel):
    """ClickHouse connection parameters."""

    host: str = Field("localhost", description="ClickHouse server hostname")
    port: PositiveInt = Field(9000, description="ClickHouse native protocol port")
    database: str = Field("shadow", description="Default database name")
    user: str = Field("default", description="ClickHouse username")
    password: str = Field("", description="ClickHouse password (leave empty for no auth)")
    connect_timeout: PositiveInt = Field(10, description="Connection timeout in seconds")
    verify: bool = Field(True, description="Verify TLS certificate if using TLS")

    @property
    def dsn(self) -> str:
        """Return a ClickHouse DSN string (without password for security)."""
        base = f"clickhouse://{self.host}:{self.port}/{self.database}"
        if self.user:
            base = f"clickhouse://{self.user}@{self.host}:{self.port}/{self.database}"
        return base

    @field_validator("password")
    @classmethod
    def warn_if_password_in_env(cls, v: str) -> str:
        """Issue a warning if password is provided in plaintext (use secrets)."""
        if v and v != "":
            warnings.warn(
                "ClickHouse password set in plaintext. Consider using a secret manager.",
                UserWarning,
                stacklevel=2,
            )
        return v


class RedisSettings(BaseModel):
    """Redis connection settings (used for locks and caching)."""

    host: str = Field("localhost", description="Redis server host")
    port: PositiveInt = Field(6379, description="Redis server port")
    db: int = Field(0, description="Redis database index (0‑15)")
    password: Optional[str] = Field(None, description="Redis password (if any)")
    ssl: bool = Field(False, description="Use SSL for Redis connection")
    socket_timeout: PositiveInt = Field(5, description="Socket timeout in seconds")
    retry_on_timeout: bool = Field(True, description="Retry on timeout")
    max_connections: PositiveInt = Field(20, description="Maximum connections in pool")

    @property
    def url(self) -> str:
        """Return a Redis connection URL."""
        scheme = "rediss" if self.ssl else "redis"
        auth = f":{self.password}@" if self.password else ""
        return f"{scheme}://{auth}{self.host}:{self.port}/{self.db}"


class ModelSettings(BaseModel):
    """Machine learning model hyperparameters and paths."""

    path: Path = Field(Path("models"), description="Directory where models are stored")
    anomaly_threshold: float = Field(
        0.95, ge=0.0, le=1.0, description="Threshold for anomaly detection (0‑1)"
    )
    retrain_interval_hours: PositiveInt = Field(
        24, description="Retrain models every N hours"
    )
    min_train_samples: PositiveInt = Field(
        1000, description="Minimum samples required to start training"
    )
    enable_mlflow: bool = Field(True, description="Log experiments to MLflow")
    mlflow_experiment_name: str = Field("shadow_ndr", description="MLflow experiment name")
    mlflow_tracking_uri: Optional[str] = Field(None, description="MLflow tracking server URI")

    @field_validator("path", mode="before")
    @classmethod
    def ensure_path(cls, v: Union[str, Path]) -> Path:
        """Convert string to Path and ensure directory exists."""
        p = Path(v)
        p.mkdir(parents=True, exist_ok=True)
        return p


class FeatureSettings(BaseModel):
    """Feature engineering parameters."""

    window_seconds: PositiveInt = Field(
        300, description="Time window for rolling statistics (seconds)"
    )
    prediction_horizon_minutes: PositiveInt = Field(
        60, description="Default forecast horizon in minutes"
    )
    max_lag_steps: PositiveInt = Field(
        48, description="Maximum number of lag features to generate"
    )
    use_temporal_features: bool = Field(True, description="Include hour, day, month, etc.")
    use_rolling_stats: bool = Field(True, description="Include rolling mean/std")
    use_fourier_terms: bool = Field(False, description="Include Fourier seasonality terms")


class ServerSettings(BaseModel):
    """HTTP server settings (FastAPI)."""

    host: str = Field("0.0.0.0", description="Bind address")
    port: PositiveInt = Field(8001, description="Bind port (8001 for ML service)")
    reload: bool = Field(False, description="Auto‑reload on code changes (development only)")
    workers: Optional[PositiveInt] = Field(None, description="Number of uvicorn workers")
    log_level: LogLevel = Field(LogLevel.INFO, description="Logging level")
    cors_origins: List[str] = Field(
        ["*"], description="Allowed CORS origins (list of strings)"
    )
    request_timeout_seconds: PositiveInt = Field(60, description="HTTP request timeout")

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        """Allow CORS_ORIGINS to be a comma‑separated string."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v


class NotificationSettings(BaseModel):
    """Webhook notifications for training events."""

    enabled: bool = Field(False, description="Enable webhook notifications")
    url: Optional[AnyHttpUrl] = Field(None, description="Webhook URL")
    retry_count: PositiveInt = Field(3, description="Number of retries on failure")
    timeout_seconds: PositiveInt = Field(5, description="Webhook request timeout")

    @model_validator(mode="after")
    def validate_webhook(self) -> Self:
        """If enabled, URL must be provided."""
        if self.enabled and self.url is None:
            raise ValueError("Notification URL must be provided when enabled")
        return self


# =============================================================================
# Main Settings class (aggregates all)
# =============================================================================

class Settings(BaseSettings):
    """
    Root configuration for the Shadow NDR ML service.

    All environment variables with the prefix `SHADOW_` are automatically mapped.
    Example:
        SHADOW_DATABASE__HOST=clickhouse.example.com
        SHADOW_MODEL__RETRAIN_INTERVAL_HOURS=12
        SHADOW_SERVER__PORT=8080
    """

    model_config = SettingsConfigDict(
        env_prefix="SHADOW_",           # all variables must start with SHADOW_
        env_nested_delimiter="__",      # use __ to separate nested keys
        case_sensitive=False,
        env_file=".env",                 # load from .env file if present
        env_file_encoding="utf-8",
        extra="ignore",                   # ignore unknown env vars
        json_schema_extra={
            "title": "Shadow NDR ML Configuration",
            "description": "Complete settings for the ML service",
        },
    )

    # Nested configurations
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    model: ModelSettings = Field(default_factory=ModelSettings)
    features: FeatureSettings = Field(default_factory=FeatureSettings)
    server: ServerSettings = Field(default_factory=ServerSettings)
    notifications: NotificationSettings = Field(default_factory=NotificationSettings)

    # Top‑level global settings (rare)
    environment: str = Field("development", description="Runtime environment (dev/staging/prod)")
    debug: bool = Field(False, description="Enable debug mode (more verbose logs)")
    secret_key: str = Field("change_me", description="Secret key for internal use")

    # -------------------------------------------------------------------------
    # Validators
    # -------------------------------------------------------------------------
    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        """Ensure environment is one of allowed values."""
        allowed = {"development", "staging", "production"}
        if v.lower() not in allowed:
            raise ValueError(f"environment must be one of {allowed}")
        return v.lower()

    @field_validator("secret_key")
    @classmethod
    def warn_if_default_secret(cls, v: str) -> str:
        """Issue a strong warning if the default secret key is used."""
        if v == "change_me":
            warnings.warn(
                "SECRET_KEY is still the default value. Set a strong secret in production!",
                UserWarning,
                stacklevel=2,
            )
        return v

    # -------------------------------------------------------------------------
    # Computed properties (read‑only)
    # -------------------------------------------------------------------------
    @property
    def is_production(self) -> bool:
        """Return True if environment is 'production'."""
        return self.environment == "production"

    @property
    def is_development(self) -> bool:
        """Return True if environment is 'development'."""
        return self.environment == "development"

    # -------------------------------------------------------------------------
    # Serialization helpers
    # -------------------------------------------------------------------------
    def dict(self, **kwargs) -> Dict[str, Any]:
        """Return a dictionary representation (excluding secrets by default)."""
        exclude_secrets = kwargs.pop("exclude_secrets", True)
        data = super().model_dump(**kwargs)
        if exclude_secrets:
            # Remove sensitive fields (you can extend this list)
            data["database"].pop("password", None)
            data["redis"].pop("password", None)
            data.pop("secret_key", None)
        return data

    def json(self, **kwargs) -> str:
        """Return a JSON representation (excluding secrets by default)."""
        return json.dumps(self.dict(**kwargs), indent=2, default=str)

    def reload(self) -> None:
        """
        Reload configuration from environment variables (by clearing cache).
        Use this after changing environment variables at runtime.
        """
        get_settings.cache_clear()


# =============================================================================
# Cached singleton
# =============================================================================

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return a cached instance of the settings.

    The cache can be cleared by calling `get_settings.cache_clear()` or
    `settings.reload()` on the returned object.
    """
    try:
        return Settings()
    except ValidationError as e:
        # Pretty‑print validation errors
        print("❌ Configuration validation failed:")
        for error in e.errors():
            loc = " -> ".join(str(l) for l in error["loc"])
            print(f"  • {loc}: {error['msg']} (got {error.get('input')})")
        raise


# =============================================================================
# Global instance for convenience (cached)
# =============================================================================
settings = get_settings()

# =============================================================================
# Example usage (if run directly)
# =============================================================================
if __name__ == "__main__":
    print("✅ Configuration loaded successfully:")
    print(f"   Environment: {settings.environment}")
    print(f"   Database:   {settings.database.dsn}")
    print(f"   Redis:      {settings.redis.url}")
    print(f"   Models dir: {settings.model.path}")
    print("\nFull config (secrets hidden):")
    print(settings.json(exclude_secrets=True))