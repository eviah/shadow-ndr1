# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  Shadow NDR – Ultimate AI Configuration                                  ║
║  The most powerful configuration system for railway cybersecurity        ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import os
import json
import warnings
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import quote_plus

from pydantic import (
    BaseModel,
    Field,
    SecretStr,
    field_validator,
    model_validator,
    ConfigDict,
    AnyUrl,
)
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing_extensions import Self

# =============================================================================
# Enums for clarity
# =============================================================================

class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"

class MLStrategy(str, Enum):
    STANDARD = "standard"
    FEDERATED = "federated"
    ADVERSARIAL = "adversarial"
    ENSEMBLE = "ensemble"

class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class ScalerType(str, Enum):
    STANDARD = "standard"
    ROBUST = "robust"
    MINMAX = "minmax"

# =============================================================================
# Sub‑configurations
# =============================================================================

class DatabaseSettings(BaseModel):
    """PostgreSQL connection settings."""
    host: str = "localhost"
    port: int = Field(5432, ge=1, le=65535)
    user: str = "postgres"
    password: SecretStr = SecretStr("shadow123")
    database: str = "shadow"
    min_size: int = Field(5, ge=1, le=100)
    max_size: int = Field(20, ge=1, le=200)
    ssl_mode: str = "disable"
    connect_timeout: int = 10

    @property
    def dsn(self) -> str:
        """Connection string for asyncpg."""
        return f"postgresql://{self.user}:{quote_plus(self.password.get_secret_value())}@{self.host}:{self.port}/{self.database}"

    @field_validator("password")
    @classmethod
    def warn_default_password(cls, v: SecretStr) -> SecretStr:
        if v.get_secret_value() == "shadow123":
            warnings.warn("Using default PostgreSQL password. Change it in production!", UserWarning)
        return v


class ClickHouseSettings(BaseModel):
    """ClickHouse time‑series database settings."""
    host: str = "localhost"
    port: int = Field(9000, ge=1, le=65535)
    database: str = "shadow"
    user: str = "default"
    password: SecretStr = SecretStr("")
    connect_timeout: int = 10
    pool_size: int = Field(10, ge=1, le=50)
    compress: bool = True

    @property
    def dsn(self) -> str:
        auth = f"{self.user}:{quote_plus(self.password.get_secret_value())}@" if self.password.get_secret_value() else ""
        return f"clickhouse://{auth}{self.host}:{self.port}/{self.database}"


class RedisSettings(BaseModel):
    """Redis cache and session store."""
    host: str = "localhost"
    port: int = Field(6379, ge=1, le=65535)
    db: int = Field(0, ge=0, le=15)
    password: SecretStr = SecretStr("")
    ssl: bool = False
    max_connections: int = Field(20, ge=1, le=200)
    decode_responses: bool = True

    @property
    def url(self) -> str:
        scheme = "rediss" if self.ssl else "redis"
        auth = f":{quote_plus(self.password.get_secret_value())}@" if self.password.get_secret_value() else ""
        return f"{scheme}://{auth}{self.host}:{self.port}/{self.db}"


class MQSettings(BaseModel):
    """Message queue (Kafka / RabbitMQ) settings."""
    type: str = "kafka"  # kafka, rabbitmq
    brokers: List[str] = ["localhost:9092"]
    topic_prefix: str = "shadow"
    group_id: str = "shadow-api"
    auto_offset_reset: str = "earliest"
    enable_auto_commit: bool = True


class MLModelSettings(BaseModel):
    """Machine learning model configuration."""
    path: Path = Path("models")
    version: str = "latest"
    anomaly_threshold: float = Field(0.95, ge=0.0, le=1.0)
    retrain_interval_hours: int = 24
    min_train_samples: int = 1000
    drift_detection: bool = True
    adwin_delta: float = 0.002
    feature_drift_alpha: float = 0.01
    use_shap: bool = True
    use_lstm: bool = True
    lstm_seq_len: int = 16
    lstm_hidden: int = 64
    lstm_layers: int = 2
    lstm_epochs: int = 30
    use_online_learner: bool = True
    online_lr: float = 1e-3
    online_hidden: int = 128
    use_adversarial_training: bool = True
    adv_epsilon: float = 0.03
    adv_steps: int = 10
    adv_epochs: int = 15
    use_federated: bool = False
    fed_epsilon: float = 1.0
    fed_delta: float = 1e-5
    fed_rounds: int = 10
    use_ensemble: bool = True
    ensemble_weights: List[float] = [0.18, 0.12, 0.08, 0.07, 0.10, 0.07, 0.13, 0.10, 0.15]

    @field_validator("path", mode="before")
    @classmethod
    def ensure_path(cls, v: Union[str, Path]) -> Path:
        p = Path(v)
        p.mkdir(parents=True, exist_ok=True)
        return p


class AISettings(BaseModel):
    """Top‑level AI configuration – the brain of the system."""
    strategy: MLStrategy = MLStrategy.ENSEMBLE
    enable_anomaly_detection: bool = True
    enable_prediction: bool = True
    enable_explainability: bool = True
    enable_auto_retrain: bool = True
    enable_adaptive_threshold: bool = True
    adaptive_percentile: float = Field(95.0, ge=0.0, le=100.0)
    mlflow_tracking_uri: Optional[AnyUrl] = None
    mlflow_experiment: str = "shadow-ndr"
    model_registry_uri: Optional[AnyUrl] = None
    feature_store_uri: Optional[AnyUrl] = None
    synthetic_anomaly_augmentation: bool = True
    synthetic_anomaly_ratio: float = Field(0.10, ge=0.0, le=1.0)
    synthetic_anomaly_strategy: str = "boundary"

    @model_validator(mode="after")
    def validate_strategy(self) -> Self:
        if self.strategy == MLStrategy.FEDERATED and not self.enable_federated:
            raise ValueError("Federated learning requires enable_federated=True")
        return self

    @property
    def enable_federated(self) -> bool:
        return self.strategy == MLStrategy.FEDERATED

    @property
    def enable_adversarial(self) -> bool:
        return self.strategy == MLStrategy.ADVERSARIAL


class ServerSettings(BaseModel):
    """HTTP server settings for the API."""
    host: str = "0.0.0.0"
    port: int = Field(8000, ge=1, le=65535)
    reload: bool = False
    workers: Optional[int] = None
    log_level: LogLevel = LogLevel.INFO
    request_timeout: int = 60
    max_body_size: int = 10 * 1024 * 1024  # 10 MB

    @property
    def bind(self) -> str:
        return f"{self.host}:{self.port}"


class AuthSettings(BaseModel):
    """Authentication and authorization."""
    secret_key: SecretStr = SecretStr("change-this-in-production")
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    password_hash_rounds: int = 12
    enable_api_key: bool = True
    api_key_header: str = "X-API-Key"

    @field_validator("secret_key")
    @classmethod
    def warn_default_secret(cls, v: SecretStr) -> SecretStr:
        if v.get_secret_value() == "change-this-in-production":
            warnings.warn("Using default secret key! Set a strong secret in production.", UserWarning)
        return v


class SecuritySettings(BaseModel):
    """CORS, TLS, rate limiting."""
    cors_origins: List[str] = ["*"]
    rate_limit_enabled: bool = True
    rate_limit_per_minute: int = 60
    tls_enabled: bool = False
    tls_cert_file: Optional[Path] = None
    tls_key_file: Optional[Path] = None


class LoggingSettings(BaseModel):
    """Structured logging configuration."""
    level: LogLevel = LogLevel.INFO
    format: str = "json"  # json or text
    file: Optional[Path] = None
    syslog: bool = False
    syslog_host: str = "localhost"
    syslog_port: int = 514


class MonitoringSettings(BaseModel):
    """Prometheus / OpenTelemetry."""
    enabled: bool = True
    prometheus_port: int = Field(9090, ge=1, le=65535)
    prometheus_endpoint: str = "/metrics"
    otel_enabled: bool = False
    otel_exporter: str = "otlp"
    otel_endpoint: str = "localhost:4317"


# =============================================================================
# Main Settings Class (AI‑Powered)
# =============================================================================

class Settings(BaseSettings):
    """
    Ultimate AI‑powered configuration for Shadow NDR.

    Loads from environment variables, .env file, and optionally from a remote AI service.
    Supports dynamic overrides based on performance metrics and AI‑driven tuning.
    """

    model_config = SettingsConfigDict(
        env_prefix="SHADOW_",
        env_nested_delimiter="__",
        case_sensitive=False,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        json_schema_extra={
            "title": "Shadow NDR Configuration",
            "description": "The most advanced configuration system for railway cybersecurity",
        },
    )

    # Environment
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False
    instance_id: str = Field(default_factory=lambda: os.getenv("HOSTNAME", "unknown"))

    # Nested configurations
    database: DatabaseSettings = DatabaseSettings()
    clickhouse: ClickHouseSettings = ClickHouseSettings()
    redis: RedisSettings = RedisSettings()
    mq: MQSettings = MQSettings()
    ml_model: MLModelSettings = MLModelSettings()
    ai: AISettings = AISettings()
    server: ServerSettings = ServerSettings()
    auth: AuthSettings = AuthSettings()
    security: SecuritySettings = SecuritySettings()
    logging: LoggingSettings = LoggingSettings()
    monitoring: MonitoringSettings = MonitoringSettings()

    # =========================================================================
    # AI‑Powered Dynamic Overrides
    # =========================================================================

    # This section holds settings that can be tuned by an AI optimiser
    # (e.g., based on observed false positive rates, latency, etc.)
    dynamic_threshold: float = Field(0.95, description="Current anomaly threshold (may be adjusted by AI)")
    dynamic_contamination: float = Field(0.05, description="Estimated anomaly proportion (auto‑tuned)")
    dynamic_lof_neighbors: int = Field(20, description="LOF n_neighbors (auto‑tuned)")

    # Feature flags for experimental AI modules
    enable_ai_config_optimizer: bool = False
    enable_ai_threshold_adaptation: bool = True
    enable_ai_feature_selection: bool = False
    enable_ai_hyperparameter_search: bool = True

    # =========================================================================
    # Derived Properties & Helpers
    # =========================================================================

    @property
    def is_production(self) -> bool:
        return self.environment == Environment.PRODUCTION

    @property
    def is_development(self) -> bool:
        return self.environment == Environment.DEVELOPMENT

    @property
    def mlflow_uri(self) -> Optional[str]:
        return str(self.ai.mlflow_tracking_uri) if self.ai.mlflow_tracking_uri else None

    def dict(self, exclude_secrets: bool = True, **kwargs) -> Dict[str, Any]:
        """Return a dictionary with secrets optionally hidden."""
        data = super().model_dump(**kwargs)
        if exclude_secrets:
            # Hide password fields
            data["database"]["password"] = "***"
            data["clickhouse"]["password"] = "***"
            data["redis"]["password"] = "***"
            data["auth"]["secret_key"] = "***"
        return data

    def to_json(self, indent: int = 2, exclude_secrets: bool = True) -> str:
        """JSON representation, optionally hiding secrets."""
        return json.dumps(self.dict(exclude_secrets=exclude_secrets), indent=indent, default=str)

    # =========================================================================
    # Validators & Post‑processing
    # =========================================================================

    @field_validator("dynamic_threshold")
    @classmethod
    def threshold_range(cls, v: float) -> float:
        if not 0 <= v <= 1:
            raise ValueError("dynamic_threshold must be in [0,1]")
        return v

    @field_validator("dynamic_contamination")
    @classmethod
    def contamination_range(cls, v: float) -> float:
        if not 0 <= v <= 0.5:
            raise ValueError("dynamic_contamination must be in [0,0.5]")
        return v

    @model_validator(mode="after")
    def validate_environment_consistency(self) -> Self:
        if self.is_production:
            if self.debug:
                raise ValueError("Debug mode cannot be enabled in production")
            if self.auth.secret_key.get_secret_value() == "change-this-in-production":
                raise ValueError("Secret key must be set in production")
            if self.security.cors_origins == ["*"]:
                warnings.warn("CORS origins set to '*' in production. This is insecure!", UserWarning)
        return self


# =============================================================================
# Cached Singleton
# =============================================================================

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached instance of the settings."""
    return Settings()


# =============================================================================
# Global instance for convenience
# =============================================================================
settings = get_settings()

# =============================================================================
# Example usage (if run directly)
# =============================================================================
if __name__ == "__main__":
    print("✅ Configuration loaded successfully")
    print(f"Environment: {settings.environment}")
    print(f"PostgreSQL:  {settings.database.dsn.split('@')[0]}...")
    print(f"ClickHouse:  {settings.clickhouse.dsn}")
    print(f"Redis:       {settings.redis.url.split('@')[-1]}")
    print(f"ML Strategy: {settings.ai.strategy}")
    print(f"Dynamic threshold: {settings.dynamic_threshold}")
    print("\nFull config (secrets hidden):")
    print(settings.to_json())