"""
core/__init__.py
Shadow NDR ML v5.0 – Core module exports.
Quantum-safe, post-quantum ready, with full defense stack.
"""

from .config import (
    QuantumConfig,
    get_config,
    set_config,
    encrypt_data,
    decrypt_data,
    reload_config,
    config_instance,
    derive_key_argon2,
    hybrid_encrypt,
    hybrid_decrypt
)

from .secrets import (
    SecretVault,
    secret_vault,
    rotate_all_secrets,
    get_secret,
    verify_hmac,
    sign_data,
    rotate_secret,
    split_secret_shamir,
    recover_secret_shamir,
    QuantumRandom
)

from .constants import (
    # Paths
    PROJECT_ROOT, MODELS_DIR, DATA_DIR, LOGS_DIR, BACKUP_DIR, QUARANTINE_DIR, RAG_DIR,
    # ML hyperparameters
    DEFAULT_RANDOM_STATE, N_ESTIMATORS, MAX_DEPTH, LEARNING_RATE, DROPOUT_RATE, BATCH_SIZE,
    # Domain constants
    THREAT_LEVELS, ATTACK_TYPES, SUPPORTED_PROTOCOLS,
    # Defense parameters (200 layers)
    CHAMELEON_INTERVAL, HEAL_SCORE_THRESHOLD, HEAL_WINDOW,
    PARASITE_RUNS_INVERT, PARASITE_RUNS_DELETE, SUICIDE_THRESHOLD,
    QUANTUM_NOISE_MIN, QUANTUM_NOISE_MAX, REFLECTION_RPS_THRESHOLD,
    PHANTOM_PPS, POISON_TRAP_MULTIPLIER, QUARANTINE_TIMEOUT_SEC,
    MAX_CONCURRENT_TECHNIQUES, POST_QUANTUM_KEM, KYBER_PARAMETERS,
    # Defense flags
    DEFENSE_FLAGS
)

from .exceptions import (
    ShadowNDRError, ConfigError, SecurityError, ModelError,
    PoisoningError, QuarantineError, SuicideError,
    HoneypotError, DeceptionError, FingerprintError,
    QuantumError, SelfHealError, PostQuantumError,
    ShamirError, TPMError
)

__all__ = [
    "QuantumConfig", "get_config", "set_config", "encrypt_data", "decrypt_data",
    "reload_config", "config_instance", "derive_key_argon2", "hybrid_encrypt", "hybrid_decrypt",
    "SecretVault", "secret_vault", "rotate_all_secrets", "get_secret", "verify_hmac",
    "sign_data", "rotate_secret", "split_secret_shamir", "recover_secret_shamir", "QuantumRandom",
    "PROJECT_ROOT", "MODELS_DIR", "DATA_DIR", "LOGS_DIR", "BACKUP_DIR", "QUARANTINE_DIR", "RAG_DIR",
    "DEFAULT_RANDOM_STATE", "N_ESTIMATORS", "MAX_DEPTH", "LEARNING_RATE", "DROPOUT_RATE", "BATCH_SIZE",
    "THREAT_LEVELS", "ATTACK_TYPES", "SUPPORTED_PROTOCOLS",
    "CHAMELEON_INTERVAL", "HEAL_SCORE_THRESHOLD", "HEAL_WINDOW",
    "PARASITE_RUNS_INVERT", "PARASITE_RUNS_DELETE", "SUICIDE_THRESHOLD",
    "QUANTUM_NOISE_MIN", "QUANTUM_NOISE_MAX", "REFLECTION_RPS_THRESHOLD",
    "PHANTOM_PPS", "POISON_TRAP_MULTIPLIER", "QUARANTINE_TIMEOUT_SEC",
    "MAX_CONCURRENT_TECHNIQUES", "POST_QUANTUM_KEM", "KYBER_PARAMETERS", "DEFENSE_FLAGS",
    "ShadowNDRError", "ConfigError", "SecurityError", "ModelError",
    "PoisoningError", "QuarantineError", "SuicideError",
    "HoneypotError", "DeceptionError", "FingerprintError",
    "QuantumError", "SelfHealError", "PostQuantumError", "ShamirError", "TPMError"
]