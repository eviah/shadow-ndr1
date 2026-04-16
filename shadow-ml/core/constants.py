"""
core/constants.py
Galactic constants for Shadow NDR ML v5.0 – includes all 200 defense layers,
post‑quantum parameters, and aviation security specifics.
"""

from pathlib import Path

# ============================================================================
# Paths
# ============================================================================
PROJECT_ROOT = Path(__file__).parent.parent
MODELS_DIR = PROJECT_ROOT / "models"
DATA_DIR = PROJECT_ROOT / "data"
LOGS_DIR = PROJECT_ROOT / "logs"
BACKUP_DIR = PROJECT_ROOT / "backups"
QUARANTINE_DIR = PROJECT_ROOT / "quarantine"
CONFIG_DIR = PROJECT_ROOT / "config"
RAG_DIR = PROJECT_ROOT / "rag"

# ============================================================================
# ML Hyperparameters (Enhanced)
# ============================================================================
DEFAULT_RANDOM_STATE = 42
N_ESTIMATORS = 500
MAX_DEPTH = 18
LEARNING_RATE = 0.015
DROPOUT_RATE = 0.4
BATCH_SIZE = 256
NUM_EPOCHS_BASE = 100
EARLY_STOPPING_PATIENCE = 15
GRADIENT_CLIP_NORM = 1.0

# ============================================================================
# Domain constants (Aviation + Cyber)
# ============================================================================
THREAT_LEVELS = ("low", "medium", "high", "critical", "emergency", "apocalyptic")
ATTACK_TYPES = (
    "ads-b_spoofing", "ransomware", "gps_jamming", "mode_s_hijack",
    "acars_injection", "sql_injection", "ddos", "mitm", "poisoning",
    "model_stealing", "adversarial_evasion", "data_exfil", "brute_force",
    "replay_attack", "timing_attack", "side_channel", "reconnaissance",
    "privilege_escalation", "backdoor", "rootkit", "rogue_device",
    "radio_frequency_hijack", "satellite_spoofing", "aircraft_takeover"
)
SUPPORTED_PROTOCOLS = (
    "tcp", "udp", "icmp", "dns", "dhcp", "mqtt", "amqp",
    "modbus", "dnp3", "sip", "rtp", "adsb", "acars",
    "mode_s", "vdl", "cpdlc", "aeromacs", "iec104", "mqtts", "coap",
    "gps_l1", "gps_l2", "galileo", "glonass", "iridium"
)

# ============================================================================
# 200 Defense Layers – Parameters
# ============================================================================
# Chameleon
CHAMELEON_INTERVAL = 2 * 3600      # every 2 hours
CHAMELEON_JITTER = 300             # +-5 minutes
# Self‑Heal
HEAL_SCORE_THRESHOLD = 0.65
HEAL_WINDOW = 10
# AI Parasite
PARASITE_RUNS_INVERT = 80
PARASITE_RUNS_DELETE = 400
# Suicide
SUICIDE_THRESHOLD = 0.98
SUICIDE_VERIFICATION_REQUESTS = 3
# Quantum Noise
QUANTUM_NOISE_MIN = 0.001
QUANTUM_NOISE_MAX = 0.20
QUANTUM_NOISE_DISTRIBUTION = "gaussian"  # or "laplace", "uniform"
# Reflection
REFLECTION_RPS_THRESHOLD = 250
REFLECTION_AMPLIFICATION_FACTOR = 2.0
# Phantom
PHANTOM_PPS = 25000
PHANTOM_TTL = 60                   # seconds
# Poison Trap
POISON_TRAP_MULTIPLIER = 20
POISON_TRAP_FEEDBACK_LOOPS = 3
# Quarantine
QUARANTINE_TIMEOUT_SEC = 5.0
QUARANTINE_AIRGAP_SIM = True
# Misc
MAX_CONCURRENT_TECHNIQUES = 100
GHOST_ASSET_REFRESH = 300          # seconds

# ============================================================================
# Post‑Quantum Cryptography
# ============================================================================
POST_QUANTUM_KEM = "Kyber512"
KYBER_PARAMETERS = {
    "512": {"security_level": 128, "ciphertext_size": 768, "public_key_size": 800},
    "768": {"security_level": 192, "ciphertext_size": 1088, "public_key_size": 1184},
    "1024": {"security_level": 256, "ciphertext_size": 1568, "public_key_size": 1568}
}
POST_QUANTUM_SIG = "Dilithium2"

# ============================================================================
# Defense Flags (all 20 categories)
# ============================================================================
DEFENSE_FLAGS = {
    "honeypot": True,
    "canary_tokens": True,
    "reverse_poisoning": True,
    "web_of_deception": True,
    "quantum_noise": True,
    "self_healing": True,
    "ai_parasite": True,
    "evolving_defense": True,
    "poison_trap": True,
    "phantom_traffic": True,
    "neural_backdoor": True,
    "distributed_counter": True,
    "data_quarantine": True,
    "attacker_fingerprinting": True,
    "suicide_model": True,
    "chameleon_model": True,
    "ghost_assets": True,
    "attack_reflection": True,
    "attacker_profiling": True,
    "zero_trust": True,
    "chaos_engineering": True,
    "phoenix_rebirth": True,
    "omega_protocol": True,
    "death_star_defense": True
}

# ============================================================================
# Network & API (Enhanced)
# ============================================================================
DEFAULT_API_PORT = 8443
DEFAULT_API_WORKERS = 16
RATE_LIMIT_PER_SEC = 1000
RATE_LIMIT_PER_MIN = 50000
JWT_EXPIRY_HOURS = 6
TLS_VERSION = "TLSv1.3"
CIPHER_SUITES = ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]

# ============================================================================
# Monitoring & Observability
# ============================================================================
METRICS_EXPORT_PORT = 9090
HEALTH_CHECK_INTERVAL_SEC = 15
ALERT_BUFFER_SIZE = 50000
TRACE_SAMPLING_RATE = 0.05

# ============================================================================
# Red Team / Chaos Testing
# ============================================================================
SIMULATOR_THREAT_INTERVAL_SEC = 10
SIMULATOR_MAX_CONCURRENT = 10
RED_TEAM_AUTO_RUN = False
CHAOS_MONKEY_ENABLED = False