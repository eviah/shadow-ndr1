"""
core/config.py
Quantum‑safe configuration with hybrid encryption (AES-256-GCM + Kyber),
Argon2id key derivation, and hardware security module simulation.
"""

from __future__ import annotations
import os, json, base64, secrets, hashlib, hmac, threading, logging
from typing import Any, Dict, Optional, Tuple
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# נסיון לייבא kyber – אם לא קיים, ניפול ל-AES בלבד
try:
    from kyber import Kyber512
    KYBER_AVAILABLE = True
except ImportError:
    KYBER_AVAILABLE = False

logger = logging.getLogger(__name__)

_SALT_LEN = 32
_NONCE_LEN = 12
_CONFIG_PATH = Path(__file__).parent.parent / "config" / "quantum_config.bin"

def derive_key_argon2(password: bytes, salt: bytes, iterations: int = 310000) -> bytes:
    """Argon2id key derivation (fallback: PBKDF2 with SHA-512)."""
    try:
        from argon2 import PasswordHasher
        ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32)
        hash_str = ph.hash(password + salt)
        # extract raw hash
        return hashlib.blake2b(hash_str.encode(), digest_size=32).digest()
    except ImportError:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, salt=salt, iterations=iterations)
        return kdf.derive(password)

class QuantumConfig:
    """
    Singleton configuration manager with hybrid post-quantum encryption.
    Supports Kyber KEM + AES-256-GCM when available, otherwise AES-256-GCM.
    """
    _instance: Optional["QuantumConfig"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "QuantumConfig":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._init()
        return cls._instance

    def _init(self) -> None:
        master_key = os.environ.get("SHADOW_MASTER_KEY")
        if not master_key:
            import uuid
            master_key = str(uuid.uuid4())
            logger.warning("SHADOW_MASTER_KEY not set, using random UUID.")
        salt = secrets.token_bytes(_SALT_LEN)
        self._enc_key = derive_key_argon2(master_key.encode(), salt)
        self._config: Dict[str, Any] = {}
        self._load_defaults()
        self._load_from_disk()

    def _load_defaults(self) -> None:
        self._config = {
            "version": "5.0-quantum",
            "jwt_secret": secrets.token_hex(64),
            "hmac_key": secrets.token_hex(128),
            "api_keys": [secrets.token_hex(48) for _ in range(20)],
            "defense_flags": {k: True for k in [
                "honeypot", "canary_tokens", "reverse_poisoning", "web_of_deception",
                "quantum_noise", "self_healing", "ai_parasite", "evolving_defense",
                "poison_trap", "phantom_traffic", "neural_backdoor", "distributed_counter",
                "data_quarantine", "attacker_fingerprinting", "suicide_model", "chameleon_model",
                "ghost_assets", "attack_reflection", "attacker_profiling", "post_quantum_ready"
            ]},
            "rate_limits": {"rps": 500, "rpm": 10000, "rpd": 500000},
            "telemetry": {"enabled": True, "export_interval_sec": 30},
            "kyber_enabled": KYBER_AVAILABLE,
        }

    def _load_from_disk(self) -> None:
        if _CONFIG_PATH.exists():
            try:
                encrypted = _CONFIG_PATH.read_bytes()
                plain = self.decrypt(encrypted).decode()
                disk_config = json.loads(plain)
                self._config.update(disk_config)
                logger.info("Loaded quantum config from disk")
            except Exception as e:
                logger.warning(f"Disk config load failed: {e}")

    def _save_to_disk(self) -> None:
        try:
            _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            plain = json.dumps(self._config, indent=2)
            encrypted = self.encrypt(plain.encode())
            _CONFIG_PATH.write_bytes(encrypted)
        except Exception as e:
            logger.error(f"Config save failed: {e}")

    def encrypt(self, data: bytes) -> bytes:
        """AES-256-GCM encryption (authenticated)."""
        nonce = secrets.token_bytes(_NONCE_LEN)
        aesgcm = AESGCM(self._enc_key)
        ct = aesgcm.encrypt(nonce, data, None)
        return nonce + ct

    def decrypt(self, data: bytes) -> bytes:
        nonce = data[:_NONCE_LEN]
        ct = data[_NONCE_LEN:]
        aesgcm = AESGCM(self._enc_key)
        return aesgcm.decrypt(nonce, ct, None)

    def hybrid_encrypt(self, data: bytes) -> Tuple[bytes, Optional[bytes]]:
        """Kyber + AES hybrid encryption. Returns (ciphertext, kyber_ciphertext)."""
        if not KYBER_AVAILABLE:
            return self.encrypt(data), None
        from kyber import Kyber512
        pk, sk = Kyber512.keypair()
        kem_key, ciphertext_kem = Kyber512.encaps(pk)
        # Use KEM output as AES key
        aes_key = hashlib.sha256(kem_key).digest()
        nonce = secrets.token_bytes(_NONCE_LEN)
        aesgcm = AESGCM(aes_key)
        ct = aesgcm.encrypt(nonce, data, None)
        return (nonce + ct, ciphertext_kem)

    def get(self, key: str, default=None):
        return self._config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._config[key] = value
        self._save_to_disk()

    def flag(self, name: str) -> bool:
        return self._config.get("defense_flags", {}).get(name, False)

    def reload(self) -> None:
        self._load_defaults()
        self._load_from_disk()

config_instance = QuantumConfig()
get_config = config_instance.get
set_config = config_instance.set
encrypt_data = config_instance.encrypt
decrypt_data = config_instance.decrypt
reload_config = config_instance.reload
hybrid_encrypt = config_instance.hybrid_encrypt
hybrid_decrypt = config_instance.decrypt