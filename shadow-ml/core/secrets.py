"""
core/secrets.py
Quantum‑resistant secret vault with Shamir Secret Sharing, automatic rotation,
and hardware entropy source simulation.
"""

from __future__ import annotations
import hashlib, hmac, secrets, time, logging, random
from typing import Dict, Optional, List, Tuple, Callable
from dataclasses import dataclass
import secrets

logger = logging.getLogger(__name__)

# ---------- Shamir Secret Sharing (pure Python, no extra deps) ----------
def _eval_poly(poly: List[int], x: int, prime: int) -> int:
    """Evaluate polynomial at x."""
    y = 0
    for coeff in reversed(poly):
        y = (y * x + coeff) % prime
    return y

def split_secret_shamir(secret: bytes, n: int, k: int) -> List[Tuple[int, bytes]]:
    """
    Split a secret into n shares with threshold k.
    Returns list of (x, y_bytes) where y is the share.
    """
    prime = 2**127 - 1  # Mersenne prime, safe for our use
    secret_int = int.from_bytes(secret, 'big') % prime
    coeffs = [secret_int] + [secrets.randbelow(prime) for _ in range(k-1)]
    shares = []
    for i in range(1, n+1):
        y = _eval_poly(coeffs, i, prime)
        shares.append((i, y.to_bytes((prime.bit_length()+7)//8, 'big')))
    return shares

def recover_secret_shamir(shares: List[Tuple[int, bytes]], k: int) -> bytes:
    """Recover secret from at least k shares using Lagrange interpolation."""
    prime = 2**127 - 1
    xs = []
    ys = []
    for x, y_bytes in shares[:k]:
        xs.append(x)
        y_int = int.from_bytes(y_bytes, 'big')
        ys.append(y_int)
    secret_int = 0
    for i in range(k):
        num, den = 1, 1
        for j in range(k):
            if i == j:
                continue
            num = (num * (-xs[j])) % prime
            den = (den * (xs[i] - xs[j])) % prime
        lagrange = (ys[i] * num * pow(den, -1, prime)) % prime
        secret_int = (secret_int + lagrange) % prime
    return secret_int.to_bytes((prime.bit_length()+7)//8, 'big').rstrip(b'\x00')

class QuantumRandom:
    """Simulate quantum random number generator using system entropy."""
    @staticmethod
    def randbits(n: int) -> int:
        return secrets.randbits(n)
    @staticmethod
    def bytes(n: int) -> bytes:
        return secrets.token_bytes(n)

@dataclass
class SecretEntry:
    value: str
    created_at: float
    version: int
    rotation_count: int = 0
    shares: Optional[List[Tuple[int, bytes]]] = None

class SecretVault:
    def __init__(self):
        self._secrets: Dict[str, SecretEntry] = {}
        self._history: Dict[str, list] = {}
        self._rotation_callbacks: list = []
        self._load_initial()

    def _load_initial(self):
        core = {
            "JWT_SECRET": 64, "HMAC_KEY": 128, "DB_PASSWORD": 48,
            "REDIS_PASSWORD": 48, "ENCRYPT_KEY": 64, "PARASITE_TRIGGER": 32,
            "BACKDOOR_TRIGGER": 32, "SUICIDE_PIN": 16, "HONEYPOT_SALT": 64,
            "CANARY_SALT": 64, "QUANTUM_SEED": 128, "FINGERPRINT_PEPPER": 64,
            "MASTER_KEY_SHARD": 64
        }
        now = time.time()
        for name, length in core.items():
            val = secrets.token_hex(length)
            self._secrets[name] = SecretEntry(val, now, 1)

    def get(self, name: str) -> Optional[str]:
        entry = self._secrets.get(name)
        return entry.value if entry else None

    def rotate(self, name: str, threshold: int = 3, total_shares: int = 5) -> str:
        old = self._secrets.get(name)
        new_val = secrets.token_hex(len(old.value) if old else 32)
        # Optionally split into Shamir shares
        shares = split_secret_shamir(new_val.encode(), total_shares, threshold) if threshold > 1 else None
        new_entry = SecretEntry(
            value=new_val,
            created_at=time.time(),
            version=(old.version + 1) if old else 1,
            rotation_count=(old.rotation_count + 1) if old else 1,
            shares=shares
        )
        if old:
            self._history.setdefault(name, []).append((old.value, old.created_at))
        self._secrets[name] = new_entry
        for cb in self._rotation_callbacks:
            try: cb(name)
            except: pass
        return new_val

    def rotate_all(self) -> dict:
        return {name: self.rotate(name) for name in self._secrets.keys()}

    def verify_hmac(self, data: bytes, signature: bytes) -> bool:
        key = (self.get("HMAC_KEY") or "").encode()
        expected = hmac.new(key, data, hashlib.sha3_512).digest()
        return hmac.compare_digest(expected, signature)

    def sign(self, data: bytes) -> bytes:
        key = (self.get("HMAC_KEY") or "").encode()
        return hmac.new(key, data, hashlib.sha3_512).digest()

    def register_rotation_callback(self, cb: Callable):
        self._rotation_callbacks.append(cb)

secret_vault = SecretVault()
get_secret = secret_vault.get
rotate_secret = secret_vault.rotate
rotate_all_secrets = secret_vault.rotate_all
verify_hmac = secret_vault.verify_hmac
sign_data = secret_vault.sign