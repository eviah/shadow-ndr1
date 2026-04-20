"""
core/rate_limiter.py — token-bucket rate limiter keyed by IP + path bucket.

Zero extra dependency. Thread-safe, in-memory. Good enough for a single
uvicorn process; for multi-worker, mirror via Redis (future).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass
class BucketConfig:
    capacity: int           # max tokens
    refill_per_second: float


_DEFAULT = BucketConfig(capacity=60, refill_per_second=1.0)   # 60/min
_RAG = BucketConfig(capacity=10, refill_per_second=10.0 / 60.0)  # 10/min
_TRAIN = BucketConfig(capacity=5, refill_per_second=5.0 / 60.0)  # 5/min
_AUTH = BucketConfig(capacity=5, refill_per_second=5.0 / 60.0)   # 5/min login


def _bucket_for_path(path: str) -> BucketConfig:
    p = path.lower()
    if p.startswith("/rag/"):
        return _RAG
    if p.startswith("/auth/"):
        return _AUTH
    if p.startswith("/ml/train") or p.startswith("/rl/feedback") or p.startswith("/ml/federated"):
        return _TRAIN
    return _DEFAULT


class RateLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state: Dict[Tuple[str, str], Tuple[float, float]] = {}  # (ip, bucket_name) -> (tokens, last_ts)

    def allow(self, ip: str, path: str) -> Tuple[bool, int]:
        """Return (allowed, retry_after_seconds)."""
        cfg = _bucket_for_path(path)
        bucket_name = "rag" if cfg is _RAG else ("train" if cfg is _TRAIN else ("auth" if cfg is _AUTH else "default"))
        key = (ip or "-", bucket_name)
        now = time.time()
        with self._lock:
            tokens, last = self._state.get(key, (float(cfg.capacity), now))
            elapsed = max(0.0, now - last)
            tokens = min(float(cfg.capacity), tokens + elapsed * cfg.refill_per_second)
            if tokens >= 1.0:
                tokens -= 1.0
                self._state[key] = (tokens, now)
                return True, 0
            retry = int((1.0 - tokens) / cfg.refill_per_second) + 1
            self._state[key] = (tokens, now)
            return False, retry


_INSTANCE: Optional[RateLimiter] = None


def get_limiter() -> RateLimiter:
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = RateLimiter()
    return _INSTANCE
