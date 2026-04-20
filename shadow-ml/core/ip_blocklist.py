"""
core/ip_blocklist.py — in-memory IP blocklist with TTL.

Used by audit middleware + canary tripwires. Thread-safe. No Redis dep
required; will opportunistically mirror to Redis if a client is available.
"""

from __future__ import annotations

import threading
import time
from typing import Dict, Optional


class IPBlocklist:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._blocked: Dict[str, float] = {}  # ip -> expiry_ts
        self._fail_counts: Dict[str, list] = {}  # ip -> [recent failure timestamps]

    def block(self, ip: str, ttl_seconds: int, reason: str = "") -> None:
        if not ip:
            return
        with self._lock:
            self._blocked[ip] = time.time() + ttl_seconds
        # Best-effort Redis mirror
        try:
            from .redis_client import get_redis  # optional
            r = get_redis()
            if r is not None:
                r.setex(f"shadow:blocked:{ip}", ttl_seconds, reason or "1")
        except Exception:
            pass

    def is_blocked(self, ip: str) -> bool:
        if not ip:
            return False
        with self._lock:
            exp = self._blocked.get(ip)
            if exp is None:
                return False
            if time.time() > exp:
                self._blocked.pop(ip, None)
                return False
            return True

    def record_failure(
        self,
        ip: str,
        *,
        threshold: int = 20,
        window_seconds: int = 60,
        block_seconds: int = 900,
    ) -> bool:
        """Record a failure; return True if this triggered a block."""
        if not ip:
            return False
        now = time.time()
        with self._lock:
            times = self._fail_counts.setdefault(ip, [])
            times[:] = [t for t in times if now - t < window_seconds]
            times.append(now)
            if len(times) >= threshold:
                self._blocked[ip] = now + block_seconds
                times.clear()
                return True
        return False

    def unblock(self, ip: str) -> None:
        with self._lock:
            self._blocked.pop(ip, None)
            self._fail_counts.pop(ip, None)

    def stats(self) -> Dict[str, int]:
        with self._lock:
            now = time.time()
            active = sum(1 for exp in self._blocked.values() if exp > now)
            return {"active_blocks": active, "tracked_ips": len(self._fail_counts)}


_INSTANCE: Optional[IPBlocklist] = None


def get_blocklist() -> IPBlocklist:
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = IPBlocklist()
    return _INSTANCE
