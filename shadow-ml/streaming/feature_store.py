"""
streaming/feature_store.py — SHADOW-ML Feature Store v10.0

Low-latency ML feature store for real-time inference context.
Caches per-aircraft histories, ICAO baselines, IP reputation,
and active telemetry for instant retrieval during neural inference.

Backends (auto-selected):
  1. Redis  — sub-millisecond latency, distributed (preferred)
  2. In-memory LRU — zero-config fallback

Features:
  • Aircraft ICAO24 baseline (normal speed/altitude/route)
  • IP reputation scores (aggregated from threat feeds)
  • Flow history windows (last N packets per 5-tuple)
  • Protocol-specific feature norms per sensor
  • TTL-based expiry for stale baselines
"""

from __future__ import annotations

import json
import logging
import math
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("shadow.streaming.feature_store")

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class AircraftBaseline:
    """Normal operating envelope for a specific ICAO24 aircraft."""
    icao24: str
    callsign: str
    avg_altitude_ft: float = 35_000.0
    std_altitude_ft: float = 2_000.0
    avg_speed_kt: float = 450.0
    std_speed_kt: float = 30.0
    typical_routes: List[str] = field(default_factory=list)
    typical_squawk: str = "7000"
    operator_icao: str = ""
    aircraft_type: str = ""
    first_seen: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    update_count: int = 0

    def deviation_score(self, altitude_ft: float, speed_kt: float) -> float:
        """Z-score based deviation from normal envelope."""
        alt_z = abs(altitude_ft - self.avg_altitude_ft) / max(1, self.std_altitude_ft)
        spd_z = abs(speed_kt - self.avg_speed_kt) / max(1, self.std_speed_kt)
        # Normalise to 0-1
        return min(1.0, (alt_z + spd_z) / 6.0)

    def update(self, altitude_ft: float, speed_kt: float, alpha: float = 0.05) -> None:
        """Online exponential moving average update."""
        self.avg_altitude_ft = (1 - alpha) * self.avg_altitude_ft + alpha * altitude_ft
        self.avg_speed_kt = (1 - alpha) * self.avg_speed_kt + alpha * speed_kt
        deviation_alt = abs(altitude_ft - self.avg_altitude_ft)
        deviation_spd = abs(speed_kt - self.avg_speed_kt)
        self.std_altitude_ft = math.sqrt((1 - alpha) * self.std_altitude_ft**2 + alpha * deviation_alt**2)
        self.std_speed_kt = math.sqrt((1 - alpha) * self.std_speed_kt**2 + alpha * deviation_spd**2)
        self.last_updated = time.time()
        self.update_count += 1


@dataclass
class IPReputation:
    ip: str
    threat_score: float = 0.0        # 0=clean, 1=malicious
    categories: List[str] = field(default_factory=list)
    country: str = ""
    asn: str = ""
    abuse_reports: int = 0
    last_seen_attack: Optional[float] = None
    sources: List[str] = field(default_factory=list)
    ttl_expiry: float = field(default_factory=lambda: time.time() + 3600)

    @property
    def expired(self) -> bool:
        return time.time() > self.ttl_expiry


@dataclass
class FlowHistory:
    """Recent packet history for a 5-tuple flow."""
    src_ip: str; dst_ip: str; src_port: int; dst_port: int; protocol: int
    packets: List[Dict[str, float]] = field(default_factory=list)
    bytes_total: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    max_history: int = 100

    def add_packet(self, length: int, flags: int, payload_entropy: float) -> None:
        self.packets.append({
            "ts": time.time(), "len": length,
            "flags": flags, "entropy": payload_entropy,
        })
        if len(self.packets) > self.max_history:
            self.packets.pop(0)
        self.bytes_total += length
        self.last_seen = time.time()

    def feature_vector(self) -> List[float]:
        if not self.packets:
            return [0.0] * 8
        lengths = [p["len"] for p in self.packets]
        entropies = [p["entropy"] for p in self.packets]
        n = len(self.packets)
        mu_len = sum(lengths) / n
        mu_ent = sum(entropies) / n
        duration = self.last_seen - self.first_seen + 1e-6
        return [
            n / 100.0,
            self.bytes_total / 1_000_000.0,
            mu_len / 1500.0,
            math.sqrt(sum((l - mu_len)**2 for l in lengths) / n) / 1500.0,
            mu_ent / 8.0,
            n / duration,          # packets per second
            self.bytes_total / duration / 1_000_000.0,  # Mbps
            float(self.protocol == 6),   # is TCP
        ]

    @property
    def flow_key(self) -> str:
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.protocol}"


# ---------------------------------------------------------------------------
# LRU In-Memory store
# ---------------------------------------------------------------------------

class _LRUStore:
    def __init__(self, max_size: int = 100_000):
        self._cache: OrderedDict = OrderedDict()
        self._max = max_size

    def set(self, key: str, value: Any, ttl: float = 3600.0) -> None:
        if key in self._cache:
            self._cache.move_to_end(key)
        self._cache[key] = {"v": value, "exp": time.time() + ttl}
        if len(self._cache) > self._max:
            self._cache.popitem(last=False)

    def get(self, key: str) -> Optional[Any]:
        entry = self._cache.get(key)
        if not entry:
            return None
        if time.time() > entry["exp"]:
            del self._cache[key]
            return None
        self._cache.move_to_end(key)
        return entry["v"]

    def delete(self, key: str) -> None:
        self._cache.pop(key, None)

    def __len__(self) -> int:
        return len(self._cache)


# ---------------------------------------------------------------------------
# Redis backend
# ---------------------------------------------------------------------------

class _RedisStore:
    def __init__(self, host: str = "localhost", port: int = 6379, db: int = 0):
        import redis
        self._r = redis.Redis(host=host, port=port, db=db, decode_responses=True)
        self._r.ping()
        logger.info("Redis feature store connected: %s:%d", host, port)

    def set(self, key: str, value: Any, ttl: float = 3600.0) -> None:
        self._r.setex(key, int(ttl), json.dumps(value, default=str))

    def get(self, key: str) -> Optional[Any]:
        raw = self._r.get(key)
        return json.loads(raw) if raw else None

    def delete(self, key: str) -> None:
        self._r.delete(key)

    def __len__(self) -> int:
        return self._r.dbsize()


# ---------------------------------------------------------------------------
# Main Feature Store
# ---------------------------------------------------------------------------

class FeatureStore:
    """
    SHADOW-ML Feature Store v10.0

    Instant-access cache for ML inference context:
      • Aircraft ICAO baselines (deviation scoring)
      • IP reputation (threat intelligence)
      • Flow histories (per-session packet stats)
    """

    VERSION = "10.0.0"

    def __init__(self, redis_host: str = "localhost", redis_port: int = 6379,
                 use_redis: bool = True):
        self._store = self._init_store(redis_host, redis_port, use_redis)
        self._stats = {"hits": 0, "misses": 0, "writes": 0}
        logger.info("FeatureStore v%s initialised (backend=%s)", self.VERSION,
                    "redis" if isinstance(self._store, _RedisStore) else "lru")

    # ── Aircraft baselines ───────────────────────────────────────────────────

    def get_aircraft_baseline(self, icao24: str) -> Optional[AircraftBaseline]:
        raw = self._get(f"aircraft:{icao24}")
        if raw:
            return AircraftBaseline(**raw) if isinstance(raw, dict) else raw
        return None

    def update_aircraft_baseline(self, icao24: str, altitude_ft: float,
                                  speed_kt: float, callsign: str = "") -> AircraftBaseline:
        baseline = self.get_aircraft_baseline(icao24)
        if not baseline:
            baseline = AircraftBaseline(icao24=icao24, callsign=callsign,
                                        avg_altitude_ft=altitude_ft, avg_speed_kt=speed_kt)
        else:
            baseline.update(altitude_ft, speed_kt)
        self._set(f"aircraft:{icao24}", asdict(baseline), ttl=86400)
        return baseline

    def get_deviation_score(self, icao24: str, altitude_ft: float, speed_kt: float) -> float:
        baseline = self.get_aircraft_baseline(icao24)
        if not baseline:
            return 0.0  # No baseline = no anomaly score
        return baseline.deviation_score(altitude_ft, speed_kt)

    # ── IP reputation ────────────────────────────────────────────────────────

    def get_ip_reputation(self, ip: str) -> Optional[IPReputation]:
        raw = self._get(f"ip:{ip}")
        if raw:
            return IPReputation(**raw) if isinstance(raw, dict) else raw
        return None

    def set_ip_reputation(self, rep: IPReputation) -> None:
        ttl = max(60, rep.ttl_expiry - time.time())
        self._set(f"ip:{rep.ip}", asdict(rep), ttl=ttl)

    def get_ip_threat_score(self, ip: str) -> float:
        rep = self.get_ip_reputation(ip)
        return rep.threat_score if rep and not rep.expired else 0.0

    # ── Flow history ─────────────────────────────────────────────────────────

    def get_flow(self, flow_key: str) -> Optional[FlowHistory]:
        raw = self._get(f"flow:{flow_key}")
        if raw and isinstance(raw, dict):
            fh = FlowHistory(**{k: v for k, v in raw.items() if k != "packets"})
            fh.packets = raw.get("packets", [])
            return fh
        return None

    def update_flow(self, flow: FlowHistory, packet_len: int,
                    flags: int, entropy: float) -> FlowHistory:
        flow.add_packet(packet_len, flags, entropy)
        self._set(f"flow:{flow.flow_key}", asdict(flow), ttl=300)
        return flow

    # ── Bulk context retrieval ───────────────────────────────────────────────

    def get_inference_context(self, ip: str, icao24: Optional[str] = None) -> Dict[str, float]:
        """Single call to get all relevant context for neural engine enrichment."""
        ctx = {
            "ip_threat_score": self.get_ip_threat_score(ip),
            "aircraft_deviation": self.get_deviation_score(icao24, 35000, 450) if icao24 else 0.0,
        }
        return ctx

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        hit_rate = self._stats["hits"] / max(1, self._stats["hits"] + self._stats["misses"])
        return {
            "cache_hits": self._stats["hits"],
            "cache_misses": self._stats["misses"],
            "cache_writes": self._stats["writes"],
            "hit_rate_pct": round(100 * hit_rate, 2),
            "cache_size": len(self._store),
            "backend": "redis" if isinstance(self._store, _RedisStore) else "lru",
        }

    # ── Private ──────────────────────────────────────────────────────────────

    def _get(self, key: str) -> Optional[Any]:
        val = self._store.get(key)
        if val is not None:
            self._stats["hits"] += 1
        else:
            self._stats["misses"] += 1
        return val

    def _set(self, key: str, value: Any, ttl: float = 3600) -> None:
        self._store.set(key, value, ttl=ttl)
        self._stats["writes"] += 1

    @staticmethod
    def _init_store(host: str, port: int, use_redis: bool):
        if use_redis:
            try:
                return _RedisStore(host=host, port=port)
            except Exception as exc:
                logger.warning("Redis unavailable (%s) — using LRU store", exc)
        return _LRUStore(max_size=100_000)
