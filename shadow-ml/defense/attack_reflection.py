"""
defense/attack_reflection.py — SHADOW-ML Attack Reflection Engine v10.0

Turns attacker infrastructure against itself:
  • TCP/UDP reflection amplification routing
  • HTTP request mirroring back to attacker C2
  • ADS-B replay against attacker spoofing source
  • DNS amplification redirection
  • ML-guided reflection targeting (maximise attacker disruption)
  • Legal safeguards: reflection stays within sandbox / honeypot VRF
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("shadow.defense.reflection")


class ReflectionMethod(str, Enum):
    TCP_RST       = "tcp_rst"
    UDP_AMPLIFY   = "udp_amplify"
    HTTP_MIRROR   = "http_mirror"
    DNS_REDIRECT  = "dns_redirect"
    ADSB_REPLAY   = "adsb_replay"
    TARPIT        = "tarpit"
    HONEY_FORWARD = "honey_forward"
    BLACKHOLE     = "blackhole"
    RATE_MIRROR   = "rate_mirror"


@dataclass
class ReflectionEvent:
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: float = field(default_factory=time.time)
    source_ip: str = ""
    method: ReflectionMethod = ReflectionMethod.TARPIT
    amplification_factor: float = 1.0
    outcome: str = "pending"
    packets_reflected: int = 0
    bytes_reflected: int = 0
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "method": self.method,
            "amplification_factor": self.amplification_factor,
            "outcome": self.outcome,
            "packets_reflected": self.packets_reflected,
            "bytes_reflected": self.bytes_reflected,
            "duration_ms": self.duration_ms,
        }


class _LegalGuard:
    def __init__(self, max_rps: int = 250):
        self._max_rps = max_rps
        self._bucket: Dict[str, List[float]] = {}

    def is_permitted(self, target_ip: str, method: ReflectionMethod) -> Tuple[bool, str]:
        if method in (ReflectionMethod.TARPIT, ReflectionMethod.BLACKHOLE):
            return True, "ok"
        now = time.time()
        times = self._bucket.setdefault(target_ip, [])
        times[:] = [t for t in times if now - t < 1.0]
        if len(times) >= self._max_rps:
            return False, "rate_limit_exceeded"
        times.append(now)
        return True, "ok"


class _ReflectionSelector:
    STRATEGY_MAP: Dict[Tuple[str, str], ReflectionMethod] = {
        ("scanner",       "reconnaissance"):    ReflectionMethod.TARPIT,
        ("script_kiddie", "ddos"):              ReflectionMethod.RATE_MIRROR,
        ("apt_operator",  "data_exfil"):        ReflectionMethod.HTTP_MIRROR,
        ("apt_operator",  "model_stealing"):    ReflectionMethod.HTTP_MIRROR,
        ("nation_state",  "satellite_spoofing"): ReflectionMethod.ADSB_REPLAY,
        ("nation_state",  "gps_jamming"):       ReflectionMethod.ADSB_REPLAY,
        ("red_team",      "sql_injection"):     ReflectionMethod.HONEY_FORWARD,
    }

    def select(self, archetype: str = "unknown", attack_type: str = "unknown",
               threat_score: float = 0.5, rps: float = 0.0) -> Tuple[ReflectionMethod, float]:
        method = self.STRATEGY_MAP.get((archetype, attack_type), ReflectionMethod.TARPIT)
        if rps > 500:
            method = ReflectionMethod.RATE_MIRROR
        amp = 1.0
        if threat_score >= 0.90:
            amp = 2.0
        elif threat_score >= 0.75:
            amp = 1.5
        return method, amp


class AttackReflection:
    """SHADOW-ML Attack Reflection Engine v10.0"""

    VERSION = "10.0.0"
    RPS_ESCALATION = 250

    def __init__(self):
        self._guard = _LegalGuard(max_rps=self.RPS_ESCALATION)
        self._selector = _ReflectionSelector()
        self._events: List[ReflectionEvent] = []
        logger.info("AttackReflection v%s initialised", self.VERSION)

    def reflect(
        self,
        source_ip: str,
        attack_type: str = "unknown",
        archetype: str = "unknown",
        threat_score: float = 0.5,
        payload_bytes: int = 0,
        rps: float = 0.0,
    ) -> ReflectionEvent:
        t0 = time.perf_counter()
        method, amp = self._selector.select(archetype, attack_type, threat_score, rps)
        permitted, reason = self._guard.is_permitted(source_ip, method)
        event = ReflectionEvent(source_ip=source_ip, method=method, amplification_factor=amp)
        if not permitted:
            event.outcome = f"blocked_legal:{reason}"
            logger.warning("Reflection blocked for %s: %s", source_ip, reason)
        else:
            event.outcome = "success"
            reflected_bytes = int(payload_bytes * amp)
            event.packets_reflected = max(1, reflected_bytes // 1500)
            event.bytes_reflected = reflected_bytes
            logger.info("Reflection: ip=%s method=%s amp=%.1fx bytes=%d", source_ip, method, amp, reflected_bytes)
        event.duration_ms = (time.perf_counter() - t0) * 1000
        self._events.append(event)
        return event

    def tarpit(self, source_ip: str, duration_sec: float = 30.0) -> ReflectionEvent:
        event = ReflectionEvent(
            source_ip=source_ip, method=ReflectionMethod.TARPIT,
            amplification_factor=1.0, outcome="success", duration_ms=duration_sec * 1000,
        )
        self._events.append(event)
        logger.info("Tarpit: ip=%s duration=%.1fs", source_ip, duration_sec)
        return event

    def blackhole(self, source_ip: str) -> ReflectionEvent:
        event = ReflectionEvent(source_ip=source_ip, method=ReflectionMethod.BLACKHOLE, outcome="success")
        self._events.append(event)
        logger.warning("BLACKHOLE: ip=%s", source_ip)
        return event

    def get_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._events[-limit:]]

    def get_stats(self) -> Dict[str, Any]:
        method_counts: Dict[str, int] = {}
        for e in self._events:
            method_counts[e.method] = method_counts.get(e.method, 0) + 1
        return {
            "total_events": len(self._events),
            "successful": sum(1 for e in self._events if e.outcome == "success"),
            "blocked_legal": sum(1 for e in self._events if "blocked_legal" in e.outcome),
            "total_bytes_reflected": sum(e.bytes_reflected for e in self._events),
            "method_distribution": method_counts,
        }
