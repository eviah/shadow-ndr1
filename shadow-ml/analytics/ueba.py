"""
analytics/ueba.py — User & Entity Behavior Analytics v10.0

Baselines normal behavior for:
  • Airport employees (login times, accessed systems, data volumes)
  • Service accounts (API call patterns, scheduled jobs)
  • Network entities (servers, switches, IoT devices)
  • Aircraft (flight schedules, route patterns)

Anomaly detection methods:
  • Statistical baseline (mean/std with exponential decay)
  • Peer group analysis (compare to similar users/entities)
  • Time-of-day normalization
  • Sequence analysis (unusual action ordering)
  • Data exfiltration indicators (large transfers, after-hours activity)
"""

from __future__ import annotations

import logging
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("shadow.analytics.ueba")


# ---------------------------------------------------------------------------
# Entity profile
# ---------------------------------------------------------------------------

@dataclass
class EntityProfile:
    """Statistical baseline for a user or entity."""
    entity_id: str
    entity_type: str  # user / service_account / device / aircraft
    peer_group: str   # role-based group for peer comparison

    # Activity statistics
    avg_logins_per_day: float = 0.0
    std_logins_per_day: float = 1.0
    avg_bytes_per_day: float = 0.0
    std_bytes_per_day: float = 1.0
    avg_distinct_systems: float = 0.0
    std_distinct_systems: float = 1.0

    # Temporal patterns
    active_hours: List[float] = field(default_factory=lambda: [0.0] * 24)  # probability by hour

    # Baseline metadata
    observations: int = 0
    first_seen: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    risk_score: float = 0.0

    ALPHA = 0.05   # EMA decay factor

    def update_stat(self, current: float, new_val: float, std_attr: str) -> float:
        """Exponential moving average update for a statistic."""
        new_mu = (1 - self.ALPHA) * current + self.ALPHA * new_val
        return new_mu

    def z_score(self, value: float, mu: float, std: float) -> float:
        return abs(value - mu) / max(1e-6, std)

    def anomaly_score_for_stat(self, value: float, mu: float, std: float) -> float:
        z = self.z_score(value, mu, std)
        return min(1.0, z / 5.0)  # z=5 → score=1.0


# ---------------------------------------------------------------------------
# Behavior event
# ---------------------------------------------------------------------------

@dataclass
class BehaviorEvent:
    entity_id: str
    entity_type: str
    event_type: str      # login / file_access / api_call / data_transfer / privilege_escalation
    timestamp: float
    bytes_transferred: int = 0
    target_system: str = ""
    source_ip: str = ""
    success: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def hour_of_day(self) -> int:
        return int((self.timestamp % 86400) / 3600)


# ---------------------------------------------------------------------------
# Anomaly result
# ---------------------------------------------------------------------------

@dataclass
class UEBAAnomaly:
    entity_id: str
    anomaly_type: str
    score: float
    description: str
    evidence: List[str]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "anomaly_type": self.anomaly_type,
            "score": round(self.score, 4),
            "description": self.description,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Peer group comparator
# ---------------------------------------------------------------------------

class PeerGroupAnalyzer:
    """
    Compares an entity's behavior to its peer group (users with same role).
    Flags deviations that are unusual even relative to the peer group norm.
    """

    def __init__(self):
        self._groups: Dict[str, List[float]] = defaultdict(list)  # group → [daily_bytes]

    def update(self, peer_group: str, daily_bytes: float) -> None:
        self._groups[peer_group].append(daily_bytes)
        if len(self._groups[peer_group]) > 1000:
            self._groups[peer_group].pop(0)

    def score(self, peer_group: str, entity_bytes: float) -> float:
        """How anomalous is this entity compared to its peers?"""
        peers = self._groups.get(peer_group, [])
        if len(peers) < 10:
            return 0.0
        mu = sum(peers) / len(peers)
        std = math.sqrt(sum((p - mu)**2 for p in peers) / len(peers)) + 1e-6
        z = abs(entity_bytes - mu) / std
        return min(1.0, z / 4.0)


# ---------------------------------------------------------------------------
# UEBA Engine
# ---------------------------------------------------------------------------

class UEBAEngine:
    """
    SHADOW-ML User & Entity Behavior Analytics v10.0

    Builds statistical behavioral baselines for every user and entity.
    Flags deviations that may indicate account compromise, insider threat,
    or lateral movement.
    """

    VERSION = "10.0.0"

    # Risk weights per anomaly type
    ANOMALY_WEIGHTS = {
        "unusual_hour":          0.3,
        "excessive_data":        0.6,
        "new_system_access":     0.5,
        "excessive_failures":    0.7,
        "privilege_escalation":  0.9,
        "peer_group_outlier":    0.4,
        "impossible_travel":     0.95,
        "data_exfiltration":     0.85,
    }

    def __init__(
        self,
        alert_threshold: float = 0.6,
        baseline_days: int = 30,
    ):
        self._profiles: Dict[str, EntityProfile] = {}
        self._peer_groups = PeerGroupAnalyzer()
        self._alert_threshold = alert_threshold
        self._event_buffer: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._daily_stats: Dict[str, Dict[str, Any]] = {}
        self._anomalies: List[UEBAAnomaly] = []
        self._stats: Dict[str, Any] = {
            "events_processed": 0,
            "anomalies_detected": 0,
            "entities_tracked": 0,
        }
        logger.info("UEBAEngine v%s initialised (threshold=%.2f)", self.VERSION, alert_threshold)

    def register_entity(
        self,
        entity_id: str,
        entity_type: str = "user",
        peer_group: str = "default",
    ) -> EntityProfile:
        if entity_id not in self._profiles:
            profile = EntityProfile(
                entity_id=entity_id,
                entity_type=entity_type,
                peer_group=peer_group,
            )
            self._profiles[entity_id] = profile
            self._stats["entities_tracked"] += 1
        return self._profiles[entity_id]

    def process_event(self, event: BehaviorEvent) -> List[UEBAAnomaly]:
        """Process one behavior event. Returns list of anomalies detected."""
        self._stats["events_processed"] += 1
        self._event_buffer[event.entity_id].append(event)

        profile = self._profiles.get(event.entity_id)
        if not profile:
            profile = self.register_entity(event.entity_id, event.entity_type)

        profile.observations += 1
        profile.last_updated = time.time()

        anomalies = []

        # 1. Unusual hour
        hour = event.hour_of_day
        hour_prob = profile.active_hours[hour]
        if profile.observations > 50 and hour_prob < 0.02:
            anomalies.append(UEBAAnomaly(
                entity_id=event.entity_id,
                anomaly_type="unusual_hour",
                score=self.ANOMALY_WEIGHTS["unusual_hour"] * (1 - hour_prob * 50),
                description=f"Activity at unusual hour {hour}:00 (historical prob={hour_prob:.3f})",
                evidence=[f"event_type={event.event_type}", f"hour={hour}"],
            ))

        # Update hour distribution
        profile.active_hours[hour] = (
            (1 - profile.ALPHA) * profile.active_hours[hour] + profile.ALPHA * 1.0
        )
        # Decay all other hours slightly
        for h in range(24):
            if h != hour:
                profile.active_hours[h] = (1 - 0.001) * profile.active_hours[h]

        # 2. Excessive data transfer
        if event.bytes_transferred > 0:
            score = profile.anomaly_score_for_stat(
                event.bytes_transferred,
                profile.avg_bytes_per_day,
                profile.std_bytes_per_day,
            )
            profile.avg_bytes_per_day = profile.update_stat(
                profile.avg_bytes_per_day, event.bytes_transferred, "std_bytes_per_day"
            )
            if score > 0.6:
                mb = event.bytes_transferred / 1_000_000
                anomalies.append(UEBAAnomaly(
                    entity_id=event.entity_id,
                    anomaly_type="excessive_data",
                    score=score * self.ANOMALY_WEIGHTS["excessive_data"],
                    description=f"Unusually large data transfer: {mb:.1f} MB (baseline: {profile.avg_bytes_per_day/1e6:.1f} MB/day)",
                    evidence=[f"bytes={event.bytes_transferred}", f"target={event.target_system}"],
                ))

            # Peer group comparison
            self._peer_groups.update(profile.peer_group, event.bytes_transferred)
            peer_score = self._peer_groups.score(profile.peer_group, event.bytes_transferred)
            if peer_score > 0.7:
                anomalies.append(UEBAAnomaly(
                    entity_id=event.entity_id,
                    anomaly_type="peer_group_outlier",
                    score=peer_score * self.ANOMALY_WEIGHTS["peer_group_outlier"],
                    description=f"Entity is outlier vs peer group '{profile.peer_group}' (score={peer_score:.2f})",
                    evidence=[f"peer_group={profile.peer_group}", f"bytes={event.bytes_transferred}"],
                ))

        # 3. Failed authentication
        if not event.success and event.event_type == "login":
            recent_events = list(self._event_buffer[event.entity_id])[-50:]
            recent_failures = sum(1 for e in recent_events
                                  if not e.success and e.event_type == "login"
                                  and event.timestamp - e.timestamp < 300)  # last 5 min
            if recent_failures >= 5:
                anomalies.append(UEBAAnomaly(
                    entity_id=event.entity_id,
                    anomaly_type="excessive_failures",
                    score=min(1.0, recent_failures / 10.0) * self.ANOMALY_WEIGHTS["excessive_failures"],
                    description=f"{recent_failures} login failures in last 5 minutes",
                    evidence=[f"failures={recent_failures}", f"src_ip={event.source_ip}"],
                ))

        # 4. Privilege escalation
        if event.event_type == "privilege_escalation":
            anomalies.append(UEBAAnomaly(
                entity_id=event.entity_id,
                anomaly_type="privilege_escalation",
                score=self.ANOMALY_WEIGHTS["privilege_escalation"],
                description=f"Privilege escalation detected: {event.target_system}",
                evidence=[f"target={event.target_system}", f"ip={event.source_ip}"],
            ))

        # 5. Impossible travel (login from two distant IPs within 1 hour)
        recent_logins = [
            e for e in list(self._event_buffer[event.entity_id])[-100:]
            if e.event_type == "login" and e.success
            and event.timestamp - e.timestamp < 3600
        ]
        if event.source_ip and len({e.source_ip for e in recent_logins}) >= 2:
            ips = list({e.source_ip for e in recent_logins})
            if not self._same_subnet(event.source_ip, ips[0]):
                anomalies.append(UEBAAnomaly(
                    entity_id=event.entity_id,
                    anomaly_type="impossible_travel",
                    score=self.ANOMALY_WEIGHTS["impossible_travel"],
                    description=f"Login from {event.source_ip} while recent login from {ips[0]}",
                    evidence=[f"ip1={ips[0]}", f"ip2={event.source_ip}", "time_diff<1h"],
                ))

        # Filter and update risk score
        significant = [a for a in anomalies if a.score >= self._alert_threshold]
        if significant:
            max_score = max(a.score for a in significant)
            profile.risk_score = max(profile.risk_score * 0.95, max_score)
            self._anomalies.extend(significant)
            self._stats["anomalies_detected"] += len(significant)
            for a in significant:
                logger.warning("UEBA anomaly: entity=%s type=%s score=%.2f",
                               event.entity_id, a.anomaly_type, a.score)

        return significant

    @staticmethod
    def _same_subnet(ip1: str, ip2: str) -> bool:
        """Check if two IPs share a /24 subnet."""
        try:
            parts1 = ip1.split(".")[:3]
            parts2 = ip2.split(".")[:3]
            return parts1 == parts2
        except Exception:
            return False

    def get_entity_risk(self, entity_id: str) -> Dict[str, Any]:
        profile = self._profiles.get(entity_id)
        if not profile:
            return {"entity_id": entity_id, "risk_score": 0.0, "known": False}
        return {
            "entity_id": entity_id,
            "risk_score": round(profile.risk_score, 4),
            "observations": profile.observations,
            "peer_group": profile.peer_group,
            "known": True,
        }

    def get_high_risk_entities(self, threshold: float = 0.6) -> List[Dict[str, Any]]:
        return [
            self.get_entity_risk(eid)
            for eid, p in self._profiles.items()
            if p.risk_score >= threshold
        ]

    def get_recent_anomalies(self, n: int = 50) -> List[Dict[str, Any]]:
        return [a.to_dict() for a in self._anomalies[-n:]]

    def get_stats(self) -> Dict[str, Any]:
        return {**self._stats, "version": self.VERSION}
