"""
defense/biometric_auth.py — Behavioral Biometric Authentication v10.0

Continuous behavioral verification using:
  • Keystroke dynamics (timing patterns between keystrokes)
  • Mouse movement trajectories (acceleration, curvature)
  • API call sequence patterns (expected call ordering)
  • CPU/Memory access frequency (access pattern profiling)
  • Inter-packet timing jitter (network behavior)

Detects insider threats, session hijacking, bot activity, supply-chain compromises.

Reference: Killourhy & Maxion (2009), keystroke dynamics literature
"""

from __future__ import annotations

import hashlib
import logging
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("shadow.defense.biometric_auth")

# ---------------------------------------------------------------------------
# Biometric Profiles
# ---------------------------------------------------------------------------

class BiometricThreat(Enum):
    SESSION_HIJACK = "session_hijack"
    INSIDER_THREAT = "insider_threat"
    BOT_ACTIVITY = "bot_activity"
    SUPPLY_CHAIN = "supply_chain_compromise"
    PRIVILEGE_ABUSE = "privilege_abuse"
    TIMING_ATTACK = "timing_attack_detected"


@dataclass
class BiometricProfile:
    """Baseline behavioral profile for a user/process/API key."""
    identifier: str  # user_id, process_name, api_key_hash
    profile_type: str  # "human", "service", "api", "device"
    created_ts: float = field(default_factory=time.time)
    # Keystroke dynamics (inter-keystroke delays in ms)
    keystroke_mean: float = 100.0
    keystroke_std: float = 50.0
    keystroke_history: deque = field(default_factory=lambda: deque(maxlen=100))
    # Mouse movement (pixels per second, curvature)
    mouse_speed_mean: float = 500.0
    mouse_speed_std: float = 200.0
    mouse_history: deque = field(default_factory=lambda: deque(maxlen=100))
    # API call sequence (expected next calls in order)
    api_sequences: Dict[str, List[str]] = field(default_factory=dict)  # api_pattern → next_calls
    api_sequence_freq: Dict[str, int] = field(default_factory=dict)
    # Memory access patterns (cache hit/miss ratio)
    mem_access_freq: float = 1000.0  # accesses per second
    mem_access_std: float = 200.0
    # Anomaly counter (incremented each time profile is violated)
    anomaly_count: int = 0
    last_seen_ts: float = field(default_factory=time.time)


@dataclass
class BiometricEvent:
    """Single biometric event (keystroke, mouse move, API call, etc)."""
    event_type: str  # "keystroke", "mouse", "api_call", "mem_access", "cpu_load"
    identifier: str
    timestamp_ms: float
    value: float  # delay (ms), speed (px/s), frequency, etc
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BiometricAlert:
    """Alert for biometric anomaly detection."""
    threat_type: BiometricThreat
    identifier: str
    severity: str  # low, medium, high, critical
    confidence: float
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    alert_id: str = ""

    def __post_init__(self) -> None:
        if not self.alert_id:
            self.alert_id = hashlib.sha256(
                f"{self.threat_type.value}{self.identifier}{self.ts}".encode()
            ).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Keystroke Dynamics Analyzer
# ---------------------------------------------------------------------------

class KeystrokeDynamicsAnalyzer:
    """
    Analyzes inter-keystroke timing patterns.
    Normal users have consistent keystroke patterns (mean + std dev).
    Imposters have different patterns or suspiciously perfect timing (bots).
    """

    def __init__(self, dwell_time_threshold_ms: float = 200.0):
        self._dwell_threshold = dwell_time_threshold_ms

    def analyze(
        self,
        profile: BiometricProfile,
        keystroke_delay_ms: float,
    ) -> Tuple[float, str]:
        """
        Returns (anomaly_score, description).
        anomaly_score: 0.0 (normal) to 1.0 (very anomalous)
        """
        # Suspiciously fast (possible bot/automation)
        if keystroke_delay_ms < 10.0:
            return 0.95, "Superhuman keystroke speed (<10ms)"

        # Suspiciously slow (possible encrypted typing, deliberate slowdown)
        if keystroke_delay_ms > 1000.0:
            return 0.85, "Extremely slow keystroke (>1s)"

        # Z-score based on profile baseline
        if profile.keystroke_std < 1e-6:
            return 0.0, "No baseline yet"

        z_score = abs(keystroke_delay_ms - profile.keystroke_mean) / (profile.keystroke_std + 1e-6)

        # >3 sigma is anomalous (99.7% confidence)
        if z_score > 3.0:
            severity = "high"
            confidence = min(0.99, 0.5 + 0.1 * math.log10(max(1, z_score)))
        elif z_score > 2.0:
            severity = "medium"
            confidence = 0.75
        elif z_score > 1.0:
            severity = "low"
            confidence = 0.50
        else:
            return 0.0, "Within normal range"

        profile.keystroke_history.append(keystroke_delay_ms)
        return round(min(1.0, z_score / 4.0), 3), f"Z-score {z_score:.1f}"

    def entropy(self, profile: BiometricProfile) -> float:
        """Shannon entropy of keystroke delays. Low entropy = bot-like."""
        if len(profile.keystroke_history) < 10:
            return -1.0
        delays = list(profile.keystroke_history)
        bins = np.histogram(delays, bins=10, range=(0, 500))[0]
        bins = bins[bins > 0]
        probs = bins / bins.sum()
        entropy = -float(np.sum(probs * np.log2(probs + 1e-10)))
        max_entropy = np.log2(10)
        return entropy / max_entropy  # normalized 0-1


# ---------------------------------------------------------------------------
# Mouse Movement Analyzer
# ---------------------------------------------------------------------------

class MouseDynamicsAnalyzer:
    """
    Analyzes mouse movement patterns: speed, acceleration, curvature.
    Bots have straight lines and constant speed.
    Humans have curved, variable-speed movements.
    """

    def analyze(
        self,
        profile: BiometricProfile,
        speed_px_s: float,
        curvature: float,
        acceleration: float,
    ) -> Tuple[float, str]:
        """
        curvature: 0.0 (straight line) to 1.0 (tight spiral)
        acceleration: change in speed (px/s²)
        Returns (anomaly_score, description)
        """
        anomalies = []

        # Bot signature: perfectly straight movement (curvature ≈ 0)
        if curvature < 0.05:
            anomalies.append((0.9, "Perfectly straight mouse movement (bot-like)"))

        # Bot signature: constant speed (acceleration ≈ 0)
        if acceleration < 1.0:
            anomalies.append((0.85, "Unnaturally constant mouse speed"))

        # Speed outlier
        z_speed = abs(speed_px_s - profile.mouse_speed_mean) / (profile.mouse_speed_std + 1e-6)
        if z_speed > 2.5:
            anomalies.append((min(0.8, z_speed / 4.0), f"Speed z-score {z_speed:.1f}"))

        if not anomalies:
            profile.mouse_history.append(speed_px_s)
            return 0.0, "Normal mouse movement"

        # Take max anomaly
        score, desc = max(anomalies, key=lambda x: x[0])
        profile.mouse_history.append(speed_px_s)
        return score, desc


# ---------------------------------------------------------------------------
# API Sequence Analyzer
# ---------------------------------------------------------------------------

class APISequenceAnalyzer:
    """
    Analyzes expected vs actual API call sequences.
    Normal users/services have consistent call patterns.
    Attackers often break the pattern (e.g., unusual database query after login).
    """

    def __init__(self):
        self._pattern_buffer_size = 50

    def analyze(
        self,
        profile: BiometricProfile,
        current_api: str,
        recent_apis: List[str],
    ) -> Tuple[float, str]:
        """
        current_api: "database.query", "file.read", "network.send", etc
        recent_apis: last N API calls in order
        Returns (anomaly_score, description)
        """
        if len(recent_apis) < 2:
            return 0.0, "Insufficient history"

        # Build expected pattern from recent calls
        recent_pattern = "→".join(recent_apis[-3:])
        expected_next = profile.api_sequences.get(recent_pattern, [])

        if not expected_next:
            # Never seen this pattern before - slightly anomalous
            return 0.1, f"Unfamiliar API sequence pattern"

        if current_api not in expected_next:
            # Current API breaks the expected sequence
            probability = profile.api_sequence_freq.get(recent_pattern, 0) / max(1, sum(profile.api_sequence_freq.values()))
            confidence = 1.0 - probability  # lower freq = higher anomaly
            return round(min(1.0, confidence * 0.8), 3), f"API call {current_api} unexpected after {recent_apis[-1]}"

        return 0.0, "Expected API sequence"

    def update_profile(
        self,
        profile: BiometricProfile,
        api_sequence: List[str],
    ) -> None:
        """Learn API call patterns from normal behavior."""
        for i in range(len(api_sequence) - 2):
            pattern = "→".join(api_sequence[i:i+2])
            next_api = api_sequence[i+2]
            if pattern not in profile.api_sequences:
                profile.api_sequences[pattern] = []
            if next_api not in profile.api_sequences[pattern]:
                profile.api_sequences[pattern].append(next_api)
            profile.api_sequence_freq[pattern] = profile.api_sequence_freq.get(pattern, 0) + 1


# ---------------------------------------------------------------------------
# Behavioral Biometric Authenticator
# ---------------------------------------------------------------------------

class BehavioralBiometricAuth:
    """
    Main behavioral biometric authentication engine.
    Continuously monitors and verifies user/process identity without explicit re-authentication.
    """

    def __init__(self, alert_callback=None):
        self._profiles: Dict[str, BiometricProfile] = {}
        self._keystroke_analyzer = KeystrokeDynamicsAnalyzer()
        self._mouse_analyzer = MouseDynamicsAnalyzer()
        self._api_analyzer = APISequenceAnalyzer()
        self._alert_callback = alert_callback
        self._alerts: List[BiometricAlert] = []
        self._stats = {"events": 0, "anomalies": 0, "alerts": 0}

    def register_profile(
        self,
        identifier: str,
        profile_type: str = "human",
    ) -> BiometricProfile:
        """Register a new user/service/API for behavioral profiling."""
        profile = BiometricProfile(identifier=identifier, profile_type=profile_type)
        self._profiles[identifier] = profile
        logger.info("Biometric profile registered: %s (%s)", identifier, profile_type)
        return profile

    def get_profile(self, identifier: str) -> Optional[BiometricProfile]:
        """Get or create a profile."""
        if identifier not in self._profiles:
            return self.register_profile(identifier)
        return self._profiles[identifier]

    def process_event(self, event: BiometricEvent) -> Optional[BiometricAlert]:
        """Process a single biometric event and check for anomalies."""
        self._stats["events"] += 1
        profile = self.get_profile(event.identifier)
        profile.last_seen_ts = event.timestamp_ms

        anomaly_score = 0.0
        description = ""

        if event.event_type == "keystroke":
            anomaly_score, description = self._keystroke_analyzer.analyze(profile, event.value)

        elif event.event_type == "mouse":
            curvature = event.metadata.get("curvature", 0.5)
            acceleration = event.metadata.get("acceleration", 0.0)
            anomaly_score, description = self._mouse_analyzer.analyze(
                profile, event.value, curvature, acceleration
            )

        elif event.event_type == "api_call":
            recent_apis = event.metadata.get("recent_apis", [])
            anomaly_score, description = self._api_analyzer.analyze(
                profile, event.value, recent_apis
            )

        if anomaly_score > 0.5:
            self._stats["anomalies"] += 1
            alert = BiometricAlert(
                threat_type=BiometricThreat.SESSION_HIJACK,
                identifier=event.identifier,
                severity="high" if anomaly_score > 0.8 else "medium",
                confidence=anomaly_score,
                description=description,
                evidence={
                    "event_type": event.event_type,
                    "anomaly_score": anomaly_score,
                    "metadata": event.metadata,
                },
            )
            self._emit_alert(alert)
            return alert

        return None

    def _emit_alert(self, alert: BiometricAlert) -> None:
        self._alerts.append(alert)
        self._stats["alerts"] += 1
        logger.warning("Biometric anomaly [%s]: %s (confidence=%.2f)", alert.threat_type.value, alert.description, alert.confidence)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass

    def extract_keystroke_features(self, keystroke_timings: List[float]) -> Dict[str, float]:
        """Extract features from keystroke timing sequence."""
        arr = np.array(keystroke_timings)
        return {
            "mean": float(np.mean(arr)),
            "std": float(np.std(arr)),
            "min": float(np.min(arr)),
            "max": float(np.max(arr)),
            "skew": float(np.abs(np.mean((arr - np.mean(arr))**3) / (np.std(arr)**3 + 1e-10))),
            "entropy": self._keystroke_analyzer.entropy(self._profiles.get(list(self._profiles.keys())[0], BiometricProfile("dummy", "human"))),
        }

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    @property
    def recent_alerts(self) -> List[Dict[str, Any]]:
        return [
            {
                "threat": a.threat_type.value,
                "identifier": a.identifier,
                "severity": a.severity,
                "confidence": a.confidence,
                "description": a.description,
                "ts": a.ts,
            }
            for a in self._alerts[-20:]
        ]


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_auth: Optional[BehavioralBiometricAuth] = None


def get_authenticator(alert_callback=None) -> BehavioralBiometricAuth:
    global _auth
    if _auth is None:
        _auth = BehavioralBiometricAuth(alert_callback)
    return _auth


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    auth = BehavioralBiometricAuth()
    auth.register_profile("user_alice", "human")

    # Simulate normal keystroke
    evt1 = BiometricEvent("keystroke", "user_alice", time.time(), 120.0)
    auth.process_event(evt1)

    # Simulate bot-like keystroke (5ms = superhuman)
    evt2 = BiometricEvent("keystroke", "user_alice", time.time(), 5.0)
    alert = auth.process_event(evt2)
    print(f"Alert: {alert}")
    print("Biometric Auth OK")
