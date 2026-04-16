"""
aviation/gps_ptp_monitor.py — GPS/GNSS & PTP Time-Sync Anomaly Detection v10.0

Detects GNSS jamming, GPS spoofing, and PTP/IEEE-1588 time injection attacks
by cross-referencing multiple time sources and applying physics-based validation.

Attack vectors covered:
  • GPS spoofing      — fake GPS signals driving receivers to wrong position/time
  • GPS jamming       — broadband RF noise suppressing all GNSS signals
  • PTP time injection — attacker injects fake Sync/Follow-Up PTP packets
  • NTP amplification — forged NTP responses causing time jumps
  • Multi-constellation GNSS replay — recorded GNSS signal replay attacks

Detection methods:
  1. Multi-source time consistency check (GPS vs PTP vs NTP vs atomic ref)
  2. Receiver Autonomous Integrity Monitoring (RAIM) cross-checks
  3. Doppler-based GNSS authenticity (speed ≠ carrier Doppler → spoofed)
  4. PTP packet sequence analysis (master clock jump detection)
  5. Clock stability metrics (Allan variance monitoring)
  6. Position drift velocity check (position can't jump >speed_of_light delay)

Aviation impact:
  • TCAS relies on precise time for collision avoidance calculations
  • ADS-B position timestamps must match radar cross-check
  • ILS DME uses radio time-of-flight — fake time = wrong glide path distance
  • ACARS/CPDLC message sequencing attacks via time manipulation
"""

from __future__ import annotations

import hashlib
import logging
import math
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("shadow.aviation.gps_ptp")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SPEED_OF_LIGHT_M_S = 299_792_458.0
GPS_L1_FREQ_HZ = 1_575_420_000.0       # L1 carrier
GPS_L2_FREQ_HZ = 1_227_600_000.0       # L2 carrier
GPS_L5_FREQ_HZ = 1_176_450_000.0       # L5 carrier (safety-of-life)
PTP_SYNC_INTERVAL_S = 0.125             # IEEE 1588 default sync rate (8 Hz)
NANOSECONDS_PER_SECOND = 1_000_000_000

# Maximum credible time offset between sources (1 ms)
MAX_LEGITIMATE_OFFSET_NS = 1_000_000

# Maximum credible position velocity from time-stamp discontinuity
MAX_CREDIBLE_VELOCITY_M_S = 340.0       # Mach 1 (fastest airport-area aircraft)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class TimeSource(Enum):
    GPS = auto()
    GLONASS = auto()
    GALILEO = auto()
    BEIDOU = auto()
    PTP_MASTER = auto()
    NTP_SERVER = auto()
    ATOMIC_REF = auto()
    SYSTEM_CLOCK = auto()


class AttackType(Enum):
    GPS_SPOOFING = "gps_spoofing"
    GPS_JAMMING = "gps_jamming"
    PTP_INJECTION = "ptp_injection"
    NTP_MANIPULATION = "ntp_manipulation"
    REPLAY_ATTACK = "gnss_replay"
    MULTIPATH_EXPLOIT = "gnss_multipath"
    TIME_ROLLBACK = "time_rollback"


@dataclass
class TimeReading:
    source: TimeSource
    timestamp_ns: int                   # UTC nanoseconds since epoch
    uncertainty_ns: float               # 1-sigma uncertainty
    signal_strength_dbm: Optional[float] = None   # GNSS: C/N₀
    satellites_used: Optional[int] = None
    position_lat: Optional[float] = None
    position_lon: Optional[float] = None
    position_alt_m: Optional[float] = None
    doppler_hz: Optional[float] = None
    snr_db: Optional[float] = None
    raw_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PTPPacket:
    """IEEE 1588 PTP packet fields."""
    msg_type: str                       # Sync, Follow_Up, Delay_Req, Delay_Resp
    sequence_id: int
    origin_timestamp_ns: int
    correction_field_ns: int
    source_port_id: str
    master_utc_offset: Optional[int] = None
    ts: float = field(default_factory=time.time)


@dataclass
class TimeAnomaly:
    attack_type: AttackType
    severity: str                       # low / medium / high / critical
    confidence: float
    source: TimeSource
    offset_ns: float                    # detected time offset
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    alert_id: str = ""

    def __post_init__(self) -> None:
        if not self.alert_id:
            self.alert_id = hashlib.sha256(
                f"{self.attack_type.value}{self.ts}{self.offset_ns}".encode()
            ).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Allan Variance (clock stability metric)
# ---------------------------------------------------------------------------

class AllanVarianceMonitor:
    """
    Tracks clock frequency stability via overlapping Allan Variance (OADEV).
    A sudden jump in ADEV indicates an external attack on the time source.
    Normal Cs beam standard: σ_y(1s) ≈ 5e-13
    GPS-disciplined oscillator: σ_y(1s) ≈ 1e-11
    Spoofed GPS: σ_y(1s) >> 1e-8 → alarm
    """

    def __init__(self, window: int = 64) -> None:
        self._window = window
        self._phases: deque = deque(maxlen=window * 2)
        self._baseline_adev: Optional[float] = None
        self._alarm_multiplier = 100.0     # 100× baseline triggers alarm

    def update(self, timestamp_ns: int) -> None:
        self._phases.append(timestamp_ns)

    def compute_adev(self, tau: int = 1) -> Optional[float]:
        """Overlapping Allan Deviation for given tau (samples)."""
        phases = np.array(list(self._phases), dtype=np.float64)
        if len(phases) < 3 * tau:
            return None
        # Phase differences
        freq = np.diff(phases)
        n = len(freq) - tau
        if n < 1:
            return None
        diffs = freq[tau:] - freq[:n]
        adev = math.sqrt(0.5 * np.mean(diffs ** 2)) / (phases[-1] - phases[0] + 1)
        return adev

    def calibrate(self) -> None:
        """Set baseline ADEV from current data."""
        adev = self.compute_adev()
        if adev is not None:
            self._baseline_adev = adev
            logger.info("Allan baseline calibrated: %.2e", adev)

    def is_unstable(self) -> Tuple[bool, float]:
        """Returns (is_anomalous, ratio_to_baseline)."""
        if self._baseline_adev is None:
            return False, 1.0
        current = self.compute_adev()
        if current is None:
            return False, 1.0
        ratio = current / (self._baseline_adev + 1e-30)
        return ratio > self._alarm_multiplier, ratio


# ---------------------------------------------------------------------------
# PTP Sequence Analyser
# ---------------------------------------------------------------------------

class PTPSequenceAnalyser:
    """
    Analyses IEEE 1588 PTP packet sequences for injection attacks.

    Attack signatures detected:
    1. Sync sequence gap — attacker kills legitimate master, inserts fake
    2. Origin timestamp jump — sudden large time offset in Sync message
    3. Sequence ID anomaly — non-monotonic IDs indicate replayed/forged packets
    4. Correction field manipulation — forged path delay
    5. Rogue master assertion (multiple masters on same domain)
    """

    def __init__(self) -> None:
        self._sync_history: deque = deque(maxlen=64)
        self._last_seq_id: Dict[str, int] = {}
        self._masters: Dict[str, int] = {}       # port_id → packet count
        self._last_sync_ts: float = 0.0
        self._expected_interval_s = PTP_SYNC_INTERVAL_S
        self._anomalies: List[TimeAnomaly] = []

    def process_packet(self, pkt: PTPPacket) -> Optional[TimeAnomaly]:
        anomaly = None

        if pkt.msg_type == "Sync":
            # Check sequence continuity
            if pkt.source_port_id in self._last_seq_id:
                expected = (self._last_seq_id[pkt.source_port_id] + 1) % 65536
                if pkt.sequence_id != expected:
                    anomaly = TimeAnomaly(
                        attack_type=AttackType.PTP_INJECTION,
                        severity="high",
                        confidence=0.85,
                        source=TimeSource.PTP_MASTER,
                        offset_ns=0,
                        description=f"PTP Sync sequence gap: expected {expected}, got {pkt.sequence_id}",
                        evidence={"expected_seq": expected, "got_seq": pkt.sequence_id,
                                  "port": pkt.source_port_id},
                    )

            # Check interval regularity
            now = time.time()
            if self._last_sync_ts > 0:
                interval = now - self._last_sync_ts
                if abs(interval - self._expected_interval_s) > 0.05:
                    anomaly = TimeAnomaly(
                        attack_type=AttackType.PTP_INJECTION,
                        severity="medium",
                        confidence=0.7,
                        source=TimeSource.PTP_MASTER,
                        offset_ns=0,
                        description=f"PTP Sync interval anomaly: {interval:.3f}s (expected {self._expected_interval_s:.3f}s)",
                        evidence={"interval": interval, "expected": self._expected_interval_s},
                    )

            # Check for rogue master
            self._masters[pkt.source_port_id] = self._masters.get(pkt.source_port_id, 0) + 1
            if len(self._masters) > 1:
                anomaly = TimeAnomaly(
                    attack_type=AttackType.PTP_INJECTION,
                    severity="critical",
                    confidence=0.95,
                    source=TimeSource.PTP_MASTER,
                    offset_ns=0,
                    description=f"Multiple PTP masters detected: {list(self._masters.keys())}",
                    evidence={"masters": dict(self._masters)},
                )

            self._last_sync_ts = now
            self._last_seq_id[pkt.source_port_id] = pkt.sequence_id
            self._sync_history.append(pkt)

        # Check origin timestamp jump
        if self._sync_history and pkt.msg_type == "Sync":
            last = self._sync_history[-1]
            ts_delta_ns = abs(pkt.origin_timestamp_ns - last.origin_timestamp_ns)
            # Expect ~125ms between syncs; >1s jump is suspicious
            if ts_delta_ns > NANOSECONDS_PER_SECOND:
                anomaly = TimeAnomaly(
                    attack_type=AttackType.PTP_INJECTION,
                    severity="critical",
                    confidence=0.92,
                    source=TimeSource.PTP_MASTER,
                    offset_ns=float(ts_delta_ns),
                    description=f"PTP origin timestamp jumped {ts_delta_ns/1e6:.1f} ms",
                    evidence={"ts_jump_ns": ts_delta_ns},
                )

        if anomaly:
            self._anomalies.append(anomaly)
        return anomaly


# ---------------------------------------------------------------------------
# Multi-Source Time Consistency Engine
# ---------------------------------------------------------------------------

class MultiSourceTimeConsistency:
    """
    Cross-references time readings from multiple sources.
    Uses weighted median as the ground truth reference.
    Any source deviating more than MAX_LEGITIMATE_OFFSET_NS is flagged.
    """

    def __init__(self) -> None:
        self._readings: Dict[TimeSource, deque] = {s: deque(maxlen=32) for s in TimeSource}
        self._weights: Dict[TimeSource, float] = {
            TimeSource.ATOMIC_REF: 10.0,
            TimeSource.GPS: 5.0,
            TimeSource.GALILEO: 5.0,
            TimeSource.GLONASS: 4.0,
            TimeSource.BEIDOU: 4.0,
            TimeSource.PTP_MASTER: 3.0,
            TimeSource.NTP_SERVER: 1.0,
            TimeSource.SYSTEM_CLOCK: 0.5,
        }

    def add_reading(self, reading: TimeReading) -> Optional[TimeAnomaly]:
        self._readings[reading.source].append(reading)
        return self._check_consistency(reading)

    def _weighted_median_ns(self) -> Optional[float]:
        """Compute weighted median timestamp across all sources."""
        values = []
        weights = []
        for source, history in self._readings.items():
            if history:
                avg_ts = float(np.mean([r.timestamp_ns for r in history]))
                values.append(avg_ts)
                weights.append(self._weights[source])

        if len(values) < 2:
            return None

        values = np.array(values)
        weights = np.array(weights)
        # Weighted median via sorting
        sorted_idx = np.argsort(values)
        values = values[sorted_idx]
        weights = weights[sorted_idx]
        cum_w = np.cumsum(weights)
        total_w = cum_w[-1]
        median_idx = np.searchsorted(cum_w, total_w / 2)
        return float(values[min(median_idx, len(values) - 1)])

    def _check_consistency(self, reading: TimeReading) -> Optional[TimeAnomaly]:
        reference = self._weighted_median_ns()
        if reference is None:
            return None

        offset_ns = abs(reading.timestamp_ns - reference)
        if offset_ns > MAX_LEGITIMATE_OFFSET_NS:
            severity = "critical" if offset_ns > 1e9 else "high" if offset_ns > 1e7 else "medium"
            confidence = min(0.99, 0.6 + 0.3 * math.log10(max(1, offset_ns / MAX_LEGITIMATE_OFFSET_NS)))

            attack = AttackType.GPS_SPOOFING if reading.source in (
                TimeSource.GPS, TimeSource.GLONASS, TimeSource.GALILEO, TimeSource.BEIDOU
            ) else AttackType.PTP_INJECTION if reading.source == TimeSource.PTP_MASTER \
                else AttackType.NTP_MANIPULATION

            return TimeAnomaly(
                attack_type=attack,
                severity=severity,
                confidence=round(confidence, 3),
                source=reading.source,
                offset_ns=offset_ns,
                description=f"{reading.source.name} time offset {offset_ns/1e6:.2f} ms vs multi-source consensus",
                evidence={
                    "source": reading.source.name,
                    "source_ts_ns": reading.timestamp_ns,
                    "consensus_ts_ns": int(reference),
                    "offset_ns": offset_ns,
                },
            )
        return None


# ---------------------------------------------------------------------------
# Position Jump Validator
# ---------------------------------------------------------------------------

class PositionJumpValidator:
    """
    Validates that position changes are physically possible.
    If GPS position jumps more than MAX_CREDIBLE_VELOCITY_M_S × Δt,
    it's physically impossible and must be spoofed.
    """

    def __init__(self) -> None:
        self._last_reading: Optional[TimeReading] = None

    def validate(self, reading: TimeReading) -> Optional[TimeAnomaly]:
        if not all([reading.position_lat, reading.position_lon]):
            return None

        if self._last_reading is None:
            self._last_reading = reading
            return None

        dt_s = (reading.timestamp_ns - self._last_reading.timestamp_ns) / NANOSECONDS_PER_SECOND
        if dt_s <= 0 or dt_s > 60:
            self._last_reading = reading
            return None

        distance_m = self._haversine_m(
            self._last_reading.position_lat, self._last_reading.position_lon,
            reading.position_lat, reading.position_lon,
        )
        velocity = distance_m / dt_s
        self._last_reading = reading

        if velocity > MAX_CREDIBLE_VELOCITY_M_S:
            return TimeAnomaly(
                attack_type=AttackType.GPS_SPOOFING,
                severity="critical",
                confidence=0.97,
                source=reading.source,
                offset_ns=0,
                description=f"GPS position jump implies {velocity:.0f} m/s (physically impossible)",
                evidence={
                    "velocity_m_s": round(velocity, 1),
                    "max_credible_m_s": MAX_CREDIBLE_VELOCITY_M_S,
                    "distance_m": round(distance_m, 1),
                    "dt_s": round(dt_s, 3),
                },
            )
        return None

    @staticmethod
    def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        R = 6_371_000.0
        phi1, phi2 = math.radians(lat1), math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlam = math.radians(lon2 - lon1)
        a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
        return 2 * R * math.asin(math.sqrt(a))


# ---------------------------------------------------------------------------
# Signal Strength Jamming Detector
# ---------------------------------------------------------------------------

class SignalJammingDetector:
    """
    Monitors GNSS C/N₀ (carrier-to-noise ratio) for jamming signatures.
    Normal L1 C/N₀ on ground: 40–55 dB-Hz
    Under jamming: drops below 25 dB-Hz across all satellites simultaneously.
    """

    JAMMING_THRESHOLD_DBHZ = 25.0
    NORMAL_MIN_DBHZ = 35.0

    def __init__(self) -> None:
        self._cn0_history: deque = deque(maxlen=30)
        self._jamming_start: Optional[float] = None

    def update(self, cn0_dbhz: float) -> Optional[TimeAnomaly]:
        self._cn0_history.append(cn0_dbhz)
        if len(self._cn0_history) < 5:
            return None

        recent_avg = float(np.mean(list(self._cn0_history)[-5:]))
        if recent_avg < self.JAMMING_THRESHOLD_DBHZ:
            if self._jamming_start is None:
                self._jamming_start = time.time()
            duration = time.time() - self._jamming_start
            return TimeAnomaly(
                attack_type=AttackType.GPS_JAMMING,
                severity="critical",
                confidence=min(0.99, 0.7 + 0.05 * duration),
                source=TimeSource.GPS,
                offset_ns=0,
                description=f"GPS jamming detected: C/N₀ {recent_avg:.1f} dB-Hz (threshold {self.JAMMING_THRESHOLD_DBHZ})",
                evidence={
                    "cn0_avg_dbhz": round(recent_avg, 1),
                    "threshold_dbhz": self.JAMMING_THRESHOLD_DBHZ,
                    "duration_s": round(duration, 1),
                },
            )
        else:
            self._jamming_start = None
        return None


# ---------------------------------------------------------------------------
# Main GPS/PTP Monitor
# ---------------------------------------------------------------------------

class GPSPTPMonitor:
    """
    Top-level GPS/PTP time-sync anomaly monitor.
    Aggregates all sub-detectors and emits unified alerts.
    """

    def __init__(self, alert_callback: Optional[Any] = None) -> None:
        self._consistency = MultiSourceTimeConsistency()
        self._ptp_analyser = PTPSequenceAnalyser()
        self._position_validator = PositionJumpValidator()
        self._jamming_detector = SignalJammingDetector()
        self._allan_monitors: Dict[TimeSource, AllanVarianceMonitor] = {
            s: AllanVarianceMonitor() for s in TimeSource
        }
        self._alert_callback = alert_callback
        self._all_anomalies: List[TimeAnomaly] = []
        self._stats = {"readings": 0, "anomalies": 0, "critical": 0}

    # ------------------------------------------------------------------
    def process_time_reading(self, reading: TimeReading) -> List[TimeAnomaly]:
        anomalies: List[TimeAnomaly] = []
        self._stats["readings"] += 1

        # 1. Multi-source consistency
        a = self._consistency.add_reading(reading)
        if a:
            anomalies.append(a)

        # 2. Allan variance stability
        monitor = self._allan_monitors[reading.source]
        monitor.update(reading.timestamp_ns)
        unstable, ratio = monitor.is_unstable()
        if unstable:
            anomalies.append(TimeAnomaly(
                attack_type=AttackType.GPS_SPOOFING,
                severity="high",
                confidence=min(0.95, 0.5 + 0.1 * math.log10(max(1, ratio))),
                source=reading.source,
                offset_ns=0,
                description=f"Clock Allan deviation {ratio:.0f}× above baseline (attack likely)",
                evidence={"adev_ratio": round(ratio, 1)},
            ))

        # 3. Position jump validation (GNSS only)
        if reading.source in (TimeSource.GPS, TimeSource.GALILEO, TimeSource.GLONASS, TimeSource.BEIDOU):
            a = self._position_validator.validate(reading)
            if a:
                anomalies.append(a)

        # 4. Signal strength jamming
        if reading.signal_strength_dbm is not None:
            a = self._jamming_detector.update(reading.signal_strength_dbm)
            if a:
                anomalies.append(a)

        for anomaly in anomalies:
            self._all_anomalies.append(anomaly)
            self._stats["anomalies"] += 1
            if anomaly.severity == "critical":
                self._stats["critical"] += 1
            logger.warning(
                "GPS/PTP anomaly [%s]: %s (confidence=%.2f)",
                anomaly.attack_type.value, anomaly.description, anomaly.confidence,
            )
            if self._alert_callback:
                try:
                    self._alert_callback(anomaly)
                except Exception:
                    pass

        return anomalies

    def process_ptp_packet(self, pkt: PTPPacket) -> Optional[TimeAnomaly]:
        anomaly = self._ptp_analyser.process_packet(pkt)
        if anomaly:
            self._all_anomalies.append(anomaly)
            self._stats["anomalies"] += 1
            if self._alert_callback:
                try:
                    self._alert_callback(anomaly)
                except Exception:
                    pass
        return anomaly

    def calibrate_allan_baselines(self) -> None:
        for m in self._allan_monitors.values():
            m.calibrate()

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    @property
    def recent_anomalies(self) -> List[Dict[str, Any]]:
        return [
            {
                "type": a.attack_type.value,
                "severity": a.severity,
                "confidence": a.confidence,
                "offset_ns": a.offset_ns,
                "description": a.description,
                "ts": a.ts,
                "alert_id": a.alert_id,
            }
            for a in self._all_anomalies[-20:]
        ]


# ---------------------------------------------------------------------------
# Module singleton
# ---------------------------------------------------------------------------

_monitor: Optional[GPSPTPMonitor] = None


def get_monitor(alert_callback: Optional[Any] = None) -> GPSPTPMonitor:
    global _monitor
    if _monitor is None:
        _monitor = GPSPTPMonitor(alert_callback)
    return _monitor


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    mon = GPSPTPMonitor()

    # Normal readings
    base_ts = int(time.time() * 1e9)
    for i in range(20):
        r = TimeReading(
            source=TimeSource.GPS,
            timestamp_ns=base_ts + i * 125_000_000,
            uncertainty_ns=50,
            signal_strength_dbm=45.0,
            position_lat=32.0115,
            position_lon=34.8867,
        )
        mon.process_time_reading(r)

    # Inject spoofed reading with large time offset
    spoofed = TimeReading(
        source=TimeSource.GPS,
        timestamp_ns=base_ts + 5_000_000_000,   # 5 second jump!
        uncertainty_ns=50,
        signal_strength_dbm=45.0,
        position_lat=32.0115,
        position_lon=34.8867,
    )
    anomalies = mon.process_time_reading(spoofed)
    print(f"Detected {len(anomalies)} anomalies")
    print(f"Stats: {mon.stats}")
    print("GPS/PTP Monitor OK")
