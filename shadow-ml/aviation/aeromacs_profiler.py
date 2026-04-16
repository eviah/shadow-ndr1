"""
aviation/aeromacs_profiler.py — AeroMACS Zero-Trust Profiler v10.0

AeroMACS (Aeronautical Mobile Airport Communication System) is the ICAO-standardised
WiMAX (IEEE 802.16) based airport surface communications network.
Used for: gate management, ground vehicle communications, taxiway control,
aircraft surface data link, and ACARS on the airport surface.

AeroMACS operates at 5.091–5.150 GHz (S-band, safety-of-life allocation).
Attack surface is significant: WiMAX protocol stack vulnerabilities,
rogue base stations, subscriber station (SS) spoofing.

Zero-Trust Profiling model:
  • Every subscriber station (aircraft, vehicle, gate) gets a behavioral profile
  • Any deviation from the profile = anomaly
  • Profiles: bandwidth usage, connection patterns, message types, timing

Specific threat detection:
  1. Rogue Base Station (eNodeB) — attacker sets up fake AeroMACS BS
  2. SS Identity Spoofing — fake MAC/HARQ/SS identity
  3. Bandwidth Exhaustion — flooding attack on AeroMACS radio
  4. Zone Boundary Violation — device connects from wrong physical sector
  5. Unexpected Protocol — non-AeroMACS data on AeroMACS bearer
  6. Connection Sequence Anomaly — WiMAX state machine violation
"""

from __future__ import annotations

import hashlib
import logging
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np

logger = logging.getLogger("shadow.aviation.aeromacs")

# ---------------------------------------------------------------------------
# AeroMACS Constants
# ---------------------------------------------------------------------------

AEROMACS_FREQ_MHZ_LOW = 5091.0
AEROMACS_FREQ_MHZ_HIGH = 5150.0
AEROMACS_CHANNEL_BW_MHZ = 5.0
AEROMACS_MAX_SUBSCRIBERS = 60          # per base station sector
AEROMACS_MAX_BANDWIDTH_KBPS = 10_000  # ~10 Mbps per sector

# Normal device types on AeroMACS
KNOWN_DEVICE_TYPES = {
    "AIRCRAFT": 1,
    "GROUND_VEHICLE": 2,
    "GATE_TERMINAL": 3,
    "ATMS_SERVER": 4,    # Airport Traffic Management System
    "WEATHER_SENSOR": 5,
    "RUNWAY_LIGHT": 6,
}

# WiMAX connection states
WIMAX_STATES = [
    "POWER_DOWN", "INITIAL_SCAN", "SYNCHRONISED",
    "CAPABILITY_NEGOTIATION", "AUTHENTICATION",
    "REGISTRATION", "CONNECTED", "IDLE",
]

VALID_WIMAX_TRANSITIONS: Dict[str, Set[str]] = {
    "POWER_DOWN": {"INITIAL_SCAN"},
    "INITIAL_SCAN": {"SYNCHRONISED"},
    "SYNCHRONISED": {"CAPABILITY_NEGOTIATION", "INITIAL_SCAN"},
    "CAPABILITY_NEGOTIATION": {"AUTHENTICATION", "SYNCHRONISED"},
    "AUTHENTICATION": {"REGISTRATION", "SYNCHRONISED"},
    "REGISTRATION": {"CONNECTED", "SYNCHRONISED"},
    "CONNECTED": {"IDLE", "INITIAL_SCAN"},
    "IDLE": {"CONNECTED", "INITIAL_SCAN"},
}


class AeroMACSAttack(Enum):
    ROGUE_BASE_STATION = "rogue_bs"
    SS_SPOOFING = "ss_spoofing"
    BANDWIDTH_EXHAUSTION = "bandwidth_exhaustion"
    ZONE_VIOLATION = "zone_boundary_violation"
    PROTOCOL_ANOMALY = "protocol_anomaly"
    STATE_MACHINE_VIOLATION = "wimax_state_violation"
    REPLAY_ATTACK = "replay_attack"
    DEAUTH_FLOOD = "deauth_flood"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class AeroMACSDevice:
    """Profile of a subscriber station (aircraft, vehicle, terminal)."""
    ss_mac: str                          # 48-bit MAC
    device_type: str
    sector_id: str                       # expected physical sector
    registered_ts: float = field(default_factory=time.time)
    last_seen_ts: float = field(default_factory=time.time)
    # Behavioral baselines (EWMA)
    avg_bandwidth_kbps: float = 100.0
    avg_session_duration_s: float = 300.0
    typical_connection_hour: Optional[int] = None    # hour of day (0-23)
    known_message_types: Set[str] = field(default_factory=set)
    connection_count: int = 0
    anomaly_count: int = 0
    wimax_state: str = "POWER_DOWN"
    rssi_baseline_dbm: float = -70.0


@dataclass
class AeroMACSEvent:
    """Single AeroMACS protocol event."""
    event_type: str              # CONNECT, DISCONNECT, DATA, HANDOVER, AUTH, DEAUTH
    ss_mac: str
    bs_id: str                   # base station identifier
    sector_id: str
    timestamp_s: float
    bandwidth_kbps: float = 0.0
    message_type: Optional[str] = None
    rssi_dbm: float = -70.0
    snr_db: float = 20.0
    wimax_state: Optional[str] = None
    payload_bytes: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AeroMACSAnomaly:
    attack_type: AeroMACSAttack
    severity: str
    confidence: float
    ss_mac: str
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    alert_id: str = ""

    def __post_init__(self) -> None:
        if not self.alert_id:
            self.alert_id = hashlib.sha256(
                f"{self.attack_type.value}{self.ss_mac}{self.ts}".encode()
            ).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Per-Device Behavioural Profiler
# ---------------------------------------------------------------------------

class DeviceProfiler:
    """
    Maintains and updates behavioural baseline for one AeroMACS device.
    Uses EWMA (exponential weighted moving average) for all metrics.
    """

    ALPHA = 0.1    # EWMA smoothing factor

    def __init__(self, device: AeroMACSDevice) -> None:
        self.device = device
        self._bw_history: deque = deque(maxlen=50)
        self._session_history: deque = deque(maxlen=20)
        self._last_connect_ts: Optional[float] = None
        self._hourly_activity: List[int] = [0] * 24

    def update(self, event: AeroMACSEvent) -> None:
        self.device.last_seen_ts = event.timestamp_s

        if event.event_type == "CONNECT":
            self._last_connect_ts = event.timestamp_s
            self.device.connection_count += 1
            hour = int((event.timestamp_s % 86400) / 3600)
            self._hourly_activity[hour] += 1

        if event.event_type == "DISCONNECT" and self._last_connect_ts:
            duration = event.timestamp_s - self._last_connect_ts
            self.device.avg_session_duration_s = (
                (1 - self.ALPHA) * self.device.avg_session_duration_s + self.ALPHA * duration
            )
            self._session_history.append(duration)

        if event.bandwidth_kbps > 0:
            self.device.avg_bandwidth_kbps = (
                (1 - self.ALPHA) * self.device.avg_bandwidth_kbps + self.ALPHA * event.bandwidth_kbps
            )
            self._bw_history.append(event.bandwidth_kbps)

        if event.message_type:
            self.device.known_message_types.add(event.message_type)

        if event.wimax_state:
            self.device.wimax_state = event.wimax_state

    def bandwidth_zscore(self, bw_kbps: float) -> float:
        if len(self._bw_history) < 5:
            return 0.0
        arr = np.array(list(self._bw_history))
        std = arr.std()
        if std < 1:
            return 0.0
        return abs(bw_kbps - arr.mean()) / std

    def is_active_during_unusual_hours(self, ts_s: float) -> bool:
        hour = int((ts_s % 86400) / 3600)
        if self.device.device_type == "AIRCRAFT":
            # Aircraft should not have maintenance comms between 03:00-04:00 local unless scheduled
            return 3 <= hour <= 4
        return False


# ---------------------------------------------------------------------------
# Base Station Validator
# ---------------------------------------------------------------------------

class BaseStationValidator:
    """
    Validates that base stations are legitimate registered AeroMACS BSes.
    Rogue BS detection: unexpected BS ID appears, or known BS shows wrong
    sector/frequency characteristics.
    """

    def __init__(self) -> None:
        self._registered_bs: Dict[str, Dict[str, Any]] = {}   # bs_id → config
        self._bs_event_counts: Dict[str, int] = defaultdict(int)
        self._rogue_candidates: Set[str] = set()

    def register_bs(self, bs_id: str, sector_id: str, freq_mhz: float) -> None:
        self._registered_bs[bs_id] = {
            "sector_id": sector_id,
            "freq_mhz": freq_mhz,
            "registered_ts": time.time(),
        }
        logger.info("AeroMACS BS registered: %s (sector=%s, %.1f MHz)", bs_id, sector_id, freq_mhz)

    def validate_bs(self, bs_id: str, sector_id: str, freq_mhz: float) -> Optional[AeroMACSAnomaly]:
        self._bs_event_counts[bs_id] += 1

        # Unknown BS
        if bs_id not in self._registered_bs:
            self._rogue_candidates.add(bs_id)
            return AeroMACSAnomaly(
                attack_type=AeroMACSAttack.ROGUE_BASE_STATION,
                severity="critical",
                confidence=0.92,
                ss_mac="BROADCAST",
                description=f"Unknown AeroMACS base station {bs_id} (not in registered list)",
                evidence={"bs_id": bs_id, "sector_id": sector_id, "freq_mhz": freq_mhz},
            )

        # Frequency anomaly
        registered = self._registered_bs[bs_id]
        if abs(freq_mhz - registered["freq_mhz"]) > 0.1:
            return AeroMACSAnomaly(
                attack_type=AeroMACSAttack.ROGUE_BASE_STATION,
                severity="high",
                confidence=0.85,
                ss_mac="BROADCAST",
                description=f"AeroMACS BS {bs_id} operating on {freq_mhz:.1f} MHz (expected {registered['freq_mhz']:.1f})",
                evidence={"bs_id": bs_id, "expected_freq": registered["freq_mhz"], "actual_freq": freq_mhz},
            )

        # Sector mismatch
        if sector_id != registered["sector_id"]:
            return AeroMACSAnomaly(
                attack_type=AeroMACSAttack.ZONE_VIOLATION,
                severity="medium",
                confidence=0.75,
                ss_mac="BROADCAST",
                description=f"AeroMACS BS {bs_id} reporting from sector {sector_id} (registered to {registered['sector_id']})",
                evidence={"bs_id": bs_id, "expected_sector": registered["sector_id"], "actual_sector": sector_id},
            )

        return None


# ---------------------------------------------------------------------------
# Main AeroMACS Profiler
# ---------------------------------------------------------------------------

class AeroMACSProfiler:
    """
    Zero-Trust profiler for the AeroMACS airport surface network.
    Maintains per-device profiles and validates every event against them.
    """

    def __init__(self, alert_callback: Optional[Any] = None) -> None:
        self._devices: Dict[str, AeroMACSDevice] = {}
        self._profilers: Dict[str, DeviceProfiler] = {}
        self._bs_validator = BaseStationValidator()
        self._alert_callback = alert_callback
        self._anomalies: List[AeroMACSAnomaly] = []
        self._deauth_counters: Dict[str, int] = defaultdict(int)
        self._deauth_window: Dict[str, float] = {}
        self._stats = {"events": 0, "anomalies": 0, "devices": 0}

    # ------------------------------------------------------------------
    def register_device(self, ss_mac: str, device_type: str, sector_id: str) -> None:
        device = AeroMACSDevice(ss_mac=ss_mac, device_type=device_type, sector_id=sector_id)
        self._devices[ss_mac] = device
        self._profilers[ss_mac] = DeviceProfiler(device)
        self._stats["devices"] += 1
        logger.info("AeroMACS device registered: %s (%s, sector=%s)", ss_mac, device_type, sector_id)

    def register_base_station(self, bs_id: str, sector_id: str, freq_mhz: float) -> None:
        self._bs_validator.register_bs(bs_id, sector_id, freq_mhz)

    # ------------------------------------------------------------------
    def process_event(self, event: AeroMACSEvent) -> List[AeroMACSAnomaly]:
        self._stats["events"] += 1
        anomalies: List[AeroMACSAnomaly] = []

        # 1. Validate base station
        bs_anomaly = self._bs_validator.validate_bs(event.bs_id, event.sector_id, 5095.0)
        if bs_anomaly:
            anomalies.append(bs_anomaly)

        # 2. Unknown subscriber station
        if event.ss_mac not in self._devices:
            anomalies.append(AeroMACSAnomaly(
                attack_type=AeroMACSAttack.SS_SPOOFING,
                severity="high",
                confidence=0.78,
                ss_mac=event.ss_mac,
                description=f"Unknown AeroMACS subscriber station {event.ss_mac}",
                evidence={"ss_mac": event.ss_mac, "bs_id": event.bs_id},
            ))
        else:
            device = self._devices[event.ss_mac]
            profiler = self._profilers[event.ss_mac]

            # 3. Zone boundary violation
            if event.sector_id != device.sector_id:
                anomalies.append(AeroMACSAnomaly(
                    attack_type=AeroMACSAttack.ZONE_VIOLATION,
                    severity="medium",
                    confidence=0.72,
                    ss_mac=event.ss_mac,
                    description=f"Device {event.ss_mac} connected from sector {event.sector_id} (expected {device.sector_id})",
                    evidence={"expected": device.sector_id, "actual": event.sector_id},
                ))

            # 4. Bandwidth exhaustion
            bw_z = profiler.bandwidth_zscore(event.bandwidth_kbps)
            if event.bandwidth_kbps > AEROMACS_MAX_BANDWIDTH_KBPS * 0.9:
                anomalies.append(AeroMACSAnomaly(
                    attack_type=AeroMACSAttack.BANDWIDTH_EXHAUSTION,
                    severity="high",
                    confidence=min(0.95, 0.6 + 0.05 * bw_z),
                    ss_mac=event.ss_mac,
                    description=f"AeroMACS bandwidth spike: {event.bandwidth_kbps:.0f} kbps (z={bw_z:.1f})",
                    evidence={"bw_kbps": event.bandwidth_kbps, "zscore": round(bw_z, 1)},
                ))

            # 5. WiMAX state machine violation
            if event.wimax_state and event.wimax_state != device.wimax_state:
                current = device.wimax_state
                valid_next = VALID_WIMAX_TRANSITIONS.get(current, set())
                if event.wimax_state not in valid_next:
                    anomalies.append(AeroMACSAnomaly(
                        attack_type=AeroMACSAttack.STATE_MACHINE_VIOLATION,
                        severity="medium",
                        confidence=0.80,
                        ss_mac=event.ss_mac,
                        description=f"WiMAX invalid transition {current} → {event.wimax_state}",
                        evidence={"from": current, "to": event.wimax_state},
                    ))

            # 6. Deauth flood detection
            if event.event_type == "DEAUTH":
                now = event.timestamp_s
                if event.ss_mac not in self._deauth_window:
                    self._deauth_window[event.ss_mac] = now
                    self._deauth_counters[event.ss_mac] = 1
                elif now - self._deauth_window[event.ss_mac] < 10.0:
                    self._deauth_counters[event.ss_mac] += 1
                    if self._deauth_counters[event.ss_mac] > 5:
                        anomalies.append(AeroMACSAnomaly(
                            attack_type=AeroMACSAttack.DEAUTH_FLOOD,
                            severity="high",
                            confidence=0.88,
                            ss_mac=event.ss_mac,
                            description=f"Deauth flood from {event.ss_mac}: {self._deauth_counters[event.ss_mac]} in 10s",
                            evidence={"count": self._deauth_counters[event.ss_mac]},
                        ))
                else:
                    self._deauth_window[event.ss_mac] = now
                    self._deauth_counters[event.ss_mac] = 1

            # Update profile
            profiler.update(event)

        for a in anomalies:
            self._anomalies.append(a)
            self._stats["anomalies"] += 1
            logger.warning("AeroMACS anomaly [%s]: %s", a.attack_type.value, a.description)
            if self._alert_callback:
                try:
                    self._alert_callback(a)
                except Exception:
                    pass

        return anomalies

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    @property
    def device_profiles(self) -> Dict[str, Dict[str, Any]]:
        return {
            mac: {
                "type": d.device_type,
                "sector": d.sector_id,
                "connections": d.connection_count,
                "anomalies": d.anomaly_count,
                "avg_bw_kbps": round(d.avg_bandwidth_kbps, 1),
                "state": d.wimax_state,
            }
            for mac, d in self._devices.items()
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_profiler: Optional[AeroMACSProfiler] = None


def get_profiler(alert_callback: Optional[Any] = None) -> AeroMACSProfiler:
    global _profiler
    if _profiler is None:
        _profiler = AeroMACSProfiler(alert_callback)
    return _profiler


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    profiler = AeroMACSProfiler()
    profiler.register_base_station("BS-GATE-A", "TERMINAL_A", 5095.0)
    profiler.register_device("AA:BB:CC:DD:EE:01", "AIRCRAFT", "TERMINAL_A")
    profiler.register_device("AA:BB:CC:DD:EE:02", "GROUND_VEHICLE", "APRON_WEST")

    # Normal events
    for i in range(5):
        ev = AeroMACSEvent(
            event_type="DATA", ss_mac="AA:BB:CC:DD:EE:01",
            bs_id="BS-GATE-A", sector_id="TERMINAL_A",
            timestamp_s=time.time() + i, bandwidth_kbps=500.0 + i * 10,
        )
        profiler.process_event(ev)

    # Rogue BS
    rogue_ev = AeroMACSEvent(
        event_type="CONNECT", ss_mac="AA:BB:CC:DD:EE:01",
        bs_id="BS-ROGUE-ATTACKER", sector_id="TERMINAL_A",
        timestamp_s=time.time(),
    )
    anomalies = profiler.process_event(rogue_ev)
    print(f"Rogue BS anomalies: {len(anomalies)}")
    print(f"Stats: {profiler.stats}")
    print("AeroMACS Profiler OK")
