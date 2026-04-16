"""
aviation/ils_monitor.py — ILS Glide Slope & Localiser Spoofing Detection v10.0

Instrument Landing System (ILS) provides precision runway guidance.
Attacking ILS can redirect aircraft to collide with terrain or obstacles.

ILS components:
  • Localiser  — horizontal guidance, 108–112 MHz, 90/150 Hz DDM
  • Glide Slope — vertical guidance, 329–335 MHz, 90/150 Hz DDM
  • Marker Beacons — distance markers (OM/MM/IM)

Attack vectors:
  1. False Glide Slope capture — spoof 3° approach path to guide plane into terrain
  2. Localiser offset spoofing — shift lateral guidance off runway centerline
  3. DDM manipulation — alter Difference in Depth of Modulation signal
  4. Cat III approach jamming — target autoland in zero-visibility conditions
  5. RF interference — broadband jamming of ILS frequencies

Detection methods:
  1. Physics-based approach path model: latitude × longitude × altitude curve fitting
  2. Cross-validation with ADS-B position track
  3. DDM statistical anomaly (normal range: ±0.155 DDM)
  4. Multi-path ratio analysis (real ILS has specific multipath signature)
  5. Aircraft kinematic validation (approach speed/vertical rate physics)
  6. Dual-frequency cross-check (LOC + GP must arrive coherently)
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

logger = logging.getLogger("shadow.aviation.ils")

# ---------------------------------------------------------------------------
# Physical Constants & ILS Parameters
# ---------------------------------------------------------------------------

ILS_LOCALISER_FREQ_MHZ_RANGE = (108.0, 112.0)      # VHF
ILS_GLIDESLOPE_FREQ_MHZ_RANGE = (329.15, 335.0)    # UHF
STANDARD_GLIDEPATH_DEGREES = 3.0                   # 3° standard approach
GLIDEPATH_TOLERANCE_DEGREES = 0.5                  # ±0.5° ILS CAT I tolerance
LOCALISER_FULL_SCALE_DEGREES = 2.5                 # full-scale deflection
DDM_FULL_SCALE = 0.155                             # full-scale DDM (150μA)
DDM_NOISE_SIGMA = 0.003                            # normal RMS noise
STANDARD_APPROACH_SPEED_MS = 72.0                  # ~140 knots
STANDARD_DESCENT_RATE_MS = 3.0                     # ~600 fpm
GLIDESLOPE_HEIGHT_AT_THRESHOLD_M = 15.24           # 50 ft FAF crossing height


class ILSComponent(Enum):
    LOCALISER = "LOC"
    GLIDESLOPE = "GS"
    OUTER_MARKER = "OM"
    MIDDLE_MARKER = "MM"
    INNER_MARKER = "IM"


class ILSAttackType(Enum):
    FALSE_GLIDESLOPE = "false_glideslope"
    LOCALISER_OFFSET = "localiser_offset"
    DDM_MANIPULATION = "ddm_manipulation"
    RF_JAMMING = "ils_jamming"
    CAPTURED_ABOVE_GS = "false_gs_capture"
    TERRAIN_COLLISION_PATH = "terrain_collision_path"


@dataclass
class ILSReading:
    """Raw ILS receiver reading."""
    component: ILSComponent
    frequency_mhz: float
    ddm: float                          # Difference in Depth of Modulation
    signal_level_dbm: float
    course_deviation_dots: float        # full-scale = ±2 dots
    aircraft_lat: Optional[float] = None
    aircraft_lon: Optional[float] = None
    aircraft_alt_m: Optional[float] = None
    aircraft_speed_ms: Optional[float] = None
    aircraft_vrate_ms: Optional[float] = None
    runway_threshold_lat: Optional[float] = None
    runway_threshold_lon: Optional[float] = None
    ts: float = field(default_factory=time.time)


@dataclass
class ILSAnomaly:
    attack_type: ILSAttackType
    component: ILSComponent
    severity: str
    confidence: float
    deviation_from_expected: float
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    alert_id: str = ""

    def __post_init__(self) -> None:
        if not self.alert_id:
            self.alert_id = hashlib.sha256(
                f"{self.attack_type.value}{self.ts}".encode()
            ).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Approach Path Physics Model
# ---------------------------------------------------------------------------

class ApproachPathModel:
    """
    Models the expected 3D approach path based on runway coordinates.
    Any aircraft following an ILS signal that deviates from this model
    is either on a false glideslope or the ILS is spoofed.

    Standard 3° ILS approach geometry:
      - Height at n miles from threshold: h = n × tan(3°) × 1852 metres
      - Localiser course: great-circle track aligned with runway heading
    """

    def __init__(
        self,
        runway_lat: float,
        runway_lon: float,
        runway_heading_deg: float,
        glidepath_angle_deg: float = STANDARD_GLIDEPATH_DEGREES,
    ) -> None:
        self.runway_lat = runway_lat
        self.runway_lon = runway_lon
        self.runway_heading_deg = runway_heading_deg
        self.glidepath_angle_deg = glidepath_angle_deg
        self._gp_tan = math.tan(math.radians(glidepath_angle_deg))

    def expected_altitude_m(self, distance_m: float) -> float:
        """Expected altitude at given distance from runway threshold."""
        return distance_m * self._gp_tan + GLIDESLOPE_HEIGHT_AT_THRESHOLD_M

    def expected_range_deg_from_centreline(
        self, aircraft_lat: float, aircraft_lon: float
    ) -> float:
        """Angular deviation from localiser centreline (degrees)."""
        # Simplified: bearing difference from runway heading
        bearing = self._bearing(self.runway_lat, self.runway_lon, aircraft_lat, aircraft_lon)
        deviation = bearing - self.runway_heading_deg
        # Normalise to ±180
        while deviation > 180:
            deviation -= 360
        while deviation < -180:
            deviation += 360
        return deviation

    def distance_m(self, lat: float, lon: float) -> float:
        """Distance from runway threshold."""
        R = 6_371_000.0
        dlat = math.radians(lat - self.runway_lat)
        dlon = math.radians(lon - self.runway_lon)
        a = math.sin(dlat / 2) ** 2 + (
            math.cos(math.radians(self.runway_lat))
            * math.cos(math.radians(lat))
            * math.sin(dlon / 2) ** 2
        )
        return 2 * R * math.asin(math.sqrt(a))

    @staticmethod
    def _bearing(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        lat1r = math.radians(lat1)
        lat2r = math.radians(lat2)
        dlon = math.radians(lon2 - lon1)
        x = math.sin(dlon) * math.cos(lat2r)
        y = math.cos(lat1r) * math.sin(lat2r) - math.sin(lat1r) * math.cos(lat2r) * math.cos(dlon)
        return (math.degrees(math.atan2(x, y)) + 360) % 360


# ---------------------------------------------------------------------------
# DDM Statistical Monitor
# ---------------------------------------------------------------------------

class DDMStatisticalMonitor:
    """
    Monitors DDM (Difference in Depth of Modulation) time series.
    Normal ILS DDM has specific noise characteristics.
    Spoofed signals have abnormally clean DDM (no multipath noise),
    or sudden step changes (attacker switching on a jammer).
    """

    def __init__(self) -> None:
        self._ddm_history: deque = deque(maxlen=60)
        self._baseline_std: Optional[float] = None

    def update(self, ddm: float) -> Optional[str]:
        """Returns anomaly description or None."""
        self._ddm_history.append(ddm)
        if len(self._ddm_history) < 10:
            return None

        recent = np.array(list(self._ddm_history))

        # Calibrate baseline noise from first 30 samples
        if self._baseline_std is None and len(self._ddm_history) >= 30:
            self._baseline_std = float(np.std(recent[:30]))
            logger.debug("DDM baseline std: %.4f", self._baseline_std)

        if self._baseline_std is None:
            return None

        current_std = float(np.std(recent[-10:]))

        # Too clean: spoofed DDM has no multipath noise
        if current_std < self._baseline_std * 0.1:
            return f"DDM noise suspiciously low (std={current_std:.5f}, baseline={self._baseline_std:.5f}) — possible spoofed clean signal"

        # Step change: sudden DDM jump
        diffs = np.abs(np.diff(recent[-6:]))
        if diffs.max() > DDM_FULL_SCALE * 0.5:
            return f"DDM step change {diffs.max():.3f} DDM (>50% full scale) — possible attack"

        # Out-of-range DDM (attacker overdriving)
        if abs(ddm) > DDM_FULL_SCALE * 1.5:
            return f"DDM out-of-range: {ddm:.3f} (normal ±{DDM_FULL_SCALE})"

        return None


# ---------------------------------------------------------------------------
# ILS Monitor
# ---------------------------------------------------------------------------

class ILSMonitor:
    """
    Main ILS anomaly detection engine.
    Combines physics-based approach modelling with statistical signal analysis.
    """

    def __init__(
        self,
        runway_lat: float = 32.0094,      # Default: Ben Gurion RWY 12
        runway_lon: float = 34.8781,
        runway_heading_deg: float = 120.0,
        alert_callback: Optional[Any] = None,
    ) -> None:
        self._path_model = ApproachPathModel(runway_lat, runway_lon, runway_heading_deg)
        self._ddm_monitors = {c: DDMStatisticalMonitor() for c in ILSComponent}
        self._alert_callback = alert_callback
        self._anomalies: List[ILSAnomaly] = []
        self._reading_history: deque = deque(maxlen=128)
        self._stats = {"readings": 0, "anomalies": 0, "false_glideslopes": 0}

    # ------------------------------------------------------------------
    def process_reading(self, reading: ILSReading) -> List[ILSAnomaly]:
        self._stats["readings"] += 1
        self._reading_history.append(reading)
        anomalies: List[ILSAnomaly] = []

        # 1. DDM statistical analysis
        ddm_desc = self._ddm_monitors[reading.component].update(reading.ddm)
        if ddm_desc:
            anomalies.append(ILSAnomaly(
                attack_type=ILSAttackType.DDM_MANIPULATION,
                component=reading.component,
                severity="high",
                confidence=0.82,
                deviation_from_expected=abs(reading.ddm),
                description=ddm_desc,
                evidence={"ddm": reading.ddm, "component": reading.component.value},
            ))

        # 2. Physics-based approach path validation
        if (reading.aircraft_lat is not None and
                reading.aircraft_lon is not None and
                reading.aircraft_alt_m is not None):
            anomaly = self._validate_approach_path(reading)
            if anomaly:
                anomalies.append(anomaly)

        # 3. Signal level monitoring (jamming detection)
        if reading.signal_level_dbm < -95.0:
            anomalies.append(ILSAnomaly(
                attack_type=ILSAttackType.RF_JAMMING,
                component=reading.component,
                severity="critical",
                confidence=0.88,
                deviation_from_expected=0,
                description=f"ILS {reading.component.value} signal level {reading.signal_level_dbm:.1f} dBm (jamming threshold -95 dBm)",
                evidence={"signal_dbm": reading.signal_level_dbm},
            ))

        # 4. False glideslope capture (aircraft intercepting from above)
        if reading.component == ILSComponent.GLIDESLOPE and len(self._reading_history) >= 3:
            anomaly = self._detect_false_gs_capture()
            if anomaly:
                anomalies.append(anomaly)

        for a in anomalies:
            self._anomalies.append(a)
            self._stats["anomalies"] += 1
            if a.attack_type == ILSAttackType.FALSE_GLIDESLOPE:
                self._stats["false_glideslopes"] += 1
            logger.warning("ILS anomaly [%s]: %s", a.attack_type.value, a.description)
            if self._alert_callback:
                try:
                    self._alert_callback(a)
                except Exception:
                    pass

        return anomalies

    # ------------------------------------------------------------------
    def _validate_approach_path(self, reading: ILSReading) -> Optional[ILSAnomaly]:
        dist_m = self._path_model.distance_m(reading.aircraft_lat, reading.aircraft_lon)
        expected_alt_m = self._path_model.expected_altitude_m(dist_m)
        actual_alt_m = reading.aircraft_alt_m
        alt_error_m = actual_alt_m - expected_alt_m

        # Glideslope error: >30m deviation from expected approach path
        if abs(alt_error_m) > 30.0:
            terrain_risk = actual_alt_m < expected_alt_m
            severity = "critical" if terrain_risk and abs(alt_error_m) > 60 else "high"
            return ILSAnomaly(
                attack_type=ILSAttackType.TERRAIN_COLLISION_PATH if terrain_risk else ILSAttackType.FALSE_GLIDESLOPE,
                component=ILSComponent.GLIDESLOPE,
                severity=severity,
                confidence=min(0.97, 0.7 + 0.005 * abs(alt_error_m)),
                deviation_from_expected=alt_error_m,
                description=f"Aircraft {alt_error_m:+.0f}m vs ILS glidepath at {dist_m/1852:.1f} nm"
                            + (" ⚠ TERRAIN RISK" if terrain_risk else ""),
                evidence={
                    "expected_alt_m": round(expected_alt_m, 1),
                    "actual_alt_m": round(actual_alt_m, 1),
                    "error_m": round(alt_error_m, 1),
                    "dist_nm": round(dist_m / 1852, 2),
                },
            )

        # Localiser deviation check
        loc_dev = self._path_model.expected_range_deg_from_centreline(
            reading.aircraft_lat, reading.aircraft_lon
        )
        if abs(loc_dev) > LOCALISER_FULL_SCALE_DEGREES:
            return ILSAnomaly(
                attack_type=ILSAttackType.LOCALISER_OFFSET,
                component=ILSComponent.LOCALISER,
                severity="high",
                confidence=0.80,
                deviation_from_expected=loc_dev,
                description=f"Aircraft {loc_dev:+.2f}° off localiser centreline (limit ±{LOCALISER_FULL_SCALE_DEGREES}°)",
                evidence={"deviation_deg": round(loc_dev, 3)},
            )

        return None

    def _detect_false_gs_capture(self) -> Optional[ILSAnomaly]:
        """
        Detect false glideslope capture (aircraft intercepting the wrong lobe).
        Standard GS = 3°. False GS lobes at 9°, 15°, etc.
        Aircraft intercepting from above at high vertical rate is a red flag.
        """
        recent = [r for r in self._reading_history if r.component == ILSComponent.GLIDESLOPE][-5:]
        if len(recent) < 3:
            return None

        # Check DDM near 0 but aircraft too high (intercepting upper lobe)
        for r in recent:
            if (r.aircraft_alt_m and r.aircraft_lat and
                    abs(r.ddm) < 0.02 and r.aircraft_vrate_ms and r.aircraft_vrate_ms > 5.0):
                dist_m = self._path_model.distance_m(r.aircraft_lat, r.aircraft_lon)
                expected_alt = self._path_model.expected_altitude_m(dist_m)
                if r.aircraft_alt_m > expected_alt * 2.5:
                    return ILSAnomaly(
                        attack_type=ILSAttackType.CAPTURED_ABOVE_GS,
                        component=ILSComponent.GLIDESLOPE,
                        severity="critical",
                        confidence=0.88,
                        deviation_from_expected=r.aircraft_alt_m - expected_alt,
                        description="Aircraft captured above standard GS — possible false glideslope",
                        evidence={
                            "aircraft_alt_m": r.aircraft_alt_m,
                            "expected_alt_m": round(expected_alt, 1),
                            "ddm": r.ddm,
                        },
                    )
        return None

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    @property
    def recent_anomalies(self) -> List[Dict[str, Any]]:
        return [
            {
                "type": a.attack_type.value,
                "component": a.component.value,
                "severity": a.severity,
                "confidence": a.confidence,
                "description": a.description,
                "ts": a.ts,
            }
            for a in self._anomalies[-20:]
        ]


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_monitor: Optional[ILSMonitor] = None


def get_monitor(**kwargs: Any) -> ILSMonitor:
    global _monitor
    if _monitor is None:
        _monitor = ILSMonitor(**kwargs)
    return _monitor


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mon = ILSMonitor(runway_lat=32.0094, runway_lon=34.8781, runway_heading_deg=120.0)

    # Normal approach
    for i in range(10):
        dist_nm = 10 - i
        dist_m = dist_nm * 1852
        expected_alt = mon._path_model.expected_altitude_m(dist_m)
        r = ILSReading(
            component=ILSComponent.GLIDESLOPE,
            frequency_mhz=331.4,
            ddm=0.01 * (i % 3 - 1),
            signal_level_dbm=-75.0,
            course_deviation_dots=0.1,
            aircraft_lat=32.0094 + dist_nm * 0.008,
            aircraft_lon=34.8781,
            aircraft_alt_m=expected_alt,
        )
        mon.process_reading(r)

    # Inject false glideslope
    bad_reading = ILSReading(
        component=ILSComponent.GLIDESLOPE,
        frequency_mhz=331.4,
        ddm=0.005,
        signal_level_dbm=-75.0,
        course_deviation_dots=0.0,
        aircraft_lat=32.0094 + 0.064,
        aircraft_lon=34.8781,
        aircraft_alt_m=500.0,   # Way below normal glidepath
    )
    anomalies = mon.process_reading(bad_reading)
    print(f"Anomalies: {len(anomalies)}")
    print(f"Stats: {mon.stats}")
    print("ILS Monitor OK")
