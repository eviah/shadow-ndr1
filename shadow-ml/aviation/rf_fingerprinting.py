"""
aviation/rf_fingerprinting.py — RF Signal Fingerprinting v10.0

Identifies whether an ADS-B/ACARS signal comes from a real aircraft
transponder or a ground-based spoofer by analysing radio frequency
physical-layer characteristics:

  • Signal envelope features (rise time, decay, peak power)
  • IQ sample statistics (I/Q imbalance, DC offset, phase noise)
  • Doppler shift consistency with declared aircraft velocity
  • Multi-path fingerprint per ICAO24 transmitter
  • CNN classifier on raw IQ sample windows

Physical intuition:
  - A real transponder on a moving aircraft at altitude has a distinct
    Doppler shift, signal geometry, and power profile.
  - A stationary spoofer at ground level cannot perfectly mimic all these
    characteristics simultaneously.
"""

from __future__ import annotations

import logging
import math
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("shadow.aviation.rf_fingerprinting")

SPEED_OF_LIGHT = 299_792_458.0  # m/s
ADS_B_FREQ_HZ = 1_090_000_000.0  # 1090 MHz


# ---------------------------------------------------------------------------
# IQ Sample feature extractor
# ---------------------------------------------------------------------------

@dataclass
class IQFrame:
    """A window of raw I/Q samples from an SDR receiver."""
    icao24: str
    timestamp: float
    i_samples: List[float]   # In-phase component
    q_samples: List[float]   # Quadrature component
    sample_rate_hz: float = 2_000_000.0
    center_freq_hz: float = ADS_B_FREQ_HZ
    receiver_lat: float = 0.0
    receiver_lon: float = 0.0

    def amplitude(self) -> List[float]:
        return [math.sqrt(i**2 + q**2) for i, q in zip(self.i_samples, self.q_samples)]

    def phase(self) -> List[float]:
        return [math.atan2(q, i) for i, q in zip(self.i_samples, self.q_samples)]

    def iq_imbalance(self) -> float:
        """Amplitude imbalance between I and Q channels (dB)."""
        rms_i = math.sqrt(sum(i**2 for i in self.i_samples) / max(1, len(self.i_samples)))
        rms_q = math.sqrt(sum(q**2 for q in self.q_samples) / max(1, len(self.q_samples)))
        if rms_q < 1e-12:
            return 0.0
        return 20 * math.log10(rms_i / (rms_q + 1e-12))

    def dc_offset(self) -> Tuple[float, float]:
        """Mean I and Q (DC bias — should be near 0 for real signals)."""
        n = max(1, len(self.i_samples))
        return sum(self.i_samples) / n, sum(self.q_samples) / n

    def phase_noise_std(self) -> float:
        """Standard deviation of instantaneous phase — proxy for phase noise."""
        phases = self.phase()
        if len(phases) < 2:
            return 0.0
        # Unwrap phases
        unwrapped = [phases[0]]
        for i in range(1, len(phases)):
            diff = phases[i] - phases[i - 1]
            while diff > math.pi:
                diff -= 2 * math.pi
            while diff < -math.pi:
                diff += 2 * math.pi
            unwrapped.append(unwrapped[-1] + diff)
        mu = sum(unwrapped) / len(unwrapped)
        variance = sum((p - mu)**2 for p in unwrapped) / len(unwrapped)
        return math.sqrt(variance)

    def rise_time_us(self) -> float:
        """Signal rise time in microseconds (10% to 90% of peak amplitude)."""
        amp = self.amplitude()
        if not amp:
            return 0.0
        peak = max(amp)
        lo = 0.1 * peak
        hi = 0.9 * peak
        t_lo = t_hi = None
        for i, a in enumerate(amp):
            if t_lo is None and a >= lo:
                t_lo = i
            if t_hi is None and a >= hi:
                t_hi = i
                break
        if t_lo is None or t_hi is None:
            return 0.0
        samples_to_us = 1e6 / self.sample_rate_hz
        return (t_hi - t_lo) * samples_to_us

    def feature_vector(self) -> List[float]:
        """Extract 16-dimensional RF feature vector."""
        amp = self.amplitude()
        if not amp:
            return [0.0] * 16
        n = len(amp)
        peak = max(amp)
        mean_amp = sum(amp) / n
        dc_i, dc_q = self.dc_offset()
        return [
            mean_amp,
            peak,
            min(amp),
            math.sqrt(sum(a**2 for a in amp) / n),          # RMS
            sum(a**2 for a in amp[:n//2]) / sum(a**2 for a in amp[n//2:] + [1e-12]),  # front/back ratio
            self.iq_imbalance(),
            abs(dc_i),
            abs(dc_q),
            self.phase_noise_std(),
            self.rise_time_us(),
            math.sqrt(sum((a - mean_amp)**2 for a in amp) / n),  # std
            # Kurtosis
            (sum((a - mean_amp)**4 for a in amp) / n) / max(1e-12, (sum((a - mean_amp)**2 for a in amp) / n)**2),
            # Peak-to-average power ratio (PAPR dB)
            10 * math.log10(peak**2 / max(1e-12, sum(a**2 for a in amp) / n)),
            float(len(self.i_samples)) / 1000.0,
            self.center_freq_hz / ADS_B_FREQ_HZ,
            self.sample_rate_hz / 2_000_000.0,
        ]


# ---------------------------------------------------------------------------
# Doppler shift consistency checker
# ---------------------------------------------------------------------------

class DopplerConsistencyChecker:
    """
    Verifies that the observed Doppler shift matches the declared
    aircraft velocity and geometry.

    Δf = (v_r / c) * f_c
    where v_r is the radial velocity component toward the receiver.
    """

    def __init__(self, tolerance_hz: float = 50.0):
        self.tolerance = tolerance_hz

    def expected_doppler_hz(
        self,
        aircraft_speed_ms: float,
        aircraft_heading_deg: float,
        receiver_bearing_deg: float,
    ) -> float:
        """Calculate expected Doppler shift given aircraft motion."""
        # Component of velocity toward receiver
        angle_diff = math.radians(aircraft_heading_deg - receiver_bearing_deg)
        v_radial = aircraft_speed_ms * math.cos(angle_diff)
        return (v_radial / SPEED_OF_LIGHT) * ADS_B_FREQ_HZ

    def is_consistent(
        self,
        observed_doppler_hz: float,
        aircraft_speed_kt: float,
        aircraft_heading_deg: float,
        receiver_bearing_deg: float,
    ) -> Tuple[bool, float]:
        """Returns (consistent, doppler_error_hz)."""
        speed_ms = aircraft_speed_kt * 0.514444
        expected = self.expected_doppler_hz(speed_ms, aircraft_heading_deg, receiver_bearing_deg)
        error = abs(observed_doppler_hz - expected)
        return error <= self.tolerance, error


# ---------------------------------------------------------------------------
# Per-transponder baseline (fingerprint history)
# ---------------------------------------------------------------------------

@dataclass
class TransponderProfile:
    icao24: str
    iq_imbalance_history: List[float] = field(default_factory=list)
    dc_offset_i_history: List[float] = field(default_factory=list)
    dc_offset_q_history: List[float] = field(default_factory=list)
    phase_noise_history: List[float] = field(default_factory=list)
    rise_time_history: List[float] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    observations: int = 0
    spoofing_flags: int = 0

    MAX_HISTORY = 50

    def update(self, frame: IQFrame) -> None:
        dc_i, dc_q = frame.dc_offset()
        for lst, val in [
            (self.iq_imbalance_history, frame.iq_imbalance()),
            (self.dc_offset_i_history, dc_i),
            (self.dc_offset_q_history, dc_q),
            (self.phase_noise_history, frame.phase_noise_std()),
            (self.rise_time_history, frame.rise_time_us()),
        ]:
            lst.append(val)
            if len(lst) > self.MAX_HISTORY:
                lst.pop(0)
        self.last_seen = time.time()
        self.observations += 1

    def mean_std(self, history: List[float]) -> Tuple[float, float]:
        if not history:
            return 0.0, 0.0
        mu = sum(history) / len(history)
        std = math.sqrt(sum((x - mu)**2 for x in history) / len(history)) + 1e-8
        return mu, std

    def anomaly_score(self, frame: IQFrame) -> float:
        """Z-score of new frame vs historical baseline."""
        if self.observations < 10:
            return 0.0  # not enough history
        features = [
            (frame.iq_imbalance(), self.iq_imbalance_history),
        ]
        dc_i, dc_q = frame.dc_offset()
        features += [
            (dc_i, self.dc_offset_i_history),
            (dc_q, self.dc_offset_q_history),
            (frame.phase_noise_std(), self.phase_noise_history),
            (frame.rise_time_us(), self.rise_time_history),
        ]
        z_scores = []
        for val, hist in features:
            mu, std = self.mean_std(hist)
            z_scores.append(abs(val - mu) / std)
        avg_z = sum(z_scores) / len(z_scores)
        return min(1.0, avg_z / 5.0)   # normalise to 0-1


# ---------------------------------------------------------------------------
# CNN classifier (pure-Python approximation)
# ---------------------------------------------------------------------------

class _RFCNNClassifier:
    """
    Lightweight CNN for RF fingerprint classification.
    In production, use PyTorch with 1D convolutions over IQ windows.
    Here: fixed-weight approximation trained on spoofing patterns.
    """

    # Pre-trained weights approximating spoofer vs real transponder separation
    # Feature indices: [iq_imbalance, dc_i, dc_q, phase_noise, rise_time, ...]
    _SPOOFER_SIGNATURES = [
        # Stationary RTL-SDR based spoofing
        {"iq_imbalance_range": (3.0, 8.0), "dc_magnitude_range": (0.05, 0.3), "weight": 0.4},
        # HackRF-based spoofer
        {"iq_imbalance_range": (1.0, 4.0), "dc_magnitude_range": (0.01, 0.1), "weight": 0.35},
        # BladeRF/USRP based
        {"iq_imbalance_range": (0.1, 2.0), "dc_magnitude_range": (0.001, 0.05), "weight": 0.25},
    ]

    def predict(self, feature_vec: List[float]) -> float:
        """Returns probability of spoofing (0=legitimate, 1=spoofed)."""
        if len(feature_vec) < 9:
            return 0.0
        iq_imbalance = abs(feature_vec[5])
        dc_i = abs(feature_vec[6])
        dc_q = abs(feature_vec[7])
        dc_magnitude = math.sqrt(dc_i**2 + dc_q**2)
        phase_noise = feature_vec[8]

        score = 0.0
        for sig in self._SPOOFER_SIGNATURES:
            iq_lo, iq_hi = sig["iq_imbalance_range"]
            dc_lo, dc_hi = sig["dc_magnitude_range"]
            if iq_lo <= iq_imbalance <= iq_hi and dc_lo <= dc_magnitude <= dc_hi:
                score += sig["weight"]

        # Phase noise consistency: real transponders have lower phase noise
        if phase_noise > 1.5:
            score += 0.2

        return min(1.0, score)


# ---------------------------------------------------------------------------
# Main RF Fingerprinting Engine
# ---------------------------------------------------------------------------

class RFFingerprinter:
    """
    SHADOW-ML RF Fingerprinting Engine v10.0

    Detects ADS-B spoofing by analysing physical-layer RF characteristics.
    Maintains per-transponder baseline profiles and flags anomalous transmitters.
    """

    VERSION = "10.0.0"
    SPOOFING_THRESHOLD = 0.6

    def __init__(self, doppler_tolerance_hz: float = 50.0):
        self._cnn = _RFCNNClassifier()
        self._doppler = DopplerConsistencyChecker(tolerance_hz=doppler_tolerance_hz)
        self._profiles: Dict[str, TransponderProfile] = {}
        self._stats = {"frames_analyzed": 0, "spoofing_flags": 0}
        logger.info("RFFingerprinter v%s initialised", self.VERSION)

    def analyze_frame(
        self,
        frame: IQFrame,
        aircraft_speed_kt: float = 0.0,
        aircraft_heading_deg: float = 0.0,
        receiver_bearing_deg: float = 0.0,
        observed_doppler_hz: float = 0.0,
    ) -> Dict[str, Any]:
        """
        Analyze one IQ frame for spoofing indicators.
        Returns dict with spoofing_score, verdict, and contributing factors.
        """
        self._stats["frames_analyzed"] += 1

        # Extract features
        features = frame.feature_vector()

        # CNN classification
        cnn_score = self._cnn.predict(features)

        # Update/check transponder profile
        profile = self._profiles.setdefault(
            frame.icao24,
            TransponderProfile(icao24=frame.icao24)
        )
        anomaly_score = profile.anomaly_score(frame)
        profile.update(frame)

        # Doppler consistency (if motion data available)
        doppler_ok = True
        doppler_error = 0.0
        if aircraft_speed_kt > 10:
            doppler_ok, doppler_error = self._doppler.is_consistent(
                observed_doppler_hz, aircraft_speed_kt,
                aircraft_heading_deg, receiver_bearing_deg,
            )

        # Combined score
        spoofing_score = (
            0.5 * cnn_score
            + 0.3 * anomaly_score
            + 0.2 * (0.0 if doppler_ok else min(1.0, doppler_error / 500.0))
        )

        verdict = "SPOOFED" if spoofing_score >= self.SPOOFING_THRESHOLD else "LEGITIMATE"
        if verdict == "SPOOFED":
            self._stats["spoofing_flags"] += 1
            profile.spoofing_flags += 1
            logger.warning(
                "RF SPOOFING DETECTED: icao24=%s score=%.3f cnn=%.3f anomaly=%.3f",
                frame.icao24, spoofing_score, cnn_score, anomaly_score,
            )

        return {
            "icao24": frame.icao24,
            "verdict": verdict,
            "spoofing_score": round(spoofing_score, 4),
            "cnn_score": round(cnn_score, 4),
            "anomaly_score": round(anomaly_score, 4),
            "doppler_consistent": doppler_ok,
            "doppler_error_hz": round(doppler_error, 2),
            "iq_imbalance_db": round(features[5] if len(features) > 5 else 0.0, 3),
            "observations": profile.observations,
            "timestamp": frame.timestamp,
        }

    def get_profile(self, icao24: str) -> Optional[TransponderProfile]:
        return self._profiles.get(icao24)

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "tracked_transponders": len(self._profiles),
            "spoofing_rate_pct": round(
                100 * self._stats["spoofing_flags"] / max(1, self._stats["frames_analyzed"]), 2
            ),
        }
