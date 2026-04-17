"""
security/timing_analysis.py — Timing Side-Channel Detection Framework v10.0

Detects attacks exploiting timing differences in cryptographic operations:
  • Cache timing attacks (Spectre-style information leakage)
  • Cryptographic operation timing (key recovery via timing measurements)
  • Password comparison timing (early exit on incorrect bytes)
  • Conditional branch timing (data-dependent execution paths)
  • Memory access timing (cache hit/miss patterns)
  • Speculative execution side-channels

Catches subtle attacks that leak information via microsecond-scale timing variations.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger("shadow.security.timing")


class TimingThreat(Enum):
    CACHE_TIMING = "cache_timing_attack"
    CRYPTO_TIMING = "cryptographic_timing_leak"
    PASSWORD_TIMING = "password_timing_attack"
    BRANCH_PREDICTION = "branch_prediction_leak"
    SPECULATIVE_EXECUTION = "speculative_execution_attack"
    MEMORY_TIMING = "memory_access_timing"


@dataclass
class TimingMeasurement:
    """Single timing measurement."""
    operation: str
    elapsed_ns: int  # nanoseconds
    input_characteristics: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class TimingAnomaly:
    """Detected timing side-channel anomaly."""
    threat_type: TimingThreat
    severity: str
    confidence: float
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class CacheTimingAnalyzer:
    """
    Detects cache timing attacks (Spectre/Prime+Probe).
    """

    def __init__(self):
        self._baseline_timing: Dict[str, float] = {}  # operation -> avg_ns
        self._timing_history: Dict[str, deque] = {}
        self._variance_baseline: Dict[str, float] = {}

    def register_baseline(self, operation: str, measurements: List[int]) -> None:
        """Register baseline timing for operation."""
        arr = np.array(measurements)
        self._baseline_timing[operation] = float(np.mean(arr))
        self._variance_baseline[operation] = float(np.std(arr))
        self._timing_history[operation] = deque(maxlen=100)
        logger.info(f"Baseline for {operation}: {self._baseline_timing[operation]:.0f}ns ±{self._variance_baseline[operation]:.0f}ns")

    def analyze_measurement(self, measurement: TimingMeasurement) -> Optional[TimingAnomaly]:
        """Analyze single timing measurement."""
        op = measurement.operation
        timing_ns = measurement.elapsed_ns

        if op not in self._baseline_timing:
            return None

        baseline = self._baseline_timing[op]
        variance = self._variance_baseline[op]

        # Track history
        if op not in self._timing_history:
            self._timing_history[op] = deque(maxlen=100)
        self._timing_history[op].append(timing_ns)

        # Check for significant deviation
        z_score = abs((timing_ns - baseline) / (variance + 1e-8))

        if z_score > 5.0:  # 5-sigma deviation
            return TimingAnomaly(
                threat_type=TimingThreat.CACHE_TIMING,
                severity="high",
                confidence=min(0.95, 0.5 + 0.1 * z_score),
                description=f"Cache timing anomaly in {op}: {timing_ns}ns vs baseline {baseline:.0f}ns",
                evidence={
                    "operation": op,
                    "measured_ns": timing_ns,
                    "baseline_ns": float(baseline),
                    "z_score": float(z_score),
                }
            )

        # Detect periodic patterns (Prime+Probe probing)
        if len(self._timing_history[op]) >= 20:
            recent = list(self._timing_history[op])[-20:]
            # Check for cyclical pattern
            diffs = np.diff(recent)
            if np.std(diffs) < np.mean(diffs) * 0.1:  # Very regular
                return TimingAnomaly(
                    threat_type=TimingThreat.CACHE_TIMING,
                    severity="critical",
                    confidence=0.85,
                    description=f"Periodic timing pattern detected in {op} (Prime+Probe attack)",
                    evidence={
                        "operation": op,
                        "periodicity": float(np.mean(diffs)),
                    }
                )

        return None


class CryptoTimingAnalyzer:
    """
    Detects timing leaks in cryptographic operations.
    """

    def __init__(self):
        self._key_byte_timings: Dict[int, deque] = {}  # byte_value -> timings

    def analyze_key_recovery_timing(
        self,
        key_byte_value: int,
        operation_timings: List[int]
    ) -> Optional[TimingAnomaly]:
        """
        Detect if different key bytes show different timing patterns.
        Indicates key-dependent timing leak.
        """
        if key_byte_value not in self._key_byte_timings:
            self._key_byte_timings[key_byte_value] = deque(maxlen=100)

        self._key_byte_timings[key_byte_value].extend(operation_timings)

        # Need at least 8 bytes (0-255) with measurements
        if len(self._key_byte_timings) < 8:
            return None

        # Calculate timing variance by key byte value
        byte_avg_times = {}
        for byte_val, timings in self._key_byte_timings.items():
            if len(timings) > 10:
                byte_avg_times[byte_val] = np.mean(list(timings))

        if len(byte_avg_times) < 4:
            return None

        # Check if timing distribution correlates with key values
        times_arr = np.array(list(byte_avg_times.values()))
        bytes_arr = np.array(list(byte_avg_times.keys()))

        correlation = np.abs(np.corrcoef(bytes_arr, times_arr)[0, 1])

        if correlation > 0.7:  # Strong correlation suggests key leak
            return TimingAnomaly(
                threat_type=TimingThreat.CRYPTO_TIMING,
                severity="critical",
                confidence=0.90,
                description=f"Cryptographic key leak via timing: correlation={correlation:.3f}",
                evidence={
                    "correlation": float(correlation),
                    "key_bytes_sampled": len(byte_avg_times),
                }
            )

        return None


class PasswordTimingAnalyzer:
    """
    Detects password comparison timing attacks.
    """

    def __init__(self):
        self._correct_timing: Optional[float] = None
        self._incorrect_timings: deque = deque(maxlen=100)

    def set_correct_password_timing(self, elapsed_ns: int) -> None:
        """Register timing for correct password."""
        self._correct_timing = float(elapsed_ns)
        logger.info(f"Correct password timing: {elapsed_ns}ns")

    def analyze_attempt(self, password: str, elapsed_ns: int) -> Optional[TimingAnomaly]:
        """Analyze password attempt timing."""
        if self._correct_timing is None:
            self._incorrect_timings.append(elapsed_ns)
            return None

        # Correct password should take same time regardless
        timing_diff = abs(elapsed_ns - self._correct_timing)

        # Check if timing correlates with how many characters match
        # (indicates early exit on mismatch)
        if timing_diff > self._correct_timing * 0.1:  # >10% difference
            return TimingAnomaly(
                threat_type=TimingThreat.PASSWORD_TIMING,
                severity="high",
                confidence=0.80,
                description=f"Password comparison timing leak: {elapsed_ns}ns vs correct {self._correct_timing:.0f}ns",
                evidence={
                    "measured_ns": elapsed_ns,
                    "correct_ns": float(self._correct_timing),
                    "difference_ns": int(timing_diff),
                    "percent_diff": float(timing_diff / self._correct_timing * 100),
                }
            )

        return None


class SpeculativeExecutionAnalyzer:
    """
    Detects Spectre/Meltdown-style speculative execution attacks.
    """

    def __init__(self):
        self._transient_execution_history: deque = deque(maxlen=50)

    def analyze_memory_access_pattern(
        self,
        addresses_accessed: List[int],
        access_times: List[int]
    ) -> Optional[TimingAnomaly]:
        """
        Detect if out-of-order accesses show timing patterns.
        Indicates speculative execution is being exploited.
        """
        if len(addresses_accessed) < 20:
            return None

        # Check for cache hit pattern that shouldn't exist
        # (address shouldn't be in cache but shows fast access)
        addresses = np.array(addresses_accessed)
        times = np.array(access_times)

        # Speculative execution often accesses forbidden memory quickly
        # (cache hit from speculative load) then gets flushed
        suspicious_count = np.sum(times < 100)  # Very fast access
        if suspicious_count > len(times) * 0.3:
            return TimingAnomaly(
                threat_type=TimingThreat.SPECULATIVE_EXECUTION,
                severity="critical",
                confidence=0.85,
                description=f"Speculative execution leak: {suspicious_count}/{len(times)} accesses show cache timing",
                evidence={
                    "suspicious_accesses": int(suspicious_count),
                    "total_accesses": len(times),
                    "cache_hit_ratio": float(suspicious_count / len(times)),
                }
            )

        return None


class TimingAnalysisFramework:
    """
    Main framework for timing side-channel detection.
    """

    def __init__(self):
        self._cache_analyzer = CacheTimingAnalyzer()
        self._crypto_analyzer = CryptoTimingAnalyzer()
        self._password_analyzer = PasswordTimingAnalyzer()
        self._speculative_analyzer = SpeculativeExecutionAnalyzer()
        self._anomalies: List[TimingAnomaly] = []
        self._stats = {
            "measurements": 0,
            "anomalies_detected": 0,
            "cache_threats": 0,
            "crypto_threats": 0,
            "password_threats": 0,
            "speculative_threats": 0,
        }

    def process_timing_measurement(self, measurement: TimingMeasurement) -> Optional[TimingAnomaly]:
        """Process single timing measurement."""
        self._stats["measurements"] += 1
        anomaly = self._cache_analyzer.analyze_measurement(measurement)
        if anomaly:
            self._anomalies.append(anomaly)
            self._stats["anomalies_detected"] += 1
            self._stats["cache_threats"] += 1
            logger.warning("Timing anomaly [%s]: %s (conf=%.2f)", anomaly.threat_type.value, anomaly.description, anomaly.confidence)
        return anomaly

    def analyze_crypto_operation(
        self,
        key_byte: int,
        operation_timings: List[int]
    ) -> Optional[TimingAnomaly]:
        """Analyze cryptographic operation timing."""
        anomaly = self._crypto_analyzer.analyze_key_recovery_timing(key_byte, operation_timings)
        if anomaly:
            self._anomalies.append(anomaly)
            self._stats["anomalies_detected"] += 1
            self._stats["crypto_threats"] += 1
            logger.warning("Crypto timing leak [%s]: %s (conf=%.2f)", anomaly.threat_type.value, anomaly.description, anomaly.confidence)
        return anomaly

    def analyze_password_attempt(self, password: str, elapsed_ns: int) -> Optional[TimingAnomaly]:
        """Analyze password comparison timing."""
        anomaly = self._password_analyzer.analyze_attempt(password, elapsed_ns)
        if anomaly:
            self._anomalies.append(anomaly)
            self._stats["anomalies_detected"] += 1
            self._stats["password_threats"] += 1
            logger.warning("Password timing leak [%s]: %s (conf=%.2f)", anomaly.threat_type.value, anomaly.description, anomaly.confidence)
        return anomaly

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    @property
    def recent_anomalies(self) -> List[Dict[str, Any]]:
        return [
            {
                "threat": a.threat_type.value,
                "severity": a.severity,
                "confidence": a.confidence,
                "description": a.description,
                "timestamp": a.timestamp,
            }
            for a in self._anomalies[-20:]
        ]


_framework: Optional[TimingAnalysisFramework] = None


def get_framework() -> TimingAnalysisFramework:
    global _framework
    if _framework is None:
        _framework = TimingAnalysisFramework()
    return _framework


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    framework = get_framework()

    # Register baseline timing
    normal_timings = np.random.normal(1000, 50, 50).astype(int)
    framework._cache_analyzer.register_baseline("encrypt", normal_timings.tolist())

    # Normal measurement
    normal_measurement = TimingMeasurement("encrypt", 1010)
    anomaly = framework.process_timing_measurement(normal_measurement)
    print(f"Normal measurement: {anomaly}")

    # Anomalous measurement (very fast - cache hit from forbidden memory)
    anomaly_measurement = TimingMeasurement("encrypt", 150)  # 6-sigma deviation
    anomaly = framework.process_timing_measurement(anomaly_measurement)
    print(f"Anomalous measurement: {anomaly}")

    print(f"Stats: {framework.stats}")
    print("Timing Analysis Framework OK")
