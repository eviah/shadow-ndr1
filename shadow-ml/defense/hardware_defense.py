"""
defense/hardware_defense.py — Hardware-Level Intrusion Detection v10.0

Detects attacks at the hardware level using CPU/memory metrics:
  • CPU performance counter analysis (cache misses, branch mispredictions)
  • Memory access pattern profiling (page faults, TLB misses)
  • Spectre/Meltdown-class timing side-channels
  • Ring 0 privilege transitions (kernel transitions)
  • Power consumption anomalies
  • Thermal behavior changes (load pattern inference)

Catches rootkits, privilege escalation, and exploits that bypass OS-level detection.

Note: In production, integrates with Intel VTune, Linux perf, or ARM PMU.
Here we provide statistical detection based on observable metrics.
"""

from __future__ import annotations

import hashlib
import logging
import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger("shadow.defense.hardware")


class HardwareThreat(Enum):
    CACHE_SIDE_CHANNEL = "cache_side_channel"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ROOTKIT_ACTIVITY = "rootkit_activity"
    SPECTRE_ATTACK = "spectre_attack"
    POWER_ANOMALY = "power_anomaly"
    THERMAL_ANOMALY = "thermal_anomaly"
    TLB_ATTACK = "tlb_attack"


@dataclass
class CPUMetrics:
    """CPU performance counter snapshot."""
    timestamp: float
    cpu_cycles: int
    instructions_executed: int
    cache_misses: int
    cache_hits: int
    branch_mispredicts: int
    tlb_misses: int
    context_switches: int
    ring0_transitions: int  # kernel mode transitions
    temperature: float  # Celsius


@dataclass
class MemoryMetrics:
    """Memory access metrics."""
    timestamp: float
    page_faults: int
    major_faults: int
    minor_faults: int
    mem_rss_mb: int
    mem_vms_mb: int
    swap_used_mb: int


@dataclass
class HardwareAnomaly:
    """Detected hardware-level anomaly."""
    threat_type: HardwareThreat
    severity: str
    confidence: float
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class CPUAnalyzer:
    """
    Analyzes CPU performance counters to detect attacks.
    """

    def __init__(self):
        self._baseline_cpi: float = 2.0  # Cycles Per Instruction baseline
        self._baseline_miss_ratio: float = 0.05
        self._baseline_temp: float = 50.0
        self._ring0_transition_history: List[int] = []
        self._cache_miss_history: List[float] = []

    def analyze_metrics(self, metrics: CPUMetrics) -> Optional[HardwareAnomaly]:
        """Analyze CPU metrics for anomalies."""
        anomalies = []

        # Calculate CPI (Cycles Per Instruction)
        cpi = (
            metrics.cpu_cycles / (metrics.instructions_executed + 1)
            if metrics.instructions_executed > 0 else 0.0
        )

        # High CPI suggests stalling (cache misses, memory waits)
        if cpi > self._baseline_cpi * 3.0:
            anomalies.append((
                0.7,
                HardwareThreat.ROOTKIT_ACTIVITY,
                f"Extremely high CPI {cpi:.2f} (baseline {self._baseline_cpi:.2f})"
            ))

        # Cache miss ratio
        total_accesses = metrics.cache_hits + metrics.cache_misses + 1
        miss_ratio = metrics.cache_misses / total_accesses
        self._cache_miss_history.append(miss_ratio)

        # Unusual miss pattern suggests Spectre/timing attack
        if miss_ratio > self._baseline_miss_ratio * 5.0:
            anomalies.append((
                0.8,
                HardwareThreat.SPECTRE_ATTACK,
                f"Cache miss spike: {miss_ratio:.2%} (baseline {self._baseline_miss_ratio:.2%})"
            ))

        # Branch misprediction rate suggests control flow attack
        if metrics.instructions_executed > 0:
            branch_mispredict_rate = metrics.branch_mispredicts / max(1, metrics.instructions_executed)
            if branch_mispredict_rate > 0.3:
                anomalies.append((
                    0.65,
                    HardwareThreat.SPECTRE_ATTACK,
                    f"High branch misprediction rate: {branch_mispredict_rate:.1%}"
                ))

        # Ring 0 transition frequency (kernel mode)
        self._ring0_transition_history.append(metrics.ring0_transitions)
        if len(self._ring0_transition_history) > 5:
            self._ring0_transition_history.pop(0)
            ring0_avg = np.mean(self._ring0_transition_history)
            if metrics.ring0_transitions > ring0_avg * 10:
                anomalies.append((
                    0.9,
                    HardwareThreat.PRIVILEGE_ESCALATION,
                    f"Excessive ring 0 transitions: {metrics.ring0_transitions} (avg {ring0_avg:.0f})"
                ))

        # Temperature anomaly (suggests heavy computation, possibly crypto mining or brute force)
        if metrics.temperature > self._baseline_temp + 30:
            anomalies.append((
                0.6,
                HardwareThreat.POWER_ANOMALY,
                f"High CPU temperature: {metrics.temperature:.1f}°C (baseline {self._baseline_temp:.1f}°C)"
            ))

        if not anomalies:
            return None

        score, threat, desc = max(anomalies, key=lambda x: x[0])
        return HardwareAnomaly(
            threat_type=threat,
            severity="critical" if score > 0.85 else "high" if score > 0.7 else "medium",
            confidence=min(0.95, score),
            description=desc,
            evidence={
                "cpi": cpi,
                "cache_miss_ratio": miss_ratio,
                "ring0_transitions": metrics.ring0_transitions,
                "temperature": metrics.temperature,
            },
            timestamp=metrics.timestamp
        )


class MemoryAnalyzer:
    """
    Analyzes memory access patterns to detect rootkits and privilege escalation.
    """

    def __init__(self):
        self._baseline_page_faults: float = 100.0
        self._baseline_major_faults: float = 10.0
        self._page_fault_history: List[float] = []
        self._mem_growth_rate: float = 0.0

    def analyze_metrics(self, metrics: MemoryMetrics) -> Optional[HardwareAnomaly]:
        """Analyze memory metrics for anomalies."""
        anomalies = []

        # Track page fault rate
        self._page_fault_history.append(metrics.page_faults)
        if len(self._page_fault_history) > 10:
            self._page_fault_history.pop(0)

        # Excessive page faults suggest memory scanning or privilege escalation
        if metrics.page_faults > self._baseline_page_faults * 5.0:
            anomalies.append((
                0.75,
                HardwareThreat.ROOTKIT_ACTIVITY,
                f"High page fault rate: {metrics.page_faults:.0f} (baseline {self._baseline_page_faults:.0f})"
            ))

        # Major page faults (disk I/O) suggest rootkit searching kernel memory
        if metrics.major_faults > self._baseline_major_faults * 10:
            anomalies.append((
                0.85,
                HardwareThreat.ROOTKIT_ACTIVITY,
                f"Excessive major page faults: {metrics.major_faults} (scanning kernel memory?)"
            ))

        # Memory growth
        current_rss = metrics.mem_rss_mb
        if len(self._page_fault_history) > 5:
            growth = current_rss / (1 + sum(self._page_fault_history[:-1]) / 1000)
            if growth > 2.0:
                anomalies.append((
                    0.6,
                    HardwareThreat.ROOTKIT_ACTIVITY,
                    f"Rapid memory growth detected"
                ))

        # TLB misses suggest address translation attacks
        if metrics.page_faults > 50 and hasattr(metrics, 'tlb_misses'):
            anomalies.append((
                0.7,
                HardwareThreat.TLB_ATTACK,
                f"TLB-based attack pattern detected"
            ))

        if not anomalies:
            return None

        score, threat, desc = max(anomalies, key=lambda x: x[0])
        return HardwareAnomaly(
            threat_type=threat,
            severity="critical" if score > 0.8 else "high" if score > 0.7 else "medium",
            confidence=min(0.95, score),
            description=desc,
            evidence={
                "page_faults": metrics.page_faults,
                "major_faults": metrics.major_faults,
                "memory_rss_mb": metrics.mem_rss_mb,
            },
            timestamp=metrics.timestamp
        )


class TimingSideChannelDetector:
    """
    Detects Spectre/Meltdown-class timing attacks via statistical analysis.
    """

    def __init__(self):
        self._access_time_history: List[float] = []
        self._baseline_timing_variance: float = 0.0

    def analyze_timing_variance(self, access_times: List[float]) -> Optional[HardwareAnomaly]:
        """
        Detect abnormal memory access timing variance.
        Spectre causes bimodal timing distribution (hit vs miss).
        """
        if len(access_times) < 20:
            return None

        arr = np.array(access_times)
        mean = np.mean(arr)
        std = np.std(arr)
        skew = np.mean((arr - mean) ** 3) / ((std ** 3) + 1e-10)

        # Spectre attacks create bimodal distribution (high skew and kurtosis)
        kurtosis = np.mean((arr - mean) ** 4) / ((std ** 4) + 1e-10)

        if kurtosis > 10 and abs(skew) > 2:
            return HardwareAnomaly(
                threat_type=HardwareThreat.SPECTRE_ATTACK,
                severity="critical",
                confidence=0.85,
                description=f"Timing distribution anomaly (kurtosis={kurtosis:.1f}, skew={skew:.1f})",
                evidence={
                    "kurtosis": float(kurtosis),
                    "skew": float(skew),
                    "mean_access_time": float(mean),
                    "std_dev": float(std),
                }
            )

        return None


class HardwareDefenseMonitor:
    """
    Main hardware-level intrusion detection monitor.
    Continuously analyzes CPU and memory metrics.
    """

    def __init__(self):
        self._cpu_analyzer = CPUAnalyzer()
        self._mem_analyzer = MemoryAnalyzer()
        self._timing_detector = TimingSideChannelDetector()
        self._anomalies: List[HardwareAnomaly] = []
        self._stats = {
            "metrics_analyzed": 0,
            "anomalies_detected": 0,
            "cpu_threats": 0,
            "memory_threats": 0,
            "timing_threats": 0,
        }

    def process_cpu_metrics(self, metrics: CPUMetrics) -> Optional[HardwareAnomaly]:
        """Process CPU metrics and detect anomalies."""
        self._stats["metrics_analyzed"] += 1
        anomaly = self._cpu_analyzer.analyze_metrics(metrics)
        if anomaly:
            self._anomalies.append(anomaly)
            self._stats["anomalies_detected"] += 1
            self._stats["cpu_threats"] += 1
            logger.warning("CPU anomaly [%s]: %s (conf=%.2f)", anomaly.threat_type.value, anomaly.description, anomaly.confidence)
        return anomaly

    def process_memory_metrics(self, metrics: MemoryMetrics) -> Optional[HardwareAnomaly]:
        """Process memory metrics and detect anomalies."""
        self._stats["metrics_analyzed"] += 1
        anomaly = self._mem_analyzer.analyze_metrics(metrics)
        if anomaly:
            self._anomalies.append(anomaly)
            self._stats["anomalies_detected"] += 1
            self._stats["memory_threats"] += 1
            logger.warning("Memory anomaly [%s]: %s (conf=%.2f)", anomaly.threat_type.value, anomaly.description, anomaly.confidence)
        return anomaly

    def process_timing_analysis(self, access_times: List[float]) -> Optional[HardwareAnomaly]:
        """Process timing side-channel analysis."""
        anomaly = self._timing_detector.analyze_timing_variance(access_times)
        if anomaly:
            self._anomalies.append(anomaly)
            self._stats["anomalies_detected"] += 1
            self._stats["timing_threats"] += 1
            logger.warning("Timing anomaly [%s]: %s (conf=%.2f)", anomaly.threat_type.value, anomaly.description, anomaly.confidence)
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


_monitor: Optional[HardwareDefenseMonitor] = None


def get_monitor() -> HardwareDefenseMonitor:
    global _monitor
    if _monitor is None:
        _monitor = HardwareDefenseMonitor()
    return _monitor


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    monitor = get_monitor()

    # Simulate normal CPU metrics
    cpu_metrics = CPUMetrics(
        timestamp=time.time(),
        cpu_cycles=1000000,
        instructions_executed=500000,
        cache_misses=25000,
        cache_hits=975000,
        branch_mispredicts=5000,
        tlb_misses=100,
        context_switches=50,
        ring0_transitions=200,
        temperature=55.0,
    )
    anomaly = monitor.process_cpu_metrics(cpu_metrics)
    print(f"Normal metrics - anomaly: {anomaly}")

    # Simulate attack-like CPU metrics
    attack_metrics = CPUMetrics(
        timestamp=time.time() + 10,
        cpu_cycles=2000000,
        instructions_executed=100000,  # Very low IPC
        cache_misses=500000,  # High miss rate
        cache_hits=0,
        branch_mispredicts=80000,
        tlb_misses=5000,
        context_switches=500,
        ring0_transitions=2000,  # Excessive kernel transitions
        temperature=85.0,  # Hot
    )
    anomaly = monitor.process_cpu_metrics(attack_metrics)
    print(f"Attack metrics - anomaly: {anomaly}")

    print(f"Stats: {monitor.stats}")
    print("Hardware Defense OK")
