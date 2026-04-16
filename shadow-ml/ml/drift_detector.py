"""
ml/drift_detector.py — Concept Drift Detector v10.0

Automatically detects when network traffic behavior changes,
triggering model retraining before false positives spike.

Methods:
  • ADWIN (Adaptive Windowing) — for mean drift
  • Page-Hinkley Test — for gradual drift
  • Population Stability Index (PSI) — for distribution shift
  • Kolmogorov-Smirnov test — two-sample distribution comparison
  • CUSUM (Cumulative Sum Control Chart)

Integration:
  • Auto-notifies MLflow when drift is detected
  • Triggers federated learning aggregation
  • Feeds into RL reward shaping
"""

from __future__ import annotations

import logging
import math
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Deque, Dict, List, Optional, Tuple

logger = logging.getLogger("shadow.ml.drift")


class DriftSeverity(str, Enum):
    NONE     = "none"
    WARNING  = "warning"
    DRIFT    = "drift"
    CRITICAL = "critical"


@dataclass
class DriftEvent:
    detector: str
    severity: DriftSeverity
    timestamp: float = field(default_factory=time.time)
    statistic: float = 0.0
    threshold: float = 0.0
    description: str = ""
    auto_retrain_triggered: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detector": self.detector,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "statistic": round(self.statistic, 4),
            "threshold": self.threshold,
            "description": self.description,
            "auto_retrain_triggered": self.auto_retrain_triggered,
        }


# ---------------------------------------------------------------------------
# ADWIN — Adaptive Windowing
# ---------------------------------------------------------------------------

class ADWIN:
    """
    ADWIN: Adaptive Windowing for concept drift detection.
    Maintains an adaptive window that shrinks when drift is detected.
    Reference: Bifet & Gavaldà, 2007.
    """

    def __init__(self, delta: float = 0.002):
        self.delta = delta
        self._window: Deque[float] = deque()
        self._n: int = 0
        self._total: float = 0.0
        self.drift_detected: bool = False

    def add(self, value: float) -> bool:
        """Add new observation. Returns True if drift detected."""
        self._window.append(value)
        self._n += 1
        self._total += value
        self.drift_detected = self._test_drift()
        return self.drift_detected

    def _test_drift(self) -> bool:
        n = len(self._window)
        if n < 10:
            return False
        vals = list(self._window)
        mu = self._total / n
        # Check each split point
        for i in range(5, n - 5):
            n0, n1 = i, n - i
            mu0 = sum(vals[:i]) / n0
            mu1 = sum(vals[i:]) / n1
            epsilon_cut = math.sqrt((1/(2*n0) + 1/(2*n1)) * math.log(4*n/self.delta))
            if abs(mu0 - mu1) > epsilon_cut:
                # Shrink window to newer half
                self._window = deque(vals[i:])
                self._n = n1
                self._total = sum(self._window)
                return True
        return False

    @property
    def mean(self) -> float:
        return self._total / max(1, len(self._window))


# ---------------------------------------------------------------------------
# Page-Hinkley Test
# ---------------------------------------------------------------------------

class PageHinkley:
    """Detects gradual concept drift via cumulative sum of deviations."""

    def __init__(self, threshold: float = 50.0, delta: float = 0.005):
        self.threshold = threshold
        self.delta = delta
        self._sum = 0.0
        self._min_sum = 0.0
        self._n = 0
        self._mu: float = 0.0
        self.drift_detected: bool = False

    def add(self, value: float) -> bool:
        self._n += 1
        self._mu += (value - self._mu) / self._n
        self._sum += value - self._mu - self.delta
        self._min_sum = min(self._min_sum, self._sum)
        self.drift_detected = (self._sum - self._min_sum) > self.threshold
        return self.drift_detected


# ---------------------------------------------------------------------------
# Population Stability Index (PSI)
# ---------------------------------------------------------------------------

def _psi(expected: List[float], actual: List[float], n_bins: int = 10) -> float:
    """PSI < 0.1: no drift. 0.1-0.2: moderate. > 0.2: significant drift."""
    eps = 1e-6
    mn = min(min(expected), min(actual))
    mx = max(max(expected), max(actual))
    if mx == mn:
        return 0.0
    bins = [mn + i * (mx - mn) / n_bins for i in range(n_bins + 1)]

    def bucket(vals: List[float]) -> List[float]:
        counts = [0.0] * n_bins
        for v in vals:
            idx = min(n_bins - 1, int((v - mn) / (mx - mn) * n_bins))
            counts[idx] += 1
        total = max(1, sum(counts))
        return [c / total for c in counts]

    exp_pct = bucket(expected)
    act_pct = bucket(actual)
    psi = sum(
        (a - e) * math.log((a + eps) / (e + eps))
        for a, e in zip(act_pct, exp_pct)
    )
    return max(0.0, psi)


# ---------------------------------------------------------------------------
# KS Test
# ---------------------------------------------------------------------------

def _ks_statistic(a: List[float], b: List[float]) -> float:
    """Two-sample Kolmogorov-Smirnov statistic."""
    combined = sorted(set(a + b))
    na, nb = len(a), len(b)
    a_set = sorted(a)
    b_set = sorted(b)
    max_d = 0.0
    ia = ib = 0
    for v in combined:
        while ia < na and a_set[ia] <= v:
            ia += 1
        while ib < nb and b_set[ib] <= v:
            ib += 1
        d = abs(ia / na - ib / nb)
        max_d = max(max_d, d)
    return max_d


# ---------------------------------------------------------------------------
# CUSUM
# ---------------------------------------------------------------------------

class CUSUM:
    """CUSUM control chart for change-point detection."""

    def __init__(self, threshold: float = 8.0, k: float = 0.5):
        self.threshold = threshold
        self.k = k
        self._s_high = 0.0
        self._s_low = 0.0
        self._mu: float = 0.0
        self._n: int = 0
        self.drift_detected: bool = False

    def add(self, value: float) -> bool:
        self._n += 1
        self._mu += (value - self._mu) / self._n
        self._s_high = max(0.0, self._s_high + value - self._mu - self.k)
        self._s_low  = max(0.0, self._s_low  - value + self._mu - self.k)
        self.drift_detected = (self._s_high > self.threshold or self._s_low > self.threshold)
        return self.drift_detected


# ---------------------------------------------------------------------------
# Unified Drift Monitor
# ---------------------------------------------------------------------------

class DriftDetector:
    """
    SHADOW-ML Drift Detector v10.0

    Runs 5 drift detection algorithms in parallel.
    Any 2+ detectors agreeing triggers a drift event.
    """

    VERSION = "10.0.0"
    PSI_WARNING_THRESHOLD = 0.10
    PSI_DRIFT_THRESHOLD   = 0.20
    KS_DRIFT_THRESHOLD    = 0.30

    def __init__(self, retrain_callback: Optional[Any] = None):
        self._adwin = ADWIN(delta=0.002)
        self._ph = PageHinkley(threshold=50.0)
        self._cusum = CUSUM(threshold=8.0)
        self._reference: Optional[List[float]] = None
        self._current_window: Deque[float] = deque(maxlen=1000)
        self._events: List[DriftEvent] = []
        self._retrain_callback = retrain_callback
        self._stats = {"observations": 0, "drift_events": 0}
        logger.info("DriftDetector v%s initialised", self.VERSION)

    def observe(self, score: float) -> Optional[DriftEvent]:
        """Feed a model prediction score. Returns DriftEvent if drift detected, else None."""
        self._current_window.append(score)
        self._stats["observations"] += 1

        # Set reference distribution on first 200 observations
        if len(self._current_window) == 200 and not self._reference:
            self._reference = list(self._current_window)
            logger.info("DriftDetector: reference distribution set (%d samples)", len(self._reference))
            return None

        detectors_fired = []

        if self._adwin.add(score):
            detectors_fired.append(("adwin", abs(score - self._adwin.mean)))
        if self._ph.add(score):
            detectors_fired.append(("page_hinkley", self._ph._sum - self._ph._min_sum))
        if self._cusum.add(score):
            detectors_fired.append(("cusum", max(self._cusum._s_high, self._cusum._s_low)))

        # PSI and KS tests every 500 observations
        if self._reference and len(self._current_window) >= 200 and self._stats["observations"] % 500 == 0:
            current = list(self._current_window)[-200:]
            psi = _psi(self._reference, current)
            ks = _ks_statistic(self._reference[:100], current[:100])
            if psi > self.PSI_DRIFT_THRESHOLD:
                detectors_fired.append(("psi", psi))
            if ks > self.KS_DRIFT_THRESHOLD:
                detectors_fired.append(("ks_test", ks))

        if len(detectors_fired) >= 2:
            return self._emit_drift(detectors_fired)
        return None

    def observe_batch(self, scores: List[float]) -> List[DriftEvent]:
        events = []
        for s in scores:
            evt = self.observe(s)
            if evt:
                events.append(evt)
        return events

    def get_events(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._events]

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "drift_rate": round(self._stats["drift_events"] / max(1, self._stats["observations"]), 6),
            "current_mean": round(
                sum(self._current_window) / max(1, len(self._current_window)), 4
            ),
            "reference_mean": round(
                sum(self._reference) / len(self._reference), 4
            ) if self._reference else None,
        }

    def _emit_drift(self, detectors: List[Tuple[str, float]]) -> DriftEvent:
        names = [d[0] for d in detectors]
        stat = max(d[1] for d in detectors)
        severity = DriftSeverity.CRITICAL if len(detectors) >= 4 else DriftSeverity.DRIFT
        event = DriftEvent(
            detector="+".join(names),
            severity=severity,
            statistic=stat,
            threshold=self.PSI_DRIFT_THRESHOLD,
            description=f"Drift detected by {len(detectors)} methods: {', '.join(names)}",
        )
        self._events.append(event)
        self._stats["drift_events"] += 1
        logger.warning("CONCEPT DRIFT DETECTED: detectors=%s severity=%s stat=%.4f",
                       names, severity, stat)
        if self._retrain_callback:
            try:
                self._retrain_callback(event)
                event.auto_retrain_triggered = True
            except Exception as exc:
                logger.error("Retrain callback failed: %s", exc)
        return event
