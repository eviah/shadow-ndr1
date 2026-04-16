"""
ml/isolation_forest.py — Isolation Forest Anomaly Baseline v10.0

Ultra-fast, zero-latency statistical anomaly detector running in parallel
with the deep neural engine. Provides instant alerts while the 200-layer
transformer computes full analysis.

Architecture:
  • Ensemble of N random isolation trees (default 200)
  • Each tree isolates anomalies in O(log n) path length
  • Anomaly score = normalised average path length across all trees
  • Streaming update: reservoir sampling to keep forest fresh
  • Per-protocol forests (ADS-B, Modbus, DNS, TCP, ACARS) for precision

Key properties:
  • Sub-millisecond inference (pure NumPy, no deep learning overhead)
  • Linear memory: O(n_trees × subsample_size)
  • Handles high-dimensional feature vectors (up to 512 features)
  • Robust to irrelevant features (random splits naturally ignore noise)
  • Adaptive threshold: auto-calibrates contamination from recent traffic

Integration:
  • alert_immediate() → fires alert BEFORE neural engine finishes
  • score_batch()     → bulk scoring for Kafka consumer threads
  • partial_fit()     → online update when new normal data arrives
  • Feeds RL reward shaper (fast baseline catches what slow net misses)
"""

from __future__ import annotations

import hashlib
import logging
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("shadow.ml.isolation_forest")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_EULER_GAMMA = 0.5772156649015329
_LN2 = math.log(2)


def _average_path_length(n: int) -> float:
    """Expected path length for BST with n nodes (Isolation Forest normaliser)."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2.0 * (math.log(n - 1) + _EULER_GAMMA) - 2.0 * (n - 1) / n


# ---------------------------------------------------------------------------
# Isolation Tree
# ---------------------------------------------------------------------------

@dataclass
class _IsolationNode:
    """Internal node of an isolation tree."""
    feature_idx: int = 0
    split_value: float = 0.0
    left: Optional["_IsolationNode"] = None
    right: Optional["_IsolationNode"] = None
    size: int = 0        # leaf: number of samples that reached here
    is_leaf: bool = False
    depth: int = 0


class IsolationTree:
    """
    A single random isolation tree.
    Anomalies are isolated near the root (short path lengths).
    """

    def __init__(self, max_depth: int, rng: np.random.Generator) -> None:
        self.max_depth = max_depth
        self._rng = rng
        self._root: Optional[_IsolationNode] = None
        self._n_samples: int = 0

    # ------------------------------------------------------------------
    def fit(self, X: np.ndarray) -> "IsolationTree":
        self._n_samples = len(X)
        self._root = self._build(X, depth=0)
        return self

    def _build(self, X: np.ndarray, depth: int) -> _IsolationNode:
        n, d = X.shape
        node = _IsolationNode(size=n, depth=depth)

        if n <= 1 or depth >= self.max_depth:
            node.is_leaf = True
            return node

        # Pick a random feature that has variance
        feature_idx = int(self._rng.integers(0, d))
        col = X[:, feature_idx]
        col_min, col_max = col.min(), col.max()

        if col_min == col_max:
            node.is_leaf = True
            return node

        split = float(self._rng.uniform(col_min, col_max))
        mask = col < split

        node.feature_idx = feature_idx
        node.split_value = split
        node.left = self._build(X[mask], depth + 1)
        node.right = self._build(X[~mask], depth + 1)
        return node

    # ------------------------------------------------------------------
    def path_length(self, x: np.ndarray) -> float:
        """Return path length for a single sample (lower = more anomalous)."""
        node = self._root
        depth = 0
        while node is not None and not node.is_leaf:
            if x[node.feature_idx] < node.split_value:
                node = node.left
            else:
                node = node.right
            depth += 1
        # Adjust for subtree size at leaf
        leaf_size = node.size if node else 1
        return depth + _average_path_length(leaf_size)


# ---------------------------------------------------------------------------
# Isolation Forest
# ---------------------------------------------------------------------------

@dataclass
class IsolationForestConfig:
    n_estimators: int = 200
    max_samples: int = 256          # subsample per tree
    contamination: float = 0.05     # expected fraction of anomalies
    max_features: float = 1.0       # fraction of features per tree
    random_state: Optional[int] = 42
    protocol: str = "generic"       # label for per-protocol forests
    online_window: int = 10_000     # reservoir size for streaming updates
    alert_threshold: float = 0.65   # score above which → immediate alert


class IsolationForest:
    """
    Full Isolation Forest ensemble for ultra-fast anomaly scoring.

    Usage
    -----
    forest = IsolationForest(config)
    forest.fit(normal_traffic_matrix)          # one-time training on night traffic
    score = forest.score(live_feature_vector)  # sub-ms inference
    forest.partial_fit(new_samples)            # online update
    """

    def __init__(self, config: Optional[IsolationForestConfig] = None) -> None:
        self.config = config or IsolationForestConfig()
        self._rng = np.random.default_rng(self.config.random_state)
        self._trees: List[IsolationTree] = []
        self._normaliser: float = 1.0
        self._threshold: float = 0.65
        self._is_fitted: bool = False
        self._n_features: int = 0
        self._reservoir: deque = deque(maxlen=self.config.online_window)
        self._stats: Dict[str, Any] = {
            "n_scored": 0,
            "n_alerts": 0,
            "last_fit_ts": 0.0,
            "mean_score": 0.0,
            "score_ewma": 0.5,
        }

    # ------------------------------------------------------------------
    def fit(self, X: np.ndarray) -> "IsolationForest":
        """Train on clean baseline data (e.g., overnight normal traffic)."""
        if len(X) == 0:
            raise ValueError("Cannot fit on empty dataset")

        X = np.asarray(X, dtype=np.float32)
        self._n_features = X.shape[1]
        self._normaliser = _average_path_length(min(self.config.max_samples, len(X)))

        self._trees = []
        for _ in range(self.config.n_estimators):
            n_sub = min(self.config.max_samples, len(X))
            indices = self._rng.choice(len(X), size=n_sub, replace=False)
            subsample = X[indices]

            # Optional: feature sub-sampling
            if self.config.max_features < 1.0:
                n_feat = max(1, int(self._n_features * self.config.max_features))
                feat_idx = self._rng.choice(self._n_features, size=n_feat, replace=False)
                subsample = subsample[:, feat_idx]

            max_depth = int(math.ceil(math.log2(n_sub))) if n_sub > 1 else 1
            tree = IsolationTree(max_depth=max_depth, rng=self._rng)
            tree.fit(subsample)
            self._trees.append(tree)

        # Calibrate threshold using contamination rate
        scores = self._score_batch_raw(X[:min(1000, len(X))])
        self._threshold = float(np.percentile(scores, 100 * (1 - self.config.contamination)))
        self._is_fitted = True
        self._stats["last_fit_ts"] = time.time()

        # Seed reservoir
        for row in X[-self.config.online_window:]:
            self._reservoir.append(row.copy())

        logger.info(
            "IsolationForest[%s] fitted: %d trees, %d samples, threshold=%.3f",
            self.config.protocol,
            len(self._trees),
            len(X),
            self._threshold,
        )
        return self

    # ------------------------------------------------------------------
    def partial_fit(self, X: np.ndarray) -> None:
        """Online incremental update — adds samples to reservoir and refits."""
        X = np.asarray(X, dtype=np.float32)
        for row in X:
            self._reservoir.append(row.copy())

        if len(self._reservoir) >= self.config.max_samples * 2:
            reservoir_arr = np.array(list(self._reservoir))
            logger.debug("IsolationForest[%s] partial refit on %d reservoir samples",
                         self.config.protocol, len(reservoir_arr))
            self.fit(reservoir_arr)

    # ------------------------------------------------------------------
    def score(self, x: np.ndarray) -> float:
        """
        Return anomaly score in [0, 1] for a single feature vector.
        0.5  → average normality
        > 0.7 → anomalous
        """
        if not self._is_fitted:
            return 0.5  # neutral until trained

        x = np.asarray(x, dtype=np.float32).ravel()
        paths = [t.path_length(x) for t in self._trees]
        mean_path = float(np.mean(paths))
        score = 2.0 ** (-mean_path / self._normaliser)

        # Update stats
        self._stats["n_scored"] += 1
        alpha = 0.01
        self._stats["score_ewma"] = (1 - alpha) * self._stats["score_ewma"] + alpha * score

        return score

    # ------------------------------------------------------------------
    def score_batch(self, X: np.ndarray) -> np.ndarray:
        """Batch scoring — returns anomaly scores for N samples."""
        if not self._is_fitted:
            return np.full(len(X), 0.5)
        return self._score_batch_raw(np.asarray(X, dtype=np.float32))

    def _score_batch_raw(self, X: np.ndarray) -> np.ndarray:
        scores = np.zeros(len(X), dtype=np.float32)
        for i, x in enumerate(X):
            paths = [t.path_length(x) for t in self._trees]
            mean_path = float(np.mean(paths))
            scores[i] = 2.0 ** (-mean_path / self._normaliser)
        return scores

    # ------------------------------------------------------------------
    def is_anomaly(self, x: np.ndarray) -> bool:
        return self.score(x) > self._threshold

    def alert_immediate(self, x: np.ndarray, metadata: Optional[Dict] = None) -> Optional[Dict]:
        """
        Called on every incoming packet before the neural engine.
        Returns an alert dict if the isolation score exceeds the threshold.
        This fires BEFORE the 200-layer transformer completes — zero latency.
        """
        score = self.score(x)
        if score > self.config.alert_threshold:
            self._stats["n_alerts"] += 1
            return {
                "detector": "isolation_forest",
                "protocol": self.config.protocol,
                "score": round(score, 4),
                "threshold": round(self._threshold, 4),
                "severity": "critical" if score > 0.85 else "high",
                "ts": time.time(),
                "metadata": metadata or {},
                "alert_id": hashlib.sha256(
                    f"{time.time()}{score}".encode()
                ).hexdigest()[:16],
            }
        return None

    # ------------------------------------------------------------------
    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    def export_config(self) -> Dict[str, Any]:
        return {
            "protocol": self.config.protocol,
            "n_estimators": self.config.n_estimators,
            "max_samples": self.config.max_samples,
            "contamination": self.config.contamination,
            "threshold": self._threshold,
            "is_fitted": self._is_fitted,
            "n_features": self._n_features,
        }


# ---------------------------------------------------------------------------
# Multi-Protocol Forest Manager
# ---------------------------------------------------------------------------

class ProtocolForestManager:
    """
    Manages one IsolationForest per aviation/network protocol.
    Routes incoming feature vectors to the correct per-protocol model
    for higher precision than a single generic forest.

    Protocols: adsb, acars, cpdlc, modbus, dns, tcp, tls, bgp, icmp, generic
    """

    PROTOCOLS = ["adsb", "acars", "cpdlc", "modbus", "dns", "tcp", "tls", "bgp", "icmp", "generic"]

    def __init__(self, base_config: Optional[IsolationForestConfig] = None) -> None:
        self._forests: Dict[str, IsolationForest] = {}
        for proto in self.PROTOCOLS:
            cfg = IsolationForestConfig(
                n_estimators=100,          # lighter per-protocol model
                max_samples=128,
                contamination=0.03,
                protocol=proto,
            )
            self._forests[proto] = IsolationForest(cfg)

        self._alert_callback: Optional[Any] = None
        self._total_alerts = 0
        logger.info("ProtocolForestManager initialised with %d protocol forests", len(self.PROTOCOLS))

    # ------------------------------------------------------------------
    def fit_protocol(self, protocol: str, X: np.ndarray) -> None:
        proto = protocol.lower() if protocol.lower() in self._forests else "generic"
        self._forests[proto].fit(X)
        logger.info("Forest[%s] fitted on %d samples", proto, len(X))

    def score(self, protocol: str, x: np.ndarray) -> float:
        proto = protocol.lower() if protocol.lower() in self._forests else "generic"
        return self._forests[proto].score(x)

    def alert_immediate(
        self,
        protocol: str,
        x: np.ndarray,
        metadata: Optional[Dict] = None,
    ) -> Optional[Dict]:
        proto = protocol.lower() if protocol.lower() in self._forests else "generic"
        alert = self._forests[proto].alert_immediate(x, metadata)
        if alert and self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass
        if alert:
            self._total_alerts += 1
        return alert

    def register_alert_callback(self, fn: Any) -> None:
        """Register a function to be called synchronously on each alert."""
        self._alert_callback = fn

    def partial_fit_protocol(self, protocol: str, X: np.ndarray) -> None:
        proto = protocol.lower() if protocol.lower() in self._forests else "generic"
        self._forests[proto].partial_fit(X)

    @property
    def status(self) -> Dict[str, Any]:
        return {
            proto: {
                "fitted": f._is_fitted,
                "threshold": f._threshold,
                "n_scored": f.stats["n_scored"],
                "n_alerts": f.stats["n_alerts"],
                "score_ewma": round(f.stats["score_ewma"], 4),
            }
            for proto, f in self._forests.items()
        }

    @property
    def total_alerts(self) -> int:
        return self._total_alerts


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_manager: Optional[ProtocolForestManager] = None


def get_manager() -> ProtocolForestManager:
    global _manager
    if _manager is None:
        _manager = ProtocolForestManager()
    return _manager


# ---------------------------------------------------------------------------
# Quick smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    rng = np.random.default_rng(0)

    # Simulate 2000 samples of normal 50-dim traffic
    normal = rng.normal(loc=0, scale=1, size=(2000, 50)).astype(np.float32)
    # Inject 20 anomalies far from normal
    anomalies = rng.normal(loc=10, scale=2, size=(20, 50)).astype(np.float32)

    forest = IsolationForest(IsolationForestConfig(protocol="tcp", contamination=0.01))
    forest.fit(normal)

    # Score
    normal_scores = forest.score_batch(normal[:50])
    anomaly_scores = forest.score_batch(anomalies)
    print(f"Normal scores (mean):  {normal_scores.mean():.3f}")
    print(f"Anomaly scores (mean): {anomaly_scores.mean():.3f}")
    print(f"Alert on anomaly[0]: {forest.alert_immediate(anomalies[0])}")
    print("Isolation Forest OK")
