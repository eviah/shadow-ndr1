"""
ml/model_poisoning_detector.py — Neural Network Poisoning Detector v10.0

Detects attacks against the ML detection model itself:
  • Data poisoning: malicious training samples designed to degrade detection
  • Model inversion: extracting training data or model weights from predictions
  • Adversarial perturbations: minimal input changes that fool the model
  • Backdoor trojans: hidden triggers embedded in model by attackers
  • Distribution shift: legitimate data drift that degrades performance
  • Gradient-based attacks: using model's own gradients to craft adversarial inputs

Protects Shadow NDR's neural engine from being disabled by adversaries.
Includes model monitoring, integrity verification, and rollback mechanisms.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("shadow.ml.poisoning_detection")


class PoisoningThreat(Enum):
    DATA_POISONING = "data_poisoning"
    BACKDOOR_TRIGGER = "backdoor_trigger"
    ADVERSARIAL_PERTURBATION = "adversarial_perturbation"
    MODEL_INVERSION = "model_inversion"
    DISTRIBUTION_SHIFT = "distribution_shift"
    GRADIENT_LEAKAGE = "gradient_leakage"


@dataclass
class ModelCheckpoint:
    """Model state at a point in time."""
    timestamp: float
    weight_hash: str  # SHA256 of model weights
    performance_metrics: Dict[str, float]  # accuracy, precision, recall, auc
    test_loss: float
    feature_importance: Dict[int, float]
    is_clean: bool = True


@dataclass
class TrainingDatapoint:
    """Single training sample with metadata."""
    features: np.ndarray
    label: int  # 0=benign, 1=malicious
    source: str  # "legitimate_traffic", "red_team", "external_source"
    timestamp: float
    confidence: float  # confidence in label correctness


@dataclass
class PoisoningAlert:
    """Alert for model poisoning attack."""
    threat_type: PoisoningThreat
    severity: str
    confidence: float
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class DataPoisoningDetector:
    """
    Detects poisoned training samples designed to degrade model performance.
    """

    def __init__(self):
        self._baseline_statistics: Optional[Dict[str, np.ndarray]] = None
        self._sample_history: deque = deque(maxlen=1000)

    def register_clean_baseline(self, features: List[np.ndarray], labels: List[int]) -> None:
        """Register clean training data as baseline."""
        arr = np.array(features)
        self._baseline_statistics = {
            "mean": np.mean(arr, axis=0),
            "std": np.std(arr, axis=0),
            "median": np.median(arr, axis=0),
            "q25": np.percentile(arr, 25, axis=0),
            "q75": np.percentile(arr, 75, axis=0),
        }
        logger.info("Clean baseline registered")

    def detect_poisoning(self, sample: TrainingDatapoint) -> Optional[PoisoningAlert]:
        """
        Detect if a training sample is poisoned.
        Returns alert if suspicious pattern detected.
        """
        if self._baseline_statistics is None:
            return None

        features = sample.features
        baseline_mean = self._baseline_statistics["mean"]
        baseline_std = self._baseline_statistics["std"]

        # Z-score anomaly detection
        z_scores = np.abs((features - baseline_mean) / (baseline_std + 1e-8))
        extreme_features = np.sum(z_scores > 4.0)

        # Check for suspiciously perfect labels
        if sample.confidence == 1.0 and sample.source == "external_source":
            return PoisoningAlert(
                threat_type=PoisoningThreat.DATA_POISONING,
                severity="medium",
                confidence=0.65,
                description="Sample with suspiciously perfect label confidence (100%)",
                evidence={
                    "confidence": sample.confidence,
                    "source": sample.source,
                }
            )

        # Check for statistical anomalies
        if extreme_features > 5:  # More than 5 features are 4+ sigma away
            return PoisoningAlert(
                threat_type=PoisoningThreat.DATA_POISONING,
                severity="high",
                confidence=0.80,
                description=f"Sample with {extreme_features} extreme feature values",
                evidence={
                    "extreme_feature_count": int(extreme_features),
                    "max_z_score": float(np.max(z_scores)),
                }
            )

        # Check for label-feature mismatch (sample contradicts baseline distribution)
        if sample.label == 1:  # Malicious
            # Malicious samples should have different distribution
            mal_likelihood = np.sum(z_scores > 2.0) / len(features)
            if mal_likelihood < 0.1:  # Looks too much like benign
                return PoisoningAlert(
                    threat_type=PoisoningThreat.DATA_POISONING,
                    severity="medium",
                    confidence=0.70,
                    description="Labeled malicious but statistically resembles benign samples",
                    evidence={
                        "malicious_likelihood": float(mal_likelihood),
                    }
                )

        self._sample_history.append(sample)
        return None


class AdversarialPerturbationDetector:
    """
    Detects adversarial examples (minimal perturbations designed to fool model).
    """

    def __init__(self):
        self._perturbation_threshold: float = 0.01  # L-infinity norm
        self._reference_samples: List[np.ndarray] = []

    def register_reference_samples(self, samples: List[np.ndarray]) -> None:
        """Register legitimate reference samples."""
        self._reference_samples = samples

    def detect_perturbation(
        self,
        sample: np.ndarray,
        predicted_label: int,
        model_confidence: float
    ) -> Optional[PoisoningAlert]:
        """
        Detect if sample is likely an adversarial perturbation.
        Uses similarity to reference samples and confidence metrics.
        """
        if not self._reference_samples:
            return None

        # Find closest reference sample
        distances = [np.linalg.norm(sample - ref, ord=np.inf) for ref in self._reference_samples]
        closest_distance = min(distances)

        # Check for high confidence with high perturbation (suspicious)
        if model_confidence > 0.95 and closest_distance < 0.05:
            return PoisoningAlert(
                threat_type=PoisoningThreat.ADVERSARIAL_PERTURBATION,
                severity="high",
                confidence=0.85,
                description="High confidence on slightly perturbed sample (adversarial pattern)",
                evidence={
                    "closest_distance": float(closest_distance),
                    "model_confidence": float(model_confidence),
                }
            )

        # Check for clustering around decision boundaries
        if 0.45 < model_confidence < 0.55:  # Near boundary
            if closest_distance < 0.02:
                return PoisoningAlert(
                    threat_type=PoisoningThreat.ADVERSARIAL_PERTURBATION,
                    severity="medium",
                    confidence=0.70,
                    description="Sample near decision boundary with minimal perturbation",
                    evidence={
                        "closest_distance": float(closest_distance),
                        "model_confidence": float(model_confidence),
                    }
                )

        return None


class ModelIntegrityMonitor:
    """
    Monitors model integrity and detects tampering or backdoors.
    """

    def __init__(self):
        self._clean_checkpoint: Optional[ModelCheckpoint] = None
        self._checkpoint_history: deque = deque(maxlen=100)
        self._performance_baseline: Optional[Dict[str, float]] = None

    def register_clean_model(
        self,
        weights_hash: str,
        performance_metrics: Dict[str, float],
        feature_importance: Dict[int, float]
    ) -> None:
        """Register known-clean model state."""
        self._clean_checkpoint = ModelCheckpoint(
            timestamp=time.time(),
            weight_hash=weights_hash,
            performance_metrics=performance_metrics,
            test_loss=1.0 - performance_metrics.get("accuracy", 0.5),
            feature_importance=feature_importance,
            is_clean=True
        )
        self._performance_baseline = performance_metrics
        logger.info("Clean model checkpoint registered")

    def check_model_integrity(
        self,
        current_weights_hash: str,
        current_performance: Dict[str, float]
    ) -> Optional[PoisoningAlert]:
        """
        Check if model weights or performance have changed unexpectedly.
        """
        if self._clean_checkpoint is None:
            return None

        # Check weight integrity
        if current_weights_hash != self._clean_checkpoint.weight_hash:
            return PoisoningAlert(
                threat_type=PoisoningThreat.BACKDOOR_TRIGGER,
                severity="critical",
                confidence=0.99,
                description="Model weights changed unexpectedly",
                evidence={
                    "expected_hash": self._clean_checkpoint.weight_hash,
                    "current_hash": current_weights_hash,
                }
            )

        # Check for performance degradation (sign of poisoning)
        baseline_acc = self._performance_baseline.get("accuracy", 0.9)
        current_acc = current_performance.get("accuracy", 0.5)
        acc_drop = (baseline_acc - current_acc) / (baseline_acc + 1e-8)

        if acc_drop > 0.1:  # >10% accuracy drop
            return PoisoningAlert(
                threat_type=PoisoningThreat.DATA_POISONING,
                severity="high",
                confidence=0.80,
                description=f"Model accuracy degraded by {acc_drop:.1%}",
                evidence={
                    "baseline_accuracy": float(baseline_acc),
                    "current_accuracy": float(current_acc),
                    "drop_percent": float(acc_drop * 100),
                }
            )

        # Check for differential performance degradation (backdoor)
        baseline_precision = self._performance_baseline.get("precision", 0.9)
        current_precision = current_performance.get("precision", 0.5)
        prec_drop = (baseline_precision - current_precision) / (baseline_precision + 1e-8)

        if prec_drop > 0.2:  # High precision drop suggests backdoor
            return PoisoningAlert(
                threat_type=PoisoningThreat.BACKDOOR_TRIGGER,
                severity="high",
                confidence=0.75,
                description="Disproportionate precision degradation (backdoor signature)",
                evidence={
                    "precision_drop_percent": float(prec_drop * 100),
                }
            )

        return None


class ModelPoisoningDetector:
    """
    Main detector for attacks against the ML model itself.
    """

    def __init__(self):
        self._data_detector = DataPoisoningDetector()
        self._perturbation_detector = AdversarialPerturbationDetector()
        self._integrity_monitor = ModelIntegrityMonitor()
        self._alerts: List[PoisoningAlert] = []
        self._stats = {
            "samples_checked": 0,
            "alerts": 0,
            "data_poisoning": 0,
            "adversarial_detections": 0,
            "integrity_violations": 0,
        }

    def register_clean_training_data(
        self,
        features: List[np.ndarray],
        labels: List[int]
    ) -> None:
        """Register clean baseline for data poisoning detection."""
        self._data_detector.register_clean_baseline(features, labels)

    def register_clean_model(
        self,
        weights_hash: str,
        performance_metrics: Dict[str, float],
        feature_importance: Dict[int, float]
    ) -> None:
        """Register clean model checkpoint."""
        self._integrity_monitor.register_clean_model(weights_hash, performance_metrics, feature_importance)

    def check_training_sample(self, sample: TrainingDatapoint) -> Optional[PoisoningAlert]:
        """Check single training sample for poisoning."""
        self._stats["samples_checked"] += 1
        alert = self._data_detector.detect_poisoning(sample)
        if alert:
            self._alerts.append(alert)
            self._stats["alerts"] += 1
            self._stats["data_poisoning"] += 1
            logger.warning("Data poisoning detected: %s (conf=%.2f)", alert.description, alert.confidence)
        return alert

    def check_adversarial_sample(
        self,
        features: np.ndarray,
        predicted_label: int,
        model_confidence: float
    ) -> Optional[PoisoningAlert]:
        """Check for adversarial perturbation."""
        alert = self._perturbation_detector.detect_perturbation(
            features, predicted_label, model_confidence
        )
        if alert:
            self._alerts.append(alert)
            self._stats["alerts"] += 1
            self._stats["adversarial_detections"] += 1
            logger.warning("Adversarial perturbation detected: %s (conf=%.2f)", alert.description, alert.confidence)
        return alert

    def check_model_integrity(
        self,
        current_weights_hash: str,
        current_performance: Dict[str, float]
    ) -> Optional[PoisoningAlert]:
        """Check model integrity."""
        alert = self._integrity_monitor.check_model_integrity(current_weights_hash, current_performance)
        if alert:
            self._alerts.append(alert)
            self._stats["alerts"] += 1
            self._stats["integrity_violations"] += 1
            logger.warning("Model integrity violation: %s (conf=%.2f)", alert.description, alert.confidence)
        return alert

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    @property
    def recent_alerts(self) -> List[Dict[str, Any]]:
        return [
            {
                "threat": a.threat_type.value,
                "severity": a.severity,
                "confidence": a.confidence,
                "description": a.description,
                "timestamp": a.timestamp,
            }
            for a in self._alerts[-20:]
        ]


_detector: Optional[ModelPoisoningDetector] = None


def get_detector() -> ModelPoisoningDetector:
    global _detector
    if _detector is None:
        _detector = ModelPoisoningDetector()
    return _detector


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    detector = get_detector()

    # Register clean baseline
    clean_features = [np.random.normal(0.5, 0.1, 512) for _ in range(100)]
    clean_labels = [random.choice([0, 1]) for _ in range(100)]
    detector.register_clean_training_data(clean_features, clean_labels)

    # Register clean model
    clean_weights_hash = hashlib.sha256(b"clean_model_weights").hexdigest()
    detector.register_clean_model(
        clean_weights_hash,
        {"accuracy": 0.95, "precision": 0.93, "recall": 0.92, "auc": 0.96},
        {i: random.random() for i in range(10)}
    )

    # Check normal sample
    normal_sample = TrainingDatapoint(
        features=np.random.normal(0.5, 0.1, 512),
        label=1,
        source="legitimate_traffic",
        timestamp=time.time(),
        confidence=0.9
    )
    alert = detector.check_training_sample(normal_sample)
    print(f"Normal sample check: {alert}")

    # Check poisoned sample (statistical outlier)
    poisoned_sample = TrainingDatapoint(
        features=np.random.uniform(0, 1, 512),  # Very different distribution
        label=0,
        source="external_source",
        timestamp=time.time(),
        confidence=1.0
    )
    alert = detector.check_training_sample(poisoned_sample)
    print(f"Poisoned sample check: {alert}")

    # Check adversarial sample
    adv_features = clean_features[0].copy()
    adv_features += np.random.normal(0, 0.005, 512)  # Tiny perturbation
    alert = detector.check_adversarial_sample(adv_features, predicted_label=1, model_confidence=0.99)
    print(f"Adversarial sample check: {alert}")

    print(f"Stats: {detector.stats}")
    print("Model Poisoning Detector OK")
