"""
ml/adversarial_defense.py — Adversarial ML Defense v10.0

Defends the neural engine against adversarial packet manipulation.
Attackers who craft packets to evade detection are countered by:

  • FGSM / PGD Adversarial Training — expose model to attacks during training
  • Feature Squeezing — reduce feature precision to strip adversarial noise
  • Randomized Smoothing — certified robustness via majority vote over noisy copies
  • Input Reconstruction Defense — autoencode + diff to detect perturbed inputs
  • Ensemble Disagreement Detection — if sub-models disagree on a sample, flag it
  • Adaptive Threshold Adjustment — tighten thresholds during adversarial surges
  • Red-Teaming Engine — AI agent that generates adversarial packets to test defenses

Reference: Goodfellow et al. 2015 (FGSM), Carlini & Wagner 2017, Cohen et al. 2019
"""

from __future__ import annotations

import logging
import math
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("shadow.ml.adversarial_defense")


# ---------------------------------------------------------------------------
# Attack generators (used by the Red-Teaming Engine)
# ---------------------------------------------------------------------------

class _FGSM:
    """
    Fast Gradient Sign Method — single-step ε-bounded perturbation.
    Requires gradient of loss w.r.t. input features.
    We approximate gradients via finite differences.
    """

    def __init__(self, epsilon: float = 0.05):
        self.epsilon = epsilon

    def perturb(
        self,
        features: List[float],
        predict_fn: Callable[[List[float]], float],
    ) -> List[float]:
        """Return adversarial example: x + ε * sign(∇_x L)."""
        grad = self._fd_gradient(features, predict_fn)
        return [
            max(0.0, min(1.0, x + self.epsilon * math.copysign(1.0, g)))
            for x, g in zip(features, grad)
        ]

    @staticmethod
    def _fd_gradient(
        features: List[float],
        predict_fn: Callable[[List[float]], float],
        eps: float = 1e-3,
    ) -> List[float]:
        grad = []
        f0 = predict_fn(features)
        for i in range(len(features)):
            perturbed = features[:]
            perturbed[i] += eps
            f1 = predict_fn(perturbed)
            grad.append((f1 - f0) / eps)
        return grad


class _PGD:
    """
    Projected Gradient Descent — iterative FGSM with projection back to ε-ball.
    Stronger attack than FGSM; useful for adversarial training.
    """

    def __init__(self, epsilon: float = 0.05, alpha: float = 0.01, num_steps: int = 10):
        self.epsilon = epsilon
        self.alpha = alpha
        self.num_steps = num_steps

    def perturb(
        self,
        features: List[float],
        predict_fn: Callable[[List[float]], float],
    ) -> List[float]:
        x_adv = features[:]
        for _ in range(self.num_steps):
            grad = _FGSM._fd_gradient(x_adv, predict_fn)
            # Step
            x_adv = [xi + self.alpha * math.copysign(1.0, g) for xi, g in zip(x_adv, grad)]
            # Project back to ε-ball around original
            x_adv = [
                max(0.0, min(1.0, max(orig - self.epsilon, min(orig + self.epsilon, xi))))
                for orig, xi in zip(features, x_adv)
            ]
        return x_adv


class _CWAttack:
    """
    Carlini & Wagner L2 attack — optimisation-based, finds minimal perturbation.
    Simplified version using coordinate descent.
    """

    def __init__(self, confidence: float = 0.1, max_iter: int = 50, lr: float = 0.01):
        self.confidence = confidence
        self.max_iter = max_iter
        self.lr = lr

    def perturb(
        self,
        features: List[float],
        predict_fn: Callable[[List[float]], float],
        target_score: float = 0.0,    # target: push score toward 0 (evasion)
    ) -> List[float]:
        x_adv = features[:]
        for _ in range(self.max_iter):
            score = predict_fn(x_adv)
            if score < self.confidence:
                break                  # evasion achieved
            grad = _FGSM._fd_gradient(x_adv, predict_fn)
            x_adv = [
                max(0.0, min(1.0, xi - self.lr * g))
                for xi, g in zip(x_adv, grad)
            ]
        return x_adv


# ---------------------------------------------------------------------------
# Defense mechanisms
# ---------------------------------------------------------------------------

class FeatureSqueezer:
    """
    Feature Squeezing: reduce feature precision to remove adversarial noise.
    Two squeezers: bit-depth reduction + median smoothing.
    If squeezed prediction differs significantly from original → adversarial.
    """

    def __init__(self, bit_depth: int = 4, threshold: float = 0.15):
        self.levels = 2 ** bit_depth
        self.threshold = threshold

    def squeeze_bits(self, features: List[float]) -> List[float]:
        """Quantise each feature to `bit_depth` bits."""
        return [round(f * self.levels) / self.levels for f in features]

    def squeeze_median(self, features: List[float], window: int = 3) -> List[float]:
        """Apply median filter across feature neighbours."""
        n = len(features)
        result = []
        half = window // 2
        for i in range(n):
            lo = max(0, i - half)
            hi = min(n, i + half + 1)
            neighbourhood = sorted(features[lo:hi])
            result.append(neighbourhood[len(neighbourhood) // 2])
        return result

    def is_adversarial(
        self,
        features: List[float],
        predict_fn: Callable[[List[float]], float],
    ) -> Tuple[bool, float]:
        """
        Returns (is_adversarial, score_diff).
        """
        orig_score = predict_fn(features)
        sq_bits = self.squeeze_bits(features)
        sq_med = self.squeeze_median(features)
        score_bits = predict_fn(sq_bits)
        score_med = predict_fn(sq_med)
        max_diff = max(abs(orig_score - score_bits), abs(orig_score - score_med))
        return max_diff > self.threshold, max_diff


class RandomizedSmoother:
    """
    Randomized Smoothing (Cohen et al., 2019).
    Certifies prediction under ℓ2 perturbation by majority vote over
    N noisy copies. Returns certified radius for the winning class.
    """

    def __init__(self, sigma: float = 0.1, n_samples: int = 100, alpha: float = 0.001):
        self.sigma = sigma
        self.n_samples = n_samples
        self.alpha = alpha          # confidence level for certification

    def predict(
        self,
        features: List[float],
        predict_fn: Callable[[List[float]], float],
        threshold: float = 0.5,
    ) -> Tuple[int, float, float]:
        """
        Returns (class_label, abstain_prob, certified_radius).
        class_label: 1=threat, 0=benign, -1=abstain
        """
        scores = []
        for _ in range(self.n_samples):
            noisy = [f + self._gauss() * self.sigma for f in features]
            scores.append(predict_fn(noisy))

        n_threat = sum(1 for s in scores if s >= threshold)
        n_benign = self.n_samples - n_threat
        p_hat = n_threat / self.n_samples

        # Clopper-Pearson lower bound on p_hat
        p_lower = self._cp_lower(n_threat, self.n_samples, self.alpha)

        if p_lower > 0.5:
            label = 1
            certified_radius = self.sigma * _norm_ppf(p_lower)
        elif 1 - p_lower > 0.5:
            label = 0
            certified_radius = self.sigma * _norm_ppf(1 - p_lower)
        else:
            label = -1   # abstain
            certified_radius = 0.0

        return label, p_hat, max(0.0, certified_radius)

    @staticmethod
    def _gauss() -> float:
        # Box-Muller transform
        u1 = (int.from_bytes(os.urandom(4), "little") + 0.5) / 2**32
        u2 = (int.from_bytes(os.urandom(4), "little") + 0.5) / 2**32
        return math.sqrt(-2 * math.log(u1)) * math.cos(2 * math.pi * u2)

    @staticmethod
    def _cp_lower(k: int, n: int, alpha: float) -> float:
        """Clopper-Pearson lower confidence bound (approximation)."""
        if k == 0:
            return 0.0
        p = k / n
        z = 1.96  # ~97.5th percentile for alpha=0.05
        margin = z * math.sqrt(p * (1 - p) / n)
        return max(0.0, p - margin)


def _norm_ppf(p: float) -> float:
    """Rational approximation of the normal quantile function."""
    if p <= 0 or p >= 1:
        return 0.0
    p = max(1e-9, min(1 - 1e-9, p))
    # Abramowitz & Stegun approximation
    t = math.sqrt(-2 * math.log(min(p, 1 - p)))
    c = [2.515517, 0.802853, 0.010328]
    d = [1.432788, 0.189269, 0.001308]
    num = c[0] + c[1] * t + c[2] * t**2
    den = 1 + d[0] * t + d[1] * t**2 + d[2] * t**3
    z = t - num / den
    return z if p >= 0.5 else -z


class EnsembleDetector:
    """
    Adversarial examples are often detected by disagreement between
    multiple sub-models trained on different data subsets.
    """

    def __init__(self, n_models: int = 5, disagreement_threshold: float = 0.3):
        self.n_models = n_models
        self.threshold = disagreement_threshold
        # Seed perturbations for each sub-model
        self._offsets = [
            [math.sin(i * 0.7 + j * 0.3) * 0.01 for j in range(512)]
            for i in range(n_models)
        ]

    def detect(
        self,
        features: List[float],
        predict_fn: Callable[[List[float]], float],
    ) -> Tuple[bool, float]:
        """Returns (is_adversarial, variance_of_scores)."""
        scores = []
        for offset in self._offsets:
            perturbed = [f + o for f, o in zip(features, offset)]
            scores.append(predict_fn(perturbed))
        mu = sum(scores) / len(scores)
        variance = sum((s - mu)**2 for s in scores) / len(scores)
        return variance > self.threshold, variance


# ---------------------------------------------------------------------------
# Adversarial Training Buffer
# ---------------------------------------------------------------------------

class AdversarialTrainingBuffer:
    """
    Maintains a buffer of adversarial examples for augmented training.
    The model trainer should periodically call drain() to get fresh examples.
    """

    def __init__(self, max_size: int = 10_000, attack_ratio: float = 0.5):
        self._buffer: List[Tuple[List[float], float]] = []
        self.max_size = max_size
        self.attack_ratio = attack_ratio
        self._fgsm = _FGSM(epsilon=0.05)
        self._pgd = _PGD(epsilon=0.05, num_steps=10)
        self._stats = {"generated": 0, "drained": 0}

    def generate_and_store(
        self,
        features: List[float],
        label: float,
        predict_fn: Callable[[List[float]], float],
    ) -> None:
        """Generate adversarial versions of a sample and add to buffer."""
        import random; rng = random.Random()

        attack = rng.choice([self._fgsm, self._pgd])
        try:
            adv = attack.perturb(features, predict_fn)
            self._buffer.append((adv, label))
            if len(self._buffer) > self.max_size:
                self._buffer.pop(0)
            self._stats["generated"] += 1
        except Exception as exc:
            logger.debug("Adversarial generation failed: %s", exc)

    def drain(self, n: int = 256) -> List[Tuple[List[float], float]]:
        """Return up to n samples and clear them from buffer."""
        samples = self._buffer[:n]
        self._buffer = self._buffer[n:]
        self._stats["drained"] += len(samples)
        return samples

    def get_stats(self) -> Dict[str, int]:
        return {**self._stats, "buffer_size": len(self._buffer)}


# ---------------------------------------------------------------------------
# Red-Teaming Engine
# ---------------------------------------------------------------------------

class RedTeamingEngine:
    """
    Autonomous adversarial red-team: continuously generates adversarial packets
    and tests whether the main neural engine can be fooled.
    Logs success/failure rates to guide model hardening.
    """

    def __init__(self):
        self._fgsm = _FGSM(epsilon=0.05)
        self._pgd = _PGD(epsilon=0.10, num_steps=20)
        self._cw = _CWAttack(max_iter=30)
        self._results: List[Dict[str, Any]] = []
        self._stats = {"attacks": 0, "successes": 0, "evasion_rate": 0.0}

    def run_attack(
        self,
        features: List[float],
        original_score: float,
        predict_fn: Callable[[List[float]], float],
        attack: str = "pgd",
    ) -> Dict[str, Any]:
        """
        Execute one adversarial attack. Returns result dict with:
        - adversarial_features, adversarial_score, evasion_achieved, score_drop
        """
        t0 = time.perf_counter()
        attackers = {
            "fgsm": self._fgsm,
            "pgd": self._pgd,
            "cw": self._cw,
        }
        attacker = attackers.get(attack, self._pgd)
        adv_features = attacker.perturb(features, predict_fn)
        adv_score = predict_fn(adv_features)
        score_drop = original_score - adv_score
        evasion = adv_score < 0.5 and original_score >= 0.5

        result = {
            "attack": attack,
            "original_score": round(original_score, 4),
            "adversarial_score": round(adv_score, 4),
            "score_drop": round(score_drop, 4),
            "evasion_achieved": evasion,
            "perturbation_norm": round(
                math.sqrt(sum((a - b)**2 for a, b in zip(adv_features, features))), 4
            ),
            "ms": round((time.perf_counter() - t0) * 1000, 2),
        }
        self._results.append(result)
        self._stats["attacks"] += 1
        if evasion:
            self._stats["successes"] += 1
        self._stats["evasion_rate"] = (
            self._stats["successes"] / max(1, self._stats["attacks"])
        )
        logger.info(
            "RedTeam[%s]: orig=%.3f adv=%.3f evasion=%s",
            attack, original_score, adv_score, evasion,
        )
        return result

    def get_stats(self) -> Dict[str, Any]:
        return {**self._stats, "total_results": len(self._results)}


# ---------------------------------------------------------------------------
# Main Adversarial Defense Layer
# ---------------------------------------------------------------------------

class AdversarialDefenseLayer:
    """
    SHADOW-ML Adversarial Defense Layer v10.0

    Multi-layer defense pipeline:
      1. Feature Squeezing — strip ε-noise from incoming features
      2. Ensemble Disagreement — detect adversarial perturbations
      3. Randomized Smoothing — certified robustness for flagged samples
      4. Adaptive threshold — tighten if adversarial surge detected

    Usage:
      defense = AdversarialDefenseLayer()
      result = defense.screen(features, predict_fn)
      if result["is_adversarial"]:
          # use result["safe_score"] instead of raw score
    """

    VERSION = "10.0.0"

    def __init__(
        self,
        squeezer_threshold: float = 0.15,
        ensemble_threshold: float = 0.25,
        smoothing_sigma: float = 0.1,
        adaptive_surge_window: int = 100,
        adaptive_surge_rate: float = 0.3,
    ):
        self._squeezer = FeatureSqueezer(threshold=squeezer_threshold)
        self._ensemble = EnsembleDetector(disagreement_threshold=ensemble_threshold)
        self._smoother = RandomizedSmoother(sigma=smoothing_sigma, n_samples=50)
        self._red_team = RedTeamingEngine()
        self._adv_buffer = AdversarialTrainingBuffer()

        # Adaptive threshold tracking
        self._surge_window = adaptive_surge_window
        self._surge_threshold = adaptive_surge_rate
        self._recent_flags: List[bool] = []
        self._base_threshold = 0.5
        self._current_threshold = 0.5

        self._stats: Dict[str, Any] = {
            "screened": 0,
            "flagged_adversarial": 0,
            "squeezer_flags": 0,
            "ensemble_flags": 0,
            "smoother_abstains": 0,
            "adaptive_tightenings": 0,
        }
        logger.info("AdversarialDefenseLayer v%s initialised", self.VERSION)

    def screen(
        self,
        features: List[float],
        predict_fn: Callable[[List[float]], float],
        run_smoother: bool = False,
    ) -> Dict[str, Any]:
        """
        Screen one feature vector for adversarial manipulation.
        Returns dict with: is_adversarial, safe_score, methods_triggered, certified_radius
        """
        self._stats["screened"] += 1
        methods_triggered = []
        is_adv = False

        # Layer 1: Feature Squeezing
        sq_adv, sq_diff = self._squeezer.is_adversarial(features, predict_fn)
        if sq_adv:
            methods_triggered.append("feature_squeezing")
            is_adv = True
            self._stats["squeezer_flags"] += 1

        # Layer 2: Ensemble Disagreement
        ens_adv, ens_var = self._ensemble.detect(features, predict_fn)
        if ens_adv:
            methods_triggered.append("ensemble_disagreement")
            is_adv = True
            self._stats["ensemble_flags"] += 1

        # Layer 3: Randomized Smoothing (only when flagged or requested)
        certified_radius = 0.0
        label = None
        if is_adv or run_smoother:
            label, p_hat, certified_radius = self._smoother.predict(features, predict_fn)
            if label == -1:
                methods_triggered.append("smoother_abstain")
                self._stats["smoother_abstains"] += 1

        # Adaptive threshold update
        self._update_adaptive_threshold(is_adv)

        # Safe score: use squeezed features if adversarial
        if is_adv:
            safe_features = self._squeezer.squeeze_bits(
                self._squeezer.squeeze_median(features)
            )
            safe_score = predict_fn(safe_features)
            self._stats["flagged_adversarial"] += 1
        else:
            safe_score = predict_fn(features)

        return {
            "is_adversarial": is_adv,
            "methods_triggered": methods_triggered,
            "squeezer_diff": round(sq_diff, 4),
            "ensemble_variance": round(ens_var, 4),
            "certified_radius": round(certified_radius, 4),
            "smoother_label": label,
            "safe_score": round(safe_score, 4),
            "adaptive_threshold": round(self._current_threshold, 4),
        }

    def _update_adaptive_threshold(self, flagged: bool) -> None:
        self._recent_flags.append(flagged)
        if len(self._recent_flags) > self._surge_window:
            self._recent_flags.pop(0)
        if len(self._recent_flags) >= self._surge_window:
            surge_rate = sum(self._recent_flags) / self._surge_window
            if surge_rate >= self._surge_threshold:
                # Adversarial surge — tighten threshold
                new_thresh = min(0.3, self._current_threshold - 0.05)
                if new_thresh < self._current_threshold:
                    self._current_threshold = new_thresh
                    self._stats["adaptive_tightenings"] += 1
                    logger.warning(
                        "Adversarial surge detected (rate=%.1f%%) — threshold→%.2f",
                        surge_rate * 100, self._current_threshold,
                    )
            else:
                # Calm — relax threshold back toward base
                self._current_threshold = min(
                    self._base_threshold,
                    self._current_threshold + 0.005,
                )

    def generate_adversarial_examples(
        self,
        features: List[float],
        label: float,
        predict_fn: Callable[[List[float]], float],
    ) -> None:
        """Generate and store adversarial examples for training augmentation."""
        self._adv_buffer.generate_and_store(features, label, predict_fn)

    def drain_training_buffer(self, n: int = 256) -> List[Tuple[List[float], float]]:
        return self._adv_buffer.drain(n)

    def run_red_team(
        self,
        features: List[float],
        original_score: float,
        predict_fn: Callable[[List[float]], float],
    ) -> Dict[str, Any]:
        return self._red_team.run_attack(features, original_score, predict_fn)

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "red_team": self._red_team.get_stats(),
            "adv_buffer": self._adv_buffer.get_stats(),
        }
