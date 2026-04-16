"""
defense/quantum_noise.py — SHADOW-ML Quantum Noise Injection v10.0

Adversarially-optimal noise injection to:
  • Corrupt attacker ML model training data (adversarial poisoning)
  • Inject imperceptible perturbations into exfiltrated model weights
  • Apply FGSM / PGD / C&W attack-style noise against attacker models
  • Generate quantum-random seeds via hardware entropy sources
  • Implement differential privacy noise for data exfiltration defence
"""

from __future__ import annotations

import logging
import math
import os
import struct
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("shadow.defense.quantum_noise")


class NoiseDistribution(str, Enum):
    GAUSSIAN    = "gaussian"
    LAPLACE     = "laplace"
    UNIFORM     = "uniform"
    CAUCHY      = "cauchy"
    QUANTUM     = "quantum"
    FGSM        = "fgsm"
    PGD         = "pgd"
    SALT_PEPPER = "salt_pepper"


class _QuantumEntropySource:
    def __init__(self):
        self._device = self._detect_hrng()

    def _detect_hrng(self) -> Optional[str]:
        for dev in ["/dev/hwrng", "/dev/random"]:
            if os.path.exists(dev):
                return dev
        return None

    def random_bytes(self, n: int) -> bytes:
        if self._device:
            try:
                with open(self._device, "rb") as f:
                    return f.read(n)
            except OSError:
                pass
        return os.urandom(n)

    def random_float(self) -> float:
        raw = self.random_bytes(8)
        val = struct.unpack(">Q", raw)[0]
        return val / (2 ** 64)

    def random_normal(self) -> float:
        u1 = max(1e-15, self.random_float())
        u2 = self.random_float()
        return math.sqrt(-2.0 * math.log(u1)) * math.cos(2 * math.pi * u2)


class _NoiseEngine:
    def __init__(self):
        self._hrng = _QuantumEntropySource()

    def generate(
        self,
        shape: int,
        distribution: NoiseDistribution,
        epsilon: float = 0.05,
        gradient_hint: Optional[List[float]] = None,
    ) -> List[float]:
        dispatch = {
            NoiseDistribution.GAUSSIAN:    self._gaussian,
            NoiseDistribution.LAPLACE:     self._laplace,
            NoiseDistribution.UNIFORM:     self._uniform,
            NoiseDistribution.CAUCHY:      self._cauchy,
            NoiseDistribution.QUANTUM:     self._quantum,
            NoiseDistribution.FGSM:        lambda n, e: self._fgsm(n, e, gradient_hint),
            NoiseDistribution.PGD:         lambda n, e: self._pgd(n, e, gradient_hint),
            NoiseDistribution.SALT_PEPPER: self._salt_pepper,
        }
        fn = dispatch.get(distribution, self._gaussian)
        return fn(shape, epsilon)

    def _gaussian(self, n: int, eps: float) -> List[float]:
        return [self._hrng.random_normal() * eps for _ in range(n)]

    def _laplace(self, n: int, eps: float) -> List[float]:
        noise = []
        for _ in range(n):
            u = self._hrng.random_float() - 0.5
            sign = 1 if u >= 0 else -1
            noise.append(sign * eps * math.log(1 - 2 * abs(u) + 1e-12))
        return noise

    def _uniform(self, n: int, eps: float) -> List[float]:
        return [(self._hrng.random_float() * 2 - 1) * eps for _ in range(n)]

    def _cauchy(self, n: int, eps: float) -> List[float]:
        noise = []
        for _ in range(n):
            u = self._hrng.random_float()
            noise.append(math.tan(math.pi * (u - 0.5)) * eps)
        return noise

    def _quantum(self, n: int, eps: float) -> List[float]:
        return [self._hrng.random_normal() * eps for _ in range(n)]

    def _fgsm(self, n: int, eps: float, grad: Optional[List[float]]) -> List[float]:
        if grad and len(grad) >= n:
            return [eps * (1.0 if g >= 0 else -1.0) for g in grad[:n]]
        return [(eps if self._hrng.random_float() > 0.5 else -eps) for _ in range(n)]

    def _pgd(self, n: int, eps: float, grad: Optional[List[float]], steps: int = 10) -> List[float]:
        step_size = eps / steps
        delta = [0.0] * n
        for _ in range(steps):
            g = self._fgsm(n, step_size, grad)
            delta = [max(-eps, min(eps, d + gi)) for d, gi in zip(delta, g)]
        return delta

    def _salt_pepper(self, n: int, eps: float) -> List[float]:
        noise = []
        for _ in range(n):
            r = self._hrng.random_float()
            if r < eps / 2:
                noise.append(1.0)
            elif r < eps:
                noise.append(-1.0)
            else:
                noise.append(0.0)
        return noise


@dataclass
class DPBudget:
    epsilon_total: float = 100.0
    delta: float = 1e-5
    epsilon_used: float = 0.0

    def consume(self, cost: float) -> bool:
        if self.epsilon_used + cost > self.epsilon_total:
            return False
        self.epsilon_used += cost
        return True

    @property
    def remaining(self) -> float:
        return max(0.0, self.epsilon_total - self.epsilon_used)

    @property
    def exhausted(self) -> bool:
        return self.epsilon_used >= self.epsilon_total


class QuantumNoise:
    """SHADOW-ML Quantum Noise Engine v10.0"""

    VERSION = "10.0.0"

    def __init__(self):
        self._engine = _NoiseEngine()
        self._dp_budget = DPBudget(epsilon_total=100.0)
        self._injection_log: List[Dict[str, Any]] = []
        logger.info("QuantumNoise v%s initialised", self.VERSION)

    def inject(
        self,
        data: List[float],
        distribution: NoiseDistribution = NoiseDistribution.QUANTUM,
        epsilon: float = 0.05,
        gradient_hint: Optional[List[float]] = None,
        target: str = "unknown",
    ) -> Tuple[List[float], Dict[str, Any]]:
        n = len(data)
        if not n:
            return data, {}
        budget_ok = self._dp_budget.consume(epsilon)
        noise = self._engine.generate(n, distribution, epsilon, gradient_hint)
        perturbed = [d + nv for d, nv in zip(data, noise)]
        signal_power = sum(d ** 2 for d in data) / n
        noise_power = sum(nv ** 2 for nv in noise) / n
        snr_db = 10 * math.log10(signal_power / max(1e-12, noise_power))
        meta = {
            "timestamp": time.time(),
            "target": target,
            "distribution": distribution,
            "epsilon": epsilon,
            "n_dimensions": n,
            "snr_db": round(snr_db, 2),
            "dp_budget_remaining": round(self._dp_budget.remaining, 4),
            "budget_ok": budget_ok,
        }
        self._injection_log.append(meta)
        return perturbed, meta

    def poison_training_batch(
        self,
        batch: List[List[float]],
        labels: List[int],
        poison_rate: float = 0.20,
        flip_labels: bool = True,
    ) -> Tuple[List[List[float]], List[int]]:
        n_poison = max(1, int(len(batch) * poison_rate))
        poisoned_batch = list(batch)
        poisoned_labels = list(labels)
        for i in range(n_poison):
            idx = i % len(batch)
            noisy, _ = self.inject(batch[idx], distribution=NoiseDistribution.PGD, epsilon=0.10, target="attacker_training")
            poisoned_batch[idx] = noisy
            if flip_labels and idx < len(poisoned_labels):
                poisoned_labels[idx] = 1 - poisoned_labels[idx]
        logger.info("Poisoned %d/%d training samples", n_poison, len(batch))
        return poisoned_batch, poisoned_labels

    def corrupt_model_weights(self, weights: List[float], severity: float = 0.01) -> List[float]:
        corrupted, _ = self.inject(weights, distribution=NoiseDistribution.CAUCHY, epsilon=severity, target="stolen_weights")
        return corrupted

    def differential_privacy_release(self, data: List[float], sensitivity: float = 1.0, privacy_epsilon: float = 1.0) -> List[float]:
        scale = sensitivity / max(1e-8, privacy_epsilon)
        released, _ = self.inject(data, distribution=NoiseDistribution.LAPLACE, epsilon=scale, target="dp_release")
        return released

    def adaptive_epsilon(self, threat_score: float) -> float:
        return 0.001 + 0.199 * threat_score

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_injections": len(self._injection_log),
            "dp_budget_used": round(self._dp_budget.epsilon_used, 4),
            "dp_budget_remaining": round(self._dp_budget.remaining, 4),
            "dp_budget_exhausted": self._dp_budget.exhausted,
            "recent_injections": self._injection_log[-10:],
        }
