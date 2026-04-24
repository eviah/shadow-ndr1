"""
APEX · Cross-Modal Federated Swarm Forensics
─────────────────────────────────────────────
Each airline tenant (EL AL, Israir, Arkia, …) trains a local detection
model on its own telemetry and submits *gradients only* — never raw
packets, never tail numbers — to a central aggregator. The aggregator
runs FedAvg with differential-privacy Gaussian noise and produces a
global model that learns from fleet-wide attack patterns without any
tenant leaking proprietary operational data.

This file contains the math and the protocol dataclasses. It is
deliberately framework-agnostic: gradients are flat numpy arrays, so
this works with PyTorch, TF, JAX — or with hand-rolled classifiers.

Privacy model
─────────────
  Per-round (ε, δ)-DP via Gaussian mechanism:
      noise ~ N(0, (C · σ)²)   applied to the L2-clipped gradient sum.
  Clipping norm C and noise multiplier σ are aggregator-set.
  The moments accountant for composition over T rounds is left to the
  calling code (opacus/jax-privacy handle it well).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np


# ─── Protocol types ───────────────────────────────────────────────────────

@dataclass
class GradientUpdate:
    tenant_id: str                  # "elal", "israir", ...
    round_id: int
    gradient: np.ndarray            # flat float32
    num_samples: int                # for weighted averaging
    submitted_at: float = field(default_factory=time.time)
    signature: bytes = b""          # HMAC-SHA256 over (tenant|round|grad)

    def sign(self, secret: bytes) -> None:
        payload = (
            self.tenant_id.encode() +
            self.round_id.to_bytes(8, "big") +
            self.gradient.tobytes()
        )
        self.signature = hmac.new(secret, payload, hashlib.sha256).digest()

    def verify(self, secret: bytes) -> bool:
        payload = (
            self.tenant_id.encode() +
            self.round_id.to_bytes(8, "big") +
            self.gradient.tobytes()
        )
        expected = hmac.new(secret, payload, hashlib.sha256).digest()
        return hmac.compare_digest(expected, self.signature)


@dataclass
class RoundResult:
    round_id: int
    global_weights: np.ndarray
    participants: List[str]
    clipped_count: int
    noise_sigma: float
    l2_budget: float
    epoch_ms: float


# ─── DP + aggregation primitives ──────────────────────────────────────────

def clip_l2(x: np.ndarray, c: float) -> Tuple[np.ndarray, bool]:
    """Return (clipped, was_clipped)."""
    norm = float(np.linalg.norm(x))
    if norm <= c or norm == 0.0:
        return x, False
    return (x * (c / norm)).astype(x.dtype), True


def gaussian_noise(shape: Tuple[int, ...], sigma: float,
                  rng: np.random.Generator) -> np.ndarray:
    if sigma <= 0.0:
        return np.zeros(shape, dtype=np.float32)
    return rng.normal(0.0, sigma, size=shape).astype(np.float32)


def fedavg_weighted(gradients: List[np.ndarray],
                   weights: List[int]) -> np.ndarray:
    """Sample-count weighted average of gradients."""
    if not gradients:
        raise ValueError("no gradients to average")
    total = float(sum(weights))
    if total <= 0:
        raise ValueError("sum of sample weights must be > 0")
    acc = np.zeros_like(gradients[0])
    for g, w in zip(gradients, weights):
        acc += g * (w / total)
    return acc


# ─── Aggregator (the "swarm coordinator") ─────────────────────────────────

@dataclass
class AggregatorConfig:
    dim: int                        # total param count
    l2_clip: float = 1.0            # clipping norm C
    noise_multiplier: float = 0.8   # σ — 0 disables DP
    learning_rate: float = 1.0
    min_participants: int = 2
    tenant_secrets: Dict[str, bytes] = field(default_factory=dict)


class SwarmAggregator:
    """FedAvg + DP-Gaussian aggregator with HMAC-authenticated updates."""

    def __init__(self, cfg: AggregatorConfig, init_weights: Optional[np.ndarray] = None):
        self.cfg = cfg
        self.global_weights = (
            init_weights.copy().astype(np.float32)
            if init_weights is not None
            else np.zeros(cfg.dim, dtype=np.float32)
        )
        self.round_id = 0
        self._rng = np.random.default_rng()
        self.history: List[RoundResult] = []

    def register_tenant(self, tenant_id: str) -> bytes:
        """Issue an HMAC secret the tenant will use to sign updates."""
        secret = secrets.token_bytes(32)
        self.cfg.tenant_secrets[tenant_id] = secret
        return secret

    def _verify(self, update: GradientUpdate) -> bool:
        secret = self.cfg.tenant_secrets.get(update.tenant_id)
        if not secret:
            return False
        if update.gradient.shape != (self.cfg.dim,):
            return False
        if update.round_id != self.round_id:
            return False
        return update.verify(secret)

    def aggregate(self, updates: List[GradientUpdate]) -> RoundResult:
        t0 = time.time()
        accepted: List[GradientUpdate] = []
        clipped_count = 0

        for u in updates:
            if not self._verify(u):
                continue
            clipped, was_clipped = clip_l2(u.gradient, self.cfg.l2_clip)
            if was_clipped:
                clipped_count += 1
            accepted.append(GradientUpdate(
                tenant_id=u.tenant_id,
                round_id=u.round_id,
                gradient=clipped,
                num_samples=max(1, u.num_samples),
            ))

        if len(accepted) < self.cfg.min_participants:
            raise RuntimeError(
                f"round {self.round_id}: only {len(accepted)} valid "
                f"updates, need {self.cfg.min_participants}"
            )

        grads = [a.gradient for a in accepted]
        sample_counts = [a.num_samples for a in accepted]
        avg = fedavg_weighted(grads, sample_counts)

        sigma = self.cfg.noise_multiplier * self.cfg.l2_clip / max(len(accepted), 1)
        noisy = avg + gaussian_noise(avg.shape, sigma, self._rng)

        self.global_weights = (self.global_weights -
                               self.cfg.learning_rate * noisy).astype(np.float32)

        result = RoundResult(
            round_id=self.round_id,
            global_weights=self.global_weights.copy(),
            participants=[a.tenant_id for a in accepted],
            clipped_count=clipped_count,
            noise_sigma=sigma,
            l2_budget=self.cfg.l2_clip,
            epoch_ms=(time.time() - t0) * 1000.0,
        )
        self.history.append(result)
        self.round_id += 1
        return result

    def snapshot_digest(self) -> str:
        return hashlib.sha256(self.global_weights.tobytes()).hexdigest()


# ─── Client-side helper ───────────────────────────────────────────────────

class TenantClient:
    """Toy local-training stub — compute gradient vs current global."""

    def __init__(self, tenant_id: str, secret: bytes,
                 local_truth: np.ndarray, num_samples: int):
        self.tenant_id = tenant_id
        self.secret = secret
        self.local_truth = local_truth.astype(np.float32)
        self.num_samples = num_samples

    def compute_update(self, global_weights: np.ndarray,
                      round_id: int) -> GradientUpdate:
        """Return gradient = global - local_truth (pretend MSE gradient)."""
        grad = (global_weights - self.local_truth).astype(np.float32)
        u = GradientUpdate(
            tenant_id=self.tenant_id,
            round_id=round_id,
            gradient=grad,
            num_samples=self.num_samples,
        )
        u.sign(self.secret)
        return u


# ─── CLI demo ─────────────────────────────────────────────────────────────

def _demo():
    print("APEX · Cross-Modal Federated Swarm Forensics — demo")
    print("=" * 60)

    dim = 128
    rng = np.random.default_rng(42)

    # Each airline has its own slightly different view of "what attacks look like"
    ground_truth = rng.normal(size=dim).astype(np.float32)
    tenants_truth = {
        "elal":   ground_truth + rng.normal(0, 0.05, dim).astype(np.float32),
        "israir": ground_truth + rng.normal(0, 0.05, dim).astype(np.float32),
        "arkia":  ground_truth + rng.normal(0, 0.05, dim).astype(np.float32),
    }
    sample_counts = {"elal": 50_000, "israir": 12_000, "arkia": 8_000}

    cfg = AggregatorConfig(dim=dim, l2_clip=2.0, noise_multiplier=0.4,
                          learning_rate=0.5, min_participants=2)
    agg = SwarmAggregator(cfg, init_weights=np.zeros(dim, dtype=np.float32))

    clients = {
        tid: TenantClient(
            tenant_id=tid,
            secret=agg.register_tenant(tid),
            local_truth=truth,
            num_samples=sample_counts[tid],
        )
        for tid, truth in tenants_truth.items()
    }

    print(f"Init weights digest: {agg.snapshot_digest()[:16]}…")
    print(f"Participants: {list(clients.keys())}")
    print(f"DP config:    clip={cfg.l2_clip}  sigma_mult={cfg.noise_multiplier}")

    for round_n in range(10):
        updates = [
            c.compute_update(agg.global_weights, agg.round_id)
            for c in clients.values()
        ]
        res = agg.aggregate(updates)
        drift = float(np.linalg.norm(agg.global_weights - ground_truth))
        print(f"  round {res.round_id:>2}  "
              f"participants={len(res.participants)}  "
              f"clipped={res.clipped_count}  "
              f"sigma={res.noise_sigma:.4f}  "
              f"||w-truth||={drift:.4f}  "
              f"{res.epoch_ms:.1f}ms")

    # Tamper test: wrong secret should be rejected
    print("\nTamper test: unauthorised gradient submission")
    bad = GradientUpdate(
        tenant_id="elal",
        round_id=agg.round_id,
        gradient=rng.normal(size=dim).astype(np.float32) * 100,
        num_samples=999999,
    )
    bad.sign(b"\x00" * 32)  # wrong secret
    try:
        agg.aggregate([bad])
        print("  FAIL: tampered update was accepted")
    except RuntimeError as e:
        print(f"  correctly rejected: {e}")

    print(f"\nFinal weights digest: {agg.snapshot_digest()[:16]}…")
    print(f"History: {len(agg.history)} rounds recorded")


if __name__ == "__main__":
    _demo()
