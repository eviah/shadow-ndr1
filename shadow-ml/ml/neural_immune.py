"""Neural Immune System — PyTorch autoencoder anomaly detector.

Behaves like an immune system:

    * The autoencoder is the *self-recognition* organ: it learns the manifold
      of "normal" traffic embeddings. Anything it can't reconstruct cheaply
      is presumed foreign.
    * The reconstruction error threshold is the *T-cell selection threshold*:
      it self-calibrates from a sliding window of recent reconstruction
      losses (mean + k·std), so it tolerates gradual drift but rejects
      sudden divergence.
    * `self_heal()` is the *clonal-expansion* step: once we accept a sample
      as benign (i.e., low reconstruction loss), we incorporate it into a
      replay buffer that the next training pass uses, so the immune memory
      stays current.

The model is intentionally small (64 → 32 → 16 → 32 → 64) so it runs on the
sensor's CPU without needing a GPU. The interface is what the rest of the
ML stack calls into: `score(features)` returns an anomaly score in [0, ∞)
and a verdict in {benign, suspicious, foreign}; `train(samples)` runs a
full epoch over the replay buffer.
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass
from typing import Deque, Iterable, List, Tuple

import numpy as np

try:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset
    _TORCH_OK = True
except ImportError:  # pragma: no cover
    torch = None  # type: ignore[assignment]
    nn = None  # type: ignore[assignment]
    _TORCH_OK = False


FEATURE_DIM = 64
LATENT_DIM = 16


def _require_torch() -> None:
    if not _TORCH_OK:
        raise RuntimeError(
            "neural_immune requires PyTorch — install with `pip install torch`"
        )


@dataclass
class Verdict:
    score: float
    label: str  # 'benign' | 'suspicious' | 'foreign'
    threshold: float


class _Autoencoder(nn.Module if _TORCH_OK else object):  # type: ignore[misc]
    """Compact tied-weight-style autoencoder."""

    def __init__(self, in_dim: int = FEATURE_DIM, latent_dim: int = LATENT_DIM):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(in_dim, 32),
            nn.ReLU(inplace=True),
            nn.Linear(32, latent_dim),
            nn.ReLU(inplace=True),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 32),
            nn.ReLU(inplace=True),
            nn.Linear(32, in_dim),
        )

    def forward(self, x):  # type: ignore[override]
        z = self.encoder(x)
        return self.decoder(z)


class NeuralImmuneSystem:
    """Online autoencoder anomaly detector with replay-driven self-healing."""

    def __init__(
        self,
        feature_dim: int = FEATURE_DIM,
        latent_dim: int = LATENT_DIM,
        replay_capacity: int = 4096,
        threshold_window: int = 512,
        threshold_k: float = 4.0,
    ):
        _require_torch()
        self._lock = threading.Lock()
        self._device = torch.device("cpu")
        self._model = _Autoencoder(feature_dim, latent_dim).to(self._device)
        self._optim = torch.optim.Adam(self._model.parameters(), lr=1e-3)
        self._loss_fn = nn.MSELoss(reduction="mean")
        self._loss_per_sample = nn.MSELoss(reduction="none")
        self._feature_dim = feature_dim

        self._replay: Deque[np.ndarray] = deque(maxlen=replay_capacity)
        self._recent_losses: Deque[float] = deque(maxlen=threshold_window)
        self._threshold_k = threshold_k
        self._cached_threshold: float = 0.5  # defaults until we've seen samples

    # ------------------------------------------------------------------ helpers

    def _to_tensor(self, x: Iterable[float] | np.ndarray) -> "torch.Tensor":
        arr = np.asarray(list(x) if not isinstance(x, np.ndarray) else x, dtype=np.float32)
        if arr.ndim == 1:
            if arr.shape[0] != self._feature_dim:
                raise ValueError(
                    f"expected {self._feature_dim} features, got {arr.shape[0]}"
                )
            arr = arr[None, :]
        elif arr.ndim != 2 or arr.shape[1] != self._feature_dim:
            raise ValueError(
                f"expected shape (N, {self._feature_dim}), got {arr.shape}"
            )
        return torch.from_numpy(arr).to(self._device)

    def _per_sample_loss(self, x: "torch.Tensor") -> "torch.Tensor":
        recon = self._model(x)
        # reduction='none' → per-element; mean over feature axis = per-sample MSE.
        return self._loss_per_sample(recon, x).mean(dim=1)

    def _refresh_threshold(self) -> None:
        if len(self._recent_losses) < 16:
            return
        losses = np.fromiter(self._recent_losses, dtype=np.float64)
        mu = float(np.mean(losses))
        sd = float(np.std(losses))
        self._cached_threshold = mu + self._threshold_k * max(sd, 1e-4)

    # -------------------------------------------------------------- public API

    @property
    def threshold(self) -> float:
        return self._cached_threshold

    @property
    def replay_size(self) -> int:
        return len(self._replay)

    def score(self, features: Iterable[float] | np.ndarray) -> Verdict:
        """Score one sample. Updates the recent-loss window for self-calibration."""
        with self._lock:
            x = self._to_tensor(features)
            self._model.eval()
            with torch.no_grad():
                loss = float(self._per_sample_loss(x).item())
            self._recent_losses.append(loss)
            self._refresh_threshold()
            label = self._classify(loss)
            return Verdict(score=loss, label=label, threshold=self._cached_threshold)

    def _classify(self, loss: float) -> str:
        if loss <= self._cached_threshold:
            return "benign"
        if loss <= self._cached_threshold * 2.0:
            return "suspicious"
        return "foreign"

    def admit(self, features: Iterable[float] | np.ndarray) -> None:
        """Accept a sample as benign — append to replay buffer for next train().

        This is the "clonal-expansion" channel: callers should only admit
        samples that downstream verification (audit log, human review) has
        confirmed as legitimate.
        """
        arr = np.asarray(list(features) if not isinstance(features, np.ndarray) else features, dtype=np.float32)
        if arr.ndim == 1:
            if arr.shape[0] != self._feature_dim:
                raise ValueError(f"expected {self._feature_dim} features")
            with self._lock:
                self._replay.append(arr)
        elif arr.ndim == 2:
            if arr.shape[1] != self._feature_dim:
                raise ValueError(f"expected (_, {self._feature_dim}) features")
            with self._lock:
                for row in arr:
                    self._replay.append(row.copy())

    def train(self, epochs: int = 1, batch_size: int = 64) -> dict:
        """Train one or more epochs over the replay buffer. Returns metrics."""
        with self._lock:
            if len(self._replay) < batch_size:
                return {"trained": False, "reason": "insufficient replay", "n": len(self._replay)}
            data = np.stack(list(self._replay), axis=0)
            tensor = torch.from_numpy(data)
            ds = TensorDataset(tensor)
            loader = DataLoader(ds, batch_size=batch_size, shuffle=True)

            self._model.train()
            losses: List[float] = []
            for _ in range(epochs):
                for (batch,) in loader:
                    batch = batch.to(self._device)
                    self._optim.zero_grad()
                    recon = self._model(batch)
                    loss = self._loss_fn(recon, batch)
                    loss.backward()
                    self._optim.step()
                    losses.append(float(loss.item()))
            mean = float(np.mean(losses)) if losses else 0.0
            return {
                "trained": True,
                "epochs": epochs,
                "samples": len(self._replay),
                "mean_loss": mean,
                "final_loss": float(losses[-1]) if losses else 0.0,
            }

    def self_heal(self, fresh_samples: Iterable[Iterable[float]] | np.ndarray) -> dict:
        """Admit fresh benign samples, then run a single training epoch.

        This is the once-per-window "T-cell maturation" cycle that should
        drive the model toward the most recent normal-traffic distribution.
        """
        self.admit(fresh_samples if isinstance(fresh_samples, np.ndarray) else list(fresh_samples))
        return self.train(epochs=1)

    def state_dict(self) -> dict:
        with self._lock:
            return {
                "model": {k: v.detach().cpu().clone() for k, v in self._model.state_dict().items()},
                "threshold": self._cached_threshold,
                "replay_size": len(self._replay),
            }


def synthetic_benign_batch(n: int, dim: int = FEATURE_DIM, seed: int = 0) -> np.ndarray:
    """Generate `n` synthetic benign samples — multivariate Gaussian on a
    low-rank manifold so the autoencoder has structure to learn."""
    rng = np.random.default_rng(seed)
    base = rng.normal(0.0, 1.0, size=(n, 4)).astype(np.float32)  # 4-d latent
    proj = rng.normal(0.0, 0.5, size=(4, dim)).astype(np.float32)
    noise = rng.normal(0.0, 0.05, size=(n, dim)).astype(np.float32)
    return base @ proj + noise


def synthetic_anomalous_batch(n: int, dim: int = FEATURE_DIM, seed: int = 1) -> np.ndarray:
    """Generate samples drawn from a totally different distribution."""
    rng = np.random.default_rng(seed)
    return rng.uniform(-3.0, 3.0, size=(n, dim)).astype(np.float32) + 5.0


def smoke_test() -> Tuple[float, float]:
    """Train on benign data and verify anomalies score higher.

    Returns (benign_mean_loss, anomalous_mean_loss).
    """
    nis = NeuralImmuneSystem()
    benign = synthetic_benign_batch(1024)
    nis.admit(benign)
    nis.train(epochs=8, batch_size=64)

    benign_test = synthetic_benign_batch(64, seed=42)
    anom_test = synthetic_anomalous_batch(64, seed=43)

    b_losses = [nis.score(s).score for s in benign_test]
    a_losses = [nis.score(s).score for s in anom_test]
    return float(np.mean(b_losses)), float(np.mean(a_losses))


if __name__ == "__main__":
    b, a = smoke_test()
    print(f"benign_mean={b:.4f} anomalous_mean={a:.4f} ratio={a/max(b,1e-6):.2f}x")
