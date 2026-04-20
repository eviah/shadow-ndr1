"""
scripts/train_trajectory_lstm.py — LSTM autoencoder over synthetic ADS-B trajectories.

Input  : (batch, seq_len=20, features=5)  where features = [lat, lon, alt, speed, heading]
Output : reconstruction.  Anomaly score = per-sequence MSE.

Training data: synthetic straight-line / great-circle-ish trajectories
   with realistic kinematics (speed ~450 kts, alt ~35k ft, heading stable).
Test anomalies (held out, unseen during training):
   * altitude jumps > 5000 ft / s
   * teleport (lat/lon jumps > 0.5°/s)
   * heading flips > 170°/s
   * GPS spoof drift (slow random walk overlaid on straight line)

Produces models/trajectory_lstm_v1.pt  and  models/trajectory_lstm_v1_meta.json.
"""

from __future__ import annotations

import json
import math
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset


SEQ_LEN = 20
FEAT_DIM = 5
HIDDEN = 64
LATENT = 16
EPOCHS = 20
BATCH = 64
LR = 1e-3
SEED = 2026

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def set_seed(s: int) -> None:
    np.random.seed(s)
    torch.manual_seed(s)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(s)


# ---------------------------------------------------------------------------
# Synthetic data
# ---------------------------------------------------------------------------

def _normal_traj(rng: np.random.Generator, n: int) -> np.ndarray:
    """
    Generate n normal commercial-flight trajectories as POSITION-INVARIANT
    features: [d_lat_from_start, d_lon_from_start, alt, speed, heading].
    Making lat/lon relative to the first frame means the model generalises
    to any geographic region (not just the training lat/lon range).
    """
    trajs = np.zeros((n, SEQ_LEN, FEAT_DIM), dtype=np.float32)
    for i in range(n):
        alt0 = rng.uniform(30000, 40000)
        speed = rng.uniform(400, 500)
        heading = rng.uniform(0, 360)
        d_lat = math.cos(math.radians(heading)) * (speed / 3600.0) / 60.0  # deg/sec approx
        d_lon = math.sin(math.radians(heading)) * (speed / 3600.0) / 60.0
        for t in range(SEQ_LEN):
            trajs[i, t, 0] = d_lat * t + rng.normal(0, 0.0005)   # Δlat from frame 0
            trajs[i, t, 1] = d_lon * t + rng.normal(0, 0.0005)   # Δlon from frame 0
            trajs[i, t, 2] = alt0 + rng.normal(0, 30)
            trajs[i, t, 3] = speed + rng.normal(0, 3)
            trajs[i, t, 4] = heading + rng.normal(0, 0.5)
    return trajs


def _anomaly_traj(rng: np.random.Generator, n: int, kind: str) -> np.ndarray:
    base = _normal_traj(rng, n)
    if kind == "alt_jump":
        for i in range(n):
            t = rng.integers(5, SEQ_LEN - 2)
            base[i, t:, 2] += rng.uniform(5000, 15000)
    elif kind == "teleport":
        for i in range(n):
            t = rng.integers(5, SEQ_LEN - 2)
            base[i, t:, 0] += rng.choice([-1, 1]) * rng.uniform(0.5, 2.0)
            base[i, t:, 1] += rng.choice([-1, 1]) * rng.uniform(0.5, 2.0)
    elif kind == "heading_flip":
        for i in range(n):
            t = rng.integers(5, SEQ_LEN - 2)
            base[i, t:, 4] = (base[i, t:, 4] + 180.0) % 360.0
    elif kind == "gps_drift":
        for i in range(n):
            drift = np.cumsum(rng.normal(0, 0.1, SEQ_LEN)).astype(np.float32)
            base[i, :, 0] += drift
            base[i, :, 1] += drift[::-1]
    return base


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

class TrajectoryLSTMAutoencoder(nn.Module):
    def __init__(self, feat: int = FEAT_DIM, hidden: int = HIDDEN, latent: int = LATENT) -> None:
        super().__init__()
        self.encoder = nn.LSTM(feat, hidden, batch_first=True)
        self.latent = nn.Linear(hidden, latent)
        self.unlatent = nn.Linear(latent, hidden)
        self.decoder = nn.LSTM(hidden, hidden, batch_first=True)
        self.head = nn.Linear(hidden, feat)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        _, (h, _) = self.encoder(x)
        z = self.latent(h.squeeze(0))
        h2 = self.unlatent(z).unsqueeze(0)
        seq = torch.zeros(x.size(0), x.size(1), h2.size(-1), device=x.device)
        out, _ = self.decoder(seq, (h2, torch.zeros_like(h2)))
        return self.head(out)


# ---------------------------------------------------------------------------
# Train / eval
# ---------------------------------------------------------------------------

def standardize(X: np.ndarray, stats: dict | None = None) -> tuple[np.ndarray, dict]:
    flat = X.reshape(-1, X.shape[-1])
    if stats is None:
        mu = flat.mean(axis=0)
        sd = flat.std(axis=0) + 1e-6
        stats = {"mu": mu.tolist(), "sd": sd.tolist()}
    else:
        mu = np.asarray(stats["mu"], dtype=np.float32)
        sd = np.asarray(stats["sd"], dtype=np.float32)
    return ((flat - mu) / sd).reshape(X.shape).astype(np.float32), stats


def recon_err(model: nn.Module, x: torch.Tensor) -> torch.Tensor:
    with torch.no_grad():
        out = model(x)
    return ((out - x) ** 2).mean(dim=(1, 2))


def main() -> None:
    set_seed(SEED)
    rng = np.random.default_rng(SEED)

    print(f"[traj_lstm] device = {DEVICE}")
    print("[traj_lstm] generating 6000 normal trajectories...")
    X_train = _normal_traj(rng, 6000)
    X_val_normal = _normal_traj(rng, 600)

    print("[traj_lstm] generating anomaly test sets...")
    test = {
        "alt_jump": _anomaly_traj(rng, 300, "alt_jump"),
        "teleport": _anomaly_traj(rng, 300, "teleport"),
        "heading_flip": _anomaly_traj(rng, 300, "heading_flip"),
        "gps_drift": _anomaly_traj(rng, 300, "gps_drift"),
        "normal": _normal_traj(rng, 300),
    }

    X_train, stats = standardize(X_train)
    X_val_normal, _ = standardize(X_val_normal, stats)

    train_ds = TensorDataset(torch.from_numpy(X_train))
    train_dl = DataLoader(train_ds, batch_size=BATCH, shuffle=True, drop_last=True)

    model = TrajectoryLSTMAutoencoder().to(DEVICE)
    opt = torch.optim.Adam(model.parameters(), lr=LR)
    loss_fn = nn.MSELoss()

    t0 = time.time()
    for epoch in range(EPOCHS):
        model.train()
        total, nb = 0.0, 0
        for (xb,) in train_dl:
            xb = xb.to(DEVICE)
            out = model(xb)
            loss = loss_fn(out, xb)
            opt.zero_grad()
            loss.backward()
            opt.step()
            total += loss.item()
            nb += 1
        if (epoch + 1) % 2 == 0 or epoch == 0:
            model.eval()
            vn, _ = standardize(_normal_traj(rng, 200), stats)
            val_err = recon_err(model, torch.from_numpy(vn).to(DEVICE)).mean().item()
            print(f"[traj_lstm] epoch {epoch+1:2d}/{EPOCHS}  train_mse={total/nb:.4f}  val_mse={val_err:.4f}")

    elapsed = time.time() - t0
    print(f"[traj_lstm] training done in {elapsed:.1f}s")

    # ---- evaluate ----
    model.eval()
    threshold_pool, _ = standardize(_normal_traj(rng, 1000), stats)
    threshold_err = recon_err(model, torch.from_numpy(threshold_pool).to(DEVICE)).cpu().numpy()
    threshold = float(np.quantile(threshold_err, 0.99))
    print(f"[traj_lstm] 99th-percentile normal err = {threshold:.4f}")

    results = {}
    all_errs = []
    all_labels = []
    for kind, X in test.items():
        X_std, _ = standardize(X, stats)
        err = recon_err(model, torch.from_numpy(X_std).to(DEVICE)).cpu().numpy()
        tp = float((err > threshold).mean()) if kind != "normal" else None
        fp = float((err > threshold).mean()) if kind == "normal" else None
        results[kind] = {
            "mean_err": float(err.mean()),
            "p50_err": float(np.median(err)),
            "p95_err": float(np.quantile(err, 0.95)),
            "detection_rate": tp,
            "false_positive_rate": fp,
        }
        label = 0 if kind == "normal" else 1
        all_errs.extend(err.tolist())
        all_labels.extend([label] * len(err))

    # AUC
    from sklearn.metrics import roc_auc_score
    auc = float(roc_auc_score(all_labels, all_errs))
    print(f"[traj_lstm] overall anomaly AUC = {auc:.4f}")
    for k, v in results.items():
        print(f"  {k:14s}  mean_err={v['mean_err']:.4f}  p95={v['p95_err']:.4f}  "
              f"detection={v['detection_rate']}  fp={v['false_positive_rate']}")

    # Save
    models_dir = Path(__file__).resolve().parent.parent / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    pt = models_dir / "trajectory_lstm_v1.pt"
    meta = models_dir / "trajectory_lstm_v1_meta.json"

    torch.save({
        "model_state": model.state_dict(),
        "arch": {"feat": FEAT_DIM, "hidden": HIDDEN, "latent": LATENT, "seq_len": SEQ_LEN},
        "stats": stats,
        "threshold_99": threshold,
    }, pt)

    meta.write_text(json.dumps({
        "version": "trajectory_lstm_v1",
        "trained_at": time.time(),
        "device": str(DEVICE),
        "epochs": EPOCHS,
        "batch": BATCH,
        "train_samples": len(X_train),
        "val_samples": len(X_val_normal),
        "threshold_99": threshold,
        "auc_anomaly": auc,
        "per_attack": results,
        "train_time_sec": elapsed,
    }, indent=2))

    print(f"[traj_lstm] saved {pt}")
    print(f"[traj_lstm] saved {meta}")


if __name__ == "__main__":
    main()
