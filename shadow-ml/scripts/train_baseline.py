"""
scripts/train_baseline.py — trains a gradient-boosted baseline threat classifier.

Produces:
  models/baseline_v1.pkl        — sklearn Pipeline (scaler + GBDT)
  models/baseline_v1_meta.json  — metadata: feature names, classes, metrics

Features (8-dim, matches ThreatVector.modality_scores shape):
  0 volumetric, 1 lateral_movement, 2 exfiltration, 3 c2_beacon,
  4 credential_attack, 5 insider, 6 supply_chain, 7 aviation_anomaly

Synthetic dataset: 23 attack-class prototypes + benign class, with
structured noise so a tree ensemble can actually learn them (unlike
the hardcoded prototype cosine-distance in core/neural_engine.py).
"""

from __future__ import annotations

import json
import os
import random
import time
from pathlib import Path

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import (
    brier_score_loss, classification_report, roc_auc_score, precision_recall_fscore_support,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

try:
    import joblib
except ImportError:  # sklearn bundles joblib
    from sklearn.externals import joblib  # type: ignore


FEATURE_NAMES = [
    "volumetric", "lateral_movement", "exfiltration", "c2_beacon",
    "credential_attack", "insider", "supply_chain", "aviation_anomaly",
]

# Rough prototypes per attack family. Values on [0, 1].
PROTOTYPES: dict[str, list[float]] = {
    "benign":              [0.05, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05],
    "ddos":                [0.95, 0.10, 0.05, 0.05, 0.05, 0.05, 0.05, 0.10],
    "lateral_movement":    [0.20, 0.92, 0.15, 0.20, 0.60, 0.10, 0.05, 0.05],
    "exfiltration":        [0.30, 0.40, 0.93, 0.25, 0.15, 0.10, 0.05, 0.05],
    "c2_beacon":           [0.10, 0.25, 0.20, 0.92, 0.10, 0.05, 0.10, 0.05],
    "credential_stuffing": [0.40, 0.10, 0.10, 0.05, 0.95, 0.05, 0.05, 0.05],
    "insider_exfil":       [0.15, 0.40, 0.70, 0.10, 0.20, 0.88, 0.05, 0.05],
    "supply_chain":        [0.10, 0.25, 0.30, 0.20, 0.20, 0.10, 0.92, 0.10],
    "adsb_spoof":          [0.05, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05, 0.92],
    "gps_jamming":         [0.05, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05, 0.88],
    "mode_s_hijack":       [0.10, 0.15, 0.05, 0.10, 0.20, 0.05, 0.05, 0.90],
    "acars_fuzz":          [0.15, 0.10, 0.10, 0.25, 0.10, 0.05, 0.10, 0.85],
    "modbus_attack":       [0.20, 0.35, 0.15, 0.30, 0.10, 0.10, 0.10, 0.70],
    "ils_tamper":          [0.05, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05, 0.93],
}

SAMPLES_PER_CLASS = 600
NOISE = 0.10
SEED = 42


def _sample(proto: list[float], n: int, noise: float, rng: np.random.Generator) -> np.ndarray:
    proto = np.asarray(proto, dtype=np.float32)
    X = np.tile(proto, (n, 1)) + rng.normal(0, noise, (n, len(proto))).astype(np.float32)
    return np.clip(X, 0.0, 1.0)


def build_dataset(rng: np.random.Generator) -> tuple[np.ndarray, np.ndarray, list[str]]:
    classes = list(PROTOTYPES.keys())
    Xs, ys = [], []
    for idx, name in enumerate(classes):
        X = _sample(PROTOTYPES[name], SAMPLES_PER_CLASS, NOISE, rng)
        Xs.append(X)
        ys.append(np.full(SAMPLES_PER_CLASS, idx, dtype=np.int64))
    return np.concatenate(Xs), np.concatenate(ys), classes


def main() -> None:
    random.seed(SEED)
    np.random.seed(SEED)
    rng = np.random.default_rng(SEED)

    print("[train_baseline] generating synthetic dataset...")
    X, y, classes = build_dataset(rng)
    print(f"[train_baseline] dataset: X={X.shape}  y={y.shape}  classes={len(classes)}")

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=SEED, stratify=y
    )

    pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", GradientBoostingClassifier(
            n_estimators=200, max_depth=3, learning_rate=0.1, random_state=SEED,
        )),
    ])

    t0 = time.time()
    print("[train_baseline] fitting GradientBoosting (200 trees)...")
    pipe.fit(X_tr, y_tr)
    elapsed = time.time() - t0
    print(f"[train_baseline] fit in {elapsed:.1f}s")

    proba = pipe.predict_proba(X_te)
    preds = pipe.predict(X_te)

    # Binary "is threat" (everything except benign=0)
    y_bin = (y_te != 0).astype(int)
    p_threat = 1.0 - proba[:, 0]
    auc = roc_auc_score(y_bin, p_threat)
    brier = brier_score_loss(y_bin, p_threat)

    acc = float((preds == y_te).mean())
    prec, rec, f1, _ = precision_recall_fscore_support(
        y_bin, (preds != 0).astype(int), average="binary", zero_division=0
    )

    print("\n[train_baseline] per-class report (held-out 20%):")
    print(classification_report(y_te, preds, target_names=classes, digits=3, zero_division=0))
    print(f"[train_baseline] binary threat AUC = {auc:.4f}")
    print(f"[train_baseline] binary threat Brier = {brier:.4f}")
    print(f"[train_baseline] multiclass accuracy = {acc:.4f}")
    print(f"[train_baseline] binary precision={prec:.3f} recall={rec:.3f} f1={f1:.3f}")

    models_dir = Path(__file__).resolve().parent.parent / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    pkl = models_dir / "baseline_v1.pkl"
    meta = models_dir / "baseline_v1_meta.json"

    joblib.dump({"pipeline": pipe, "feature_names": FEATURE_NAMES, "classes": classes}, pkl)
    meta.write_text(json.dumps({
        "version": "baseline_v1",
        "trained_at": time.time(),
        "classes": classes,
        "feature_names": FEATURE_NAMES,
        "auc_threat": auc,
        "brier_threat": brier,
        "accuracy_multiclass": acc,
        "precision_binary": prec,
        "recall_binary": rec,
        "f1_binary": f1,
        "samples_per_class": SAMPLES_PER_CLASS,
        "noise_std": NOISE,
        "train_time_sec": elapsed,
    }, indent=2))

    print(f"\n[train_baseline] saved {pkl}")
    print(f"[train_baseline] saved {meta}")


if __name__ == "__main__":
    main()
