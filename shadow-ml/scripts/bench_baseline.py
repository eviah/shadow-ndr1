"""
scripts/bench_baseline.py — honest evaluation of the trained baseline.

Loads models/baseline_v1.pkl, regenerates the same synthetic dataset with
a different RNG seed, measures:
  - binary threat AUC (is-threat vs benign)
  - multiclass macro-F1
  - calibration (Brier score)
  - p50 / p95 inference latency

Prints a BENCHMARKS.md-ready block.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np
from sklearn.metrics import (
    brier_score_loss, f1_score, roc_auc_score, classification_report,
)

from train_baseline import PROTOTYPES, FEATURE_NAMES, NOISE, SAMPLES_PER_CLASS, _sample  # type: ignore


MODELS_DIR = Path(__file__).resolve().parent.parent / "models"


def main() -> None:
    import joblib

    pkl = MODELS_DIR / "baseline_v1.pkl"
    meta = MODELS_DIR / "baseline_v1_meta.json"
    if not pkl.exists():
        raise SystemExit(f"Model not found: {pkl}. Run scripts/train_baseline.py first.")

    bundle = joblib.load(pkl)
    pipe = bundle["pipeline"]
    classes = list(bundle["classes"])

    # Use a DIFFERENT seed than training so this is an honest holdout.
    rng = np.random.default_rng(2026)
    Xs, ys = [], []
    for idx, name in enumerate(classes):
        X = _sample(PROTOTYPES[name], SAMPLES_PER_CLASS, NOISE, rng)
        Xs.append(X)
        ys.append(np.full(SAMPLES_PER_CLASS, idx, dtype=np.int64))
    X = np.concatenate(Xs).astype(np.float32)
    y = np.concatenate(ys)

    # Warm up
    pipe.predict_proba(X[:1])

    # Latency: time single-sample inference
    latencies_ms = []
    for i in range(min(500, len(X))):
        t0 = time.perf_counter()
        pipe.predict_proba(X[i:i + 1])
        latencies_ms.append((time.perf_counter() - t0) * 1000)
    latencies_ms.sort()
    p50 = latencies_ms[len(latencies_ms) // 2]
    p95 = latencies_ms[int(len(latencies_ms) * 0.95)]

    # Batch inference for accuracy metrics
    t0 = time.perf_counter()
    proba = pipe.predict_proba(X)
    batch_ms = (time.perf_counter() - t0) * 1000
    throughput = len(X) / (batch_ms / 1000)

    preds = pipe.predict(X)
    y_bin = (y != 0).astype(int)
    p_threat = 1.0 - proba[:, 0]

    auc = roc_auc_score(y_bin, p_threat)
    brier = brier_score_loss(y_bin, p_threat)
    macro_f1 = f1_score(y, preds, average="macro", zero_division=0)
    acc = float((preds == y).mean())

    print("=" * 70)
    print(f"shadow-ml baseline_v1 benchmark (fresh holdout, seed=2026)")
    print("=" * 70)
    print(f"samples:            {len(X):,}")
    print(f"classes:            {len(classes)}")
    print(f"binary threat AUC:  {auc:.4f}")
    print(f"binary Brier score: {brier:.4f}  (lower = better)")
    print(f"multiclass acc:     {acc:.4f}")
    print(f"multiclass macro F1:{macro_f1:.4f}")
    print(f"p50 latency:        {p50:.3f} ms")
    print(f"p95 latency:        {p95:.3f} ms")
    print(f"batch throughput:   {throughput:,.0f} samples/s")
    print()
    print("per-class report:")
    print(classification_report(y, preds, target_names=classes, digits=3, zero_division=0))

    if meta.exists():
        m = json.loads(meta.read_text())
        print("training-set metrics (reference):")
        print(f"  AUC={m.get('auc_threat'):.4f}  "
              f"Brier={m.get('brier_threat'):.4f}  "
              f"acc={m.get('accuracy_multiclass'):.4f}")


if __name__ == "__main__":
    main()
