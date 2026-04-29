"""Tests for the neural immune system."""

import numpy as np
import pytest

torch = pytest.importorskip("torch")

from ml.neural_immune import (
    NeuralImmuneSystem,
    synthetic_anomalous_batch,
    synthetic_benign_batch,
)


def test_train_lowers_loss_on_benign_data():
    nis = NeuralImmuneSystem()
    benign = synthetic_benign_batch(512, seed=0)
    nis.admit(benign)
    metrics_first = nis.train(epochs=1)
    metrics_last = nis.train(epochs=4)
    assert metrics_last["mean_loss"] <= metrics_first["mean_loss"] * 1.1, (
        "training should not regress mean reconstruction loss"
    )


def test_anomalies_score_higher_than_benign():
    nis = NeuralImmuneSystem()
    benign = synthetic_benign_batch(1024, seed=1)
    nis.admit(benign)
    nis.train(epochs=10, batch_size=64)

    benign_test = synthetic_benign_batch(64, seed=42)
    anom_test = synthetic_anomalous_batch(64, seed=43)

    b_mean = float(np.mean([nis.score(s).score for s in benign_test]))
    a_mean = float(np.mean([nis.score(s).score for s in anom_test]))
    assert a_mean > b_mean * 2.0, (
        f"anomalous loss ({a_mean:.4f}) should be >2x benign ({b_mean:.4f})"
    )


def test_threshold_self_calibrates():
    nis = NeuralImmuneSystem(threshold_window=64, threshold_k=3.0)
    benign = synthetic_benign_batch(256, seed=2)
    nis.admit(benign)
    nis.train(epochs=8)

    # Score 64 benign samples — threshold should converge to a finite value.
    for s in synthetic_benign_batch(64, seed=99):
        nis.score(s)
    assert nis.threshold > 0.0
    assert np.isfinite(nis.threshold)


def test_self_heal_admits_and_trains():
    nis = NeuralImmuneSystem()
    nis.admit(synthetic_benign_batch(128, seed=3))
    nis.train(epochs=2)

    before = nis.replay_size
    fresh = synthetic_benign_batch(64, seed=44)
    out = nis.self_heal(fresh)
    assert out["trained"] is True
    assert nis.replay_size == before + 64


def test_score_returns_verdict_label_for_clear_anomaly():
    nis = NeuralImmuneSystem()
    nis.admit(synthetic_benign_batch(512, seed=4))
    nis.train(epochs=12)

    # warm threshold with benign samples first
    for s in synthetic_benign_batch(64, seed=100):
        nis.score(s)

    anomaly = synthetic_anomalous_batch(1, seed=200)[0]
    v = nis.score(anomaly)
    assert v.label in ("suspicious", "foreign")


def test_invalid_feature_dim_raises():
    nis = NeuralImmuneSystem()
    with pytest.raises(ValueError):
        nis.score(np.zeros(32, dtype=np.float32))
