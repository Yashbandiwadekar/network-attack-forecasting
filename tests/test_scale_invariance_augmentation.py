"""Audit W11 part 3: scale-invariance augmentation."""
import numpy as np
import torch

from models.dataset import FeatureScaler, ScaleInvariantSequenceDataset, SequenceDataset

FEATURES = ["flow_count", "total_packets", "total_bytes", "syn_ratio"]


def _split(n=6, seq_len=4):
    rng = np.random.default_rng(0)
    X = rng.uniform(1, 100, size=(n, seq_len, len(FEATURES))).astype(np.float32)
    return {
        "X": X,
        "next_state": rng.uniform(1, 100, size=(n, len(FEATURES))).astype(np.float32),
        "future_stages": np.zeros((n, 2), dtype=np.int64),
        "infiltration": np.zeros((n, 2), dtype=np.float32),
        "current_stage": np.zeros(n, dtype=np.int64),
        "current_infiltration": np.zeros(n, dtype=np.float32),
    }


def test_standardized_shift_equals_raw_multiply_then_restandardize():
    split = _split()
    scaler = FeatureScaler().fit(split["X"])
    # scale_range (2.0, 2.0) -> deterministic k=2
    ds = ScaleInvariantSequenceDataset(split, scaler, FEATURES, scale_range=(2.0, 2.0))
    X_aug, ns_aug, _, _ = ds[0]

    raw = split["X"][0].copy()
    raw[:, :3] *= 2.0  # volume features only
    expected = np.clip(scaler.transform(raw), -scaler.clip_std, scaler.clip_std)
    # The augmentation works on already-clipped standardized values, so compare where no clipping
    # happened in either path.
    mask = np.abs(expected) < scaler.clip_std - 1e-3
    assert np.allclose(X_aug.numpy()[mask], expected[mask], atol=1e-4)


def test_ratio_features_are_untouched_and_val_dataset_is_not_augmented():
    split = _split()
    scaler = FeatureScaler().fit(split["X"])
    plain = SequenceDataset(split, scaler)
    aug = ScaleInvariantSequenceDataset(split, scaler, FEATURES, scale_range=(3.0, 3.0))
    X_aug, _, _, _ = aug[0]
    assert torch.equal(X_aug[:, 3], plain.X[0][:, 3])          # syn_ratio unchanged
    assert not torch.equal(X_aug[:, 0], plain.X[0][:, 0])       # flow_count changed
    assert torch.equal(plain[0][0], plain.X[0])                  # base dataset unaffected


def test_same_factor_applied_to_input_and_target():
    split = _split()
    scaler = FeatureScaler().fit(split["X"])
    ds = ScaleInvariantSequenceDataset(split, scaler, FEATURES, scale_range=(0.5, 0.5))
    X_aug, ns_aug, _, _ = ds[1]
    plain = SequenceDataset(split, scaler)
    k, m = 0.5, torch.tensor(scaler.mean / scaler.std, dtype=torch.float32)
    assert torch.allclose(ns_aug[0], k * plain.next_state[1][0] + (k - 1) * m[0], atol=1e-5)
    assert torch.allclose(X_aug[0, 0], k * plain.X[1][0, 0] + (k - 1) * m[0], atol=1e-5)
