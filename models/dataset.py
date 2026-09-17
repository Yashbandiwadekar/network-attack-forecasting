"""PyTorch Dataset over the windowed sequence tensors produced by pipeline/build_dataset.py,
plus the feature scaler shared between training and inference (forecast.py, the Streamlit demo).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import torch
from torch.utils.data import Dataset

from common.config import resolve_path


class FeatureScaler:
    """Per-feature standardization, fit once on the train split and reused everywhere else so
    train/val/test/inference all see features on the same scale.

    Standardized output is clipped to +/- clip_std. Without this, a feature that's nearly
    constant in training (std floored to 1.0 above) turns an ordinary out-of-distribution value
    into an extreme standardized input the model was never trained to handle, and unusual-but-
    legitimate benign traffic can swing predictions arbitrarily. See scripts/check_robustness.py
    for a runnable check of this exact failure mode against a trained checkpoint.
    """

    def __init__(self, mean: np.ndarray | None = None, std: np.ndarray | None = None, clip_std: float = 6.0):
        self.mean = mean
        self.std = std
        self.clip_std = clip_std

    def fit(self, X: np.ndarray) -> "FeatureScaler":
        flat = X.reshape(-1, X.shape[-1])
        self.mean = flat.mean(axis=0)
        self.std = flat.std(axis=0)
        self.std[self.std < 1e-6] = 1.0
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        return np.clip((X - self.mean) / self.std, -self.clip_std, self.clip_std)

    def inverse_transform(self, X: np.ndarray) -> np.ndarray:
        return X * self.std + self.mean

    def save(self, path: str | Path) -> None:
        np.savez(path, mean=self.mean, std=self.std, clip_std=self.clip_std)

    @classmethod
    def load(cls, path: str | Path) -> "FeatureScaler":
        d = np.load(path)
        clip_std = float(d["clip_std"]) if "clip_std" in d.files else 6.0
        return cls(mean=d["mean"], std=d["std"], clip_std=clip_std)


def load_split(processed_dir: Path, split: str) -> dict[str, np.ndarray]:
    d = np.load(processed_dir / f"{split}.npz", allow_pickle=True)
    return {k: d[k] for k in d.files}


def load_metadata(processed_dir: Path) -> dict[str, Any]:
    with open(processed_dir / "metadata.json", "r", encoding="utf-8") as f:
        return json.load(f)


class SequenceDataset(Dataset):
    """DataLoader-batched fields are (X, next_state, future_stages, infiltration) — see
    __getitem__. current_stage/current_infiltration (the last INPUT window's own label, used by
    models/baseline_lr.py::PersistenceBaseline) are accessed as whole-dataset tensors directly
    (`ds.current_stage`), the same way models/baseline_lr.py already reads `ds.X`/`ds.infiltration`
    outside the DataLoader — kept out of __getitem__'s tuple so DataLoader batching/training.py
    stay unchanged.
    """

    def __init__(self, split: dict[str, np.ndarray], scaler: FeatureScaler):
        self.X = torch.tensor(scaler.transform(split["X"]), dtype=torch.float32)
        self.next_state = torch.tensor(scaler.transform(split["next_state"]), dtype=torch.float32)
        self.future_stages = torch.tensor(split["future_stages"], dtype=torch.long)
        self.infiltration = torch.tensor(split["infiltration"], dtype=torch.float32)
        self.current_stage = torch.tensor(split["current_stage"], dtype=torch.long)
        self.current_infiltration = torch.tensor(split["current_infiltration"], dtype=torch.float32)
        # (N, L) window_start timestamp of every input step -- absent from datasets built before
        # the joint-GNN-training schema change; kept optional so older processed_dir/*.npz still
        # load. Only models/world_model_joint.py's training loop reads this (to look up each
        # step's WindowGraph); every other consumer of SequenceDataset is unaffected.
        self.window_times = split.get("window_times")
        self.src_ip = split.get("src_ip")
        self.scenario_id = split.get("scenario_id")

    def __len__(self) -> int:
        return len(self.X)

    def __getitem__(self, idx: int):
        return self.X[idx], self.next_state[idx], self.future_stages[idx], self.infiltration[idx]


def build_datasets(config: dict[str, Any]) -> tuple[SequenceDataset, SequenceDataset, SequenceDataset, FeatureScaler]:
    processed_dir = resolve_path(config, "processed_dir")
    train_split = load_split(processed_dir, "train")
    val_split = load_split(processed_dir, "val")
    test_split = load_split(processed_dir, "test")

    scaler = FeatureScaler().fit(train_split["X"])
    scaler.save(processed_dir / "scaler.npz")

    return (
        SequenceDataset(train_split, scaler),
        SequenceDataset(val_split, scaler),
        SequenceDataset(test_split, scaler),
        scaler,
    )
