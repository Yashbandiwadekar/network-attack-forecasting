"""Logistic regression baseline: predicts the immediate next step's infiltration probability and
MITRE stage from ONLY the current (last) window's feature vector — no temporal context, no
sequence. This is deliberately the "traditional ML classifier treats each flow in isolation"
approach the problem statement asks the world model to be benchmarked against.
"""
from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.linear_model import LogisticRegression

from models.dataset import SequenceDataset
from pipeline.mitre_mapping import STAGE_CLASSIFICATION_LABELS


class BaselineModel:
    def __init__(self, config: dict[str, Any]):
        max_iter = config["baseline"]["max_iter"]
        self.infiltration_clf = LogisticRegression(max_iter=max_iter)
        self.stage_clf = LogisticRegression(max_iter=max_iter)

    def fit(self, ds: SequenceDataset) -> "BaselineModel":
        last_window = ds.X[:, -1, :].numpy()
        infiltration_target = ds.infiltration[:, 0].numpy()
        stage_target = ds.future_stages[:, 0].numpy()

        self.infiltration_clf.fit(last_window, infiltration_target)

        mask = stage_target != -1  # exclude `impact` windows, see pipeline/mitre_mapping.py
        self.stage_clf.fit(last_window[mask], stage_target[mask])
        self._stage_classes_seen = sorted(np.unique(stage_target[mask]).tolist())
        return self

    def predict(self, last_window: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """last_window: (N, n_features). Returns (infiltration_prob (N,), stage_probs (N, n_stage_classes))."""
        infiltration_prob = self.infiltration_clf.predict_proba(last_window)[:, 1]

        n_stage_classes = len(STAGE_CLASSIFICATION_LABELS)
        raw_probs = self.stage_clf.predict_proba(last_window)
        stage_probs = np.zeros((len(last_window), n_stage_classes))
        for col, cls in enumerate(self.stage_clf.classes_):
            stage_probs[:, cls] = raw_probs[:, col]
        return infiltration_prob, stage_probs

    def save(self, path: str | Path) -> None:
        with open(path, "wb") as f:
            pickle.dump(self, f)

    @classmethod
    def load(cls, path: str | Path) -> "BaselineModel":
        with open(path, "rb") as f:
            return pickle.load(f)
