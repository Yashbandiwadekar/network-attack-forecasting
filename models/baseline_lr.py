"""Three baselines the world model is benchmarked against (eval/benchmark.py), each isolating a
different question about whether the world model's temporal modeling is actually earning its keep:

  - BaselineModel(mode="last"): logistic regression on ONLY the current window's feature vector —
    no temporal context at all. The "traditional ML classifier treats each flow in isolation"
    approach the problem statement contrasts world models against.
  - BaselineModel(mode="stacked"): logistic regression on the FULL L-window history, flattened into
    one feature vector. Same raw information as the world model gets, but no sequential/recurrent
    structure — this is the control that isolates "does having more columns explain the gap, or
    does the world model's temporal modeling itself matter."
  - PersistenceBaseline: no learning at all — predicts that whatever is true of the current window
    stays true next step. If the world model can't beat this, it isn't learning real dynamics.

    **Label-persistence ORACLE, not a deployable baseline (audit E6).** It reads
    ds.current_stage / ds.current_infiltration, which are the *ground-truth* labels of the
    window the input sequence ends on. A real deployed system never has the ground-truth label
    of "right now" — producing that label correctly is the classification problem itself. This
    is an upper-reference point ("if you could see the current label perfectly, THIS is what
    assuming no change gets you"), not a baseline a defender could run. See
    PersistenceOnPredictedLabel below for the deployable version that a defender could actually
    run: it predicts the current label from features first, and only then persists that
    prediction forward.
  - PersistenceOnPredictedLabel: the deployable counterpart to PersistenceBaseline (E6). Fits its
    own last-window classifier to *predict* the current window's stage/infiltration state from
    features (the same features a defender actually has), then persists that prediction forward
    as the next-step forecast — the same "assume no change" logic, minus the oracle input.
"""
from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any, Literal

import numpy as np
from sklearn.linear_model import LogisticRegression

from models.dataset import SequenceDataset
from pipeline.mitre_mapping import STAGE_CLASSIFICATION_LABELS


class BaselineModel:
    def __init__(self, config: dict[str, Any], mode: Literal["last", "stacked"] = "last"):
        max_iter = config["baseline"]["max_iter"]
        self.mode = mode
        self.infiltration_clf = LogisticRegression(max_iter=max_iter)
        self.stage_clf = LogisticRegression(max_iter=max_iter)

    def _extract(self, X: np.ndarray) -> np.ndarray:
        """X: (N, L, F). "last" keeps only the current window (N, F); "stacked" flattens the
        whole L-window history into one vector (N, L*F) — same information the world model sees,
        just handed to a non-sequential classifier."""
        if self.mode == "last":
            return X[:, -1, :]
        return X.reshape(X.shape[0], -1)

    def fit(self, ds: SequenceDataset) -> "BaselineModel":
        features = self._extract(ds.X.numpy())
        infiltration_target = ds.infiltration[:, 0].numpy()
        stage_target = ds.future_stages[:, 0].numpy()

        self.infiltration_clf.fit(features, infiltration_target)

        mask = stage_target != -1  # exclude `impact` windows, see pipeline/mitre_mapping.py
        self.stage_clf.fit(features[mask], stage_target[mask])
        self._stage_classes_seen = sorted(np.unique(stage_target[mask]).tolist())
        return self

    def predict(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """X: (N, L, F) — same shape as ds.X, regardless of mode; _extract does the reduction.
        Returns (infiltration_prob (N,), stage_probs (N, n_stage_classes))."""
        features = self._extract(X)
        infiltration_prob = self.infiltration_clf.predict_proba(features)[:, 1]

        n_stage_classes = len(STAGE_CLASSIFICATION_LABELS)
        raw_probs = self.stage_clf.predict_proba(features)
        stage_probs = np.zeros((len(features), n_stage_classes))
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


class PersistenceBaseline:
    """No learning: predicts the last INPUT window's own state persists into the next step.
    Needs ds.current_stage / ds.current_infiltration (see pipeline/windowing.py::build_sequences)
    — the true label of the window the sequence ends on, not a future target.

    ORACLE, not deployable (audit E6) — see module docstring above.
    """

    def predict(self, ds: SequenceDataset) -> tuple[np.ndarray, np.ndarray]:
        """Returns (infiltration_prob (N,), stage_probs (N, n_stage_classes)) — "probabilities"
        are degenerate (0.0/1.0 and one-hot) since this model doesn't learn anything."""
        infiltration_prob = ds.current_infiltration.numpy()

        n_stage_classes = len(STAGE_CLASSIFICATION_LABELS)
        current_stage = ds.current_stage.numpy()
        stage_probs = np.zeros((len(current_stage), n_stage_classes))
        valid = current_stage != -1
        stage_probs[valid, current_stage[valid]] = 1.0
        # `impact`-mapped current windows (excluded from the 5-way space) default to a uniform
        # guess rather than an arbitrary class, since persistence has no real answer for them
        stage_probs[~valid, :] = 1.0 / n_stage_classes
        return infiltration_prob, stage_probs


class PersistenceOnPredictedLabel:
    """Deployable version of PersistenceBaseline (audit E6): a defender never has the
    ground-truth label of "right now" (ds.current_stage / ds.current_infiltration) at inference
    time — only the raw feature window. This fits its own small last-window logistic-regression
    classifier to *predict* the current window's own state from features (the current-window
    equivalent of BaselineModel(mode="last"), just predicting the CURRENT label instead of the
    NEXT one), then persists that prediction forward as the next-step forecast. Same "assume no
    change" logic as PersistenceBaseline, minus the oracle input — this is the fair comparison
    point the audit asks for.
    """

    def __init__(self, config: dict[str, Any]):
        max_iter = config["baseline"]["max_iter"]
        self.infiltration_clf = LogisticRegression(max_iter=max_iter)
        self.stage_clf = LogisticRegression(max_iter=max_iter)

    def fit(self, ds: SequenceDataset) -> "PersistenceOnPredictedLabel":
        features = ds.X[:, -1, :].numpy()
        self.infiltration_clf.fit(features, ds.current_infiltration.numpy())

        current_stage = ds.current_stage.numpy()
        mask = current_stage != -1  # exclude `impact` windows, see pipeline/mitre_mapping.py
        self.stage_clf.fit(features[mask], current_stage[mask])
        return self

    def predict(self, ds: SequenceDataset) -> tuple[np.ndarray, np.ndarray]:
        """Same (infiltration_prob (N,), stage_probs (N, n_stage_classes)) interface as
        PersistenceBaseline.predict / MarkovBaseline.predict."""
        features = ds.X[:, -1, :].numpy()
        infiltration_prob = self.infiltration_clf.predict_proba(features)[:, 1]

        n_stage_classes = len(STAGE_CLASSIFICATION_LABELS)
        raw_probs = self.stage_clf.predict_proba(features)
        stage_probs = np.zeros((len(features), n_stage_classes))
        for col, cls in enumerate(self.stage_clf.classes_):
            stage_probs[:, cls] = raw_probs[:, col]
        return infiltration_prob, stage_probs
