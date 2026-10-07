"""Markov-chain baseline: the simplest possible sequence model, and the third leg of the
Markov/LSTM/Transformer architecture comparison.

Unlike BaselineModel (models/baseline_lr.py), which still sees the full dense flow-feature
vector, this model only ever sees the discrete MITRE stage the current window is already
labeled with. It isolates a different question: is the *stage label sequence itself* markovian
enough that a simple transition table predicts the next stage and infiltration outcome as well
as a model with access to the full feature history? If the world model can't clear this bar
either, the dense features and self-attention aren't earning their keep over the label sequence
alone.
"""
from __future__ import annotations

import numpy as np

from models.dataset import SequenceDataset
from pipeline.mitre_mapping import STAGE_CLASSIFICATION_LABELS


class MarkovBaseline:
    """First-order Markov chain over the label the input sequence ends on (`current_stage`,
    `current_infiltration` — the same fields PersistenceBaseline uses) predicting the next-step
    target (`future_stages[:, 0]`, `infiltration[:, 0]`). Laplace-smoothed counts, no gradient
    training. `-1`-labeled (`impact`-mapped) windows are excluded from fitting the stage
    transition table, matching how BaselineModel/the world model itself mask this class out of
    the 5-way stage space (see pipeline/mitre_mapping.py).

    ORACLE, not deployable (audit E6): predict() reads ds.current_stage, the ground-truth label of
    the window the sequence ends on. A deployed system never has that label — only the raw
    features. See models.baseline_lr.PersistenceOnPredictedLabel for the fair, deployable
    comparison point.
    """

    def __init__(self, laplace_smoothing: float = 1.0):
        self.n_stage_classes = len(STAGE_CLASSIFICATION_LABELS)
        self.smoothing = laplace_smoothing
        self.stage_transition = np.full(
            (self.n_stage_classes, self.n_stage_classes), 1.0 / self.n_stage_classes,
        )
        self.infiltration_transition = np.full(self.n_stage_classes, 0.5)

    def fit(self, ds: SequenceDataset) -> "MarkovBaseline":
        current_stage = ds.current_stage.numpy()
        future_stage = ds.future_stages[:, 0].numpy()
        infiltration = ds.infiltration[:, 0].numpy()

        stage_counts = np.full((self.n_stage_classes, self.n_stage_classes), self.smoothing)
        infil_hits = np.full(self.n_stage_classes, self.smoothing)
        infil_totals = np.full(self.n_stage_classes, 2 * self.smoothing)

        valid = current_stage != -1
        for s in range(self.n_stage_classes):
            in_state = valid & (current_stage == s)
            infil_totals[s] += in_state.sum()
            infil_hits[s] += infiltration[in_state].sum()

            transitions_out = in_state & (future_stage != -1)
            for fs in future_stage[transitions_out]:
                stage_counts[s, fs] += 1

        self.stage_transition = stage_counts / stage_counts.sum(axis=1, keepdims=True)
        self.infiltration_transition = infil_hits / infil_totals
        return self

    def predict(self, ds: SequenceDataset) -> tuple[np.ndarray, np.ndarray]:
        """Same (infiltration_prob (N,), stage_probs (N, n_stage_classes)) interface as
        BaselineModel.predict / PersistenceBaseline.predict, so eval/benchmark.py can treat all
        four models identically."""
        current_stage = ds.current_stage.numpy()
        n = len(current_stage)
        stage_probs = np.full((n, self.n_stage_classes), 1.0 / self.n_stage_classes)
        infiltration_prob = np.full(n, 0.5)

        valid = current_stage != -1
        stage_probs[valid] = self.stage_transition[current_stage[valid]]
        infiltration_prob[valid] = self.infiltration_transition[current_stage[valid]]
        return infiltration_prob, stage_probs
