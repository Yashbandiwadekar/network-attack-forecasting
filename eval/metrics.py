"""F1 / precision / recall / false-positive-rate — the benchmark metrics the problem statement
asks the world model to beat the logistic-regression baseline on.
"""
from __future__ import annotations

import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score


def binary_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.5) -> dict[str, float]:
    y_pred = (y_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "false_positive_rate": fpr,
    }


def stage_metrics(y_true: np.ndarray, y_pred: np.ndarray, valid_mask: np.ndarray) -> dict[str, float]:
    """Macro-averaged over the classes actually present in y_true[valid_mask], excluding
    `impact`-mapped windows (valid_mask=False) which aren't part of the 5-stage classification task."""
    yt, yp = y_true[valid_mask], y_pred[valid_mask]
    return {
        "f1_macro": f1_score(yt, yp, average="macro", zero_division=0),
        "precision_macro": precision_score(yt, yp, average="macro", zero_division=0),
        "recall_macro": recall_score(yt, yp, average="macro", zero_division=0),
    }
