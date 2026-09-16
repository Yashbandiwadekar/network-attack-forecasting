"""F1 / precision / recall / false-positive-rate — the benchmark metrics the problem statement
asks the world model to beat the logistic-regression baseline on.
"""
from __future__ import annotations

import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_curve


def threshold_at_fpr(y_true: np.ndarray, y_prob: np.ndarray, target_fpr: float = 0.05) -> float:
    """The score threshold that achieves the highest recall without exceeding `target_fpr`, fit
    on whatever split is passed in — callers MUST fit this on val, never on test, or the reported
    test metrics are no longer honest. This is the "defender picks a fixed false-alarm budget"
    operating point, not the default-0.5 threshold `binary_metrics` uses on its own.
    """
    fpr, tpr, thresholds = roc_curve(y_true, y_prob)
    eligible = fpr <= target_fpr
    if not eligible.any():
        return 1.0  # no threshold meets the budget — predict nothing positive
    best_idx = np.where(eligible)[0][np.argmax(tpr[eligible])]
    return float(thresholds[best_idx])


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


def lead_time_metrics(
    infiltration_trajectory: np.ndarray,
    current_infiltration: np.ndarray,
    predicted_probs: np.ndarray,
    threshold: float,
    window_seconds: int,
) -> dict[str, float] | None:
    """How many seconds of advance warning does the K-step rollout actually buy a defender?

    This is the metric the problem statement's own framing ("forecast attacker progression
    *before* compromise completes") asks for directly, and which the existing F1/precision/recall
    suite doesn't measure at all — those score every window independently and are blind to *when*
    within the horizon a correct alarm fires relative to when the attack actually starts.

    Only defined over sequences that are BENIGN right now (`current_infiltration == 0`) and
    transition to an attack state at some point within the forecast horizon — a window that's
    already mid-attack has no "lead time" to measure, by definition.

    infiltration_trajectory : (N, K) ground-truth infiltration state at each future step.
    current_infiltration    : (N,) whether the window immediately before the forecast starts
                              (t=0, i.e. "right now") is itself already under attack.
    predicted_probs         : (N, K) model's predicted infiltration probability at each future
                              step (from a real K-step autoregressive rollout, not a single-step
                              prediction repeated K times).
    threshold               : alarm fires the first step the predicted probability crosses this
                              (use the same fixed-FPR operating threshold as the rest of the
                              benchmark, fit on val — never on test).
    window_seconds          : converts step counts into a human-meaningful lead time.

    Returns None if there are no eligible benign-to-attack transitions in this test set at all
    (e.g. an all-benign or already-all-attack sample) rather than a misleading zero.
    """
    eligible = current_infiltration == 0
    lead_steps: list[int] = []
    n_transitions = 0
    n_missed = 0
    n_detected_early = 0

    for i in np.where(eligible)[0]:
        attack_steps = np.where(infiltration_trajectory[i] == 1)[0]
        if len(attack_steps) == 0:
            continue  # never attacks within the horizon — not a transition case
        onset = int(attack_steps[0])
        n_transitions += 1

        alarm_steps = np.where(predicted_probs[i] >= threshold)[0]
        if len(alarm_steps) == 0:
            n_missed += 1
            continue

        steps_early = onset - int(alarm_steps[0])
        lead_steps.append(steps_early)
        if steps_early > 0:
            n_detected_early += 1

    if n_transitions == 0:
        return None

    return {
        "n_transitions": n_transitions,
        "n_missed": n_missed,
        "miss_rate": n_missed / n_transitions,
        "pct_detected_early": n_detected_early / n_transitions,
        "mean_lead_time_s": float(np.mean(lead_steps) * window_seconds) if lead_steps else None,
        "median_lead_time_s": float(np.median(lead_steps) * window_seconds) if lead_steps else None,
    }
