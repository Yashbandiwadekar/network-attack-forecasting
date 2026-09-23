"""F1 / precision / recall / false-positive-rate — the benchmark metrics the problem statement
asks the world model to beat the logistic-regression baseline on.
"""
from __future__ import annotations

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)


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


def threshold_free_metrics(y_true: np.ndarray, y_prob: np.ndarray) -> dict[str, float | None]:
    """AUROC/AUPRC (audit E5) — summarize ranking quality across every possible threshold, so a
    single degenerate operating point (e.g. a 5% FPR budget that's unreachable at low prevalence)
    can't make a genuinely strong model look weak. Returns None for either metric if y_true has
    only one class present (undefined, not zero — sklearn raises rather than silently returning
    a misleading number, so we catch and report as unavailable instead).
    """
    result: dict[str, float | None] = {"auroc": None, "auprc": None}
    if len(np.unique(y_true)) < 2:
        return result
    result["auroc"] = float(roc_auc_score(y_true, y_prob))
    result["auprc"] = float(average_precision_score(y_true, y_prob))
    return result


def stage_metrics(y_true: np.ndarray, y_pred: np.ndarray, valid_mask: np.ndarray) -> dict[str, float]:
    """Macro-averaged over the classes actually present in y_true[valid_mask], excluding
    `impact`-mapped windows (valid_mask=False) which aren't part of the 5-stage classification task.

    Audit E4: the number of classes actually present varies by dataset/split (CIC-IDS-2018's
    original split had 4: benign + 3 attack classes; day-disjoint or leave-one-family-out splits
    can have fewer still) and is NOT always 5, so this reports it explicitly rather than a report
    header hard-coding "5-way". Also reports macro-F1 over the ATTACK classes only (excluding
    benign), since benign is usually near-perfect and pulls the all-class macro average up —
    the attack-only number is what actually says whether stages are being told apart.
    """
    yt, yp = y_true[valid_mask], y_pred[valid_mask]
    present_classes = sorted(int(c) for c in np.unique(yt))
    support = {int(c): int((yt == c).sum()) for c in present_classes}

    # class 0 is BENIGN (see pipeline/mitre_mapping.STAGE_CLASSIFICATION_LABELS). Per-class F1
    # already only credits/penalizes predictions of that specific class against ALL rows (a
    # benign row wrongly predicted as an attack class is still a false positive for that class),
    # so the attack-only average restricts which classes are AVERAGED over (via `labels=`), not
    # which rows are scored -- restricting rows to attack-only would drop those false positives
    # and unfairly inflate precision.
    attack_classes = [c for c in present_classes if c != 0]

    return {
        "n_classes_present": len(present_classes),
        "classes_present": present_classes,
        "support": support,
        "f1_macro": f1_score(yt, yp, average="macro", zero_division=0),
        "precision_macro": precision_score(yt, yp, average="macro", zero_division=0),
        "recall_macro": recall_score(yt, yp, average="macro", zero_division=0),
        "f1_macro_attack_only": (
            f1_score(yt, yp, labels=attack_classes, average="macro", zero_division=0)
            if attack_classes else None
        ),
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

    Audit E3: the original version of this metric only ever looked at sequences that DO
    transition, so a threshold low enough to alarm on almost everything scored "0 missed" for
    free while also raising false alarms on the vast majority of sequences that stay benign the
    whole horizon. This version also scores every eligible sequence that does NOT transition
    (`n_false_alarm_eligible`/`n_false_alarms`/`false_alarm_rate`) and reports `alarm_precision`
    (true early-warning alarms / all alarms raised), so a defender can see the actual cost of the
    threshold that produced the lead-time numbers above, not just the lead time in isolation.

    Returns None if there are no eligible benign-to-attack transitions in this test set at all
    (e.g. an all-benign or already-all-attack sample) rather than a misleading zero.
    """
    eligible = current_infiltration == 0
    lead_steps: list[int] = []
    n_transitions = 0
    n_missed = 0
    n_detected_early = 0
    n_true_alarms = 0
    n_false_alarm_eligible = 0
    n_false_alarms = 0

    for i in np.where(eligible)[0]:
        attack_steps = np.where(infiltration_trajectory[i] == 1)[0]
        alarm_steps = np.where(predicted_probs[i] >= threshold)[0]

        if len(attack_steps) == 0:
            # Stays benign for the whole horizon — any alarm here is a false alarm, not a "miss".
            n_false_alarm_eligible += 1
            if len(alarm_steps) > 0:
                n_false_alarms += 1
            continue

        onset = int(attack_steps[0])
        n_transitions += 1

        if len(alarm_steps) == 0:
            n_missed += 1
            continue

        n_true_alarms += 1
        steps_early = onset - int(alarm_steps[0])
        lead_steps.append(steps_early)
        if steps_early > 0:
            n_detected_early += 1

    if n_transitions == 0:
        return None

    n_alarms_raised = n_true_alarms + n_false_alarms
    return {
        "n_transitions": n_transitions,
        "n_missed": n_missed,
        "miss_rate": n_missed / n_transitions,
        "pct_detected_early": n_detected_early / n_transitions,
        "mean_lead_time_s": float(np.mean(lead_steps) * window_seconds) if lead_steps else None,
        "median_lead_time_s": float(np.median(lead_steps) * window_seconds) if lead_steps else None,
        "n_false_alarm_eligible": n_false_alarm_eligible,
        "n_false_alarms": n_false_alarms,
        "false_alarm_rate": (n_false_alarms / n_false_alarm_eligible) if n_false_alarm_eligible else None,
        "alarm_precision": (n_true_alarms / n_alarms_raised) if n_alarms_raised else None,
    }
