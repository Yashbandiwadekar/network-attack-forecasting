import numpy as np

from eval.metrics import lead_time_metrics, stage_metrics, threshold_free_metrics


# ---------------------------------------------------------------------------
# E5: threshold-free ranking metrics
# ---------------------------------------------------------------------------

def test_threshold_free_metrics_perfect_separation():
    y_true = np.array([0, 0, 0, 1, 1, 1])
    y_prob = np.array([0.1, 0.2, 0.3, 0.7, 0.8, 0.9])

    result = threshold_free_metrics(y_true, y_prob)

    assert result["auroc"] == 1.0
    assert result["auprc"] == 1.0


def test_threshold_free_metrics_returns_none_when_only_one_class_present():
    y_true = np.zeros(10)
    y_prob = np.random.default_rng(0).random(10)

    result = threshold_free_metrics(y_true, y_prob)

    assert result["auroc"] is None
    assert result["auprc"] is None


# ---------------------------------------------------------------------------
# E4: stage_metrics class count / support / attack-only macro-F1
# ---------------------------------------------------------------------------

def test_stage_metrics_reports_present_classes_and_support():
    y_true = np.array([0, 0, 0, 1, 1, 2])
    y_pred = np.array([0, 0, 1, 1, 1, 2])
    valid_mask = np.ones_like(y_true, dtype=bool)

    result = stage_metrics(y_true, y_pred, valid_mask)

    assert result["n_classes_present"] == 3
    assert result["classes_present"] == [0, 1, 2]
    assert result["support"] == {0: 3, 1: 2, 2: 1}


def test_stage_metrics_attack_only_excludes_benign_but_counts_benign_false_positives():
    # Benign (0) predicted perfectly, one attack class (1) present.
    y_true = np.array([0, 0, 1, 1])
    y_pred = np.array([0, 0, 1, 1])
    valid_mask = np.ones_like(y_true, dtype=bool)

    perfect = stage_metrics(y_true, y_pred, valid_mask)
    assert perfect["f1_macro_attack_only"] == 1.0

    # Now one benign row is wrongly predicted as the attack class -- attack-only F1 (class 1)
    # must drop because that's a false positive for class 1, even though the row's true label is
    # benign and so is excluded from "all classes averaged over benign" style scoring.
    y_pred_with_fp = np.array([1, 0, 1, 1])
    degraded = stage_metrics(y_true, y_pred_with_fp, valid_mask)
    assert degraded["f1_macro_attack_only"] < perfect["f1_macro_attack_only"]


def test_stage_metrics_attack_only_is_none_when_only_benign_present():
    y_true = np.array([0, 0, 0])
    y_pred = np.array([0, 0, 0])
    valid_mask = np.ones_like(y_true, dtype=bool)

    result = stage_metrics(y_true, y_pred, valid_mask)

    assert result["f1_macro_attack_only"] is None


# ---------------------------------------------------------------------------
# E3: lead-time false-alarm accounting
# ---------------------------------------------------------------------------

def test_lead_time_metrics_counts_false_alarms_on_non_transitioning_sequences():
    # Two sequences stay benign the whole horizon (no transition): one alarms (false alarm), one
    # doesn't. One sequence genuinely transitions and is detected correctly.
    infiltration = np.array([[0, 0, 0], [0, 0, 0], [0, 0, 1]])
    current = np.array([0.0, 0.0, 0.0])
    probs = np.array([[0.9, 0.9, 0.9], [0.1, 0.1, 0.1], [0.1, 0.1, 0.9]])

    result = lead_time_metrics(infiltration, current, probs, threshold=0.5, window_seconds=10)

    assert result["n_transitions"] == 1
    assert result["n_false_alarm_eligible"] == 2
    assert result["n_false_alarms"] == 1
    assert result["false_alarm_rate"] == 0.5
    # 1 true alarm (the transition, detected at onset) + 1 false alarm = 2 alarms raised.
    assert result["alarm_precision"] == 0.5


def test_lead_time_metrics_alarm_precision_is_one_when_no_false_alarms():
    infiltration = np.array([[0, 0, 1], [0, 0, 0]])
    current = np.array([0.0, 0.0])
    probs = np.array([[0.1, 0.1, 0.9], [0.1, 0.1, 0.1]])

    result = lead_time_metrics(infiltration, current, probs, threshold=0.5, window_seconds=10)

    assert result["n_false_alarms"] == 0
    assert result["alarm_precision"] == 1.0
