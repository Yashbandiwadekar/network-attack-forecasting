import numpy as np

from eval.metrics import binary_metrics, lead_time_metrics, stage_metrics, threshold_at_fpr


def test_threshold_at_fpr_respects_budget():
    rng = np.random.default_rng(0)
    y_true = np.array([0] * 80 + [1] * 20)
    # scores correlate with the label but aren't perfectly separable
    y_prob = np.clip(y_true * 0.5 + rng.normal(0, 0.3, size=100), 0, 1)

    threshold = threshold_at_fpr(y_true, y_prob, target_fpr=0.1)
    metrics = binary_metrics(y_true, y_prob, threshold=threshold)

    assert metrics["false_positive_rate"] <= 0.1 + 1e-9


def test_threshold_at_fpr_perfect_separation_gives_zero_fpr():
    y_true = np.array([0, 0, 0, 1, 1, 1])
    y_prob = np.array([0.1, 0.2, 0.3, 0.7, 0.8, 0.9])

    threshold = threshold_at_fpr(y_true, y_prob, target_fpr=0.05)
    metrics = binary_metrics(y_true, y_prob, threshold=threshold)

    assert metrics["false_positive_rate"] == 0.0
    assert metrics["recall"] == 1.0


def test_threshold_at_fpr_tighter_budget_never_exceeds_looser_budget():
    rng = np.random.default_rng(1)
    y_true = rng.integers(0, 2, size=200)
    y_prob = np.clip(y_true * 0.4 + rng.normal(0, 0.3, size=200), 0, 1)

    tight = threshold_at_fpr(y_true, y_prob, target_fpr=0.05)
    loose = threshold_at_fpr(y_true, y_prob, target_fpr=0.3)

    fpr_tight = binary_metrics(y_true, y_prob, threshold=tight)["false_positive_rate"]
    fpr_loose = binary_metrics(y_true, y_prob, threshold=loose)["false_positive_rate"]
    assert fpr_tight <= fpr_loose + 1e-9


def test_lead_time_metrics_perfect_early_warning():
    # One sequence: benign now, attack starts at step 3; model crosses threshold at step 1 ->
    # 2-step (20s at 10s/window) lead time.
    infiltration = np.array([[0, 0, 0, 1, 1, 1]])
    current = np.array([0.0])
    probs = np.array([[0.1, 0.9, 0.9, 0.9, 0.9, 0.9]])

    result = lead_time_metrics(infiltration, current, probs, threshold=0.5, window_seconds=10)

    assert result["n_transitions"] == 1
    assert result["n_missed"] == 0
    assert result["pct_detected_early"] == 1.0
    assert result["mean_lead_time_s"] == 20.0
    assert result["median_lead_time_s"] == 20.0


def test_lead_time_metrics_missed_transition_excluded_from_mean_but_counted_in_miss_rate():
    infiltration = np.array([[0, 0, 1, 1], [0, 0, 0, 1], [0, 0, 1, 1]])
    current = np.array([0.0, 0.0, 0.0])
    # seq0: never crosses (no alarm). seq1: alarms exactly at onset (no warning). seq2: early (lead 1).
    probs = np.array([[0.1, 0.2, 0.3, 0.4], [0.1, 0.1, 0.1, 0.6], [0.1, 0.6, 0.6, 0.6]])

    result = lead_time_metrics(infiltration, current, probs, threshold=0.5, window_seconds=10)

    assert result["n_transitions"] == 3
    assert result["n_missed"] == 2  # QC-3: no EARLY warning (no alarm + on-time)
    assert result["n_no_alarm"] == 1 and result["n_alarm_on_time"] == 1 and result["n_alarm_late"] == 0
    assert result["miss_rate"] == 2 / 3
    assert result["mean_lead_time_s"] == 10.0  # only the early detection contributes
    assert result["pct_detected_early"] == 1 / 3


def test_lead_time_metrics_late_alarm_is_not_a_detection():
    # QC-3: attack starts at step 0, alarm doesn't cross threshold until step 2 -> late, not a
    # negative-lead "detection".
    infiltration = np.array([[1, 1, 1]])
    current = np.array([0.0])
    probs = np.array([[0.1, 0.2, 0.9]])

    result = lead_time_metrics(infiltration, current, probs, threshold=0.5, window_seconds=10)

    assert result["mean_lead_time_s"] is None
    assert result["pct_detected_early"] == 0.0
    assert result["n_alarm_late"] == 1 and result["n_missed"] == 1 and result["miss_rate"] == 1.0


def test_qc3_onset_step_zero_with_only_alarm_at_step_five():
    infiltration = np.ones((1, 6))
    probs = np.zeros((1, 6)); probs[0, 5] = 0.9
    r = lead_time_metrics(infiltration, np.zeros(1), probs, 0.5, 10)
    assert r["n_missed"] == 1 and r["miss_rate"] == 1.0 and r["n_alarm_late"] == 1
    assert r["mean_lead_time_s"] is None and r["pct_detected_early"] == 0.0


def test_qc3_one_early_one_late():
    infiltration = np.zeros((2, 6)); infiltration[:, 3:] = 1
    probs = np.zeros((2, 6)); probs[0, 1] = 0.9; probs[1, 4] = 0.9
    r = lead_time_metrics(infiltration, np.zeros(2), probs, 0.5, 10)
    assert r["n_transitions"] == 2 and r["n_missed"] == 1 and r["miss_rate"] == 0.5
    assert r["n_alarm_late"] == 1 and r["pct_detected_early"] == 0.5
    assert r["mean_lead_time_s"] == 20.0 and r["median_lead_time_s"] == 20.0  # never negative


def test_qc4_stage_metrics_macro_averages_only_present_classes():
    # class 2 is predicted but absent from y_true: it must not enter the macro averages.
    yt = np.array([0, 0, 0, 1, 1]); yp = np.array([0, 0, 2, 1, 1])
    r = stage_metrics(yt, yp, np.ones(5, bool))
    assert r["n_classes_present"] == 2
    # class0: P=1 R=2/3 F1=0.8 ; class1: P=1 R=1 F1=1  -> macro over {0,1}
    assert abs(r["f1_macro"] - 0.9) < 1e-9
    assert abs(r["precision_macro"] - 1.0) < 1e-9
    assert abs(r["recall_macro"] - (2 / 3 + 1) / 2) < 1e-9


def test_qc16_threshold_at_fpr_is_always_finite():
    import json
    # positives score BELOW negatives: only eligible operating point is sklearn's inf threshold
    y = np.array([0, 0, 1]); p = np.array([0.9, 0.8, 0.1])
    t = threshold_at_fpr(y, p, target_fpr=0.0)
    assert np.isfinite(t) and t > p.max()  # still "alarm on nothing" under >=
    assert json.dumps({"t": t})
    assert (p >= t).sum() == 0


def test_lead_time_metrics_excludes_sequences_already_under_attack_right_now():
    # current_infiltration == 1 means this host is already mid-attack -- not a transition case,
    # regardless of what its future trajectory looks like.
    infiltration = np.array([[1, 1, 1]])
    current = np.array([1.0])
    probs = np.array([[0.9, 0.9, 0.9]])

    result = lead_time_metrics(infiltration, current, probs, threshold=0.5, window_seconds=10)

    assert result is None


def test_lead_time_metrics_returns_none_when_no_transitions_exist():
    infiltration = np.array([[0, 0, 0], [1, 1, 1]])
    current = np.array([0.0, 1.0])  # neither row is a "benign now, attacks later" transition
    probs = np.array([[0.1, 0.1, 0.1], [0.9, 0.9, 0.9]])

    result = lead_time_metrics(infiltration, current, probs, threshold=0.5, window_seconds=10)

    assert result is None
