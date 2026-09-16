import numpy as np

from eval.metrics import binary_metrics, lead_time_metrics, threshold_at_fpr


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
    infiltration = np.array([[0, 0, 1, 1], [0, 0, 0, 1]])
    current = np.array([0.0, 0.0])
    # First sequence: never crosses threshold (missed). Second: alarms exactly at onset (lead 0).
    probs = np.array([[0.1, 0.2, 0.3, 0.4], [0.1, 0.1, 0.1, 0.6]])

    result = lead_time_metrics(infiltration, current, probs, threshold=0.5, window_seconds=10)

    assert result["n_transitions"] == 2
    assert result["n_missed"] == 1
    assert result["miss_rate"] == 0.5
    # only the non-missed sequence contributes to the mean
    assert result["mean_lead_time_s"] == 0.0
    assert result["pct_detected_early"] == 0.0  # lead of exactly 0 is not "early"


def test_lead_time_metrics_late_detection_is_negative():
    # Attack starts at step 0, alarm doesn't cross threshold until step 2 -> lead time -2 steps.
    infiltration = np.array([[1, 1, 1]])
    current = np.array([0.0])
    probs = np.array([[0.1, 0.2, 0.9]])

    result = lead_time_metrics(infiltration, current, probs, threshold=0.5, window_seconds=10)

    assert result["mean_lead_time_s"] == -20.0
    assert result["pct_detected_early"] == 0.0


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
