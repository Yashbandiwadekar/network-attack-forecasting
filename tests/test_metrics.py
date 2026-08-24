import numpy as np

from eval.metrics import binary_metrics, threshold_at_fpr


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
