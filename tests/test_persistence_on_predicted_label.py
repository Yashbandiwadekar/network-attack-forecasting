import numpy as np
import torch

from models.baseline_lr import PersistenceOnPredictedLabel

CONFIG = {"baseline": {"max_iter": 200}}


class _FakeSequenceDataset:
    """Duck-typed stand-in for models.dataset.SequenceDataset carrying only the fields
    PersistenceOnPredictedLabel reads (X, current_stage, current_infiltration)."""

    def __init__(self, X, current_stage, current_infiltration):
        self.X = torch.tensor(X, dtype=torch.float32)
        self.current_stage = torch.tensor(current_stage, dtype=torch.long)
        self.current_infiltration = torch.tensor(current_infiltration, dtype=torch.float32)


def _linearly_separable_dataset(n: int = 200, seed: int = 0) -> _FakeSequenceDataset:
    rng = np.random.default_rng(seed)
    # One feature column that cleanly separates benign (label 0) from attack (label 1).
    signal = rng.integers(0, 2, size=n)
    noise = rng.normal(0, 0.05, size=n)
    X = np.zeros((n, 1, 3), dtype=np.float32)
    X[:, -1, 0] = signal + noise
    return _FakeSequenceDataset(X, current_stage=signal.astype(np.int64), current_infiltration=signal.astype(np.float32))


def test_fits_and_predicts_current_label_from_features_alone():
    ds = _linearly_separable_dataset()
    model = PersistenceOnPredictedLabel(CONFIG).fit(ds)

    infiltration_prob, stage_probs = model.predict(ds)

    assert infiltration_prob.shape == (len(ds.X),)
    assert stage_probs.shape[0] == len(ds.X)
    # A cleanly separable signal should be predicted correctly most of the time.
    predicted = (infiltration_prob >= 0.5).astype(int)
    accuracy = (predicted == ds.current_infiltration.numpy().astype(int)).mean()
    assert accuracy > 0.9


def test_does_not_read_ground_truth_label_directly_unlike_the_oracle():
    """The whole point of E6: this model must derive its answer from ds.X, not from
    ds.current_stage/ds.current_infiltration directly. Corrupting the labels used to FIT (but
    keeping the same features) should not change predictions made on the same features once
    fitted with a dataset whose features/labels remain consistent -- what we're really checking
    is that predict() only touches ds.X, so mutating current_stage/current_infiltration on the
    dataset passed to predict() has no effect on the output."""
    ds = _linearly_separable_dataset()
    model = PersistenceOnPredictedLabel(CONFIG).fit(ds)

    infiltration_prob_before, _ = model.predict(ds)

    # Corrupt the "ground truth" fields after fitting -- an oracle model would change its answer
    # (it reads these directly); this one must not, since predict() never touches them.
    ds.current_infiltration = torch.zeros_like(ds.current_infiltration)
    ds.current_stage = torch.zeros_like(ds.current_stage)

    infiltration_prob_after, _ = model.predict(ds)

    assert np.allclose(infiltration_prob_before, infiltration_prob_after)
