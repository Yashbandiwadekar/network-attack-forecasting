import torch

from models.markov_baseline import MarkovBaseline


class _FakeSequenceDataset:
    """Duck-typed stand-in for models.dataset.SequenceDataset carrying only the fields
    MarkovBaseline reads (current_stage, future_stages, infiltration) -- avoids building a real
    windowed dataset just to test the transition-table logic."""

    def __init__(self, current_stage, future_stage, infiltration):
        self.current_stage = torch.tensor(current_stage, dtype=torch.long)
        self.future_stages = torch.tensor(future_stage, dtype=torch.long).unsqueeze(-1)
        self.infiltration = torch.tensor(infiltration, dtype=torch.float32).unsqueeze(-1)


def test_learns_deterministic_transition_when_data_is_deterministic():
    # Stage 0 always transitions to stage 1, with infiltration always 1 next step.
    current_stage = [0, 0, 0, 0]
    future_stage = [1, 1, 1, 1]
    infiltration = [1.0, 1.0, 1.0, 1.0]
    ds = _FakeSequenceDataset(current_stage, future_stage, infiltration)

    markov = MarkovBaseline(laplace_smoothing=1e-6).fit(ds)
    infiltration_prob, stage_probs = markov.predict(ds)

    assert stage_probs[0].argmax() == 1
    assert infiltration_prob[0] > 0.99


def test_excludes_impact_mapped_windows_from_stage_transition_fit():
    # current_stage == -1 rows must not corrupt the transition table for real stages.
    current_stage = [0, 0, -1, -1]
    future_stage = [1, 1, -1, -1]
    infiltration = [1.0, 1.0, 1.0, 0.0]
    ds = _FakeSequenceDataset(current_stage, future_stage, infiltration)

    markov = MarkovBaseline(laplace_smoothing=1e-6).fit(ds)
    infiltration_prob, stage_probs = markov.predict(ds)

    assert stage_probs[0].argmax() == 1
    # -1 rows get the uniform/default fallback, not a fitted (and undefined) -1 row
    n_classes = markov.n_stage_classes
    assert infiltration_prob[2] == 0.5
    assert (stage_probs[2] == 1.0 / n_classes).all()


def test_predict_output_shapes_match_dataset_size():
    current_stage = [0, 1, 2, 0, 1]
    future_stage = [1, 2, 0, 1, 2]
    infiltration = [0.0, 1.0, 0.0, 1.0, 0.0]
    ds = _FakeSequenceDataset(current_stage, future_stage, infiltration)

    markov = MarkovBaseline().fit(ds)
    infiltration_prob, stage_probs = markov.predict(ds)

    assert infiltration_prob.shape == (5,)
    assert stage_probs.shape == (5, markov.n_stage_classes)
