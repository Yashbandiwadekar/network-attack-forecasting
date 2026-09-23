import numpy as np
import torch
import torch.nn as nn

from eval.lofo import FAMILY_DAYS, _predict_infiltration, fold_days


class _FakeWorldModel(nn.Module):
    """Mimics WorldModel's (next_state, stage_logits, infiltration_logit) output shape --
    _predict_infiltration only reads index [2]."""

    def forward(self, x):
        infiltration_logit = x[:, -1, 0]  # deterministic function of input, for equality checks
        return None, None, infiltration_logit


def test_predict_infiltration_batches_without_changing_the_result():
    torch.manual_seed(0)
    X = torch.randn(37, 3, 4)  # deliberately not a multiple of batch_size
    model = _FakeWorldModel()
    device = torch.device("cpu")

    batched = _predict_infiltration(model, X, device, batch_size=8)
    unbatched = torch.sigmoid(model(X)[2]).numpy()

    assert np.allclose(batched, unbatched)
    assert batched.shape == (37,)


def test_predict_infiltration_handles_empty_input():
    model = _FakeWorldModel()
    result = _predict_infiltration(model, torch.zeros(0, 3, 4), torch.device("cpu"))
    assert result.shape == (0,)


def test_lofo_family_days_are_disjoint_and_cover_every_labelled_day():
    seen = set()
    for family, days in FAMILY_DAYS.items():
        assert not seen & set(days), f"{family} overlaps another family's days"
        seen.update(days)


def test_fold_days_never_puts_a_family_day_in_train_or_val():
    for family in FAMILY_DAYS:
        fold = fold_days(family)
        for day in FAMILY_DAYS[family]:
            assert day not in fold["train"]
            assert day not in fold["val"]
            assert day in fold["test"]
