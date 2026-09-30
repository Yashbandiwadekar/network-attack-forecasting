import numpy as np

from models.explain import ShapExplainer, gradient_input_attribution, summarize_attention
from models.world_model import WorldModel

CONFIG = {
    "windowing": {"sequence_length": 5},
    "model": {"d_model": 8, "n_heads": 2, "n_layers": 1, "d_ff": 16, "dropout": 0.1},
}


def _model(n_features=6):
    model = WorldModel(n_features, 6, CONFIG)
    model.eval()
    return model


def test_summarize_attention_sorts_descending_and_labels_most_recent_as_t_minus_0():
    attention_row = np.array([0.1, 0.05, 0.6, 0.25])
    pairs = summarize_attention(attention_row, sequence_length=4)
    labels, weights = zip(*pairs)
    assert list(weights) == sorted(weights, reverse=True)
    assert labels[0] == "t-1"  # index 2 has the highest weight (0.6) -> label t-(4-1-2)=t-1
    assert "t-0" in labels  # most recent window (last index) is always present


def test_gradient_input_attribution_shape_and_restores_mode():
    n_features = 6
    model = _model(n_features)
    seq = np.random.randn(5, n_features).astype(np.float32)

    result = gradient_input_attribution(model, seq, [f"f{i}" for i in range(n_features)])

    assert result["attribution"].shape == (n_features,)
    assert len(result["top_features"]) == 5
    assert all(np.isfinite(result["attribution"]))
    assert model.training is False  # must not leave the model in train mode


def test_gradient_input_attribution_top_features_ranked_by_magnitude():
    n_features = 6
    model = _model(n_features)
    seq = np.random.randn(5, n_features).astype(np.float32)
    result = gradient_input_attribution(model, seq, [f"f{i}" for i in range(n_features)])
    magnitudes = [abs(v) for _, v in result["top_features"]]
    assert magnitudes == sorted(magnitudes, reverse=True)


def test_shap_explainer_shape():
    n_features = 6
    model = _model(n_features)
    background = np.random.randn(10, n_features).astype(np.float32)
    explainer = ShapExplainer(model, background, n_background=5)
    seq = np.random.randn(5, n_features).astype(np.float32)

    result = explainer.explain(seq, [f"f{i}" for i in range(n_features)], nsamples=20)

    assert result["shap_values"].shape == (n_features,)
    assert len(result["top_features"]) == 5


def test_logit_target_gives_same_ranking_as_probability_target():
    """d(prob)/dx = p(1-p) * d(logit)/dx, a per-sample constant, so switching the target must not
    change which features matter or their relative sizes -- only avoid the saturation underflow."""
    import pytest

    n_features = 6
    model = _model(n_features)
    seq = np.random.RandomState(0).randn(5, n_features).astype(np.float32)
    names = [f"f{i}" for i in range(n_features)]
    prob = gradient_input_attribution(model, seq, names, target="probability")["attribution"]
    logit = gradient_input_attribution(model, seq, names, target="logit")["attribution"]
    assert list(np.argsort(-np.abs(prob))) == list(np.argsort(-np.abs(logit)))
    ratio = prob / logit
    assert np.allclose(ratio, ratio[0], rtol=1e-3)  # one constant across all features
    with pytest.raises(ValueError):
        gradient_input_attribution(model, seq, names, target="nonsense")


def test_logit_target_survives_a_saturated_model():
    """The bug this guards: with the infiltration output pushed to saturation the probability
    gradient collapses toward zero (every UI row read 0.0%) while the logit gradient does not."""
    import torch

    n_features = 6
    model = _model(n_features)
    with torch.no_grad():
        for p in model.parameters():
            p.mul_(40.0)  # drive the logit far from 0 so sigmoid saturates
    seq = np.random.RandomState(1).randn(5, n_features).astype(np.float32)
    names = [f"f{i}" for i in range(n_features)]
    prob = np.abs(gradient_input_attribution(model, seq, names, target="probability")["attribution"]).sum()
    logit = np.abs(gradient_input_attribution(model, seq, names, target="logit")["attribution"]).sum()
    assert logit > prob * 100
