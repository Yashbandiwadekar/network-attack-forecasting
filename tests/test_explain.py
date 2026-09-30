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


def test_split_attribution_separates_provenance_and_keeps_its_weight_visible():
    """has_ip_data records where a capture came from, not what the traffic did. It must not sit in the
    behavioural ranking, but its share must NOT be hidden or renormalised away."""
    from models.explain import PROVENANCE_FEATURES, split_attribution

    names = ["flow_count", "has_ip_data", "syn_ratio", "has_packet_features", "bidir_ratio"]
    values = np.array([1.0, -3.0, 0.5, 0.0, 0.5])
    out = split_attribution(names, values, top_n=10)
    assert [e["feature"] for e in out["behavioural"]] == ["flow_count", "syn_ratio", "bidir_ratio"]
    assert not any(e["feature"] in PROVENANCE_FEATURES for e in out["behavioural"])
    prov = {e["feature"]: e for e in out["provenance"]}
    assert set(prov) == {"has_ip_data", "has_packet_features"}
    # 3 of a total 5.0 absolute attribution -- reported as 60%, not hidden, not renormalised.
    assert prov["has_ip_data"]["share"] == 0.6
    assert prov["has_ip_data"]["direction"] == "lowers"
    assert out["provenance_share_total"] == 0.6
    assert "not traffic behaviour" in prov["has_ip_data"]["note"].lower()
    # behavioural shares are still fractions of the SAME total, so together with provenance they sum to 1
    assert abs(sum(e["share"] for e in out["behavioural"]) + out["provenance_share_total"] - 1.0) < 1e-3


def test_split_attribution_handles_an_all_zero_attribution():
    from models.explain import split_attribution

    out = split_attribution(["a", "has_ip_data"], np.zeros(2))
    assert out["attribution_total_abs"] == 0.0
    assert all(e["share"] == 0.0 for e in out["behavioural"] + out["provenance"])


def test_narrative_never_names_a_provenance_flag_as_a_behavioural_shift():
    from models.explain import PROVENANCE_FEATURES
    from models.forecast import ForecastResult
    from models.narrative import generate_attack_narrative

    names = ["flow_count", "has_ip_data", "syn_ratio", "bidir_ratio"]
    deltas = np.array([[0.1, 99.0, 0.2, 0.3]])  # the provenance flag has by far the biggest delta
    k = 1
    result = ForecastResult(
        infiltration_probs=np.array([0.5]), stage_predictions=["benign"], stage_probs=np.ones((k, 6)) / 6,
        attentions=np.ones((k, 4)) / 4, transition_magnitude=np.ones(k), state_deltas=deltas,
    )
    text = generate_attack_narrative("10.0.0.1", result, names, 10, current_stage="benign")
    for flag in PROVENANCE_FEATURES:
        assert flag not in text
