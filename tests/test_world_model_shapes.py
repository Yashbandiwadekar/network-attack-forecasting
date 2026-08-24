import torch

from models.world_model import WorldModel

CONFIG = {
    "windowing": {"sequence_length": 5},
    "model": {"d_model": 16, "n_heads": 2, "n_layers": 2, "d_ff": 32, "dropout": 0.0},
}


def test_forward_shapes():
    n_features, n_stage_classes, batch = 7, 6, 4
    model = WorldModel(n_features, n_stage_classes, CONFIG)
    x = torch.randn(batch, CONFIG["windowing"]["sequence_length"], n_features)

    next_state, stage_logits, infiltration_logit = model(x)

    assert next_state.shape == (batch, n_features)
    assert stage_logits.shape == (batch, n_stage_classes)
    assert infiltration_logit.shape == (batch,)


def test_return_attention_shape_and_sums_to_one():
    n_features, n_stage_classes, batch, seq_len = 7, 6, 4, 5
    model = WorldModel(n_features, n_stage_classes, CONFIG)
    x = torch.randn(batch, seq_len, n_features)

    *_, attention = model(x, return_attention=True)

    assert attention.shape == (batch, seq_len)
    torch.testing.assert_close(attention.sum(dim=-1), torch.ones(batch), atol=1e-5, rtol=1e-5)


def test_gradients_flow_to_input_projection():
    model = WorldModel(7, 6, CONFIG)
    x = torch.randn(2, 5, 7)
    next_state, stage_logits, infiltration_logit = model(x)
    loss = next_state.sum() + stage_logits.sum() + infiltration_logit.sum()
    loss.backward()
    assert model.input_proj.weight.grad is not None
    assert model.input_proj.weight.grad.abs().sum() > 0
