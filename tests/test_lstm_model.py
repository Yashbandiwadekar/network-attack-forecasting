import torch

from models.lstm_model import LSTMWorldModel

_CONFIG = {"model": {"d_model": 16, "n_layers": 2, "dropout": 0.1}}


def test_forward_output_shapes_match_world_model_contract():
    n_features, n_stage_classes, batch, seq_len = 7, 5, 4, 6
    model = LSTMWorldModel(n_features, n_stage_classes, _CONFIG)
    x = torch.randn(batch, seq_len, n_features)

    next_state, stage_logits, infiltration_logit = model(x)

    assert next_state.shape == (batch, n_features)
    assert stage_logits.shape == (batch, n_stage_classes)
    assert infiltration_logit.shape == (batch,)


def test_single_layer_config_does_not_error_on_lstm_dropout():
    # nn.LSTM raises/warns if dropout > 0 with num_layers == 1 -- the model must guard this itself.
    model = LSTMWorldModel(4, 3, {"model": {"d_model": 8, "n_layers": 1, "dropout": 0.3}})
    x = torch.randn(2, 5, 4)
    model(x)  # must not raise


def test_gradient_step_reduces_loss_on_a_trivial_task():
    torch.manual_seed(0)
    n_features, n_stage_classes = 3, 5
    model = LSTMWorldModel(n_features, n_stage_classes, _CONFIG)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01)

    x = torch.randn(16, 4, n_features)
    target_next_state = torch.randn(16, n_features)

    losses = []
    for _ in range(20):
        optimizer.zero_grad()
        next_state, _, _ = model(x)
        loss = torch.nn.functional.mse_loss(next_state, target_next_state)
        loss.backward()
        optimizer.step()
        losses.append(loss.item())

    assert losses[-1] < losses[0]
