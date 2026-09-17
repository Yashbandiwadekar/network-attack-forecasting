import numpy as np
import torch

from models.world_model_joint import JointWorldModel
from pipeline.graph_builder import WindowGraph

_CONFIG = {
    "model": {"d_model": 16, "n_heads": 2, "d_ff": 32, "n_layers": 2, "dropout": 0.1},
    "windowing": {"sequence_length": 3},
}


def _graph(edges, edge_dim=3, seed=0):
    ids = sorted({ip for pair in edges for ip in pair})
    index = {ip: i for i, ip in enumerate(ids)}
    edge_index = np.array([[index[s] for s, _ in edges], [index[d] for _, d in edges]], dtype=np.int64)
    rng = np.random.default_rng(seed)
    edge_attr = rng.normal(size=(len(edges), edge_dim)).astype(np.float32)
    return WindowGraph(window_key=None, node_ids=ids, node_index=index, edge_index=edge_index, edge_attr=edge_attr)


def _flat_items(batch, seq_len, edge_dim=3):
    g = _graph([("A", "B"), ("B", "C")], edge_dim=edge_dim)
    return [(g, "A") for _ in range(batch * seq_len)]


def test_forward_output_shapes_match_world_model_contract():
    n_base_features, n_stage_classes, edge_dim = 5, 4, 3
    batch, seq_len = 2, 3
    model = JointWorldModel(n_base_features, n_stage_classes, _CONFIG, edge_dim=edge_dim, embed_dim=6)

    x_base = torch.randn(batch, seq_len, n_base_features)
    items = _flat_items(batch, seq_len, edge_dim)

    next_state, stage_logits, infiltration_logit = model(x_base, items)

    assert next_state.shape == (batch, n_base_features + 6)  # world model predicts its OWN input width
    assert stage_logits.shape == (batch, n_stage_classes)
    assert infiltration_logit.shape == (batch,)


def test_wrong_number_of_graph_items_raises():
    model = JointWorldModel(5, 4, _CONFIG, edge_dim=3, embed_dim=6)
    x_base = torch.randn(2, 3, 5)
    items = _flat_items(2, 3, edge_dim=3)[:-1]  # one short
    try:
        model(x_base, items)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_gradients_flow_into_both_transformer_and_graph_encoder():
    model = JointWorldModel(5, 4, _CONFIG, edge_dim=3, embed_dim=6)
    x_base = torch.randn(2, 3, 5)
    items = _flat_items(2, 3, edge_dim=3)

    next_state, stage_logits, infiltration_logit = model(x_base, items)
    loss = next_state.sum() + stage_logits.sum() + infiltration_logit.sum()
    loss.backward()

    encoder_grads = [p.grad for p in model.graph_encoder.parameters()]
    transformer_grads = [p.grad for p in model.world_model.parameters()]
    assert all(g is not None for g in encoder_grads)
    assert any(torch.any(g != 0) for g in encoder_grads)
    assert all(g is not None for g in transformer_grads)


def test_return_attention_matches_world_model_signature():
    model = JointWorldModel(5, 4, _CONFIG, edge_dim=3, embed_dim=6)
    x_base = torch.randn(2, 3, 5)
    items = _flat_items(2, 3, edge_dim=3)

    out = model(x_base, items, return_attention=True)
    assert len(out) == 4
    attention = out[-1]
    assert attention.shape == (2, 3)
