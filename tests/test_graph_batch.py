import numpy as np
import torch

from models.graph_batch import batch_window_graphs, embed_batch
from models.graph_encoder import GraphSAGEEncoder
from pipeline.graph_builder import WindowGraph


def _graph(edges, edge_dim=3, seed=0):
    ids = sorted({ip for pair in edges for ip in pair})
    index = {ip: i for i, ip in enumerate(ids)}
    edge_index = np.array([[index[s] for s, _ in edges], [index[d] for _, d in edges]], dtype=np.int64)
    rng = np.random.default_rng(seed)
    edge_attr = rng.normal(size=(len(edges), edge_dim)).astype(np.float32)
    return WindowGraph(window_key=None, node_ids=ids, node_index=index, edge_index=edge_index, edge_attr=edge_attr)


def test_batching_two_graphs_matches_separate_embed_host_calls():
    torch.manual_seed(0)
    g1 = _graph([("A", "B"), ("B", "C")], seed=1)
    g2 = _graph([("X", "Y")], seed=2)
    encoder = GraphSAGEEncoder(edge_dim=3, hidden_dim=4, out_dim=6)

    items = [(g1, "B"), (g2, "X"), (g1, "C")]
    batched = embed_batch(encoder, items, edge_dim=3)

    separate = torch.stack([encoder.embed_host(g1, "B"), encoder.embed_host(g2, "X"), encoder.embed_host(g1, "C")])

    assert torch.allclose(batched, separate, atol=1e-6)


def test_missing_host_in_batch_gives_zero_row():
    g = _graph([("A", "B")], seed=3)
    encoder = GraphSAGEEncoder(edge_dim=3, hidden_dim=4, out_dim=5)

    batched = embed_batch(encoder, [(g, "not-in-graph")], edge_dim=3)
    assert torch.allclose(batched[0], torch.zeros(5))


def test_batch_of_one_matches_unbatched_embed_window_graph():
    g = _graph([("A", "B"), ("B", "C"), ("C", "A")], seed=4)
    encoder = GraphSAGEEncoder(edge_dim=3, hidden_dim=4, out_dim=6)

    batched = embed_batch(encoder, [(g, "A")], edge_dim=3)
    unbatched = encoder.embed_host(g, "A")
    assert torch.allclose(batched[0], unbatched, atol=1e-6)


def test_node_offsets_prevent_cross_graph_message_passing():
    # Two graphs both using node label "A" at local index 0 -- after offsetting, their edges must
    # not be confused with each other in the combined graph.
    g1 = _graph([("A", "B")], seed=5)
    g2 = _graph([("A", "C")], seed=6)  # different edge_attr, same node label "A"
    encoder = GraphSAGEEncoder(edge_dim=3, hidden_dim=4, out_dim=6)

    batch = batch_window_graphs([(g1, "A"), (g2, "A")], edge_dim=3)
    # g1 has 2 nodes (A, B) at combined indices 0-1; g2's "A" must be offset to index 2, not reuse 0.
    assert batch.total_nodes == 4
    assert batch.target_rows[0].item() == g1.node_index["A"]
    assert batch.target_rows[1].item() == 2 + g2.node_index["A"]

    embedding_a1 = embed_batch(encoder, [(g1, "A")], edge_dim=3)[0]
    embedding_a2 = embed_batch(encoder, [(g2, "A")], edge_dim=3)[0]
    combined = embed_batch(encoder, [(g1, "A"), (g2, "A")], edge_dim=3)
    assert torch.allclose(combined[0], embedding_a1, atol=1e-6)
    assert torch.allclose(combined[1], embedding_a2, atol=1e-6)


def test_gradients_flow_into_encoder_parameters_through_batched_forward():
    g1 = _graph([("A", "B")], seed=7)
    g2 = _graph([("X", "Y"), ("Y", "Z")], seed=8)
    encoder = GraphSAGEEncoder(edge_dim=3, hidden_dim=4, out_dim=5)

    out = embed_batch(encoder, [(g1, "A"), (g2, "Y")], edge_dim=3)
    out.sum().backward()

    grads = [p.grad for p in encoder.parameters()]
    assert all(g is not None for g in grads)
    assert any(torch.any(g != 0) for g in grads)


def test_empty_items_list_produces_empty_output():
    encoder = GraphSAGEEncoder(edge_dim=3, hidden_dim=4, out_dim=5)
    out = embed_batch(encoder, [], edge_dim=3)
    assert out.shape == (0, 5)


def test_all_isolated_hosts_produces_all_zero_rows_no_error():
    g = _graph([("A", "B")], seed=9)
    encoder = GraphSAGEEncoder(edge_dim=3, hidden_dim=4, out_dim=5)
    out = embed_batch(encoder, [(g, "ghost1"), (g, "ghost2")], edge_dim=3)
    assert out.shape == (2, 5)
    assert torch.allclose(out, torch.zeros(2, 5))
