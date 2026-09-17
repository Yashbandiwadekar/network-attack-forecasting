import numpy as np
import torch

from models.graph_encoder import GraphSAGEEncoder, NodeSAGELayer, _scatter_mean
from pipeline.graph_builder import WindowGraph


def _graph(edges, edge_dim=3, node_ids=None):
    """edges: list of (src_ip, dst_ip) -> a WindowGraph with random-but-fixed edge_attr."""
    ids = node_ids or sorted({ip for pair in edges for ip in pair})
    index = {ip: i for i, ip in enumerate(ids)}
    edge_index = np.array([[index[s] for s, _ in edges], [index[d] for _, d in edges]], dtype=np.int64)
    rng = np.random.default_rng(0)
    edge_attr = rng.normal(size=(len(edges), edge_dim)).astype(np.float32)
    return WindowGraph(window_key=None, node_ids=ids, node_index=index, edge_index=edge_index, edge_attr=edge_attr)


def test_scatter_mean_averages_values_per_group():
    values = torch.tensor([[1.0], [3.0], [5.0]])
    index = torch.tensor([0, 0, 1])
    out = _scatter_mean(values, index, n_nodes=2)
    assert torch.allclose(out, torch.tensor([[2.0], [5.0]]))


def test_scatter_mean_zero_fills_nodes_with_no_edges():
    values = torch.tensor([[1.0]])
    index = torch.tensor([0])
    out = _scatter_mean(values, index, n_nodes=3)
    assert torch.allclose(out[1], torch.zeros(1))
    assert torch.allclose(out[2], torch.zeros(1))


def test_embed_window_graph_output_shape():
    graph = _graph([("A", "B"), ("B", "C")], edge_dim=3)
    encoder = GraphSAGEEncoder(edge_dim=3, hidden_dim=4, out_dim=8)
    embeddings = encoder.embed_window_graph(graph)
    assert embeddings.shape == (3, 8)


def test_embed_host_returns_that_hosts_row():
    graph = _graph([("A", "B"), ("B", "C")], edge_dim=3)
    encoder = GraphSAGEEncoder(edge_dim=3, hidden_dim=4, out_dim=8)
    torch.manual_seed(0)
    all_embeddings = encoder.embed_window_graph(graph)
    host_embedding = encoder.embed_host(graph, "B")
    assert torch.allclose(host_embedding, all_embeddings[graph.node_index["B"]])


def test_embed_host_returns_zeros_for_host_absent_from_graph():
    graph = _graph([("A", "B")], edge_dim=3)
    encoder = GraphSAGEEncoder(edge_dim=3, hidden_dim=4, out_dim=8)
    embedding = encoder.embed_host(graph, "Z")
    assert torch.allclose(embedding, torch.zeros(8))


def test_empty_graph_does_not_error():
    graph = WindowGraph(None, [], {}, np.zeros((2, 0), dtype=np.int64), np.zeros((0, 3), dtype=np.float32))
    encoder = GraphSAGEEncoder(edge_dim=3, hidden_dim=4, out_dim=8)
    embeddings = encoder.embed_window_graph(graph)
    assert embeddings.shape == (0, 8)


def test_directed_edges_produce_asymmetric_out_and_in_aggregates():
    # A only sends (out-heavy), C only receives (in-heavy) -- their edge-to-node aggregates
    # should differ, confirming direction isn't collapsed into one undirected signal.
    graph = _graph([("A", "B"), ("A", "C"), ("B", "C")], edge_dim=3)
    encoder = GraphSAGEEncoder(edge_dim=3, hidden_dim=4, out_dim=8)
    h0 = encoder.edge_to_node(
        torch.as_tensor(graph.edge_index, dtype=torch.long),
        torch.as_tensor(graph.edge_attr, dtype=torch.float32),
        graph.n_nodes,
    )
    a_idx, c_idx = graph.node_index["A"], graph.node_index["C"]
    out_dim = h0.shape[-1] // 2
    a_out, a_in = h0[a_idx, :out_dim], h0[a_idx, out_dim:]
    c_out, c_in = h0[c_idx, :out_dim], h0[c_idx, out_dim:]
    assert not torch.allclose(a_out, a_in)  # A sends a lot, receives nothing
    assert torch.allclose(c_out, torch.zeros(out_dim))  # C never sends


def test_node_sage_layer_gradient_flows():
    layer = NodeSAGELayer(in_dim=4, out_dim=4)
    node_embed = torch.randn(3, 4, requires_grad=True)
    edge_index = torch.tensor([[0, 1], [1, 2]], dtype=torch.long)
    out = layer(node_embed, edge_index)
    out.sum().backward()
    assert node_embed.grad is not None
    assert not torch.all(node_embed.grad == 0)


def test_inductive_new_host_at_inference_does_not_error():
    # A host never seen in this graph's own construction (fresh IP) should still produce a valid
    # embedding purely from its own edges -- no fixed node-id table anywhere in this module.
    graph = _graph([("never-seen-before-1.2.3.4", "B")], edge_dim=3)
    encoder = GraphSAGEEncoder(edge_dim=3, hidden_dim=4, out_dim=8)
    embedding = encoder.embed_host(graph, "never-seen-before-1.2.3.4")
    assert embedding.shape == (8,)
    assert torch.isfinite(embedding).all()
