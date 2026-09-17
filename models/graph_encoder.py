"""GraphSAGE-style encoder turning a pipeline.graph_builder.WindowGraph into a per-host
embedding for one window (GNN Phase 2 -- see pipeline/graph_builder.py's docstring for Phase 1).

No raw node features exist in this domain -- a host IP carries no inherent feature vector, only
the flows touching it. So this is closer to E-GraphSAGE than textbook GraphSAGE: node embeddings
are *bootstrapped from edge attributes* rather than aggregated from pre-existing node features.

Two-layer design:
  1. EdgeToNodeLayer: for every node, mean-aggregate the (transformed) attributes of its outgoing
     edges and, separately, its incoming edges, then concatenate the two. Kept separate rather
     than merged into one undirected aggregate because direction is real signal here (a scanning
     host has high out-aggregate/low in-aggregate; a DDoS reflector is the reverse) -- collapsing
     them the way pipeline/graph_features.py's component-size calculation does would throw that
     signal away.
  2. NodeSAGELayer: one more hop of standard inductive GraphSAGE-mean over the graph's *structure*
     (edge_index only, ignoring edge_attr this time) -- lets a host's embedding pick up a
     one-hop summary of its neighbors' own edge-derived state, the mechanism that should let this
     encoder pick up lateral-movement clusters (dense local neighborhoods) the same way
     pipeline/graph_features.py's `graph_component_size` does, but as a learned representation
     instead of a hand-computed scalar.

Inductive by construction (GraphSAGE, not spectral GCN) -- a host never seen during training is
handled the same as any other: its embedding is still computed from its own edges' attributes,
no fixed node-id embedding table involved anywhere in this module.

Operates on ONE window's graph per call (batched training across windows is not implemented here
-- WindowGraph objects vary in node/edge count per window, so a batching scheme belongs in
whatever training script eventually consumes this, not in the encoder itself).
"""
from __future__ import annotations

import numpy as np
import torch
import torch.nn as nn

from pipeline.graph_builder import WindowGraph


def _scatter_mean(values: torch.Tensor, index: torch.Tensor, n_nodes: int) -> torch.Tensor:
    """Mean of `values` (E, D) grouped by `index` (E,) into (n_nodes, D). Nodes with no
    contributing edges get an all-zero row -- e.g. a host that only sends and never receives has
    a zero "incoming" aggregate, which is itself informative (see EdgeToNodeLayer's docstring)
    rather than an error case to special-case around."""
    d = values.shape[-1]
    out = torch.zeros((n_nodes, d), dtype=values.dtype, device=values.device)
    counts = torch.zeros((n_nodes, 1), dtype=values.dtype, device=values.device)
    if values.shape[0] == 0:
        return out
    out.index_add_(0, index, values)
    counts.index_add_(0, index, torch.ones((values.shape[0], 1), dtype=values.dtype, device=values.device))
    return out / counts.clamp(min=1.0)


class EdgeToNodeLayer(nn.Module):
    def __init__(self, edge_dim: int, hidden_dim: int):
        super().__init__()
        self.edge_mlp = nn.Sequential(nn.Linear(edge_dim, hidden_dim), nn.ReLU())

    def forward(self, edge_index: torch.Tensor, edge_attr: torch.Tensor, n_nodes: int) -> torch.Tensor:
        """edge_index: (2, E) long, edge_attr: (E, edge_dim) -> node embeddings (n_nodes, 2*hidden_dim),
        [outgoing_aggregate | incoming_aggregate] per node."""
        msg = self.edge_mlp(edge_attr) if edge_attr.shape[0] > 0 else edge_attr.new_zeros((0, self.edge_mlp[0].out_features))
        src, dst = edge_index[0], edge_index[1]
        out_agg = _scatter_mean(msg, src, n_nodes)  # what this node sends
        in_agg = _scatter_mean(msg, dst, n_nodes)   # what this node receives
        return torch.cat([out_agg, in_agg], dim=-1)


class NodeSAGELayer(nn.Module):
    """Standard inductive GraphSAGE-mean over neighbor node embeddings, using only edge_index
    (graph structure) -- edge_attr already did its job in EdgeToNodeLayer."""

    def __init__(self, in_dim: int, out_dim: int):
        super().__init__()
        self.self_proj = nn.Linear(in_dim, out_dim)
        self.neigh_proj = nn.Linear(in_dim, out_dim)

    def forward(self, node_embed: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        n_nodes = node_embed.shape[0]
        if edge_index.shape[1] == 0:
            neigh_mean = torch.zeros_like(node_embed)
        else:
            src, dst = edge_index[0], edge_index[1]
            # Undirected neighbor mean here (unlike EdgeToNodeLayer): this hop is about "who am I
            # structurally near," not "who do I send to/receive from" -- that direction split
            # already happened at the edge layer.
            neighbor_feats = torch.cat([node_embed[dst], node_embed[src]], dim=0)
            neighbor_of = torch.cat([src, dst], dim=0)
            neigh_mean = _scatter_mean(neighbor_feats, neighbor_of, n_nodes)
        return torch.relu(self.self_proj(node_embed) + self.neigh_proj(neigh_mean))


class GraphSAGEEncoder(nn.Module):
    """Full two-layer encoder: WindowGraph -> per-node embeddings (n_nodes, out_dim)."""

    def __init__(self, edge_dim: int, hidden_dim: int = 16, out_dim: int = 16):
        super().__init__()
        self.edge_to_node = EdgeToNodeLayer(edge_dim, hidden_dim)
        self.node_sage = NodeSAGELayer(2 * hidden_dim, out_dim)
        self.out_dim = out_dim

    def forward(self, edge_index: torch.Tensor, edge_attr: torch.Tensor, n_nodes: int) -> torch.Tensor:
        h0 = self.edge_to_node(edge_index, edge_attr, n_nodes)
        return self.node_sage(h0, edge_index)

    def embed_window_graph(self, graph: WindowGraph, device: torch.device | None = None) -> torch.Tensor:
        """Convenience wrapper: WindowGraph (numpy) -> (n_nodes, out_dim) tensor of node
        embeddings, index-aligned with graph.node_ids / graph.node_index."""
        device = device or next(self.parameters()).device
        edge_index = torch.as_tensor(graph.edge_index, dtype=torch.long, device=device)
        edge_attr = torch.as_tensor(graph.edge_attr, dtype=torch.float32, device=device)
        return self.forward(edge_index, edge_attr, graph.n_nodes)

    def embed_host(self, graph: WindowGraph, host_ip: str, device: torch.device | None = None) -> torch.Tensor:
        """The single embedding a caller actually wants: this host's row from the window's node
        embeddings, to concatenate onto that host's existing per-window feature vector before it
        enters the Transformer. Returns a zero vector if `host_ip` had no flows in this window
        (e.g. it appears in the sequence but was silent this particular window) -- consistent with
        how the rest of this pipeline zero-fills absent signal rather than erroring."""
        device = device or next(self.parameters()).device
        if host_ip not in graph.node_index:
            return torch.zeros(self.out_dim, device=device)
        embeddings = self.embed_window_graph(graph, device=device)
        return embeddings[graph.node_index[host_ip]]
