"""Disjoint-union batching for pipeline.graph_builder.WindowGraph objects, so
models.graph_encoder.GraphSAGEEncoder can process many per-window graphs in a single forward
pass instead of one Python-level call per graph.

Why this exists: models/graph_encoder.py's encoder was measured at ~5ms per window graph in
Phase 2's smoke test (0.066s / 13 graphs). Joint training needs a graph embedding for every
(sample, step) pair in a training batch -- up to batch_size * sequence_length lookups per
training step (e.g. 64 * 12 = 768). At ~5ms each via a naive per-item Python loop, that is ~3.8s
per training step, which at ~13,700 steps/epoch on the real CIC-IDS-2018 train split works out to
over 14 hours per epoch -- infeasible. The ~5ms figure is dominated by per-call Python/tensor-
construction overhead, not the actual message-passing math, so batching many graphs into one
disjoint union (the same trick PyTorch Geometric's `Batch` class uses) turns many tiny forward
calls into one larger one, the same way padding/stacking ordinary tensors amortizes per-call
overhead across a batch.

Disjoint union: node indices from each constituent graph are offset by the running total of
nodes already placed in the combined graph, so no edge ever crosses between what were originally
separate graphs -- each sub-graph's nodes only ever receive messages from their own edges, which
is what makes splitting the per-item output back apart afterwards valid. A requested (graph, host)
pair whose host has no edges in that window (silent this step, or the window has no IP data) gets
a one-node isolated placeholder instead of the real graph's nodes -- cheaper than including nodes
whose embedding nothing needs, and _scatter_mean's existing no-incoming-edges zero-fill behavior
(models/graph_encoder.py) then produces exactly the same zero vector GraphSAGEEncoder.embed_host
already returns for this case, so batched and unbatched paths agree.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import torch

from pipeline.graph_builder import WindowGraph


@dataclass
class BatchedGraphInput:
    """The disjoint-union combination of many WindowGraphs, ready for one
    GraphSAGEEncoder.forward call, plus enough bookkeeping to split the output back apart."""

    edge_index: torch.Tensor    # (2, total_E) long, node indices offset into the combined graph
    edge_attr: torch.Tensor     # (total_E, edge_dim) float32
    total_nodes: int
    target_rows: torch.Tensor   # (n_items,) long -- each requested item's row in the combined
                                 # node-embedding output, in input order
    missing_mask: torch.Tensor  # (n_items,) bool -- True where the requested host had no edges
                                 # in that window (see embed_batch for why this needs special
                                 # handling instead of relying on the encoder's own zero-fill)


def batch_window_graphs(
    items: list[tuple[WindowGraph, str]],
    edge_dim: int,
    device: torch.device | None = None,
) -> BatchedGraphInput:
    """items: a flat list of (graph, target_host_ip) pairs -- e.g. every (sample, step) needed
    for one training batch."""
    device = device or torch.device("cpu")

    edge_index_parts: list[np.ndarray] = []
    edge_attr_parts: list[np.ndarray] = []
    target_rows = np.empty(len(items), dtype=np.int64)
    missing_mask = np.zeros(len(items), dtype=bool)

    node_offset = 0
    for i, (graph, host_ip) in enumerate(items):
        if graph.n_nodes == 0 or host_ip not in graph.node_index:
            # Isolated placeholder: gets zeroed explicitly in embed_batch below, since
            # NodeSAGELayer's linear layers have bias terms -- an edgeless node's h0 is zero
            # (via _scatter_mean's own zero-fill), but self_proj(0)+neigh_proj(0) is the bias,
            # not zero, so relying on the encoder alone would NOT match
            # GraphSAGEEncoder.embed_host's hardcoded-zero contract for a missing host.
            missing_mask[i] = True
            target_rows[i] = node_offset
            node_offset += 1
            continue

        if graph.n_edges > 0:
            edge_index_parts.append(graph.edge_index + node_offset)
            edge_attr_parts.append(graph.edge_attr)

        target_rows[i] = node_offset + graph.node_index[host_ip]
        node_offset += graph.n_nodes

    total_nodes = node_offset
    if edge_index_parts:
        combined_edge_index = np.concatenate(edge_index_parts, axis=1)
        combined_edge_attr = np.concatenate(edge_attr_parts, axis=0)
    else:
        combined_edge_index = np.zeros((2, 0), dtype=np.int64)
        combined_edge_attr = np.zeros((0, edge_dim), dtype=np.float32)

    return BatchedGraphInput(
        edge_index=torch.as_tensor(combined_edge_index, dtype=torch.long, device=device),
        edge_attr=torch.as_tensor(combined_edge_attr, dtype=torch.float32, device=device),
        total_nodes=total_nodes,
        target_rows=torch.as_tensor(target_rows, dtype=torch.long, device=device),
        missing_mask=torch.as_tensor(missing_mask, dtype=torch.bool, device=device),
    )


def embed_batch(
    encoder: torch.nn.Module,
    items: list[tuple[WindowGraph, str]],
    edge_dim: int,
    device: torch.device | None = None,
) -> torch.Tensor:
    """One encoder forward pass over the disjoint union of every graph in `items`, returning
    (len(items), out_dim) -- one row per requested (graph, host) pair, in input order. The
    batched replacement for calling GraphSAGEEncoder.embed_host once per item; unlike that method
    this keeps gradients flowing into the encoder's parameters (embed_host is a plain inference
    convenience, not used during joint training).

    Rows for a missing host are zeroed via multiplication rather than left to the encoder's own
    computation -- see batch_window_graphs' docstring for why NodeSAGELayer's bias terms would
    otherwise make them nonzero, unlike embed_host's hardcoded-zero shortcut for the same case.
    """
    device = device or next(encoder.parameters()).device
    batch = batch_window_graphs(items, edge_dim, device=device)
    node_embeddings = encoder(batch.edge_index, batch.edge_attr, batch.total_nodes)
    result = node_embeddings[batch.target_rows]
    keep = (~batch.missing_mask).unsqueeze(-1).to(result.dtype)
    return result * keep
