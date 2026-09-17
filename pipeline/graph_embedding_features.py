"""Learned per-window host embedding features, produced by models/graph_encoder.py's GraphSAGE
encoder over pipeline/graph_builder.py's per-window host-interaction graphs.

Complementary to (not a replacement for) pipeline/graph_features.py's five hand-crafted scalar
graph features: those are fixed formulas an analyst could compute by hand (out-degree, entropy,
component size, ...). These EMBED_DIM columns are a learned nonlinear fingerprint of the same
per-window graph structure, letting the world model pick up interaction patterns that don't have
a hand-written formula, at the cost of not being individually interpretable the way each scalar
graph feature is.

Scope, stated honestly (same ethos as every other feature in this pipeline, see e.g.
models/compliance.py's docstring for the pattern): the GraphSAGE encoder here is **frozen at
fixed random initialization**, not jointly trained end-to-end with the Transformer world model.
Randomly-initialized GNNs used as fixed nonlinear structural feature extractors is a real,
citable technique in the graph-learning literature (the graph analogue of a random projection) --
but it does mean these columns encode graph *structure* (who talks to whom, how much, in which
direction) through a fixed lens, not one optimized end-to-end for this forecasting task. Joint
training would require restructuring models/train.py from precomputed flat tensors
(models/dataset.py) to on-the-fly per-batch graph construction -- a larger change tracked as a
follow-up (see docs/05-related-work-and-competitive-landscape.md), not attempted here. The
encoder's weights are re-derived from a fixed seed on every call (`_frozen_encoder`) so this
feature-engineering step is itself fully reproducible across pipeline runs and processes.
"""
from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
import torch

from models.graph_encoder import GraphSAGEEncoder
from pipeline.graph_builder import EDGE_FEATURE_COLS, build_window_graphs

EMBED_DIM = 8
GRAPH_EMBED_SEED = 1337  # fixed so this feature is reproducible without touching global torch RNG

GRAPH_EMBEDDING_FEATURE_NAMES: list[str] = [f"graph_embed_{i}" for i in range(EMBED_DIM)]


def _frozen_encoder(
    edge_dim: int = len(EDGE_FEATURE_COLS), hidden_dim: int = 16, out_dim: int = EMBED_DIM,
    seed: int = GRAPH_EMBED_SEED,
) -> GraphSAGEEncoder:
    """A GraphSAGEEncoder with fixed, reproducible random weights -- see module docstring for why
    this is frozen rather than trained. Uses a local torch.Generator so re-deriving these weights
    never touches (or is affected by) the global RNG state models/train.py relies on for its own
    training reproducibility."""
    encoder = GraphSAGEEncoder(edge_dim, hidden_dim, out_dim)
    gen = torch.Generator().manual_seed(seed)
    with torch.no_grad():
        for p in encoder.parameters():
            p.copy_(torch.empty_like(p).normal_(0.0, 0.1, generator=gen))
    encoder.eval()
    for p in encoder.parameters():
        p.requires_grad_(False)
    return encoder


def build_graph_embedding_window_features(flow_df: pd.DataFrame, config: dict[str, Any]) -> pd.DataFrame:
    """One row per (src_ip, window_start) [+ scenario_id when present] with EMBED_DIM
    `graph_embed_*` columns -- parallel output shape to
    pipeline.graph_features.build_graph_window_features, so it plugs into the same
    merge/zero-fill convention (see pipeline.windowing.merge_graph_embedding_features).

    Runs the frozen encoder once per window graph (not once per host) -- a window's node
    embeddings are computed in a single forward pass and then indexed per host, since
    GraphSAGEEncoder.embed_host would otherwise redundantly recompute the whole graph's
    embeddings for every host in it.
    """
    window_seconds = int(config["windowing"]["window_seconds"])
    df = flow_df.copy()

    if "window_start" not in df.columns:
        df["window_start"] = df["timestamp"].dt.floor(f"{window_seconds}s")
    if "has_ip_data" not in df.columns:
        df["has_ip_data"] = 1.0

    has_scenario = "scenario_id" in df.columns
    key_cols = ["scenario_id", "window_start"] if has_scenario else ["window_start"]
    src_window_cols = (["scenario_id", "src_ip", "window_start"] if has_scenario
                        else ["src_ip", "window_start"])

    graphs = build_window_graphs(df, config)
    encoder = _frozen_encoder()

    rows: list[dict[str, Any]] = []
    with torch.no_grad():
        for window_key, graph in graphs.items():
            if graph.n_nodes == 0:
                continue
            key_parts = window_key if isinstance(window_key, tuple) else (window_key,)
            node_embeddings = (
                encoder.embed_window_graph(graph).numpy() if graph.has_ip_data
                else np.zeros((graph.n_nodes, EMBED_DIM), dtype=np.float32)
            )
            for host, idx in graph.node_index.items():
                row = dict(zip(key_cols, key_parts))
                row["src_ip"] = host
                for j, col in enumerate(GRAPH_EMBEDDING_FEATURE_NAMES):
                    row[col] = float(node_embeddings[idx, j])
                rows.append(row)

    if not rows:
        return pd.DataFrame(columns=src_window_cols + GRAPH_EMBEDDING_FEATURE_NAMES)

    result = pd.DataFrame(rows)
    return result[src_window_cols + GRAPH_EMBEDDING_FEATURE_NAMES]
