"""Per-window host-interaction graphs for GNN message passing.

pipeline/graph_features.py already computes five *scalar* graph-derived features
(out-degree, fan-out ratio, component size, etc.) per (src_ip, window) and folds them into the
existing flat feature vector the Transformer world model consumes. This module is a different,
complementary piece: it builds the actual per-window graph *structure* (nodes, edges, edge
features) that a message-passing GNN encoder needs, rather than pre-summarizing it into a
handful of scalars. See docs/05-related-work-and-competitive-landscape.md Section 4 for why this
is worth having (`raghuraj72/Vanguard-GWM`, `mithun-afk/ST-WM-Cyber` — competing teams already
building graph/spatial-temporal world models) and the follow-up research note in that doc on how
this integrates with the existing Transformer rollout.

Design (see that research note for the reasoning): **node = host (IP)**, **edge = one flow**,
with the flow's own numeric feature vector as the edge attribute (E-GraphSAGE-style — edge
features carry more signal than node features for flow data, per the current literature this
project surveyed). Edges are directed (src -> dst): direction is real signal for this domain
(a C2 beacon's edges point outward from the compromised host; a DDoS reflector's point inward),
so it isn't collapsed the way pipeline/graph_features.py's component-size calculation collapses
it for a different purpose.

This module only builds the graph -- turning it into a learned embedding (a GraphSAGE/GAT
readout layer) is a separate, not-yet-built piece (models/graph_encoder.py, still to come).
Kept as two modules on purpose: the graph structure has value on its own (e.g. for a future
graph-visualization view) independent of which encoder architecture eventually consumes it.
"""
from __future__ import annotations

import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

# The per-flow numeric columns available before windowing (pipeline/windowing.py's own
# `numeric_cols` list, duplicated rather than imported — that list is windowing's local
# aggregation detail, this is a different consumer of the same raw flow rows). These become
# each edge's feature vector: one row of flow-level signal per (src_ip -> dst_ip) contact.
EDGE_FEATURE_COLS: list[str] = [
    "total_pkts",
    "total_bytes",
    "duration_s",
    "syn_cnt",
    "ack_cnt",
    "fin_cnt",
    "rst_cnt",
    "psh_cnt",
    "urg_cnt",
    "iat_mean",
    "iat_std",
    "iat_max",
    "bidir_ratio",
    "is_tcp",
    "is_udp",
]


@dataclass
class WindowGraph:
    """One window's host-interaction graph, ready for a GNN message-passing layer.

    `node_ids[i]` is the host IP at index `i`; `edge_index[:, e] = [src_idx, dst_idx]` for edge
    `e`, matching the (2, E) convention most GNN libraries (PyG included) expect, so this can be
    handed to either a hand-rolled aggregation layer or a real PyG `MessagePassing` module without
    reshaping. Kept dependency-free (numpy only) since torch_geometric isn't in this project's
    dependency set (see requirements.txt) -- models/graph_encoder.py can convert to torch tensors
    at the point it actually needs them.
    """

    window_key: Any  # window_start, or (scenario_id, window_start) when scenario_id is present
    node_ids: list[str]
    node_index: dict[str, int]
    edge_index: np.ndarray  # (2, E) int64
    edge_attr: np.ndarray   # (E, F) float32, F = len(edge_feature_cols)
    has_ip_data: bool = True

    @property
    def n_nodes(self) -> int:
        return len(self.node_ids)

    @property
    def n_edges(self) -> int:
        return self.edge_index.shape[1]


def build_window_graph(
    window_flows: pd.DataFrame,
    window_key: Any = None,
    edge_feature_cols: list[str] | None = None,
) -> WindowGraph:
    """Build a single WindowGraph from one window's already-filtered flow rows.

    Parameters
    ----------
    window_flows :
        Flow rows for exactly one (src_ip, window_start) group's window -- i.e. all flows whose
        `window_start` falls in this window, across every host, not just one host's own flows.
        Required columns: `src_ip`, `dst_ip`. Missing edge-feature columns are treated as 0.0
        (mirrors how pipeline/windowing.py zero-fills unavailable telemetry elsewhere).
    window_key :
        Opaque identifier carried through onto the returned WindowGraph for the caller's own
        bookkeeping (e.g. the window_start timestamp, or a (scenario_id, window_start) tuple) --
        not used internally.
    edge_feature_cols :
        Defaults to EDGE_FEATURE_COLS.

    Graphs with no real IP data (pseudo-host days, see pipeline/flow_features.py's
    `_fill_missing_ip_columns`) collapse to a single self-looped node with zeroed edge features --
    consistent with how every other feature in this pipeline zero-fills unavailable IP telemetry,
    rather than raising or silently returning an empty graph a downstream encoder isn't expecting.
    """
    cols = edge_feature_cols or EDGE_FEATURE_COLS

    if window_flows.empty:
        return WindowGraph(window_key, [], {}, np.zeros((2, 0), dtype=np.int64),
                            np.zeros((0, len(cols)), dtype=np.float32), has_ip_data=True)

    has_ip_data = bool(window_flows["has_ip_data"].astype(bool).any()) if "has_ip_data" in window_flows.columns else True

    src = window_flows["src_ip"].astype(str)
    dst = window_flows["dst_ip"].astype(str) if has_ip_data else src  # pseudo-host: self-loop only

    node_ids = sorted(pd.unique(pd.concat([src, dst], ignore_index=True)))
    node_index = {ip: i for i, ip in enumerate(node_ids)}

    n_edges = len(window_flows)
    edge_index = np.empty((2, n_edges), dtype=np.int64)
    edge_index[0] = src.map(node_index).to_numpy()
    edge_index[1] = dst.map(node_index).to_numpy()

    edge_attr = np.zeros((n_edges, len(cols)), dtype=np.float32)
    if has_ip_data:
        for j, col in enumerate(cols):
            if col in window_flows.columns:
                edge_attr[:, j] = pd.to_numeric(window_flows[col], errors="coerce").fillna(0.0).to_numpy()

    return WindowGraph(window_key, node_ids, node_index, edge_index, edge_attr, has_ip_data)


def build_window_graphs(
    flow_df: pd.DataFrame,
    config: dict[str, Any],
    edge_feature_cols: list[str] | None = None,
) -> dict[Any, WindowGraph]:
    """Build one WindowGraph per time window across a whole dataset (or scenario), for
    precomputing training-time graph sequences. Mirrors pipeline/graph_features.py's own
    windowing/grouping conventions (same `window_start` floor, same `scenario_id` handling) so
    the two feature paths stay aligned on exactly which flows fall in which window.
    """
    window_seconds = int(config["windowing"]["window_seconds"])
    df = flow_df.copy()

    if "window_start" not in df.columns:
        df["window_start"] = df["timestamp"].dt.floor(f"{window_seconds}s")
    if "has_ip_data" not in df.columns:
        df["has_ip_data"] = 1.0

    group_cols = ["scenario_id", "window_start"] if "scenario_id" in df.columns else ["window_start"]

    graphs: dict[Any, WindowGraph] = {}
    for key, wdf in df.groupby(group_cols, sort=False, observed=True, dropna=False):
        graphs[key] = build_window_graph(wdf, window_key=key, edge_feature_cols=edge_feature_cols)
    return graphs


def save_window_graphs(graphs: dict[Any, WindowGraph], path: str | Path) -> None:
    """Persist a {window_key: WindowGraph} dict built by build_window_graphs to disk (plain
    pickle -- WindowGraph is a small numpy-only dataclass, no torch tensors involved, so there's
    no device/serialization concern beyond what pickle already handles). Read back by
    load_window_graphs. Used by pipeline/build_dataset.py and build_ctu13_dataset.py so joint GNN
    training (models/world_model_joint.py) can look up the exact graph behind any of a sequence's
    input steps without re-parsing the raw flow CSVs at training time.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        pickle.dump(graphs, f, protocol=pickle.HIGHEST_PROTOCOL)


class _RestrictedUnpickler(pickle.Unpickler):
    """Audit G12: window_graphs.pkl only ever holds WindowGraph objects, numpy arrays and pandas
    Timestamp keys, so only those may be reconstructed -- a tampered file cannot import arbitrary
    callables (os.system etc.). Same pattern as models/baseline_lr.py."""

    _ALLOWED_PREFIXES = ("numpy", "pipeline.graph_builder", "pandas._libs.tslibs.", "collections.")
    _ALLOWED_EXACT = {("datetime", "datetime"), ("datetime", "timedelta"), ("datetime", "timezone"),
                      ("_codecs", "encode")}
    _ALLOWED_BUILTINS = {"set", "frozenset", "slice", "complex", "list", "dict", "tuple", "bytearray"}

    def find_class(self, module, name):
        if (
            module == "numpy" or module.startswith(self._ALLOWED_PREFIXES)
            or (module, name) in self._ALLOWED_EXACT
            or (module == "builtins" and name in self._ALLOWED_BUILTINS)
        ):
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"Blocked global {module}.{name} in window-graphs file")


def load_window_graphs(path: str | Path) -> dict[Any, WindowGraph]:
    with open(path, "rb") as f:
        return _RestrictedUnpickler(f).load()


def window_graph_key(window_time: Any, scenario_id: Any = None) -> Any:
    """Reconstructs the exact dict key build_window_graphs uses for a given window, from a raw
    `window_time` value read back out of a saved sequence (models.dataset.SequenceDataset.
    window_times) -- e.g. a numpy.datetime64 (possibly a different time resolution than the
    pd.Timestamp objects build_window_graphs' own pandas groupby produces as keys). Wrapping this
    in pd.Timestamp(...) normalizes resolution so the reconstructed key hashes/compares equal to
    the original — confirmed empirically, since numpy.datetime64 and pd.Timestamp at matching
    instants but different declared units (e.g. 'us' vs 'ns') do NOT hash equal to each other
    directly. Used by joint GNN training (models/world_model_joint.py) to look up the WindowGraph
    behind any of a sequence's saved input steps.
    """
    ts = pd.Timestamp(window_time)
    return (scenario_id, ts) if scenario_id is not None else (ts,)
