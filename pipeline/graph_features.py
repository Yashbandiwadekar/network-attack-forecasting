"""Per-window host-interaction graph features.

For each (src_ip, window_start) the pipeline already maintains a row in the
flow-window DataFrame.  This module augments those rows with five features
derived from the *undirected* host-interaction graph built from the raw flows
inside each time window:

    graph_out_degree       — unique destination IPs this host contacted
    graph_fan_out_ratio    — out_degree / flow_count  (spread per flow)
    graph_fan_in_ratio     — avg unique-sources-to-my-dsts / flow_count
                             (how many other hosts share my destinations)
    graph_component_size   — number of nodes in this host's connected component
    graph_dst_entropy      — Shannon entropy of the dst_ip distribution
                             (0 = always same dst, log2(k) = k equiprobable dsts)

Why these matter for attack detection
--------------------------------------
- Scanners have high *fan_out_ratio* (one source, many destinations).
- C2-beaconing bots have low *fan_out_ratio* (few repeated contacts) but show
  up in large components shared with other compromised hosts.
- Lateral movement creates dense clusters → large *component_size*.
- Low *dst_entropy* distinguishes targeted attacks from distributed noise.
- *fan_in_ratio* flags hosts whose destinations are heavily shared
  (DDoS reflectors, pivot points).

When has_ip_data == 0 for a window (CIC-IDS-2018 days that strip real IPs),
all five features are set to 0.0 — consistent with how packet features handle
unavailable telemetry.  The model can therefore rely on these features only
on data that actually carries real IP information (e.g. CTU-13 and the one
CIC-IDS-2018 day with IPs), which is exactly the cross-dataset generalisation
signal we are after.
"""
from __future__ import annotations

from collections import Counter

import numpy as np
import pandas as pd


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _union_find_components(src_list: list, dst_list: list) -> dict[str, int]:
    """Return {node: component_size} for the *undirected* graph defined by
    (src_list[i], dst_list[i]) edges.

    Uses union-find with path compression and union-by-rank.
    No external graph library required.
    """
    parent: dict[str, str] = {}
    rank: dict[str, int] = {}

    def find(x: str) -> str:
        if x not in parent:
            parent[x] = x
            rank[x] = 0
        root = x
        while parent[root] != root:
            root = parent[root]
        # Path compression
        while parent[x] != root:
            parent[x], x = root, parent[x]
        return root

    def union(x: str, y: str) -> None:
        rx, ry = find(x), find(y)
        if rx == ry:
            return
        # Union-by-rank
        if rank[rx] < rank[ry]:
            rx, ry = ry, rx
        parent[ry] = rx
        if rank[rx] == rank[ry]:
            rank[rx] += 1

    for s, d in zip(src_list, dst_list):
        union(str(s), str(d))

    root_counts: Counter = Counter(find(x) for x in parent)
    return {x: root_counts[find(x)] for x in parent}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

GRAPH_FEATURE_NAMES: list[str] = [
    "graph_out_degree",
    "graph_fan_out_ratio",
    "graph_fan_in_ratio",
    "graph_component_size",
    "graph_dst_entropy",
]


def build_graph_window_features(
    flow_df: pd.DataFrame,
    config: dict,
) -> pd.DataFrame:
    """Compute per-window host-interaction graph features from raw flows.

    Parameters
    ----------
    flow_df : pd.DataFrame
        Normalised flow rows as produced by ``pipeline/flow_features.py`` or
        ``pipeline/adapters/ctu13.py``.  Required columns: ``timestamp``,
        ``src_ip``, ``dst_ip``.  Optional: ``has_ip_data`` (defaults to 1.0
        if absent), ``scenario_id`` (preserved as a grouping key when present).
    config : dict
        Project config loaded from ``configs/*.yaml``.  Only
        ``config["windowing"]["window_seconds"]`` is consumed.

    Returns
    -------
    pd.DataFrame
        One row per *(src_ip, window_start)* [plus *scenario_id* when
        present] with exactly the five columns listed in
        :data:`GRAPH_FEATURE_NAMES`.  All features are ``float64``.
    """
    window_seconds = int(config["windowing"]["window_seconds"])

    df = flow_df.copy()

    # ------------------------------------------------------------------ #
    # Ensure derived / optional columns exist                             #
    # ------------------------------------------------------------------ #

    if "window_start" not in df.columns:
        df["window_start"] = df["timestamp"].dt.floor(f"{window_seconds}s")

    if "has_ip_data" not in df.columns:
        df["has_ip_data"] = 1.0

    # Convert IP columns to string to avoid unhashable mixed types
    df["src_ip"] = df["src_ip"].astype(str)
    df["dst_ip"] = df["dst_ip"].astype(str)

    has_scenario = "scenario_id" in df.columns

    # Column groups used throughout
    window_cols: list[str] = (
        ["scenario_id", "window_start"] if has_scenario else ["window_start"]
    )
    src_window_cols: list[str] = (
        ["scenario_id", "src_ip", "window_start"]
        if has_scenario
        else ["src_ip", "window_start"]
    )

    # ------------------------------------------------------------------ #
    # Step 1 – Connected component sizes                                  #
    #                                                                     #
    # Build the full per-window undirected host graph and record the      #
    # component size for every node that appears.                         #
    # ------------------------------------------------------------------ #

    # Maps (window_key_tuple, ip_str) -> component_size (int)
    component_map: dict[tuple, int] = {}

    for w_key, wdf in df.groupby(
        window_cols, sort=False, observed=True, dropna=False
    ):
        if not isinstance(w_key, tuple):
            w_key = (w_key,)
        sizes = _union_find_components(
            wdf["src_ip"].tolist(),
            wdf["dst_ip"].tolist(),
        )
        for ip, sz in sizes.items():
            component_map[(w_key, ip)] = sz

    # ------------------------------------------------------------------ #
    # Step 2 – Fan-in: per dst_ip in a window, how many unique src_ips   #
    # contacted it?  Join back to flows so the aggregation below gets it. #
    # ------------------------------------------------------------------ #

    dst_fan_in = (
        df.groupby(
            window_cols + ["dst_ip"], sort=False, observed=True, dropna=False
        )["src_ip"]
        .nunique()
        .rename("_dst_fan_in")
        .reset_index()
    )
    df = df.merge(dst_fan_in, on=window_cols + ["dst_ip"], how="left")
    df["_dst_fan_in"] = df["_dst_fan_in"].fillna(1.0)

    # ------------------------------------------------------------------ #
    # Step 3 – Vectorised per-(src_ip, window) base aggregation           #
    # ------------------------------------------------------------------ #

    src_agg = (
        df.groupby(src_window_cols, sort=False, observed=True, dropna=False)
        .agg(
            _flow_count=("dst_ip", "size"),
            graph_out_degree=("dst_ip", "nunique"),
            _has_ip_data=("has_ip_data", "first"),
            _mean_dst_fan_in=("_dst_fan_in", "mean"),
        )
        .reset_index()
    )

    fc = src_agg["_flow_count"].to_numpy(dtype=np.float64)
    od = src_agg["graph_out_degree"].to_numpy(dtype=np.float64)
    mfi = src_agg["_mean_dst_fan_in"].to_numpy(dtype=np.float64)

    src_agg["graph_fan_out_ratio"] = np.where(fc > 0, od / fc, 0.0)
    # fan_in_ratio: "on average, how many OTHER src_ips contact the same
    # destinations I contact?" divided by my own flow count — a high value
    # flags shared-destination patterns (reflectors, pivots).
    src_agg["graph_fan_in_ratio"] = np.where(fc > 0, mfi / fc, 0.0)

    # ------------------------------------------------------------------ #
    # Step 4 – Map component sizes back to each aggregated row            #
    # ------------------------------------------------------------------ #

    def _comp_size(row) -> float:
        if has_scenario:
            w_key = (row["scenario_id"], row["window_start"])
        else:
            w_key = (row["window_start"],)
        return float(component_map.get((w_key, row["src_ip"]), 1))

    src_agg["graph_component_size"] = src_agg.apply(_comp_size, axis=1)

    # ------------------------------------------------------------------ #
    # Step 5 – Destination entropy (fully vectorised)                     #
    #                                                                     #
    # H = -Σ p(dst) log₂ p(dst)  over unique dst_ips per (src, window)   #
    # ------------------------------------------------------------------ #

    dst_cnts = (
        df.groupby(src_window_cols + ["dst_ip"], sort=False, observed=True, dropna=False)
        .size()
        .rename("_cnt")
        .reset_index()
    )
    dst_cnts = dst_cnts.merge(
        src_agg[src_window_cols + ["_flow_count"]], on=src_window_cols, how="left"
    )
    dst_cnts["_p"] = dst_cnts["_cnt"] / dst_cnts["_flow_count"].replace(0, np.nan)
    dst_cnts["_h"] = -(dst_cnts["_p"] * np.log2(dst_cnts["_p"] + 1e-12))

    entropy_df = (
        dst_cnts.groupby(src_window_cols, sort=False, observed=True)["_h"]
        .sum()
        .rename("graph_dst_entropy")
        .reset_index()
    )

    src_agg = src_agg.merge(entropy_df, on=src_window_cols, how="left")
    src_agg["graph_dst_entropy"] = src_agg["graph_dst_entropy"].fillna(0.0)

    # ------------------------------------------------------------------ #
    # Step 6 – Zero-fill when no real IP data                             #
    # ------------------------------------------------------------------ #

    no_ip_mask = ~src_agg["_has_ip_data"].astype(bool)
    for col in GRAPH_FEATURE_NAMES:
        src_agg.loc[no_ip_mask, col] = 0.0

    # ------------------------------------------------------------------ #
    # Clean up and return                                                 #
    # ------------------------------------------------------------------ #

    return (
        src_agg[src_window_cols + GRAPH_FEATURE_NAMES]
        .reset_index(drop=True)
    )
