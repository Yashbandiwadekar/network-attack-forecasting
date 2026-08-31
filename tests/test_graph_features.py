"""Tests for pipeline/graph_features.py.

Covers:
- Basic shape and value correctness
- Zero-fill when has_ip_data == 0 (no real IP data)
- Destination entropy edge cases (single dst, uniform distribution)
- Fan-out / fan-in ratios
- Connected component sizes
- Scenario-ID-aware grouping (CTU-13 multi-scenario case)
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from pipeline.graph_features import build_graph_window_features, GRAPH_FEATURE_NAMES

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CONFIG = {
    "windowing": {
        "window_seconds": 10,
        "sequence_length": 2,
        "forecast_horizon": 2,
        "recon_port_scan_threshold": 0.5,
    },
    "features": {
        "flow_level": [],
        "graph_level": GRAPH_FEATURE_NAMES,
        "packet_level": [],
    },
}

BASE_TIME = pd.Timestamp("2024-01-01 00:00:00")


def _make_flows(rows: list[dict]) -> pd.DataFrame:
    """Build a minimal flow DataFrame from a list of dicts.

    Each dict may contain any subset of: timestamp (seconds offset from
    BASE_TIME), src_ip, dst_ip, has_ip_data, scenario_id.
    """
    records = []
    for r in rows:
        rec = {
            "timestamp": BASE_TIME + pd.Timedelta(seconds=r.get("t", 0)),
            "src_ip": str(r.get("src_ip", "10.0.0.1")),
            "dst_ip": str(r.get("dst_ip", "10.0.0.2")),
            "has_ip_data": float(r.get("has_ip_data", 1.0)),
            "total_pkts": int(r.get("total_pkts", 1)),
            "total_bytes": int(r.get("total_bytes", 100)),
            "label": r.get("label", "BENIGN"),
        }
        if "scenario_id" in r:
            rec["scenario_id"] = r["scenario_id"]
        records.append(rec)
    return pd.DataFrame(records)


# ---------------------------------------------------------------------------
# Basic sanity
# ---------------------------------------------------------------------------

def test_output_columns_present():
    """All five graph feature columns must be present in the output."""
    df = _make_flows([
        {"t": 0, "src_ip": "A", "dst_ip": "B"},
        {"t": 1, "src_ip": "A", "dst_ip": "C"},
    ])
    out = build_graph_window_features(df, CONFIG)
    for col in GRAPH_FEATURE_NAMES:
        assert col in out.columns, f"Missing column: {col}"


def test_output_row_per_src_ip_window():
    """One output row per (src_ip, window_start)."""
    df = _make_flows([
        {"t": 0, "src_ip": "A", "dst_ip": "X"},
        {"t": 0, "src_ip": "B", "dst_ip": "Y"},
        {"t": 10, "src_ip": "A", "dst_ip": "Z"},  # second window for A
    ])
    out = build_graph_window_features(df, CONFIG)
    assert len(out) == 3  # (A, win0), (B, win0), (A, win1)


def test_out_degree_single_dst():
    """One flow to one destination → out_degree == 1."""
    df = _make_flows([{"t": 0, "src_ip": "A", "dst_ip": "X"}])
    out = build_graph_window_features(df, CONFIG)
    row = out[out["src_ip"] == "A"].iloc[0]
    assert row["graph_out_degree"] == 1.0


def test_out_degree_multiple_dsts():
    """Three flows to three distinct destinations → out_degree == 3."""
    df = _make_flows([
        {"t": 0, "src_ip": "A", "dst_ip": "X"},
        {"t": 1, "src_ip": "A", "dst_ip": "Y"},
        {"t": 2, "src_ip": "A", "dst_ip": "Z"},
    ])
    out = build_graph_window_features(df, CONFIG)
    row = out[out["src_ip"] == "A"].iloc[0]
    assert row["graph_out_degree"] == 3.0


# ---------------------------------------------------------------------------
# Fan-out ratio
# ---------------------------------------------------------------------------

def test_fan_out_ratio_all_unique():
    """out_degree == flow_count → fan_out_ratio == 1.0 (perfect spread)."""
    df = _make_flows([
        {"t": 0, "src_ip": "A", "dst_ip": "X"},
        {"t": 1, "src_ip": "A", "dst_ip": "Y"},
        {"t": 2, "src_ip": "A", "dst_ip": "Z"},
    ])
    out = build_graph_window_features(df, CONFIG)
    row = out[out["src_ip"] == "A"].iloc[0]
    assert abs(row["graph_fan_out_ratio"] - 1.0) < 1e-9


def test_fan_out_ratio_all_same_dst():
    """out_degree == 1, flow_count == 3 → fan_out_ratio == 1/3."""
    df = _make_flows([
        {"t": 0, "src_ip": "A", "dst_ip": "X"},
        {"t": 1, "src_ip": "A", "dst_ip": "X"},
        {"t": 2, "src_ip": "A", "dst_ip": "X"},
    ])
    out = build_graph_window_features(df, CONFIG)
    row = out[out["src_ip"] == "A"].iloc[0]
    assert abs(row["graph_fan_out_ratio"] - (1 / 3)) < 1e-9


# ---------------------------------------------------------------------------
# Destination entropy
# ---------------------------------------------------------------------------

def test_dst_entropy_single_destination():
    """All flows to the same dst → entropy == 0."""
    df = _make_flows([
        {"t": 0, "src_ip": "A", "dst_ip": "X"},
        {"t": 1, "src_ip": "A", "dst_ip": "X"},
        {"t": 2, "src_ip": "A", "dst_ip": "X"},
    ])
    out = build_graph_window_features(df, CONFIG)
    row = out[out["src_ip"] == "A"].iloc[0]
    assert abs(row["graph_dst_entropy"]) < 1e-6


def test_dst_entropy_uniform_two_destinations():
    """Two flows, each to a distinct dst → entropy == log2(2) == 1.0."""
    df = _make_flows([
        {"t": 0, "src_ip": "A", "dst_ip": "X"},
        {"t": 1, "src_ip": "A", "dst_ip": "Y"},
    ])
    out = build_graph_window_features(df, CONFIG)
    row = out[out["src_ip"] == "A"].iloc[0]
    assert abs(row["graph_dst_entropy"] - 1.0) < 1e-6


def test_dst_entropy_uniform_four_destinations():
    """Four equiprobable destinations → entropy == log2(4) == 2.0."""
    df = _make_flows([
        {"t": i, "src_ip": "A", "dst_ip": str(i)} for i in range(4)
    ])
    out = build_graph_window_features(df, CONFIG)
    row = out[out["src_ip"] == "A"].iloc[0]
    assert abs(row["graph_dst_entropy"] - 2.0) < 1e-6


# ---------------------------------------------------------------------------
# Connected component size
# ---------------------------------------------------------------------------

def test_component_size_isolated_pair():
    """Two isolated hosts (A→X, B→Y) → component size 2 for each."""
    df = _make_flows([
        {"t": 0, "src_ip": "A", "dst_ip": "X"},
        {"t": 0, "src_ip": "B", "dst_ip": "Y"},
    ])
    out = build_graph_window_features(df, CONFIG)
    row_a = out[out["src_ip"] == "A"].iloc[0]
    row_b = out[out["src_ip"] == "B"].iloc[0]
    assert row_a["graph_component_size"] == 2.0  # A and X in one component
    assert row_b["graph_component_size"] == 2.0  # B and Y in another


def test_component_size_star_topology():
    """A → X, A → Y, B → X creates one connected component of size 4 (A,B,X,Y)."""
    df = _make_flows([
        {"t": 0, "src_ip": "A", "dst_ip": "X"},
        {"t": 1, "src_ip": "A", "dst_ip": "Y"},
        {"t": 2, "src_ip": "B", "dst_ip": "X"},
    ])
    out = build_graph_window_features(df, CONFIG)
    # A is connected to X, Y. B is connected to X. So all four in one component.
    for _, row in out.iterrows():
        assert row["graph_component_size"] == 4.0, (
            f"Expected component size 4 for all hosts; got {row['graph_component_size']}"
        )


# ---------------------------------------------------------------------------
# Fan-in ratio
# ---------------------------------------------------------------------------

def test_fan_in_ratio_no_sharing():
    """Two src_ips contact disjoint dst_ips → fan_in_ratio reflects only self."""
    df = _make_flows([
        {"t": 0, "src_ip": "A", "dst_ip": "X"},
        {"t": 0, "src_ip": "B", "dst_ip": "Y"},
    ])
    out = build_graph_window_features(df, CONFIG)
    # Each dst_ip has exactly 1 unique src_ip → mean_dst_fan_in == 1.0
    # fan_in_ratio = 1 / flow_count = 1 / 1 = 1.0
    row_a = out[out["src_ip"] == "A"].iloc[0]
    assert abs(row_a["graph_fan_in_ratio"] - 1.0) < 1e-9


def test_fan_in_ratio_shared_destination():
    """Both A and B contact X → fan_in for X == 2. A's fan_in_ratio > B's fan_in_ratio == 1."""
    df = _make_flows([
        {"t": 0, "src_ip": "A", "dst_ip": "X"},
        {"t": 0, "src_ip": "A", "dst_ip": "X"},  # two flows to same dst
        {"t": 0, "src_ip": "B", "dst_ip": "X"},
    ])
    out = build_graph_window_features(df, CONFIG)
    # X is contacted by 2 unique srcs (A, B). mean_dst_fan_in for A == 2.
    row_a = out[out["src_ip"] == "A"].iloc[0]
    # fan_in_ratio_A = 2 / flow_count_A = 2 / 2 = 1.0
    assert abs(row_a["graph_fan_in_ratio"] - 1.0) < 1e-9

    row_b = out[out["src_ip"] == "B"].iloc[0]
    # fan_in_ratio_B = 2 / flow_count_B = 2 / 1 = 2.0
    assert abs(row_b["graph_fan_in_ratio"] - 2.0) < 1e-9


# ---------------------------------------------------------------------------
# Zero-fill when has_ip_data == 0
# ---------------------------------------------------------------------------

def test_zero_fill_no_ip_data():
    """All graph features must be 0.0 when has_ip_data == 0."""
    df = _make_flows([
        {"t": 0, "src_ip": "NETWORK-2024-01-01", "dst_ip": "UNKNOWN", "has_ip_data": 0.0},
        {"t": 1, "src_ip": "NETWORK-2024-01-01", "dst_ip": "UNKNOWN", "has_ip_data": 0.0},
    ])
    out = build_graph_window_features(df, CONFIG)
    assert len(out) == 1
    for col in GRAPH_FEATURE_NAMES:
        assert out.iloc[0][col] == 0.0, (
            f"Expected 0.0 for {col} when has_ip_data=0; got {out.iloc[0][col]}"
        )


def test_mixed_ip_availability():
    """Windows with has_ip_data=1 compute real features; those with 0 are zero-filled."""
    df = _make_flows([
        # Window 0: real IP data
        {"t": 0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "has_ip_data": 1.0},
        {"t": 1, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.3", "has_ip_data": 1.0},
        # Window 1 (t+10): pseudo-host, no real IPs
        {"t": 10, "src_ip": "NETWORK-2024-01-01", "dst_ip": "UNKNOWN", "has_ip_data": 0.0},
    ])
    out = build_graph_window_features(df, CONFIG)

    real_row = out[out["src_ip"] == "10.0.0.1"].iloc[0]
    pseudo_row = out[out["src_ip"] == "NETWORK-2024-01-01"].iloc[0]

    assert real_row["graph_out_degree"] == 2.0
    assert real_row["graph_dst_entropy"] > 0.0

    for col in GRAPH_FEATURE_NAMES:
        assert pseudo_row[col] == 0.0, (
            f"Expected 0.0 for {col} in pseudo-host row; got {pseudo_row[col]}"
        )


# ---------------------------------------------------------------------------
# Scenario-ID-aware grouping (CTU-13 multi-scenario)
# ---------------------------------------------------------------------------

def test_scenario_id_isolation():
    """Hosts from different scenarios must NOT share a connected component."""
    df = _make_flows([
        # Scenario 1: A → X
        {"t": 0, "src_ip": "A", "dst_ip": "X", "scenario_id": 1},
        # Scenario 2: A → X (same IPs, different scenario)
        {"t": 0, "src_ip": "A", "dst_ip": "X", "scenario_id": 2},
    ])
    out = build_graph_window_features(df, CONFIG)
    assert "scenario_id" in out.columns
    assert len(out) == 2  # one row per (scenario_id, src_ip, window_start)

    s1 = out[out["scenario_id"] == 1].iloc[0]
    s2 = out[out["scenario_id"] == 2].iloc[0]
    # Each scenario has only 2 nodes (A and X) in its own window
    assert s1["graph_component_size"] == 2.0
    assert s2["graph_component_size"] == 2.0


def test_scenario_id_separate_fan_in():
    """Fan-in counts must be per-scenario, not cross-scenario."""
    df = _make_flows([
        # Scenario 1: only A → X
        {"t": 0, "src_ip": "A", "dst_ip": "X", "scenario_id": 1},
        # Scenario 2: both A → X and B → X
        {"t": 0, "src_ip": "A", "dst_ip": "X", "scenario_id": 2},
        {"t": 0, "src_ip": "B", "dst_ip": "X", "scenario_id": 2},
    ])
    out = build_graph_window_features(df, CONFIG)

    s1_a = out[(out["scenario_id"] == 1) & (out["src_ip"] == "A")].iloc[0]
    s2_a = out[(out["scenario_id"] == 2) & (out["src_ip"] == "A")].iloc[0]

    # Scenario 1: dst X has fan_in 1 → fan_in_ratio_A = 1/1 = 1.0
    assert abs(s1_a["graph_fan_in_ratio"] - 1.0) < 1e-9
    # Scenario 2: dst X has fan_in 2 → fan_in_ratio_A = 2/1 = 2.0
    assert abs(s2_a["graph_fan_in_ratio"] - 2.0) < 1e-9


# ---------------------------------------------------------------------------
# All features are finite (no NaN / Inf)
# ---------------------------------------------------------------------------

def test_all_values_finite():
    """No NaN or Inf should appear in graph features, even for edge-case flows."""
    rng = np.random.default_rng(42)
    n = 200
    src_ips = [f"10.0.0.{rng.integers(1, 20)}" for _ in range(n)]
    dst_ips = [f"10.0.1.{rng.integers(1, 50)}" for _ in range(n)]
    times = rng.integers(0, 60, size=n)

    df = _make_flows([
        {"t": int(times[i]), "src_ip": src_ips[i], "dst_ip": dst_ips[i]}
        for i in range(n)
    ])
    out = build_graph_window_features(df, CONFIG)

    for col in GRAPH_FEATURE_NAMES:
        vals = out[col].to_numpy()
        assert np.all(np.isfinite(vals)), (
            f"Column {col} contains non-finite values: {vals[~np.isfinite(vals)]}"
        )
