import numpy as np
import pandas as pd

from pipeline.graph_builder import EDGE_FEATURE_COLS, build_window_graph, build_window_graphs


def _flows(rows):
    """rows: list of (src_ip, dst_ip, total_pkts) tuples -> minimal flow DataFrame."""
    df = pd.DataFrame(rows, columns=["src_ip", "dst_ip", "total_pkts"])
    df["has_ip_data"] = 1.0
    return df


def test_nodes_are_unique_hosts_across_src_and_dst():
    flows = _flows([("10.0.0.1", "10.0.0.2", 5), ("10.0.0.2", "10.0.0.3", 2)])
    graph = build_window_graph(flows)

    assert graph.node_ids == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert graph.n_nodes == 3
    assert graph.n_edges == 2


def test_edge_index_matches_src_dst_pairs_via_node_index():
    flows = _flows([("A", "B", 1), ("B", "C", 2)])
    graph = build_window_graph(flows)

    for e in range(graph.n_edges):
        src_idx, dst_idx = graph.edge_index[:, e]
        src_ip = flows.iloc[e]["src_ip"]
        dst_ip = flows.iloc[e]["dst_ip"]
        assert graph.node_ids[src_idx] == src_ip
        assert graph.node_ids[dst_idx] == dst_ip


def test_edges_are_directed_not_collapsed_like_the_scalar_graph_features():
    # A -> B and B -> A must remain two distinct directed edges, not one undirected edge.
    flows = _flows([("A", "B", 1), ("B", "A", 1)])
    graph = build_window_graph(flows)

    assert graph.n_edges == 2
    assert not np.array_equal(graph.edge_index[:, 0], graph.edge_index[:, 1])


def test_edge_attr_shape_and_values_come_from_flow_feature_columns():
    flows = pd.DataFrame({
        "src_ip": ["A", "B"],
        "dst_ip": ["B", "C"],
        "total_pkts": [10.0, 20.0],
        "total_bytes": [1000.0, 2000.0],
        "has_ip_data": [1.0, 1.0],
    })
    graph = build_window_graph(flows, edge_feature_cols=["total_pkts", "total_bytes"])

    assert graph.edge_attr.shape == (2, 2)
    assert list(graph.edge_attr[0]) == [10.0, 1000.0]
    assert list(graph.edge_attr[1]) == [20.0, 2000.0]


def test_missing_edge_feature_column_zero_fills_rather_than_erroring():
    flows = _flows([("A", "B", 1)])
    graph = build_window_graph(flows, edge_feature_cols=["total_pkts", "duration_s"])

    assert graph.edge_attr.shape == (1, 2)
    assert graph.edge_attr[0, 0] == 1.0
    assert graph.edge_attr[0, 1] == 0.0  # duration_s absent from the input frame


def test_no_ip_data_window_collapses_to_self_loop_with_zeroed_features():
    flows = pd.DataFrame({
        "src_ip": ["NETWORK-2018-02-14"] * 3,
        "dst_ip": ["10.0.0.5", "10.0.0.6", "10.0.0.7"],  # would normally differ, but ignored
        "total_pkts": [10.0, 20.0, 30.0],
        "has_ip_data": [0.0, 0.0, 0.0],
    })
    graph = build_window_graph(flows)

    assert graph.node_ids == ["NETWORK-2018-02-14"]
    assert graph.has_ip_data is False
    assert np.all(graph.edge_attr == 0.0)


def test_empty_window_returns_an_empty_graph_not_an_error():
    graph = build_window_graph(pd.DataFrame(columns=["src_ip", "dst_ip"]))
    assert graph.n_nodes == 0
    assert graph.n_edges == 0
    assert graph.edge_attr.shape == (0, len(EDGE_FEATURE_COLS))


def test_build_window_graphs_groups_by_window_start():
    df = pd.DataFrame({
        "src_ip": ["A", "B", "A"],
        "dst_ip": ["B", "C", "C"],
        "timestamp": pd.to_datetime(["2024-01-01 00:00:01", "2024-01-01 00:00:02", "2024-01-01 00:00:15"]),
        "total_pkts": [1.0, 2.0, 3.0],
        "has_ip_data": [1.0, 1.0, 1.0],
    })
    config = {"windowing": {"window_seconds": 10}}
    graphs = build_window_graphs(df, config)

    assert len(graphs) == 2  # one window for [0s,10s), one for [10s,20s)
    first_window_graph = graphs[list(graphs.keys())[0]]
    assert first_window_graph.n_edges == 2


def test_build_window_graphs_respects_scenario_id_grouping():
    df = pd.DataFrame({
        "scenario_id": ["s1", "s2"],
        "src_ip": ["A", "A"],
        "dst_ip": ["B", "B"],
        "timestamp": pd.to_datetime(["2024-01-01 00:00:01", "2024-01-01 00:00:01"]),
        "total_pkts": [1.0, 1.0],
        "has_ip_data": [1.0, 1.0],
    })
    config = {"windowing": {"window_seconds": 10}}
    graphs = build_window_graphs(df, config)

    assert len(graphs) == 2  # same window_start, different scenario_id -> separate graphs
