import numpy as np
import pandas as pd

from pipeline.graph_embedding_features import (
    EMBED_DIM, GRAPH_EMBEDDING_FEATURE_NAMES, _frozen_encoder, build_graph_embedding_window_features,
)
from pipeline.windowing import merge_graph_embedding_features


def _flow_df():
    return pd.DataFrame({
        "src_ip": ["A", "B", "A", "C"],
        "dst_ip": ["B", "C", "C", "A"],
        "timestamp": pd.to_datetime([
            "2024-01-01 00:00:01", "2024-01-01 00:00:02",
            "2024-01-01 00:00:15", "2024-01-01 00:00:16",
        ]),
        "total_pkts": [1.0, 2.0, 3.0, 4.0],
        "has_ip_data": [1.0, 1.0, 1.0, 1.0],
    })


def _config():
    return {"windowing": {"window_seconds": 10}}


def test_frozen_encoder_is_deterministic_across_calls():
    e1 = _frozen_encoder()
    e2 = _frozen_encoder()
    for p1, p2 in zip(e1.parameters(), e2.parameters()):
        assert (p1 == p2).all()


def test_frozen_encoder_params_do_not_require_grad():
    encoder = _frozen_encoder()
    assert all(not p.requires_grad for p in encoder.parameters())


def test_output_has_one_row_per_host_per_window():
    result = build_graph_embedding_window_features(_flow_df(), _config())
    assert set(result.columns) == {"src_ip", "window_start"} | set(GRAPH_EMBEDDING_FEATURE_NAMES)
    # window 1 has hosts A, B, C (from A->B, B->C); window 2 has A, C (from A->C, C->A)
    assert len(result) == 5


def test_embedding_columns_are_finite_and_correct_width():
    result = build_graph_embedding_window_features(_flow_df(), _config())
    embed_values = result[GRAPH_EMBEDDING_FEATURE_NAMES].to_numpy()
    assert embed_values.shape == (len(result), EMBED_DIM)
    assert np.isfinite(embed_values).all()


def test_same_flows_produce_identical_embeddings_across_runs():
    r1 = build_graph_embedding_window_features(_flow_df(), _config())
    r2 = build_graph_embedding_window_features(_flow_df(), _config())
    r1 = r1.sort_values(["window_start", "src_ip"]).reset_index(drop=True)
    r2 = r2.sort_values(["window_start", "src_ip"]).reset_index(drop=True)
    pd.testing.assert_frame_equal(r1, r2)


def test_no_ip_data_window_zero_fills_embeddings():
    df = _flow_df()
    df["has_ip_data"] = 0.0
    result = build_graph_embedding_window_features(df, _config())
    embed_values = result[GRAPH_EMBEDDING_FEATURE_NAMES].to_numpy()
    assert (embed_values == 0.0).all()


def test_empty_input_returns_empty_dataframe_with_correct_columns():
    empty = pd.DataFrame(columns=["src_ip", "dst_ip", "timestamp", "total_pkts", "has_ip_data"])
    empty["timestamp"] = pd.to_datetime(empty["timestamp"])
    result = build_graph_embedding_window_features(empty, _config())
    assert list(result.columns) == ["src_ip", "window_start"] + GRAPH_EMBEDDING_FEATURE_NAMES
    assert len(result) == 0


def _flow_windows_df():
    return pd.DataFrame({
        "src_ip": ["A", "B"],
        "window_start": pd.to_datetime(["2024-01-01 00:00:00", "2024-01-01 00:00:00"]),
        "flow_count": [3.0, 1.0],
    })


def test_merge_adds_embedding_columns_from_config():
    config = {"features": {"graph_embedding": GRAPH_EMBEDDING_FEATURE_NAMES}}
    embedding_windows = pd.DataFrame({
        "src_ip": ["A", "B"],
        "window_start": pd.to_datetime(["2024-01-01 00:00:00", "2024-01-01 00:00:00"]),
        **{col: [1.0, 2.0] for col in GRAPH_EMBEDDING_FEATURE_NAMES},
    })
    merged = merge_graph_embedding_features(_flow_windows_df(), embedding_windows, config)
    assert merged.loc[merged["src_ip"] == "A", GRAPH_EMBEDDING_FEATURE_NAMES[0]].iloc[0] == 1.0
    assert merged.loc[merged["src_ip"] == "B", GRAPH_EMBEDDING_FEATURE_NAMES[0]].iloc[0] == 2.0


def test_merge_zero_fills_when_embedding_windows_is_none():
    config = {"features": {"graph_embedding": GRAPH_EMBEDDING_FEATURE_NAMES}}
    merged = merge_graph_embedding_features(_flow_windows_df(), None, config)
    assert (merged[GRAPH_EMBEDDING_FEATURE_NAMES] == 0.0).all().all()


def test_merge_is_a_noop_when_config_has_no_graph_embedding_section():
    config = {"features": {}}
    merged = merge_graph_embedding_features(_flow_windows_df(), None, config)
    assert list(merged.columns) == ["src_ip", "window_start", "flow_count"]
