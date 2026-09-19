import numpy as np
import pandas as pd
import torch

from models.train_joint import _EMPTY_GRAPH, _base_feature_mask, _build_graph_items, _iterate_batches
from pipeline.graph_builder import WindowGraph, window_graph_key
from pipeline.graph_embedding_features import GRAPH_EMBEDDING_FEATURE_NAMES


class _FakeDataset:
    def __init__(self, window_times, src_ip, scenario_id=None):
        self.window_times = window_times
        self.src_ip = src_ip
        self.scenario_id = scenario_id


def _graph(tag):
    return WindowGraph(None, ["A"], {"A": 0}, np.zeros((2, 1), dtype=np.int64),
                       np.full((1, 2), float(tag), dtype=np.float32))


def test_base_feature_mask_excludes_only_graph_embed_columns():
    config = {"features": {
        "flow_level": ["flow_count"], "graph_level": ["graph_out_degree"],
        "graph_embedding": GRAPH_EMBEDDING_FEATURE_NAMES, "packet_level": ["mean_ttl"],
    }}
    mask = _base_feature_mask(config)
    assert mask.sum() == 3
    assert mask[:2].all() and mask[-1]
    assert not mask[2:-1].any()


def test_build_graph_items_is_row_major_sample_then_step():
    t = [pd.Timestamp("2026-01-01") + pd.Timedelta(seconds=10 * i) for i in range(4)]
    times = np.array([[t[0], t[1]], [t[2], t[3]]], dtype="datetime64[ns]")
    ds = _FakeDataset(times, np.array(["h0", "h1"]))
    graphs = {window_graph_key(t[i]): _graph(i) for i in range(4)}

    items = _build_graph_items(ds, torch.tensor([1, 0]), graphs)

    assert [h for _, h in items] == ["h1", "h1", "h0", "h0"]
    assert [g.edge_attr[0, 0] for g, _ in items] == [2.0, 3.0, 0.0, 1.0]


def test_missing_window_key_falls_back_to_empty_graph():
    times = np.array([[pd.Timestamp("2026-01-01")]], dtype="datetime64[ns]")
    ds = _FakeDataset(times, np.array(["h0"]))
    items = _build_graph_items(ds, torch.tensor([0]), {})
    assert items[0][0] is _EMPTY_GRAPH


def test_missing_window_times_raises_clear_error():
    ds = _FakeDataset(None, np.array(["h0"]))
    try:
        _build_graph_items(ds, torch.tensor([0]), {})
        assert False, "expected RuntimeError"
    except RuntimeError as e:
        assert "window_times" in str(e)


def test_iterate_batches_covers_every_index_once():
    batches = _iterate_batches(10, 4, shuffle=True)
    assert sorted(torch.cat(batches).tolist()) == list(range(10))
    assert [len(b) for b in batches] == [4, 4, 2]


def test_integer_scenario_ids_match_graph_keys_instead_of_falling_back_to_empty():
    t = pd.Timestamp("2026-01-01")
    times = np.array([[t]], dtype="datetime64[ns]")
    ds = _FakeDataset(times, np.array(["h0"]), scenario_id=np.array([7]))
    graphs = {window_graph_key(t, scenario_id=7): _graph(5)}

    items = _build_graph_items(ds, torch.tensor([0]), graphs)

    assert items[0][0] is not _EMPTY_GRAPH
    assert items[0][0].edge_attr[0, 0] == 5.0
