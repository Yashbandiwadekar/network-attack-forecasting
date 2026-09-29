"""Audit G12 follow-up: no arbitrary-code deserialization left on the data-loading path."""
import pickle

import numpy as np
import pandas as pd
import pytest

from models.dataset import load_split
from pipeline.graph_builder import WindowGraph, load_window_graphs, save_window_graphs


def test_window_graphs_roundtrip_with_timestamp_keys(tmp_path):
    key = (3, pd.Timestamp("2026-01-01 00:00:10"))
    graph = WindowGraph(
        window_key=key, node_ids=["a", "b"], node_index={"a": 0, "b": 1},
        edge_index=np.array([[0], [1]], dtype=np.int64), edge_attr=np.zeros((1, 2), dtype=np.float32),
    )
    path = tmp_path / "g.pkl"
    save_window_graphs({key: graph}, path)

    loaded = load_window_graphs(path)

    assert list(loaded) == [key]
    assert loaded[key].node_ids == ["a", "b"]
    assert loaded[key].n_edges == 1


def test_window_graphs_loader_blocks_arbitrary_callables(tmp_path):
    class Evil:
        def __reduce__(self):
            import os
            return (os.system, ("echo pwned",))

    path = tmp_path / "evil.pkl"
    path.write_bytes(pickle.dumps({"x": Evil()}))

    with pytest.raises(pickle.UnpicklingError, match="Blocked global"):
        load_window_graphs(path)


def test_load_split_refuses_pickled_object_arrays(tmp_path):
    np.savez(tmp_path / "train.npz", X=np.array([{"a": 1}], dtype=object))
    with pytest.raises(ValueError):
        load_split(tmp_path, "train")


def test_load_split_reads_plain_arrays(tmp_path):
    np.savez(tmp_path / "train.npz", X=np.ones((2, 3), dtype=np.float32), src_ip=np.array(["10.0.0.1", "10.0.0.2"]))
    out = load_split(tmp_path, "train")
    assert out["X"].shape == (2, 3) and list(out["src_ip"]) == ["10.0.0.1", "10.0.0.2"]
