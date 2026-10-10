"""QC-2: dotted-name / non-allowlisted globals must be rejected by both restricted unpicklers."""
import io
import pickle

import numpy as np
import pytest

from models.baseline_lr import _RestrictedUnpickler as BaselineUnpickler
from pipeline import graph_builder
from pipeline.graph_builder import _RestrictedUnpickler as GraphUnpickler


def _stack_global_payload(module: str, name: str) -> bytes:
    """Protocol-4 pickle: STACK_GLOBAL(module, name) then call with no args."""
    def s(x: str) -> bytes:
        return b"\x8c" + bytes([len(x)]) + x.encode() + b"\x94"
    return b"\x80\x04" + s(module) + s(name) + b"\x93\x94" + b")R."


@pytest.mark.parametrize("unpickler,module", [
    (BaselineUnpickler, "sklearn.datasets._base"),
    (BaselineUnpickler, "numpy"),
    (GraphUnpickler, "numpy"),
    (GraphUnpickler, "pipeline.graph_builder"),
])
def test_dotted_name_is_blocked(unpickler, module):
    with pytest.raises(pickle.UnpicklingError):
        unpickler(io.BytesIO(_stack_global_payload(module, "os.getcwd"))).load()


@pytest.mark.parametrize("unpickler", [BaselineUnpickler, GraphUnpickler])
def test_prefix_allowed_module_arbitrary_name_blocked(unpickler):
    with pytest.raises(pickle.UnpicklingError):
        unpickler(io.BytesIO(_stack_global_payload("numpy", "save"))).load()


@pytest.mark.parametrize("proto", [2, 4, 5])
def test_baseline_roundtrip_all_protocols(proto):
    import types
    import torch
    from models.baseline_lr import BaselineModel
    rng = np.random.default_rng(0)
    n = 30
    ds = types.SimpleNamespace(
        X=torch.tensor(rng.normal(size=(n, 3, 4)).astype(np.float32)),
        infiltration=torch.tensor(rng.integers(0, 2, size=(n, 1)).astype(np.float32)),
        future_stages=torch.tensor(rng.integers(0, 3, size=(n, 1)).astype(np.int64)),
    )
    for mode in ("last", "stacked"):
        m = BaselineModel({"baseline": {"max_iter": 50}}, mode).fit(ds)
        loaded = BaselineUnpickler(io.BytesIO(pickle.dumps(m, protocol=proto))).load()
        np.testing.assert_allclose(loaded.predict(ds.X.numpy())[0], m.predict(ds.X.numpy())[0])


def test_window_graphs_roundtrip(tmp_path):
    import pandas as pd
    g = graph_builder.WindowGraph(
        window_key=(pd.Timestamp("2018-01-01 00:00:10"),), node_ids=["a", "b"],
        node_index={"a": 0, "b": 1}, edge_index=np.array([[0], [1]], dtype=np.int64),
        edge_attr=np.ones((1, 3), dtype=np.float32),
    )
    p = tmp_path / "g.pkl"
    graph_builder.save_window_graphs({g.window_key: g}, p)
    out = graph_builder.load_window_graphs(p)
    assert list(out) == [g.window_key] and out[g.window_key].node_ids == ["a", "b"]
