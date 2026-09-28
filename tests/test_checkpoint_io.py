"""Audit G12: safe checkpoint loading."""
import pickle
import glob
import pytest
import torch

from models.checkpoint_io import load_checkpoint, with_config_json
from models.baseline_lr import _RestrictedUnpickler


def test_new_style_checkpoint_roundtrips_with_json_config(tmp_path):
    p = tmp_path / "c.pt"
    torch.save(with_config_json({"model_state": {"w": torch.ones(2)}, "n_features": 3, "config": {"a": [1, 2], "b": {"c": 1.5}}}), p)
    ck = load_checkpoint(p)
    assert ck["config"] == {"a": [1, 2], "b": {"c": 1.5}} and torch.equal(ck["model_state"]["w"], torch.ones(2))


def test_malicious_checkpoint_is_refused(tmp_path):
    class Evil:
        def __reduce__(self):
            import os
            return (os.system, ("echo pwned",))
    p = tmp_path / "evil.pt"
    torch.save({"config": Evil()}, p)
    with pytest.raises(Exception):
        load_checkpoint(p)


def test_baseline_unpickler_blocks_os_system(tmp_path):
    import io, os
    class Evil:
        def __reduce__(self):
            return (os.system, ("echo pwned",))
    with pytest.raises(pickle.UnpicklingError):
        _RestrictedUnpickler(io.BytesIO(pickle.dumps(Evil()))).load()


@pytest.mark.parametrize("path", sorted(glob.glob("checkpoints*/**/*.pt", recursive=True)))
def test_existing_checkpoints_still_load(path):
    ck = load_checkpoint(path)
    assert "model_state" in ck and "config" in ck


def test_baseline_model_fit_save_load_roundtrip(tmp_path):
    """Audit G12 review: _RestrictedUnpickler had never actually loaded a real BaselineModel --
    exercise the whole fit/save/load path so an allowlist gap would show up here, not at runtime."""
    import types
    import numpy as np
    import torch as _torch
    from models.baseline_lr import BaselineModel

    n, seq_len, n_features = 40, 3, 5
    rng = np.random.default_rng(0)
    ds = types.SimpleNamespace(
        X=_torch.tensor(rng.normal(size=(n, seq_len, n_features)).astype(np.float32)),
        infiltration=_torch.tensor(rng.integers(0, 2, size=(n, 1)).astype(np.float32)),
        future_stages=_torch.tensor(rng.integers(0, 3, size=(n, 1)).astype(np.int64)),
    )
    config = {"baseline": {"max_iter": 50}}

    model = BaselineModel(config).fit(ds)
    p = tmp_path / "baseline.pkl"
    model.save(p)
    loaded = BaselineModel.load(p)

    inf_prob, stage_probs = loaded.predict(ds.X.numpy())
    assert inf_prob.shape == (n,) and stage_probs.shape[0] == n
