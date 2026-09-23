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


@pytest.mark.parametrize("path", sorted(glob.glob("checkpoints*/*.pt")))
def test_existing_checkpoints_still_load(path):
    ck = load_checkpoint(path)
    assert "model_state" in ck and "config" in ck
