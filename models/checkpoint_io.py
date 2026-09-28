"""Safe checkpoint (de)serialisation (audit G12).

Checkpoints are loaded with ``torch.load(weights_only=True)`` so a tampered file cannot execute
code. New checkpoints store the config as a JSON string (``config_json``) next to the tensors;
older checkpoints (config stored as a plain dict) still load through the same path.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import torch


def _numpy_safe_globals() -> list:
    # Only needed by the joint-GNN checkpoint, which stores a numpy bool mask.
    from numpy._core import multiarray  # numpy >= 2
    return [multiarray._reconstruct, np.ndarray, np.dtype, type(np.dtype("bool")), type(np.dtype("float32"))]


def load_checkpoint(path: str | Path, device: torch.device | str = "cpu") -> dict[str, Any]:
    with torch.serialization.safe_globals(_numpy_safe_globals()):
        checkpoint = torch.load(path, map_location=device, weights_only=True)
    if "config" not in checkpoint and "config_json" in checkpoint:
        checkpoint["config"] = json.loads(checkpoint["config_json"])
    return checkpoint


def with_config_json(checkpoint: dict[str, Any]) -> dict[str, Any]:
    """Replace the pickled-dict ``config`` entry by a JSON string for saving."""
    out = dict(checkpoint)
    out["config_json"] = json.dumps(out.pop("config"))
    return out
