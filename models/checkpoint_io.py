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


def validate_feature_names(checkpoint: dict[str, Any], feature_names: list[str]) -> None:
    """Audit W19: this is the ONE place a caller's assembled feature list is checked against what
    the checkpoint was actually trained on, by NAME and ORDER, not just count. A width-only check
    (``len(X) == n_features``) cannot catch the schema-drift bug class behind S13/G11/H3/the
    ``a60c549`` merge bug: several of those produced a matrix of the RIGHT WIDTH but the WRONG
    columns (e.g. flow-level features padded with zeros instead of real graph/packet features),
    which no shape check will ever flag.

    Checkpoints saved before this was added carry no ``feature_names`` key; those are passed
    through unchecked (same backward-compatible pattern as G12's ``weights_only`` fix) rather than
    invalidated. Every checkpoint saved after this change carries the list, so the check applies
    going forward without retraining anything already on disk.
    """
    expected = checkpoint.get("feature_names")
    if expected is None:
        return  # older checkpoint, predates this field -- nothing to check against
    if list(expected) != list(feature_names):
        raise ValueError(
            "Feature schema mismatch (audit W19): this checkpoint was trained on "
            f"{len(expected)} columns {expected!r}, but the caller assembled "
            f"{len(feature_names)} columns {list(feature_names)!r}. Refusing to score -- a "
            "matching width with mismatched columns produces silently wrong predictions, not a "
            "crash. Build the feature matrix with common.config.feature_columns(config), which "
            "is the only supported way to assemble a model input."
        )
