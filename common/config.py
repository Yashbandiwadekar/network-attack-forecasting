"""Shared config loading — every script reads configs/default.yaml through this."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def load_config(config_path: str | Path = "configs/default.yaml") -> dict[str, Any]:
    path = Path(config_path)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def resolve_path(config: dict[str, Any], key: str) -> Path:
    """Resolve a paths.<key> entry from config relative to the project root,
    with support for environment variable overrides and machine-independent paths."""
    import os

    # Check environment variable overrides first
    env_var_map = {
        "checkpoint_dir": ("PHOENIX_CHECKPOINT_DIR", "PHOENIX_MODEL_DIR", "PHOENIX_CHECKPOINTS_DIR"),
        "processed_dir": ("PHOENIX_PROCESSED_DIR", "PHOENIX_DATA_DIR"),
        "raw_flow_dir": ("PHOENIX_RAW_FLOW_DIR", "PHOENIX_DATA_DIR"),
        "raw_pcap_dir": ("PHOENIX_RAW_PCAP_DIR", "PHOENIX_DATA_DIR"),
    }
    for env_name in env_var_map.get(key, ()):
        val = os.environ.get(env_name)
        if val:
            p = Path(val)
            if not p.is_absolute():
                p = PROJECT_ROOT / p
            return p

    rel = config["paths"][key]
    path_obj = Path(rel)

    # If the path is absolute:
    if path_obj.is_absolute():
        try:
            if path_obj.exists():
                return path_obj
        except (OSError, PermissionError):
            pass
        # Fallback for foreign absolute paths (e.g. V:/Datasets on another machine)
        fallback_name = path_obj.name.lower().replace(" ", "_")
        for candidate in (
            PROJECT_ROOT / "data" / "raw" / fallback_name,
            PROJECT_ROOT / "data" / "raw" / path_obj.name,
            PROJECT_ROOT / path_obj.name,
        ):
            if candidate.exists():
                return candidate
        return PROJECT_ROOT / path_obj.name

    return PROJECT_ROOT / rel


def feature_columns(config: dict[str, Any]) -> list[str]:
    """Full ordered feature vector: flow-level → graph-level → graph-embedding → packet-level.

    The ``graph_level`` and ``graph_embedding`` sections are optional for backward
    compatibility — configs that pre-date either simply omit them and the vector is unchanged.
    """
    flow = list(config["features"]["flow_level"])
    graph = list(config["features"].get("graph_level", []))
    graph_embedding = list(config["features"].get("graph_embedding", []))
    packet = list(config["features"]["packet_level"])
    return flow + graph + graph_embedding + packet


def mitre_stages(config: dict[str, Any]) -> list[str]:
    return list(config["mitre_stages"])
