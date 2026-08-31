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
    """Resolve a paths.<key> entry from config relative to the project root."""
    rel = config["paths"][key]
    return PROJECT_ROOT / rel


def feature_columns(config: dict[str, Any]) -> list[str]:
    """Full ordered feature vector: flow-level → graph-level → packet-level features.

    The ``graph_level`` section is optional for backward compatibility — configs
    that pre-date graph features simply omit it and the vector is unchanged.
    """
    flow = list(config["features"]["flow_level"])
    graph = list(config["features"].get("graph_level", []))
    packet = list(config["features"]["packet_level"])
    return flow + graph + packet


def mitre_stages(config: dict[str, Any]) -> list[str]:
    return list(config["mitre_stages"])
