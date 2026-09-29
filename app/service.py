"""Headless backend service layer for the REST API.

Everything here was previously inline in `app/streamlit_app.py` (deleted 2026-09-29 when the React
frontend replaced it). The bodies are ported verbatim so behaviour is unchanged; only the
Streamlit cache decorators became `lru_cache`, and the functions no longer draw anything.

This module holds no fabricated values. If an artifact is missing, the caller is told so
explicitly -- there is deliberately no "analytical fallback" that invents plausible numbers,
because that is exactly how the mock backend's fabricated metrics reached the UI.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from common.config import feature_columns, load_config, resolve_path
from models.dataset import FeatureScaler, load_split
from models.forecast import ForecastEngine, latest_sequences_batch, load_world_model
from pipeline.flow_features import clean_and_normalize, load_flow_csv, load_flow_dir
from pipeline.graph_embedding_features import build_graph_embedding_window_features
from pipeline.graph_features import build_graph_window_features
from pipeline.packet_features import build_flow_records, compute_packet_window_features, load_pcap
from pipeline.windowing import (
    apply_reconnaissance_heuristic, build_flow_windows, merge_graph_embedding_features,
    merge_graph_features, merge_packet_features,
)

# Ported from streamlit_app.py. The frontend renders these as CSS classes, and treats anything
# below the lowest threshold as "good" -- the Streamlit UI showed no alert card at all there.
SEVERITY_LEVELS: list[tuple[float, str]] = [
    (0.70, "critical"),
    (0.40, "serious"),
    (0.15, "warning"),
]

MAX_CSV_UPLOAD_MB = 300
MAX_PCAP_UPLOAD_MB = 300


def severity_for(peak_prob: float) -> str:
    """Severity label for a peak probability. Unlike the Streamlit original this returns "good"
    rather than None below the lowest threshold, because the dashboard always renders a row."""
    for threshold, label in SEVERITY_LEVELS:
        if peak_prob >= threshold:
            return label
    return "good"


def stage_disclosure_note(stage: str, is_heuristic: bool) -> str:
    """Audit S6/S7 ("never invent labels... say so wherever it is shown"): a short, plain-language
    note for any stage that isn't a plain trained-classifier prediction. Empty for an ordinary
    classifier output -- most predictions still are one."""
    if stage == "exfiltration":
        return "synthetic, demo-only label — not present in real CIC-IDS-2018 data"
    if is_heuristic and stage == "impact":
        return "heuristic override on flow-volume signature, not the trained classifier"
    if is_heuristic and stage == "reconnaissance":
        return "heuristic override on port-scan signature, not the trained classifier"
    return ""


@lru_cache(maxsize=4)
def load_backend(config_path: str):
    """(config, model, scaler, shap_background). model/scaler are None when no checkpoint is
    present -- callers must handle that rather than substituting invented output."""
    config = load_config(config_path)
    checkpoint_dir = resolve_path(config, "checkpoint_dir")
    checkpoint_path = checkpoint_dir / "world_model_best.pt"
    if not checkpoint_path.exists():
        return config, None, None, None
    model, _ = load_world_model(checkpoint_path)
    scaler = FeatureScaler.load(resolve_path(config, "processed_dir") / "scaler.npz")

    background = None
    shap_path = resolve_path(config, "processed_dir") / "shap_background.npy"
    if shap_path.exists():
        background = np.load(shap_path)
    else:
        train_path = resolve_path(config, "processed_dir") / "train.npz"
        if train_path.exists():
            train_split = load_split(resolve_path(config, "processed_dir"), "train")
            full_background = scaler.transform(train_split["X"])[:, -1, :]
            np.random.seed(42)
            indices = np.random.choice(len(full_background), min(100, len(full_background)), replace=False)
            background = full_background[indices]
            np.save(shap_path, background)
    return config, model, scaler, background


def is_flow_only_model(config: dict) -> bool:
    """Audit G11: True when the checkpoint's own processed dataset was built flow-only (read from
    its metadata.json, never from a config name). Such a model has never seen packet features."""
    try:
        meta = json.loads((resolve_path(config, "processed_dir") / "metadata.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return bool(meta.get("flow_only")) or meta.get("packet_features_available") is False


def process_uploads(flow_csv_path: Path | None, pcap_path: Path | None, config: dict):
    """Audit S4: flow_csv_path is optional -- a PCAP/PCAPNG capture alone is enough to derive
    flow-level records and drive the whole pipeline, matching the problem statement's "PCAP or
    CSV" requirement. At least one of the two must be given. Returns (flow_df, windows)."""
    packet_df = load_pcap(pcap_path) if pcap_path is not None else None

    if flow_csv_path is not None:
        flow_df = clean_and_normalize(load_flow_csv(flow_csv_path, require_label=False))
    elif packet_df is not None:
        flow_df = build_flow_records(packet_df)
    else:
        raise ValueError("Need at least a flow CSV or a PCAP/PCAPNG capture.")

    flow_windows = build_flow_windows(flow_df, config)

    packet_windows = None
    if packet_df is not None and not is_flow_only_model(config):
        packet_windows = compute_packet_window_features(packet_df, config["windowing"]["window_seconds"])

    windows = merge_packet_features(flow_windows, packet_windows, config)
    graph_windows = build_graph_window_features(flow_df, config)
    windows = merge_graph_features(windows, graph_windows, config)
    embedding_windows = build_graph_embedding_window_features(flow_df, config)
    windows = merge_graph_embedding_features(windows, embedding_windows, config)
    windows = apply_reconnaissance_heuristic(windows, config)
    return flow_df, windows


@lru_cache(maxsize=2)
def load_real_data(config_path: str) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Real CIC-IDS-2018 is ~16M flows across 10 files -- 1-3 minutes on first call, hence the
    cache. Raw flow data is not shipped in the repo, so this raises in a fresh clone; callers
    should treat that as "no data loaded yet", not as an error to paper over."""
    config = load_config(config_path)
    flow_df = clean_and_normalize(load_flow_dir(resolve_path(config, "raw_flow_dir")))
    flow_windows = build_flow_windows(flow_df, config)
    graph_windows = build_graph_window_features(flow_df, config)
    windows = merge_graph_features(flow_windows, graph_windows, config)
    embedding_windows = build_graph_embedding_window_features(flow_df, config)
    windows = merge_graph_embedding_features(windows, embedding_windows, config)
    windows = merge_packet_features(windows, None, config)
    windows = apply_reconnaissance_heuristic(windows, config)
    return flow_df, windows


def score_all_hosts(engine: ForecastEngine, windows: pd.DataFrame, feature_cols: list[str], seq_len: int):
    """Peak infiltration probability + predicted stage for every eligible host, via one batched
    rollout rather than one per host. Returns None when no host has a full sequence yet."""
    host_ids, sequences = latest_sequences_batch(windows, feature_cols, seq_len)
    if not host_ids:
        return None
    return engine.rollout_batch(host_ids, sequences)


def horizon_info(config: dict[str, Any]) -> dict[str, int]:
    """The forecast horizon in both steps and wall-clock seconds. The project forecasts
    K=6 steps of 10s = 60 seconds ahead; the UI previously hardcoded K=5 with no units."""
    k = int(config["windowing"]["forecast_horizon"])
    window_seconds = int(config["windowing"]["window_seconds"])
    return {
        "horizon_k": k,
        "window_seconds": window_seconds,
        "horizon_seconds": k * window_seconds,
    }


def feature_cols_for(config: dict[str, Any]) -> list[str]:
    return feature_columns(config)
