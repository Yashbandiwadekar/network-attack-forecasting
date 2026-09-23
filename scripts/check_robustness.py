"""Manual regression check (not a pytest — needs a trained checkpoint, so it's not run in CI):
does the trained model stay calm on legitimate traffic that's simply unusual in volume?

A classic shallow-model failure mode is learning "big numbers = attack" instead of the actual
shape of attack traffic (bursty short flows, port diversity, SYN-heavy). This generates a
synthetic large-but-legitimate backup/bulk-transfer capture — long-lived, low SYN ratio, a single
destination, no port scanning, no retransmission anomalies — and checks the trained world model's
peak K-step infiltration probability stays low on it. Also demonstrates the standardized-input
clipping in models/dataset.py::FeatureScaler.transform: without it, a feature that's near-constant
in training (e.g. unique_dst_ips staying at 1 for a single long-lived connection) can turn this
kind of out-of-distribution-but-benign volume into an extreme standardized value.

Usage:
    python -m scripts.check_robustness --config configs/default.yaml
"""
from __future__ import annotations

import argparse

import numpy as np
import pandas as pd

from common.config import feature_columns, load_config, resolve_path
from models.dataset import FeatureScaler
from models.forecast import ForecastEngine, latest_sequence, load_world_model
from pipeline.flow_features import COLUMN_RENAME, clean_and_normalize
from pipeline.graph_features import build_graph_window_features
from pipeline.graph_embedding_features import build_graph_embedding_window_features
from pipeline.windowing import (
    build_flow_windows, merge_graph_embedding_features, merge_graph_features, merge_packet_features,
)

OOD_IP = "10.0.0.201"
BACKUP_SERVER_IP = "203.0.113.200"
RNG = np.random.default_rng(7)


def _ood_benign_flows(n_windows: int, window_seconds: int) -> pd.DataFrame:
    """A single long-lived, high-volume, low-diversity connection — the "big legitimate transfer"
    shape, deliberately unlike both normal short benign flows AND attack traffic (which is bursty
    and/or port-diverse rather than one sustained high-throughput stream)."""
    base_time = pd.Timestamp("2026-01-01 00:00:00")
    rows = []
    for w in range(n_windows):
        window_start = base_time + pd.Timedelta(seconds=w * window_seconds)
        for _ in range(int(RNG.integers(2, 5))):  # a handful of long flows per window, not many short ones
            rows.append({
                "Src IP": OOD_IP, "Src Port": int(RNG.integers(40000, 65000)),
                "Dst IP": BACKUP_SERVER_IP, "Dst Port": 443, "Protocol": 6,
                "Timestamp": window_start + pd.Timedelta(seconds=float(RNG.uniform(0, window_seconds))),
                "Flow Duration": int(RNG.uniform(8_000_000, 9_500_000)),  # long-lived, near a full window
                "Tot Fwd Pkts": int(RNG.integers(5000, 20000)),           # huge packet counts...
                "Tot Bwd Pkts": int(RNG.integers(2000, 8000)),
                "TotLen Fwd Pkts": int(RNG.integers(5_000_000, 50_000_000)),  # ...and huge byte counts
                "TotLen Bwd Pkts": int(RNG.integers(200_000, 2_000_000)),
                "SYN Flag Cnt": 1, "ACK Flag Cnt": int(RNG.integers(5000, 20000)),  # overwhelmingly ACK, not SYN
                "FIN Flag Cnt": 0, "RST Flag Cnt": 0, "PSH Flag Cnt": int(RNG.integers(100, 500)), "URG Flag Cnt": 0,
                "Flow IAT Mean": float(RNG.uniform(100, 1000)),
                "Flow IAT Std": float(RNG.uniform(10, 100)),
                "Flow IAT Max": float(RNG.uniform(1000, 5000)),
                "Label": "BENIGN",
            })
    return pd.DataFrame(rows)


def main(config_path: str = "configs/default.yaml") -> None:
    config = load_config(config_path)
    checkpoint_dir = resolve_path(config, "checkpoint_dir")
    processed_dir = resolve_path(config, "processed_dir")

    checkpoint_path = checkpoint_dir / "world_model_best.pt"
    if not checkpoint_path.exists():
        raise FileNotFoundError(f"No trained checkpoint at {checkpoint_path} — run `python -m models.train` first")

    model, _ = load_world_model(checkpoint_path)
    scaler = FeatureScaler.load(processed_dir / "scaler.npz")

    seq_len = config["windowing"]["sequence_length"]
    n_windows = seq_len + 2
    raw = _ood_benign_flows(n_windows, config["windowing"]["window_seconds"])
    raw.columns = [COLUMN_RENAME.get(c, c) for c in raw.columns]
    flow_df = clean_and_normalize(raw)
    windows = build_flow_windows(flow_df, config)
    graph_windows = build_graph_window_features(flow_df, config)
    windows = merge_graph_features(windows, graph_windows, config)
    windows = merge_packet_features(windows, None, config)  # flow-only capture, no PCAP
    embedding_windows = build_graph_embedding_window_features(flow_df, config)
    windows = merge_graph_embedding_features(windows, embedding_windows, config)

    feature_cols = feature_columns(config)
    raw_sequence = latest_sequence(windows, feature_cols, OOD_IP, seq_len)
    if raw_sequence is None:
        raise RuntimeError("not enough synthetic OOD-benign windows were generated — increase n_windows")

    engine = ForecastEngine(model, scaler, config)
    result = engine.rollout(raw_sequence)

    peak = float(result.infiltration_probs.max())
    peak_step = int(result.infiltration_probs.argmax())
    print(f"OOD-benign capture (large legitimate transfer, {OOD_IP} -> {BACKUP_SERVER_IP}):")
    print(f"  infiltration probability per step: {np.round(result.infiltration_probs, 4).tolist()}")
    print(f"  peak: {peak:.4f} at step {peak_step} (predicted stage: {result.stage_predictions[peak_step]})")

    threshold = 0.3
    if peak < threshold:
        print(f"  PASS — peak stays below {threshold} despite unusual volume")
    else:
        print(f"  WARNING — peak reaches {peak:.4f} (>= {threshold}); the model may be reacting to "
              "raw volume rather than attack shape. Consider more benign-volume diversity in training data.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/default.yaml")
    args = parser.parse_args()
    main(args.config)
