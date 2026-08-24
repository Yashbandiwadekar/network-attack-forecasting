"""CLI: raw CICFlowMeter CSVs (+ optional PCAP) -> windowed sequence tensors, chronologically split.

Usage:
    python -m pipeline.build_dataset --config configs/default.yaml
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from common.config import feature_columns, load_config, resolve_path
from pipeline.flow_features import load_flow_dir
from pipeline.packet_features import compute_packet_window_features, load_pcap
from pipeline.windowing import apply_reconnaissance_heuristic, build_flow_windows, build_sequences, merge_packet_features


def _load_packet_windows(pcap_dir: Path, window_seconds: int):
    if not pcap_dir.exists() or not any(pcap_dir.glob("*.pcap")):
        return None
    frames = [compute_packet_window_features(load_pcap(p), window_seconds) for p in sorted(pcap_dir.glob("*.pcap"))]
    import pandas as pd
    return pd.concat(frames, ignore_index=True) if frames else None


def _chronological_split(sequences: dict, split_config: dict) -> dict[str, dict]:
    order = np.argsort(sequences["window_end_time"])
    n = len(order)
    train_end = int(n * split_config["train_frac"])
    val_end = train_end + int(n * split_config["val_frac"])

    splits = {"train": order[:train_end], "val": order[train_end:val_end], "test": order[val_end:]}
    out = {}
    for name, idx in splits.items():
        out[name] = {k: v[idx] for k, v in sequences.items()}
    return out


def main(config_path: str = "configs/default.yaml") -> None:
    config = load_config(config_path)

    flow_dir = resolve_path(config, "raw_flow_dir")
    pcap_dir = resolve_path(config, "raw_pcap_dir")
    processed_dir = resolve_path(config, "processed_dir")
    processed_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading flows from {flow_dir}")
    flow_df = load_flow_dir(flow_dir)
    print(f"  {len(flow_df)} flows loaded")

    flow_windows = build_flow_windows(flow_df, config)
    print(f"  {len(flow_windows)} (src_ip, window) states built")

    packet_windows = _load_packet_windows(pcap_dir, config["windowing"]["window_seconds"])
    if packet_windows is None:
        print(f"  No PCAP files in {pcap_dir} — packet-level features zero-filled (flow-only mode)")
    windows = merge_packet_features(flow_windows, packet_windows, config)
    windows = apply_reconnaissance_heuristic(windows, config)

    feature_cols = feature_columns(config)
    sequences = build_sequences(windows, feature_cols, config)
    print(f"  {len(sequences['X'])} sequences built (seq_len={config['windowing']['sequence_length']}, "
          f"horizon={config['windowing']['forecast_horizon']})")

    splits = _chronological_split(sequences, config["split"])
    for name, split in splits.items():
        path = processed_dir / f"{name}.npz"
        np.savez(
            path,
            X=split["X"],
            next_state=split["next_state"],
            future_stages=split["future_stages"],
            infiltration=split["infiltration"],
            current_stage=split["current_stage"],
            current_infiltration=split["current_infiltration"],
            window_end_time=split["window_end_time"].astype("datetime64[ns]").astype(np.int64),
            src_ip=split["src_ip"],
        )
        print(f"  {name}: {len(split['X'])} sequences -> {path}")

    metadata = {
        "feature_cols": feature_cols,
        "n_features": len(feature_cols),
        "window_seconds": config["windowing"]["window_seconds"],
        "sequence_length": config["windowing"]["sequence_length"],
        "forecast_horizon": config["windowing"]["forecast_horizon"],
        "stage_labels": config["mitre_stages"],
    }
    with open(processed_dir / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"  metadata -> {processed_dir / 'metadata.json'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/default.yaml")
    args = parser.parse_args()
    main(args.config)
