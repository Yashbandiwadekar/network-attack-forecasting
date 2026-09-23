"""Build the windowed UNSW-NB15 sequence dataset (D1: second permitted dataset).

Follows the same windowing -> graph features -> graph embedding -> packet features (zero-filled,
no PCAP) -> recon heuristic -> sequences pipeline as pipeline/build_dataset.py (CIC-IDS-2018), just
swapping the adapter. Every UNSW-NB15 row has a real src/dst IP (unlike 9/10 CIC-IDS-2018 days), so
graph features carry genuine signal throughout, as with CTU-13.

Split: UNSW-NB15's 40 hosts are active across a single ~4-week capture window with attacks
interleaved throughout, not day-partitioned by attack family the way CIC-IDS-2018 is, so
chronological_split (same per-host time-ordered cut used for CIC-IDS-2018 before the E1 fix) is
used here rather than day_disjoint_split. This dataset's role is the cross-dataset zero-shot
evaluation (`eval.benchmark.run_cross_dataset`, see configs/unsw_nb15.yaml) -- the "unseen dataset"
evidence for D1/S8 does not depend on how its own internal split is drawn, only its own native
LR/persistence/Markov baselines here do, and those are secondary to the cross-dataset comparison.

Usage:
    python -m pipeline.build_unsw_dataset --config configs/unsw_nb15.yaml
"""
from __future__ import annotations

import argparse
import json

import numpy as np

from common.config import feature_columns, load_config, resolve_path
from pipeline.adapters.unsw_nb15 import load_unsw_nb15_directory
from pipeline.build_dataset import chronological_split, save_splits
from pipeline.graph_builder import build_window_graphs, save_window_graphs
from pipeline.graph_embedding_features import build_graph_embedding_window_features
from pipeline.graph_features import build_graph_window_features
from pipeline.windowing import (
    apply_reconnaissance_heuristic,
    build_flow_windows,
    build_sequences,
    merge_graph_embedding_features,
    merge_graph_features,
    merge_packet_features,
)


def build_unsw_dataset(config_path: str = "configs/unsw_nb15.yaml") -> None:
    config = load_config(config_path)
    raw_dir = resolve_path(config, "raw_flow_dir")
    processed_dir = resolve_path(config, "processed_dir")

    print("=== STEP 1: Loading UNSW-NB15 raw flows ===")
    df = load_unsw_nb15_directory(raw_dir)
    print(f"Flows: {len(df):,}")
    print(df["label"].value_counts().head(15))

    print("\n=== STEP 2: Building flow windows ===")
    windows = build_flow_windows(df, config)
    print(f"Flow windows: {len(windows):,}")

    print("\n=== STEP 2b: Building graph features ===")
    graph_windows = build_graph_window_features(df, config)
    windows = merge_graph_features(windows, graph_windows, config)

    print("\n=== STEP 2c: Building graph embedding features ===")
    window_graphs = build_window_graphs(df, config)
    embedding_windows = build_graph_embedding_window_features(df, config, graphs=window_graphs)
    windows = merge_graph_embedding_features(windows, embedding_windows, config)
    save_window_graphs(window_graphs, processed_dir / "window_graphs.pkl")

    print("\n=== STEP 3: Packet features (zero-filled -- no UNSW-NB15 PCAP downloaded) ===")
    windows = merge_packet_features(windows, None, config)

    print("\n=== STEP 4: Reconnaissance heuristic ===")
    windows = apply_reconnaissance_heuristic(windows, config)
    print(windows["stage"].value_counts())

    print("\n=== STEP 5: Building sequences ===")
    feature_cols = feature_columns(config)
    sequences = build_sequences(windows, feature_cols, config)
    num_sequences = len(sequences["X"])
    print(f"Sequences created: {num_sequences:,}")
    if num_sequences == 0:
        raise RuntimeError("No sequences were created from UNSW-NB15.")

    print("\n=== STEP 6: Chronological split (per-host) ===")
    splits = chronological_split(sequences, config["split"])
    for name, data in splits.items():
        print(f"{name}: {len(data['X']):,} sequences")

    print("\n=== STEP 7: Saving processed dataset ===")
    save_splits(splits, processed_dir)

    metadata = {
        "dataset": "UNSW-NB15",
        "source_directory": str(raw_dir),
        "feature_columns": feature_cols,
        "sequence_length": int(config["windowing"]["sequence_length"]),
        "forecast_horizon": int(config["windowing"]["forecast_horizon"]),
        "window_seconds": int(config["windowing"]["window_seconds"]),
        "flow_only": True,
        "packet_features_available": False,
        "num_windows": int(len(windows)),
        "num_sequences": int(num_sequences),
        "splits": {name: int(len(data["X"])) for name, data in splits.items()},
        "caveat": (
            "UNSW-NB15 raw CSVs only -- no PCAP downloaded, so packet-level features are "
            "zero-filled exactly as for CIC-IDS-2018 (see configs/real_data.yaml)."
        ),
    }
    (processed_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"\nSaved: {processed_dir / 'metadata.json'}")
    print("\nDATASET BUILD COMPLETE:", processed_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/unsw_nb15.yaml")
    args = parser.parse_args()
    build_unsw_dataset(args.config)
