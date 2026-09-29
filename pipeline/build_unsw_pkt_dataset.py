"""Build the PACKET-AWARE UNSW-NB15 sequence dataset (pilot for real packet features).

Same pipeline as pipeline/build_unsw_dataset.py, except that:
  * only flows inside the time the PCAPs actually cover are kept (the CSVs span 4 weeks, the captures 3 days);
  * REAL packet-level window features from scripts/extract_packet_windows.py are merged in
    (has_packet_features = 1 where a host's packets were captured in that window, 0 otherwise);
  * the split is held-out-day (`split.mode: by_day`), not per-host chronological.

Usage:
    python -m scripts.extract_packet_windows --src "V:/Datasets/UNSW NB15/pcap files" --out data/processed_unsw_pkt/packet_windows
    python -m pipeline.build_unsw_pkt_dataset --config configs/unsw_nb15_pkt.yaml
"""
from __future__ import annotations

import argparse
import json

import numpy as np
import pandas as pd

from common.config import feature_columns, load_config, resolve_path
from pipeline.adapters.unsw_nb15 import load_unsw_nb15_directory
from pipeline.build_dataset import chronological_split, day_disjoint_split, save_splits
from pipeline.fast_packet_windows import PACKET_FEATURES
from pipeline.graph_builder import build_window_graphs, save_window_graphs
from pipeline.graph_embedding_features import build_graph_embedding_window_features
from pipeline.graph_features import build_graph_window_features
from pipeline.windowing import (
    apply_reconnaissance_heuristic, build_flow_windows, build_sequences,
    merge_graph_embedding_features, merge_graph_features, merge_packet_features,
)


def load_packet_windows(directory) -> pd.DataFrame:
    files = sorted(directory.glob("*.parquet"))
    if not files:
        raise FileNotFoundError(f"No packet-window parquet files in {directory}; run scripts.extract_packet_windows first.")
    pw = pd.concat([pd.read_parquet(f) for f in files], ignore_index=True)
    pw["window_start"] = pd.to_datetime(pw["window_start"]).astype("datetime64[ns]")
    # A window can appear in two files when a capture boundary falls inside it (boundary windows are dropped
    # per file, so this is rare); keep the one with more evidence is not knowable here -> keep the first.
    return pw.drop_duplicates(["src_ip", "window_start"], keep="first")


def carve_val_block(splits: dict, positive_quantile: float, window_s: int, horizon: int) -> dict:
    """Carve a validation block out of the train day, INSIDE its attack period.

    UNSW-NB15's attacks on 2015-01-22 all happen in one ~3 hour stretch and the rest of the day is benign, so
    neither the other val day (01-23, 100% benign) nor a time-tail of 01-22 contains a single positive, which
    makes val loss and thresholds meaningless. The block starts at the `positive_quantile` of the train
    positives' times and ends just after the last positive. A sequence goes to val only if its WHOLE span
    (first input window .. horizon+1 windows past the last) lies inside the block, and stays in train only if
    its whole span lies outside it -- so no window is shared between train and val."""
    tr = splits["train"]
    end = pd.to_datetime(np.asarray(tr["window_end_time"]))
    start = pd.to_datetime(np.asarray(tr["window_times"])[:, 0])
    span_end = end + pd.Timedelta(seconds=window_s * (horizon + 1))
    pos_times = end[np.asarray(tr["infiltration"])[:, 0] > 0.5]
    v0 = pos_times.sort_values()[int(len(pos_times) * positive_quantile)]
    v1 = pos_times.max() + pd.Timedelta(seconds=window_s * (horizon + 1))
    in_val = np.asarray((start >= v0) & (span_end <= v1))
    keep_train = np.asarray((span_end < v0) | (start > v1))
    out = {k: dict(v) for k, v in splits.items()}
    out["train"] = {k: np.asarray(v)[keep_train] for k, v in tr.items()}
    block = {k: np.asarray(v)[in_val] for k, v in tr.items()}
    out["val"] = {k: np.concatenate([np.asarray(splits["val"][k]), block[k]]) if len(splits["val"]["X"]) else block[k] for k in block}
    print(f"val block {v0} .. {v1}: {int(in_val.sum()):,} sequences to val, "
          f"{int((~keep_train & ~in_val).sum()):,} dropped where they straddle the block edges")
    return out


def build(config_path: str) -> None:
    config = load_config(config_path)
    raw_dir = resolve_path(config, "raw_flow_dir")
    processed_dir = resolve_path(config, "processed_dir")
    window_s = int(config["windowing"]["window_seconds"])

    pw = load_packet_windows(processed_dir / "packet_windows")
    covered = set(pw["window_start"].unique())
    print(f"Packet windows: {len(pw):,} over {len(covered):,} distinct 10 s windows, {pw['src_ip'].nunique()} hosts")

    print("\n=== STEP 1: UNSW-NB15 flows restricted to the captured time ===")
    df = load_unsw_nb15_directory(raw_dir)
    n_all = len(df)
    df = df[df["timestamp"].dt.floor(f"{window_s}s").astype("datetime64[ns]").isin(covered)].reset_index(drop=True)
    print(f"Flows kept: {len(df):,} of {n_all:,} ({len(df) / n_all:.1%}) -- the rest fall outside the PCAP coverage")

    print("\n=== STEP 2: flow, graph and embedding features ===")
    windows = build_flow_windows(df, config)
    windows = merge_graph_features(windows, build_graph_window_features(df, config), config)
    window_graphs = build_window_graphs(df, config)
    windows = merge_graph_embedding_features(
        windows, build_graph_embedding_window_features(df, config, graphs=window_graphs), config)
    processed_dir.mkdir(parents=True, exist_ok=True)
    save_window_graphs(window_graphs, processed_dir / "window_graphs.pkl")
    windows["window_start"] = windows["window_start"].astype("datetime64[ns]")

    print("\n=== STEP 3: REAL packet features merged onto flow windows ===")
    windows = merge_packet_features(windows, pw[["src_ip", "window_start", *PACKET_FEATURES]], config)
    print(f"Flow windows: {len(windows):,}; with packet features: {int(windows['has_packet_features'].sum()):,} "
          f"({windows['has_packet_features'].mean():.1%})")

    print("\n=== STEP 4: reconnaissance heuristic (now fed real port_scan_score) ===")
    before = int((windows["stage"] == "reconnaissance").sum())
    windows = apply_reconnaissance_heuristic(windows, config)
    print(f"reconnaissance windows: {before} from UNSW labels -> {int((windows['stage'] == 'reconnaissance').sum())} after heuristic")
    day = windows["window_start"].dt.strftime("%m-%d")
    print("\nStage by day:\n", pd.crosstab(day, windows["stage"]))

    print("\n=== STEP 5: sequences ===")
    feature_cols = feature_columns(config)
    sequences = build_sequences(windows, feature_cols, config)
    print(f"Sequences: {len(sequences['X']):,}")

    print("\n=== STEP 6: split ===")
    if config["split"].get("mode") == "by_day":
        splits = day_disjoint_split(sequences, config["split"], window_s, int(config["windowing"]["forecast_horizon"]))
    else:
        splits = chronological_split(sequences, config["split"])
    if config["split"].get("val_positive_quantile"):
        splits = carve_val_block(splits, float(config["split"]["val_positive_quantile"]), window_s,
                                 int(config["windowing"]["forecast_horizon"]))
    for name, data in splits.items():
        pos = float(np.asarray(data["infiltration"])[:, 0].sum()) if len(data["X"]) else 0.0
        print(f"{name}: {len(data['X']):,} sequences, {pos:,.0f} attack-next-step positives")
    save_splits(splits, processed_dir)

    metadata = {
        "dataset": "UNSW-NB15 (packet-aware pilot)", "feature_columns": feature_cols,
        "sequence_length": int(config["windowing"]["sequence_length"]),
        "forecast_horizon": int(config["windowing"]["forecast_horizon"]), "window_seconds": window_s,
        "flow_only": False, "packet_features_available": True,
        "num_windows": int(len(windows)), "num_sequences": int(len(sequences["X"])),
        "windows_with_packet_features": int(windows["has_packet_features"].sum()),
        "splits": {k: int(len(v["X"])) for k, v in splits.items()},
        "caveat": ("Real packet features from the UNSW-NB15 PCAPs (fast parser, parity-checked against the Scapy path). "
                   "retransmit_ratio counts repeated seq numbers incl. pure ACKs (inherited definition)."),
    }
    (processed_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print("\nDONE:", processed_dir)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/unsw_nb15_pkt.yaml")
    build(ap.parse_args().config)
