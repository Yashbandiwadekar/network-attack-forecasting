"""Packet-aware CIC-IDS-2018 dataset for ONE day (Wednesday 14-02-2018), built from raw host-based PCAPs.

Inputs (produced by scripts.extract_flow_records and scripts.extract_packet_windows, both keep-at-sender/initiator):
  data/processed_cic_pkt/flow_records/*.parquet    CICFlowMeter-style flows, 120 s timeout, bidirectional
  data/processed_cic_pkt/packet_windows/*.parquet  8 packet features per (src, 10 s window)

Labels come from the attack schedule VERIFIED against the data (BUILD_REPORT.md, CIC-IDS-2018 section): packets from
18.221.219.4 to 172.31.69.25:21 (FTP-Patator, 14:33:26-16:10:31 UTC; 193,360 packets == the 193,360 FTP-BruteForce rows in
CIC's own CSV) and from 13.58.98.64 to 172.31.69.25:22 (SSH-Patator, 18:01:50-19:32:30 UTC). CIC's CSV clock is UTC-4.

Split (single day, so a time split): train on the FTP-Patator period, test on the later SSH-Patator period -- a different
attacker, protocol and port the model has never seen -- with val carved from inside the FTP period. The train/val/test
blocks share no window (a sequence belongs to a block only if its whole span is inside it).
"""
from __future__ import annotations

import argparse
import json

import numpy as np
import pandas as pd

from common.config import feature_columns, load_config, resolve_path
from pipeline.build_dataset import save_splits
from pipeline.build_unsw_pkt_dataset import carve_val_block
from pipeline.fast_packet_windows import PACKET_FEATURES, ip_to_str
from pipeline.graph_builder import build_window_graphs, save_window_graphs
from pipeline.graph_embedding_features import build_graph_embedding_window_features
from pipeline.graph_features import build_graph_window_features
from pipeline.windowing import (
    apply_reconnaissance_heuristic, build_flow_windows, build_sequences,
    merge_graph_embedding_features, merge_graph_features, merge_packet_features,
)

VICTIM = "172.31.69.25"
ATTACKS = [  # (label, attacker ip, victim port, start UTC, end UTC) -- verified against the PCAP and the CIC CSV
    ("FTP-BruteForce", "18.221.219.4", 21, "2018-02-14 14:33:26", "2018-02-14 16:10:31"),
    ("SSH-Bruteforce", "13.58.98.64", 22, "2018-02-14 18:01:50", "2018-02-14 19:32:30"),
]
TRAIN_END = pd.Timestamp("2018-02-14 17:00:00")  # between the FTP attack (ends 16:10) and the SSH attack (starts 18:01)


def load_flows(directory) -> pd.DataFrame:
    fs = sorted(directory.glob("*.parquet"))
    df = pd.concat([pd.read_parquet(f) for f in fs if f.stat().st_size], ignore_index=True)
    df["src_ip"], df["dst_ip"] = ip_to_str(df["src_ip"]), ip_to_str(df["dst_ip"])
    df["timestamp"] = pd.to_datetime(df["timestamp_s"], unit="s")
    df["label"] = "BENIGN"
    for label, src, port, t0, t1 in ATTACKS:
        m = (
            (df["src_ip"] == src) & (df["dst_ip"] == VICTIM) & (df["dst_port"] == port)
            & (df["timestamp"] >= pd.Timestamp(t0)) & (df["timestamp"] <= pd.Timestamp(t1))
        )
        df.loc[m, "label"] = label
    return df.drop(columns=["timestamp_s"])


def load_packet_windows(directory) -> pd.DataFrame:
    fs = [f for f in sorted(directory.glob("*.parquet")) if f.stat().st_size]
    pw = pd.concat([pd.read_parquet(f) for f in fs], ignore_index=True)
    pw["window_start"] = pd.to_datetime(pw["window_start"]).astype("datetime64[ns]")
    # An outside source seen by several victims gets one partial row per victim capture; unique-port / repeated-seq
    # features are not additive, so those duplicates are AVERAGED (approximation, disclosed; affects only outside
    # sources seen by several victims -- the two attackers each hit a single victim).
    return pw.groupby(["src_ip", "window_start"], as_index=False)[PACKET_FEATURES].mean()


def build(config_path: str) -> None:
    config = load_config(config_path)
    d = resolve_path(config, "processed_dir")
    window_s = int(config["windowing"]["window_seconds"])
    horizon = int(config["windowing"]["forecast_horizon"])

    print("=== flows ===")
    df = load_flows(d / "flow_records")
    print(f"{len(df):,} flows, {df['src_ip'].nunique():,} initiators; labels:\n{df['label'].value_counts().to_string()}")

    print("\n=== flow / graph / embedding features ===")
    windows = build_flow_windows(df, config)
    windows = merge_graph_features(windows, build_graph_window_features(df, config), config)
    graphs = build_window_graphs(df, config)
    windows = merge_graph_embedding_features(
        windows, build_graph_embedding_window_features(df, config, graphs=graphs), config)
    save_window_graphs(graphs, d / "window_graphs.pkl")
    windows["window_start"] = windows["window_start"].astype("datetime64[ns]")

    print("\n=== real packet features ===")
    windows = merge_packet_features(windows, load_packet_windows(d / "packet_windows"), config)
    print(f"{len(windows):,} windows; {windows['has_packet_features'].mean():.1%} have packet features")
    windows = apply_reconnaissance_heuristic(windows, config)
    print("stage counts:\n", windows["stage"].value_counts().to_string())

    print("\n=== sequences ===")
    cols = feature_columns(config)
    seq = build_sequences(windows, cols, config)
    n = len(seq["X"])
    end = pd.to_datetime(np.asarray(seq["window_end_time"]))
    start = pd.to_datetime(np.asarray(seq["window_times"])[:, 0])
    span_end = end + pd.Timedelta(seconds=window_s * (horizon + 1))
    in_train = np.asarray(span_end < TRAIN_END)
    in_test = np.asarray(start >= TRAIN_END)
    print(f"{n:,} sequences: {int(in_train.sum()):,} before {TRAIN_END}, {int(in_test.sum()):,} after, "
          f"{int((~in_train & ~in_test).sum()):,} straddling the cut (dropped)")

    def pick(mask):
        return {k: np.asarray(v)[mask] for k, v in seq.items()}

    splits = {"train": pick(in_train), "val": {k: np.asarray(v)[:0] for k, v in seq.items()}, "test": pick(in_test)}
    splits = carve_val_block(splits, float(config["split"]["val_positive_quantile"]), window_s, horizon)
    for name, s in splits.items():
        pos = float(np.asarray(s["infiltration"])[:, 0].sum())
        print(f"{name}: {len(s['X']):,} sequences, {pos:,.0f} attack-next-step positives")
    save_splits(splits, d)
    meta = {
        "dataset": "CIC-IDS-2018 Wed 14-02-2018 (packet-aware, from PCAP)", "feature_columns": cols,
        "sequence_length": int(config["windowing"]["sequence_length"]), "forecast_horizon": horizon,
        "window_seconds": window_s, "flow_only": False, "packet_features_available": True,
        "num_windows": int(len(windows)), "num_sequences": int(n),
        "splits": {k: int(len(v["X"])) for k, v in splits.items()},
        "caveat": "Flow records assembled from PCAP (120 s timeout, no FIN split); packet windows for outside sources seen "
                  "by several victims are averaged across captures; retransmit_ratio counts repeated seq incl. pure ACKs.",
    }
    (d / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print("\nDONE:", d)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/cic_pkt.yaml")
    build(ap.parse_args().config)
