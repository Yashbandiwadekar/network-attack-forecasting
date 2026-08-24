"""Time-window aggregation: per-flow rows -> per (src_ip, window) network-state vectors ->
sliding sequences ready for the world model.
"""
from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from pipeline.mitre_mapping import BENIGN, IMPACT, RECONNAISSANCE, label_to_stage, stage_to_index


def build_flow_windows(flow_df: pd.DataFrame, config: dict[str, Any]) -> pd.DataFrame:
    """Aggregate cleaned per-flow rows (from flow_features.clean_and_normalize) into per
    (src_ip, window_start) state vectors, using the flow_level feature list from config."""
    window_seconds = config["windowing"]["window_seconds"]
    df = flow_df.copy()
    df["window_start"] = df["timestamp"].dt.floor(f"{window_seconds}s")
    df["stage"] = df["label"].map(label_to_stage)

    rows = []
    for (src_ip, window_start), group in df.groupby(["src_ip", "window_start"]):
        total_pkts = group["total_pkts"].sum()
        rows.append({
            "src_ip": src_ip,
            "window_start": window_start,
            "flow_count": len(group),
            "unique_dst_ports": group["dst_port"].nunique(),
            "unique_dst_ips": group["dst_ip"].nunique(),
            "total_bytes": group["total_bytes"].sum(),
            "total_packets": total_pkts,
            "mean_duration": group["duration_s"].mean(),
            "syn_ratio": group["syn_cnt"].sum() / total_pkts if total_pkts else 0.0,
            "ack_ratio": group["ack_cnt"].sum() / total_pkts if total_pkts else 0.0,
            "fin_ratio": group["fin_cnt"].sum() / total_pkts if total_pkts else 0.0,
            "rst_ratio": group["rst_cnt"].sum() / total_pkts if total_pkts else 0.0,
            "psh_ratio": group["psh_cnt"].sum() / total_pkts if total_pkts else 0.0,
            "urg_ratio": group["urg_cnt"].sum() / total_pkts if total_pkts else 0.0,
            "mean_iat": group["iat_mean"].mean(),
            "var_iat": (group["iat_std"] ** 2).mean(),
            "max_iat": group["iat_max"].max(),
            "bidir_ratio": group["bidir_ratio"].mean(),
            "tcp_ratio": group["is_tcp"].mean(),
            "udp_ratio": group["is_udp"].mean(),
            # majority non-benign label wins the window, so one attack flow among many benign
            # flows still marks the window as an attack window (rare events must not get diluted away)
            "stage": _majority_stage(group["stage"]),
        })
    return pd.DataFrame(rows).sort_values(["src_ip", "window_start"]).reset_index(drop=True)


def _majority_stage(stages: pd.Series) -> str:
    non_benign = stages[stages != BENIGN]
    if len(non_benign) > 0:
        return non_benign.mode().iloc[0]
    return BENIGN


def merge_packet_features(
    flow_windows: pd.DataFrame, packet_windows: pd.DataFrame | None, config: dict[str, Any]
) -> pd.DataFrame:
    """Left-join packet-level window features onto flow-level windows. Windows with no PCAP
    coverage get zero-filled packet features (flow-only mode) plus an explicit
    `has_packet_features` flag — the model can then distinguish "no scan activity observed"
    from "no packet data was ever available for this window", instead of the two looking
    identical after zero-filling.
    """
    real_packet_cols = [c for c in config["features"]["packet_level"] if c != "has_packet_features"]
    merged = flow_windows.copy()
    if packet_windows is None or packet_windows.empty:
        for col in real_packet_cols:
            merged[col] = 0.0
        merged["has_packet_features"] = 0.0
        return merged
    merged = merged.merge(packet_windows, on=["src_ip", "window_start"], how="left", indicator=True)
    merged["has_packet_features"] = (merged["_merge"] == "both").astype(float)
    merged = merged.drop(columns=["_merge"])
    merged[real_packet_cols] = merged[real_packet_cols].fillna(0.0)
    return merged


def apply_reconnaissance_heuristic(windows_df: pd.DataFrame, config: dict[str, Any]) -> pd.DataFrame:
    """Relabel a benign window as reconnaissance if its port_scan_score is high AND an attack
    from the same source IP follows within forecast_horizon windows. No CIC-IDS-2018 label maps
    to reconnaissance directly (see pipeline/mitre_mapping.py); this derives it from the
    temporal-proximity-to-attack pattern instead of fabricating labels out of nowhere.
    """
    threshold = config["windowing"]["recon_port_scan_threshold"]
    horizon = config["windowing"]["forecast_horizon"]
    df = windows_df.copy()

    for src_ip, group in df.groupby("src_ip"):
        idx = group.index.to_numpy()
        stages = group["stage"].to_numpy()
        scores = group["port_scan_score"].to_numpy()
        for i in range(len(idx)):
            if stages[i] != BENIGN or scores[i] < threshold:
                continue
            future = stages[i + 1: i + 1 + horizon]
            if np.any((future != BENIGN) & (future != IMPACT)):
                df.loc[idx[i], "stage"] = RECONNAISSANCE
    return df


def build_sequences(
    windows_df: pd.DataFrame, feature_cols: list[str], config: dict[str, Any]
) -> dict[str, np.ndarray]:
    """Slide a window of length `sequence_length` per src_ip and emit training examples:
      X:                   (N, L, F)  past L state vectors
      next_state:          (N, F)     ground-truth S_t+1 for the world model's regression head
      future_stages:       (N, K)     stage index at each of the next K steps (-1 = excluded/impact)
      infiltration:        (N, K)     binary "is this future step an attack" time series
      current_stage:       (N,)       stage index of the LAST INPUT window itself (-1 = excluded/impact)
      current_infiltration: (N,)      binary "is the last input window itself an attack" — together
                                       with current_stage, this is what a persistence baseline
                                       needs (models/baseline_lr.py::PersistenceBaseline): "predict
                                       that whatever is true right now stays true next step"
      window_end_time:     (N,)       timestamp of the last input window, used for chronological split
      src_ip:              (N,)
    """
    seq_len = config["windowing"]["sequence_length"]
    horizon = config["windowing"]["forecast_horizon"]

    X, next_state, future_stages, infiltration = [], [], [], []
    current_stage, current_infiltration, window_end_time, src_ips = [], [], [], []

    for src_ip, group in windows_df.groupby("src_ip"):
        group = group.sort_values("window_start").reset_index(drop=True)
        feats = group[feature_cols].to_numpy(dtype=np.float32)
        stages = group["stage"].to_numpy()
        times = group["window_start"].to_numpy()

        n = len(group)
        last_start = n - seq_len - horizon
        for i in range(max(0, last_start + 1)):
            X.append(feats[i: i + seq_len])
            next_state.append(feats[i + seq_len])
            fut = stages[i + seq_len: i + seq_len + horizon]
            future_stages.append(np.array([_stage_idx_or_masked(s) for s in fut]))
            infiltration.append(np.array([0.0 if s == BENIGN else 1.0 for s in fut], dtype=np.float32))
            last_input_stage = stages[i + seq_len - 1]
            current_stage.append(_stage_idx_or_masked(last_input_stage))
            current_infiltration.append(0.0 if last_input_stage == BENIGN else 1.0)
            window_end_time.append(times[i + seq_len - 1])
            src_ips.append(src_ip)

    return {
        "X": np.stack(X) if X else np.zeros((0, seq_len, len(feature_cols)), dtype=np.float32),
        "next_state": np.stack(next_state) if next_state else np.zeros((0, len(feature_cols)), dtype=np.float32),
        "future_stages": np.stack(future_stages) if future_stages else np.zeros((0, horizon), dtype=np.int64),
        "infiltration": np.stack(infiltration) if infiltration else np.zeros((0, horizon), dtype=np.float32),
        "current_stage": np.array(current_stage, dtype=np.int64),
        "current_infiltration": np.array(current_infiltration, dtype=np.float32),
        "window_end_time": np.array(window_end_time),
        "src_ip": np.array(src_ips),
    }


def _stage_idx_or_masked(stage: str) -> int:
    idx = stage_to_index(stage)
    return -1 if idx is None else idx
