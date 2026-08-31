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
    (src_ip, window_start) state vectors, using the flow_level feature list from config.

    Vectorized via groupby().agg() rather than a Python loop over groups — real CIC-IDS-2018
    collapses ~16M flows into ~1.5M (src_ip, window) groups, and iterating those one at a time in
    Python took over 20 minutes; this does the equivalent work in well under a minute by pushing
    the aggregation into pandas' C implementation. The one exception is `stage` (needs the mode of
    non-benign labels per window), which still uses a per-group apply, but only over the attack
    subset of rows — typically 1-2% of the data — not all of them.
    """
    window_seconds = config["windowing"]["window_seconds"]
    df = flow_df.copy()
    df["window_start"] = df["timestamp"].dt.floor(f"{window_seconds}s")
    df["stage"] = df["label"].map(label_to_stage)
    if "has_ip_data" not in df.columns:
        df["has_ip_data"] = 1.0  # caller didn't route through flow_features.clean_and_normalize
    df["iat_var"] = df["iat_std"] ** 2

    group_keys = ["src_ip", "window_start"]
    grouped = df.groupby(group_keys, sort=False)

    agg = pd.DataFrame({
        "flow_count": grouped.size(),
        "unique_dst_ports": grouped["dst_port"].nunique(),
        "unique_dst_ips": grouped["dst_ip"].nunique(),
        "has_ip_data": grouped["has_ip_data"].first(),
        "total_bytes": grouped["total_bytes"].sum(),
        "total_packets": grouped["total_pkts"].sum(),
        "mean_duration": grouped["duration_s"].mean(),
        "mean_iat": grouped["iat_mean"].mean(),
        "var_iat": grouped["iat_var"].mean(),
        "max_iat": grouped["iat_max"].max(),
        "bidir_ratio": grouped["bidir_ratio"].mean(),
        "tcp_ratio": grouped["is_tcp"].mean(),
        "udp_ratio": grouped["is_udp"].mean(),
    })

    # dst_ip is a constant sentinel ("UNKNOWN") when has_ip_data is 0 — nunique() would trivially
    # read 1, which looks like a real "only one destination" signal but isn't
    agg.loc[agg["has_ip_data"] == 0.0, "unique_dst_ips"] = 0.0

    safe_total = agg["total_packets"].where(agg["total_packets"] > 0)  # NaN where 0, guards /0
    for ratio_col, count_col in [
        ("syn_ratio", "syn_cnt"), ("ack_ratio", "ack_cnt"), ("fin_ratio", "fin_cnt"),
        ("rst_ratio", "rst_cnt"), ("psh_ratio", "psh_cnt"), ("urg_ratio", "urg_cnt"),
    ]:
        agg[ratio_col] = (grouped[count_col].sum() / safe_total).fillna(0.0)

    # majority non-benign label wins the window, so one attack flow among many benign flows still
    # marks the window as an attack window (rare events must not get diluted away)
    attack_rows = df[df["stage"] != BENIGN]
    if len(attack_rows) > 0:
        attack_stage = attack_rows.groupby(group_keys, sort=False)["stage"].agg(lambda s: s.mode().iloc[0])
        agg["stage"] = attack_stage.reindex(agg.index)
    else:
        agg["stage"] = None
    agg["stage"] = agg["stage"].fillna(BENIGN)

    return agg.reset_index().sort_values(["src_ip", "window_start"]).reset_index(drop=True)


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
