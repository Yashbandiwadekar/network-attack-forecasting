"""Time-window aggregation, sequence building, and feature merging."""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from pipeline.mitre_mapping import (
    BENIGN,
    IMPACT,
    RECONNAISSANCE,
    label_to_stage,
    stage_to_index,
)


def build_flow_windows(
    flow_df: pd.DataFrame,
    config: dict[str, Any],
) -> pd.DataFrame:
    """Aggregate flow rows into per-(src_ip, window_start) states.

    Uses pandas vectorized aggregation instead of a Python loop over every
    individual window. This is substantially faster for large datasets such
    as CTU-13.
    """

    window_seconds = config["windowing"]["window_seconds"]

    df = flow_df.copy()

    # Ensure required columns exist.
    if "has_ip_data" not in df.columns:
        df["has_ip_data"] = 1.0

    # Create time windows.
    df["window_start"] = df["timestamp"].dt.floor(
        f"{window_seconds}s"
    )

    # Map raw labels to MITRE-style stages.
    df["stage"] = df["label"].map(label_to_stage)

    # Numeric safety.
    numeric_cols = [
        "total_pkts",
        "total_bytes",
        "duration_s",
        "syn_cnt",
        "ack_cnt",
        "fin_cnt",
        "rst_cnt",
        "psh_cnt",
        "urg_cnt",
        "iat_mean",
        "iat_std",
        "iat_max",
        "bidir_ratio",
        "is_tcp",
        "is_udp",
    ]

    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(
                df[col],
                errors="coerce",
            ).fillna(0.0)

    # ------------------------------------------------------------------
    # Pre-compute values needed by aggregation.
    # ------------------------------------------------------------------

    df["_one"] = 1.0

    # Destination IP uniqueness should be zero when IP data is unavailable.
    df["_dst_ip_value"] = df["dst_ip"].where(
        df["has_ip_data"].astype(bool),
        pd.NA,
    )

    # IAT variance contribution.
    df["_iat_var"] = df["iat_std"] ** 2

    # ------------------------------------------------------------------
    # Vectorized group aggregation.
    # ------------------------------------------------------------------

    if "scenario_id" in df.columns:
        group_cols = [
            "scenario_id",
            "src_ip",
            "window_start",
        ]
    else:
        group_cols = [
            "src_ip",
            "window_start",
        ]

    grouped = df.groupby(
        group_cols,
        sort=False,
        observed=True,
        dropna=False,
    )

    windows = grouped.agg(
        flow_count=("_one", "sum"),
        unique_dst_ports=("dst_port", "nunique"),
        unique_dst_ips=("_dst_ip_value", "nunique"),
        has_ip_data=("has_ip_data", "first"),
        total_bytes=("total_bytes", "sum"),
        total_packets=("total_pkts", "sum"),
        mean_duration=("duration_s", "mean"),
        syn_count=("syn_cnt", "sum"),
        ack_count=("ack_cnt", "sum"),
        fin_count=("fin_cnt", "sum"),
        rst_count=("rst_cnt", "sum"),
        psh_count=("psh_cnt", "sum"),
        urg_count=("urg_cnt", "sum"),
        mean_iat=("iat_mean", "mean"),
        var_iat=("_iat_var", "mean"),
        max_iat=("iat_max", "max"),
        bidir_ratio=("bidir_ratio", "mean"),
        tcp_ratio=("is_tcp", "mean"),
        udp_ratio=("is_udp", "mean"),
    ).reset_index()

    # ------------------------------------------------------------------
    # Convert packet counts to ratios.
    # ------------------------------------------------------------------

    total_packets = windows["total_packets"]

    for name, source in [
        ("syn_ratio", "syn_count"),
        ("ack_ratio", "ack_count"),
        ("fin_ratio", "fin_count"),
        ("rst_ratio", "rst_count"),
        ("psh_ratio", "psh_count"),
        ("urg_ratio", "urg_count"),
    ]:
        windows[name] = np.divide(
            windows[source],
            total_packets,
            out=np.zeros(len(windows), dtype=np.float64),
            where=total_packets.to_numpy() != 0,
        )

    # Remove temporary count columns.
    windows = windows.drop(
        columns=[
            "syn_count",
            "ack_count",
            "fin_count",
            "rst_count",
            "psh_count",
            "urg_count",
        ]
    )

    # ------------------------------------------------------------------
    # Match original behavior:
    # unique_dst_ips = 0 when no real IP data is available.
    # ------------------------------------------------------------------

    windows["unique_dst_ips"] = np.where(
        windows["has_ip_data"].astype(bool),
        windows["unique_dst_ips"],
        0.0,
    )

    # ------------------------------------------------------------------
    # Determine window stage.
    #
    # Any non-benign stage wins over benign.
    # For multiple attack stages, use the most frequent attack stage.
    # ------------------------------------------------------------------

    non_benign = df[df["stage"] != BENIGN]

    if not non_benign.empty:
        stage_counts = (
            non_benign
            .groupby(
                group_cols + ["stage"],
                sort=False,
                observed=True,
                dropna=False,
            )
            .size()
            .rename("stage_count")
            .reset_index()
        )

        # Pick the most frequent non-benign stage per window.
        stage_counts = stage_counts.sort_values(
            group_cols + ["stage_count"],
            ascending=[True] * len(group_cols) + [False],
        )

        attack_stage = (
            stage_counts
            .drop_duplicates(
                subset=group_cols,
                keep="first",
            )
            [group_cols + ["stage"]]
            .rename(columns={"stage": "attack_stage"})
        )

        windows = windows.merge(
            attack_stage,
            on=group_cols,
            how="left",
        )

        windows["stage"] = windows["attack_stage"].fillna(BENIGN)
        windows = windows.drop(columns=["attack_stage"])

    else:
        windows["stage"] = BENIGN

    # ------------------------------------------------------------------
    # Column ordering.
    # ------------------------------------------------------------------

    columns = [
        "src_ip",
        "window_start",
        "flow_count",
        "unique_dst_ports",
        "unique_dst_ips",
        "has_ip_data",
        "total_bytes",
        "total_packets",
        "mean_duration",
        "syn_ratio",
        "ack_ratio",
        "fin_ratio",
        "rst_ratio",
        "psh_ratio",
        "urg_ratio",
        "mean_iat",
        "var_iat",
        "max_iat",
        "bidir_ratio",
        "tcp_ratio",
        "udp_ratio",
        "stage",
    ]

    if "scenario_id" in windows.columns:
        columns.insert(0, "scenario_id")

    windows = windows[columns]

    return (
        windows
        .sort_values(
            group_cols,
            kind="mergesort",
        )
        .reset_index(drop=True)
    )


def _majority_stage(stages: pd.Series) -> str:
    """Return the most common non-benign stage, otherwise benign."""
    non_benign = stages[stages != BENIGN]

    if len(non_benign) > 0:
        return non_benign.mode().iloc[0]

    return BENIGN


def merge_packet_features(
    flow_windows: pd.DataFrame,
    packet_windows: pd.DataFrame | None,
    config: dict[str, Any],
) -> pd.DataFrame:
    """Merge packet-level features onto flow windows."""

    real_packet_cols = [
        c
        for c in config["features"]["packet_level"]
        if c != "has_packet_features"
    ]

    merged = flow_windows.copy()

    if packet_windows is None or packet_windows.empty:
        for col in real_packet_cols:
            merged[col] = 0.0

        merged["has_packet_features"] = 0.0

        return merged

    merged = merged.merge(
        packet_windows,
        on=["src_ip", "window_start"],
        how="left",
        indicator=True,
    )

    merged["has_packet_features"] = (
        merged["_merge"] == "both"
    ).astype(float)

    merged = merged.drop(columns=["_merge"])

    merged[real_packet_cols] = (
        merged[real_packet_cols]
        .fillna(0.0)
    )

    return merged

def merge_graph_features(
    flow_windows: pd.DataFrame,
    graph_windows: pd.DataFrame | None,
    config: dict[str, Any],
) -> pd.DataFrame:
    """Merge graph-level window features onto the flow-window DataFrame.

    Parallel to :func:`merge_packet_features`.  When *graph_windows* is
    ``None`` or empty (e.g. no real IP data was available across the whole
    capture), every graph feature column is zero-filled — consistent with the
    treatment of unavailable packet telemetry.

    The model learns to ignore these columns via the ``has_ip_data`` sentinel
    that is already part of the flow-level feature vector.

    Parameters
    ----------
    flow_windows :
        Output of :func:`build_flow_windows`.
    graph_windows :
        Output of :func:`pipeline.graph_features.build_graph_window_features`,
        or ``None``.
    config :
        Full project config.  ``config["features"].get("graph_level", [])``
        defines which columns to merge.
    """
    graph_cols = list(config["features"].get("graph_level", []))

    merged = flow_windows.copy()

    if not graph_cols:
        # No graph features configured — nothing to do.
        return merged

    if graph_windows is None or graph_windows.empty:
        for col in graph_cols:
            merged[col] = 0.0
        return merged

    # Determine join keys (preserve scenario_id when present)
    join_keys = ["src_ip", "window_start"]
    if (
        "scenario_id" in flow_windows.columns
        and "scenario_id" in graph_windows.columns
    ):
        join_keys = ["scenario_id"] + join_keys

    # Only keep keys + graph feature columns from graph_windows to avoid
    # column-name collisions on a subsequent merge.
    graph_subset = graph_windows[
        join_keys + [c for c in graph_cols if c in graph_windows.columns]
    ]

    merged = merged.merge(graph_subset, on=join_keys, how="left")

    for col in graph_cols:
        if col in merged.columns:
            merged[col] = merged[col].fillna(0.0)
        else:
            merged[col] = 0.0

    return merged


def merge_graph_embedding_features(
    flow_windows: pd.DataFrame,
    embedding_windows: pd.DataFrame | None,
    config: dict[str, Any],
) -> pd.DataFrame:
    """Merge learned graph-embedding window features onto the flow-window DataFrame. Parallel to
    merge_graph_features -- same zero-fill-when-absent convention, same join keys -- for the
    output of pipeline.graph_embedding_features.build_graph_embedding_window_features instead of
    pipeline.graph_features.build_graph_window_features.
    """
    embed_cols = list(config["features"].get("graph_embedding", []))

    merged = flow_windows.copy()

    if not embed_cols:
        return merged

    if embedding_windows is None or embedding_windows.empty:
        for col in embed_cols:
            merged[col] = 0.0
        return merged

    join_keys = ["src_ip", "window_start"]
    if (
        "scenario_id" in flow_windows.columns
        and "scenario_id" in embedding_windows.columns
    ):
        join_keys = ["scenario_id"] + join_keys

    embed_subset = embedding_windows[
        join_keys + [c for c in embed_cols if c in embedding_windows.columns]
    ]

    merged = merged.merge(embed_subset, on=join_keys, how="left")

    for col in embed_cols:
        if col in merged.columns:
            merged[col] = merged[col].fillna(0.0)
        else:
            merged[col] = 0.0

    return merged


def apply_reconnaissance_heuristic(
    windows_df: pd.DataFrame,
    config: dict[str, Any],
) -> pd.DataFrame:
    """Relabel qualifying benign windows as reconnaissance."""

    threshold = config["windowing"]["recon_port_scan_threshold"]
    horizon = config["windowing"]["forecast_horizon"]

    df = windows_df.copy()

    if "scenario_id" in df.columns:
        recon_group_cols = ["scenario_id", "src_ip"]
    else:
        recon_group_cols = ["src_ip"]

    for group_key, group in df.groupby(
        recon_group_cols,
        sort=False,
        observed=True,
    ):
        idx = group.index.to_numpy()

        stages = group["stage"].to_numpy()
        scores = group["port_scan_score"].to_numpy()

        for i in range(len(idx)):
            if stages[i] != BENIGN:
                continue

            if scores[i] < threshold:
                continue

            future = stages[
                i + 1 : i + 1 + horizon
            ]

            if np.any(
                (future != BENIGN)
                & (future != IMPACT)
            ):
                df.loc[idx[i], "stage"] = RECONNAISSANCE

    return df


def build_sequences(
    windows_df: pd.DataFrame,
    feature_cols: list[str],
    config: dict[str, Any],
) -> dict[str, np.ndarray]:
    """Build fixed-length temporal sequences with bounded memory."""

    seq_len = config["windowing"]["sequence_length"]
    horizon = config["windowing"]["forecast_horizon"]

    X_parts = []
    next_state_parts = []
    future_stage_parts = []
    infiltration_parts = []
    current_stage_parts = []
    current_infiltration_parts = []
    window_end_time_parts = []
    window_times_parts = []
    src_ip_parts = []
    scenario_id_parts = []

    if "scenario_id" in windows_df.columns:
        group_cols = ["scenario_id", "src_ip"]
    else:
        group_cols = ["src_ip"]

    for group_key, group in windows_df.groupby(
        group_cols,
        sort=False,
        observed=True,
    ):
        group = (
            group
            .sort_values("window_start")
            .reset_index(drop=True)
        )

        n = len(group)
        sample_count = n - seq_len - horizon + 1

        if sample_count <= 0:
            continue

        feats = group[feature_cols].to_numpy(
            dtype=np.float32,
            copy=True,
        )

        stages = group["stage"].to_numpy()
        times = group["window_start"].to_numpy()

        X_group = np.lib.stride_tricks.sliding_window_view(
            feats,
            seq_len,
            axis=0,
        )

        X_group = np.transpose(
            X_group,
            (0, 2, 1),
        )

        X_group = X_group[
            :sample_count
        ].copy()

        next_state_group = feats[
            seq_len:seq_len + sample_count
        ].copy()

        future_stage_group = np.empty(
            (sample_count, horizon),
            dtype=np.int64,
        )

        infiltration_group = np.empty(
            (sample_count, horizon),
            dtype=np.float32,
        )

        for j in range(horizon):
            future = stages[
                seq_len + j:
                seq_len + j + sample_count
            ]

            future_stage_group[:, j] = np.array(
                [
                    _stage_idx_or_masked(s)
                    for s in future
                ],
                dtype=np.int64,
            )

            infiltration_group[:, j] = np.array(
                [
                    0.0 if s == BENIGN else 1.0
                    for s in future
                ],
                dtype=np.float32,
            )

        current_stage_group = np.array(
            [
                _stage_idx_or_masked(s)
                for s in stages[
                    seq_len - 1:
                    seq_len - 1 + sample_count
                ]
            ],
            dtype=np.int64,
        )

        current_infiltration_group = np.array(
            [
                0.0 if s == BENIGN else 1.0
                for s in stages[
                    seq_len - 1:
                    seq_len - 1 + sample_count
                ]
            ],
            dtype=np.float32,
        )

        window_end_time_group = times[
            seq_len - 1:
            seq_len - 1 + sample_count
        ]

        # The window_start timestamp of EVERY one of the seq_len input steps per sample (not just
        # the last one, which window_end_time already captures) -- joint GNN training
        # (models/world_model_joint.py) needs this to look up the exact WindowGraph backing each
        # step, since a sequence's steps can have gaps in wall-clock time (a host silent for a
        # window simply has no row for it, so consecutive rows here aren't always window_seconds
        # apart) and so can't be reconstructed from window_end_time alone.
        window_times_group = np.lib.stride_tricks.sliding_window_view(
            times, seq_len,
        )[:sample_count].copy()

        src_ip_value = group["src_ip"].iloc[0]

        X_parts.append(X_group)
        next_state_parts.append(next_state_group)
        future_stage_parts.append(future_stage_group)
        infiltration_parts.append(infiltration_group)
        current_stage_parts.append(current_stage_group)
        current_infiltration_parts.append(
            current_infiltration_group
        )
        window_end_time_parts.append(
            window_end_time_group
        )
        window_times_parts.append(
            window_times_group
        )

        src_ip_parts.append(
            np.repeat(
                src_ip_value,
                sample_count,
            )
        )

        if "scenario_id" in windows_df.columns:
            scenario_id_value = group[
                "scenario_id"
            ].iloc[0]

            scenario_id_parts.append(
                np.repeat(
                    scenario_id_value,
                    sample_count,
                )
            )

    if not X_parts:
        result = {
            "X": np.zeros(
                (
                    0,
                    seq_len,
                    len(feature_cols),
                ),
                dtype=np.float32,
            ),
            "next_state": np.zeros(
                (
                    0,
                    len(feature_cols),
                ),
                dtype=np.float32,
            ),
            "future_stages": np.zeros(
                (0, horizon),
                dtype=np.int64,
            ),
            "infiltration": np.zeros(
                (0, horizon),
                dtype=np.float32,
            ),
            "current_stage": np.zeros(
                0,
                dtype=np.int64,
            ),
            "current_infiltration": np.zeros(
                0,
                dtype=np.float32,
            ),
            "window_end_time": np.array([]),
            "window_times": np.zeros((0, seq_len), dtype="datetime64[ns]"),
            "src_ip": np.array([]),
        }

        if "scenario_id" in windows_df.columns:
            result["scenario_id"] = np.array([])

        return result

    result = {
        "X": np.concatenate(
            X_parts,
            axis=0,
        ),
        "next_state": np.concatenate(
            next_state_parts,
            axis=0,
        ),
        "future_stages": np.concatenate(
            future_stage_parts,
            axis=0,
        ),
        "infiltration": np.concatenate(
            infiltration_parts,
            axis=0,
        ),
        "current_stage": np.concatenate(
            current_stage_parts,
            axis=0,
        ),
        "current_infiltration": np.concatenate(
            current_infiltration_parts,
            axis=0,
        ),
        "window_end_time": np.concatenate(
            window_end_time_parts,
            axis=0,
        ),
        "window_times": np.concatenate(
            window_times_parts,
            axis=0,
        ),
        "src_ip": np.concatenate(
            src_ip_parts,
            axis=0,
        ),
    }

    if "scenario_id" in windows_df.columns:
        result["scenario_id"] = np.concatenate(
            scenario_id_parts,
            axis=0,
        )

    # --------------------------------------------------------------
    # IMPORTANT:
    # Sequences are created group-by-group (scenario_id, src_ip).
    # Therefore concatenation order is NOT chronological.
    # Sort every sequence-related array using the same timestamp
    # order before the dataset is split into train/val/test.
    # --------------------------------------------------------------

    order = np.argsort(
        result["window_end_time"],
        kind="stable",
    )

    for key in result:
        result[key] = result[key][order]

    return result


def _stage_idx_or_masked(stage: str) -> int:
    idx = stage_to_index(stage)

    return -1 if idx is None else idx
