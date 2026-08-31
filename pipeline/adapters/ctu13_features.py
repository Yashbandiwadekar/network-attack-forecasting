from __future__ import annotations

import numpy as np
import pandas as pd


def add_ctu13_features(df: pd.DataFrame) -> pd.DataFrame:
    """Convert normalized CTU-13 flows into the feature schema expected by windowing.py."""

    df = df.copy()

    # CTU-13 already provides these values.
    df["total_pkts"] = pd.to_numeric(df["total_pkts"], errors="coerce")
    df["total_bytes"] = pd.to_numeric(df["total_bytes"], errors="coerce")
    df["src_bytes"] = pd.to_numeric(df["src_bytes"], errors="coerce")
    df["duration_s"] = pd.to_numeric(df["duration_s"], errors="coerce")

    # CTU-13 does not provide CICFlowMeter TCP flag counts.
    # Use conservative defaults rather than inventing packet-level measurements.
    for col in [
        "syn_cnt",
        "ack_cnt",
        "fin_cnt",
        "rst_cnt",
        "psh_cnt",
        "urg_cnt",
    ]:
        if col not in df.columns:
            df[col] = 0.0

    # CTU-13 does not provide flow inter-arrival statistics.
    for col in ["iat_mean", "iat_std", "iat_max"]:
        if col not in df.columns:
            df[col] = 0.0

    # Protocol is numeric after CTU normalization:
    # TCP = 6, UDP = 17.
    df["is_tcp"] = (df["protocol"] == 6).astype(float)
    df["is_udp"] = (df["protocol"] == 17).astype(float)

    # Approximate bidirectional activity from forward/source packets.
    # CTU-13's SrcBytes is source-direction bytes, so use bytes as a
    # conservative directional indicator.
    df["bidir_ratio"] = np.where(
        df["total_bytes"] > 0,
        np.minimum(
            df["src_bytes"],
            df["total_bytes"] - df["src_bytes"],
        ) / df["total_bytes"],
        0.0,
    )

    # Make sure required numeric columns contain finite values.
    numeric_cols = [
        "total_pkts",
        "total_bytes",
        "src_bytes",
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
        "is_tcp",
        "is_udp",
        "bidir_ratio",
    ]

    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df[numeric_cols] = (
        df[numeric_cols]
        .replace([np.inf, -np.inf], np.nan)
        .fillna(0.0)
    )

    return df