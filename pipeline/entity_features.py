from __future__ import annotations

import pandas as pd


def add_entity_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add source/destination entity statistics to network flows."""

    df = df.copy()

    # ---------------------------------------------------------
    # Ensure required columns exist
    # ---------------------------------------------------------
    required = [
        "src_ip",
        "dst_ip",
        "dst_port",
        "total_pkts",
        "total_bytes",
    ]

    missing = [
        col for col in required
        if col not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing required columns: {missing}"
        )

    # ---------------------------------------------------------
    # Basic numeric safety
    # ---------------------------------------------------------
    for col in [
        "dst_port",
        "total_pkts",
        "total_bytes",
    ]:
        df[col] = pd.to_numeric(
            df[col],
            errors="coerce",
        ).fillna(0.0)

    # ---------------------------------------------------------
    # Source entity statistics
    #
    # Entity = source IP.
    # These describe the behavior of the source across
    # the complete flow table.
    # ---------------------------------------------------------

    src_group = df.groupby(
        "src_ip",
        dropna=False,
    )

    src_stats = src_group.agg(
        src_flow_count=("dst_ip", "size"),
        src_unique_dst_ips=("dst_ip", "nunique"),
        src_unique_dst_ports=("dst_port", "nunique"),
        src_total_bytes=("total_bytes", "sum"),
        src_total_packets=("total_pkts", "sum"),
    )

    df = df.join(
        src_stats,
        on="src_ip",
    )

    # ---------------------------------------------------------
    # Destination entity statistics
    #
    # Entity = destination IP.
    # These describe how much traffic reaches that
    # destination and how many different sources contact it.
    # ---------------------------------------------------------

    dst_group = df.groupby(
        "dst_ip",
        dropna=False,
    )

    dst_stats = dst_group.agg(
        dst_flow_count=("src_ip", "size"),
        dst_unique_src_ips=("src_ip", "nunique"),
        dst_unique_src_ports=("dst_port", "nunique"),
        dst_total_bytes=("total_bytes", "sum"),
        dst_total_packets=("total_pkts", "sum"),
    )

    df = df.join(
        dst_stats,
        on="dst_ip",
    )

    # ---------------------------------------------------------
    # Degree-like graph features
    # ---------------------------------------------------------

    df["src_degree"] = (
        df["src_unique_dst_ips"]
        + df["src_unique_dst_ports"]
    )

    df["dst_degree"] = (
        df["dst_unique_src_ips"]
        + df["dst_unique_src_ports"]
    )

    # ---------------------------------------------------------
    # Per-flow relative behavior
    # ---------------------------------------------------------

    df["src_bytes_ratio"] = (
        df["total_bytes"]
        / df["src_total_bytes"].replace(0, pd.NA)
    ).fillna(0.0)

    df["src_packets_ratio"] = (
        df["total_pkts"]
        / df["src_total_packets"].replace(0, pd.NA)
    ).fillna(0.0)

    df["dst_bytes_ratio"] = (
        df["total_bytes"]
        / df["dst_total_bytes"].replace(0, pd.NA)
    ).fillna(0.0)

    df["dst_packets_ratio"] = (
        df["total_pkts"]
        / df["dst_total_packets"].replace(0, pd.NA)
    ).fillna(0.0)

    # ---------------------------------------------------------
    # Numeric cleanup
    # ---------------------------------------------------------

    feature_cols = [
        "src_flow_count",
        "src_unique_dst_ips",
        "src_unique_dst_ports",
        "src_total_bytes",
        "src_total_packets",
        "dst_flow_count",
        "dst_unique_src_ips",
        "dst_unique_src_ports",
        "dst_total_bytes",
        "dst_total_packets",
        "src_degree",
        "dst_degree",
        "src_bytes_ratio",
        "src_packets_ratio",
        "dst_bytes_ratio",
        "dst_packets_ratio",
    ]

    df[feature_cols] = (
        df[feature_cols]
        .apply(pd.to_numeric, errors="coerce")
        .fillna(0.0)
    )

    return df
