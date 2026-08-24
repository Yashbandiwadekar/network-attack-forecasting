"""Ingest CICFlowMeter CSVs (CIC-IDS-2018 format) into a cleaned, normalized per-flow DataFrame.

CICFlowMeter's raw column names vary slightly by dataset release (whitespace, casing). We rename
onto a fixed internal schema so downstream code never has to guess.
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

# raw CICFlowMeter column name -> internal name. Any raw column not listed here is dropped.
COLUMN_RENAME = {
    "Src IP": "src_ip",
    "Source IP": "src_ip",
    "Src Port": "src_port",
    "Source Port": "src_port",
    "Dst IP": "dst_ip",
    "Destination IP": "dst_ip",
    "Dst Port": "dst_port",
    "Destination Port": "dst_port",
    "Protocol": "protocol",
    "Timestamp": "timestamp",
    "Flow Duration": "duration_us",
    "Tot Fwd Pkts": "fwd_pkts",
    "Total Fwd Packet": "fwd_pkts",
    "Tot Bwd Pkts": "bwd_pkts",
    "Total Bwd packets": "bwd_pkts",
    "TotLen Fwd Pkts": "fwd_bytes",
    "Total Length of Fwd Packet": "fwd_bytes",
    "TotLen Bwd Pkts": "bwd_bytes",
    "Total Length of Bwd Packet": "bwd_bytes",
    "SYN Flag Cnt": "syn_cnt",
    "SYN Flag Count": "syn_cnt",
    "ACK Flag Cnt": "ack_cnt",
    "ACK Flag Count": "ack_cnt",
    "FIN Flag Cnt": "fin_cnt",
    "FIN Flag Count": "fin_cnt",
    "RST Flag Cnt": "rst_cnt",
    "RST Flag Count": "rst_cnt",
    "PSH Flag Cnt": "psh_cnt",
    "PSH Flag Count": "psh_cnt",
    "URG Flag Cnt": "urg_cnt",
    "URG Flag Count": "urg_cnt",
    "Flow IAT Mean": "iat_mean",
    "Flow IAT Std": "iat_std",
    "Flow IAT Max": "iat_max",
    "Label": "label",
}

STRICTLY_REQUIRED_COLUMNS = [
    "dst_port", "protocol", "timestamp",
    "duration_us", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
    "syn_cnt", "ack_cnt", "fin_cnt", "rst_cnt", "psh_cnt", "urg_cnt",
    "iat_mean", "iat_std", "iat_max", "label",
]
# Several real CIC-IDS-2018 "ML-ready" CSV releases strip these three entirely (only e.g. the
# Tuesday-20-02-2018 DDoS day keeps the full 5-tuple) — optional, not required. See
# clean_and_normalize's _fill_missing_ip_columns for how their absence is handled.
OPTIONAL_IP_COLUMNS = ["src_ip", "dst_ip", "src_port"]

TCP = 6
UDP = 17


def load_flow_csv(path: str | Path) -> pd.DataFrame:
    """Load one CICFlowMeter CSV and rename to the internal schema."""
    df = pd.read_csv(path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    df = df.rename(columns=COLUMN_RENAME)
    missing = [c for c in STRICTLY_REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"{path}: missing required columns after rename: {missing}")
    present_optional = [c for c in OPTIONAL_IP_COLUMNS if c in df.columns]
    return df[STRICTLY_REQUIRED_COLUMNS + present_optional].copy()


def _fill_missing_ip_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Without a real source IP, windowing.py can't group flows per host. Rather than crash (or
    silently mis-group), synthesize one pseudo-host per capture file per calendar day
    ("NETWORK-<date>") — this makes windowing naturally aggregate that day's WHOLE network into
    one time series instead of a per-host one. `has_ip_data` records which rows have a genuine
    source IP, so windowing.py doesn't report a fabricated `unique_dst_ips` (the sentinel dst_ip
    value below would trivially make every window read "1 unique destination", which looks like a
    real signal but means "no IP data available")."""
    if "src_ip" in df.columns:
        df["has_ip_data"] = 1.0
    else:
        day = df["timestamp"].dt.date.astype(str)
        df["src_ip"] = "NETWORK-" + day
        df["has_ip_data"] = 0.0
    if "dst_ip" not in df.columns:
        df["dst_ip"] = "UNKNOWN"
    if "src_port" not in df.columns:
        df["src_port"] = 0
    return df


def _parse_timestamp(series: pd.Series) -> pd.Series:
    """Two explicit formats tried in sequence, NOT pandas' format="mixed" + dayfirst=True
    inference — verified that combination silently corrupts unambiguous ISO dates too (it parses
    "2026-01-02" as 2026-02-01, not 2026-01-02). Real CIC-IDS-2018 uses day-first slash-separated
    timestamps (confirmed by dates like 14/02/2018, which can only be day-first — there's no 14th
    month); the synthetic sample uses ISO-style dashes. Each gets its own explicit, unambiguous
    format; only values matching neither become NaT.
    """
    day_first_slash = pd.to_datetime(series, format="%d/%m/%Y %H:%M:%S", errors="coerce")
    iso_dash = pd.to_datetime(series, format="ISO8601", errors="coerce")  # tolerates optional .microseconds
    return day_first_slash.fillna(iso_dash)


def clean_and_normalize(df: pd.DataFrame) -> pd.DataFrame:
    """Coerce types, drop unparseable rows, derive per-flow fields used by windowing.py."""
    df = df.copy()

    numeric_cols = [
        "dst_port", "protocol", "duration_us", "fwd_pkts", "bwd_pkts",
        "fwd_bytes", "bwd_bytes", "syn_cnt", "ack_cnt", "fin_cnt", "rst_cnt",
        "psh_cnt", "urg_cnt", "iat_mean", "iat_std", "iat_max",
    ]
    if "src_port" in df.columns:
        numeric_cols = ["src_port"] + numeric_cols
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df["timestamp"] = _parse_timestamp(df["timestamp"])
    df = df.dropna(subset=["timestamp", "protocol"])
    df = df.dropna(subset=numeric_cols)

    # replace inf (CICFlowMeter occasionally emits inf for rate features) before any aggregation
    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=numeric_cols)

    df = _fill_missing_ip_columns(df)

    df["label"] = df["label"].astype(str).str.strip()
    df["total_pkts"] = df["fwd_pkts"] + df["bwd_pkts"]
    df["total_bytes"] = df["fwd_bytes"] + df["bwd_bytes"]
    df["duration_s"] = df["duration_us"] / 1_000_000.0
    df["is_tcp"] = (df["protocol"] == TCP).astype(float)
    df["is_udp"] = (df["protocol"] == UDP).astype(float)
    df["bidir_ratio"] = np.minimum(df["fwd_pkts"], df["bwd_pkts"]) / df["total_pkts"].replace(0, np.nan)
    df["bidir_ratio"] = df["bidir_ratio"].fillna(0.0)

    df = df[df["total_pkts"] > 0].reset_index(drop=True)
    return df


def load_flow_dir(dir_path: str | Path) -> pd.DataFrame:
    """Load and concatenate every *.csv in a directory of CICFlowMeter output."""
    dir_path = Path(dir_path)
    frames = [clean_and_normalize(load_flow_csv(p)) for p in sorted(dir_path.glob("*.csv"))]
    if not frames:
        raise FileNotFoundError(f"No CSV files found in {dir_path}")
    return pd.concat(frames, ignore_index=True).sort_values("timestamp").reset_index(drop=True)
