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

REQUIRED_COLUMNS = [
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp",
    "duration_us", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
    "syn_cnt", "ack_cnt", "fin_cnt", "rst_cnt", "psh_cnt", "urg_cnt",
    "iat_mean", "iat_std", "iat_max", "label",
]

TCP = 6
UDP = 17


def load_flow_csv(path: str | Path) -> pd.DataFrame:
    """Load one CICFlowMeter CSV and rename to the internal schema."""
    df = pd.read_csv(path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    df = df.rename(columns=COLUMN_RENAME)
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"{path}: missing required columns after rename: {missing}")
    return df[REQUIRED_COLUMNS].copy()


def clean_and_normalize(df: pd.DataFrame) -> pd.DataFrame:
    """Coerce types, drop unparseable rows, derive per-flow fields used by windowing.py."""
    df = df.copy()

    numeric_cols = [
        "src_port", "dst_port", "protocol", "duration_us", "fwd_pkts", "bwd_pkts",
        "fwd_bytes", "bwd_bytes", "syn_cnt", "ack_cnt", "fin_cnt", "rst_cnt",
        "psh_cnt", "urg_cnt", "iat_mean", "iat_std", "iat_max",
    ]
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", format="mixed")
    df = df.dropna(subset=["timestamp", "src_ip", "protocol"])
    df = df.dropna(subset=numeric_cols)

    # replace inf (CICFlowMeter occasionally emits inf for rate features) before any aggregation
    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=numeric_cols)

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
