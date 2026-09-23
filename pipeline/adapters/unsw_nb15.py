"""Adapter for the raw UNSW-NB15 CSVs (UNSW-NB15_1.csv .. _4.csv), normalizing them onto the same
intermediate schema pipeline/windowing.py::build_flow_windows expects -- the same role
pipeline/adapters/ctu13.py plays for CTU-13.

These are the *raw* per-flow CSVs (2.54M rows total, no header row in the files themselves --
columns follow "V:/Datasets/UNSW NB15/CSV Files/NUSW-NB15_features.csv" exactly), NOT the
pre-split "Training and Testing Sets/*.csv" files, which drop srcip/dstip/Stime/Ltime entirely and
so cannot be windowed by host or time at all.

Unlike CTU-13 (always real IPs) and CIC-IDS-2018 (9/10 days have no IPs), every UNSW-NB15 row has
a real srcip/dstip and a Unix start/end timestamp (Stime/Ltime) -- a second, independent dataset
with genuine per-host, time-ordered sequences (D1), and the one dataset in the project with real
Reconnaissance labels (CIC-IDS-2018 has none).
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

# Column order per NUSW-NB15_features.csv. The raw CSVs ship with no header row.
RAW_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes",
    "sttl", "dttl", "sloss", "dloss", "service", "sload", "dload", "spkts", "dpkts",
    "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len",
    "sjit", "djit", "stime", "ltime", "sintpkt", "dintpkt", "tcprtt", "synack", "ackdat",
    "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd",
    "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "label",
]

PROTO_TO_NUMBER = {"tcp": 6, "udp": 17, "icmp": 1}


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize one raw UNSW-NB15 DataFrame (already RAW_COLUMNS-named) onto the shared schema."""

    df = df.copy()

    # attack_cat is blank/NaN for normal traffic; a few source files pad it with stray
    # whitespace (documented UNSW-NB15 CSV quirk).
    attack_cat = df["attack_cat"].astype("string").str.strip()
    df["original_label"] = attack_cat.fillna("Normal").replace("", "Normal")
    df["label"] = "unsw=" + df["original_label"]
    # Kept for parity with the CTU-13 adapter's output columns; windowing.py derives `stage`
    # from `label` via label_to_stage, not from attack_label.
    df["attack_label"] = np.where(df["original_label"].str.lower() == "normal", "benign", "attack")

    df["src_ip"] = df["srcip"].astype("string").str.strip()
    df["dst_ip"] = df["dstip"].astype("string").str.strip()
    df["src_port"] = pd.to_numeric(df["sport"], errors="coerce")
    df["dst_port"] = pd.to_numeric(df["dsport"], errors="coerce")

    df["proto"] = df["proto"].astype("string").str.strip().str.lower()
    df["protocol"] = df["proto"].map(PROTO_TO_NUMBER)

    # UNSW-NB15's Stime/Ltime are Unix epoch seconds (record start/end).
    df["timestamp"] = pd.to_datetime(
        pd.to_numeric(df["stime"], errors="coerce"), unit="s", errors="coerce",
    )
    df["duration_s"] = pd.to_numeric(df["dur"], errors="coerce")

    df["total_pkts"] = pd.to_numeric(df["spkts"], errors="coerce") + pd.to_numeric(df["dpkts"], errors="coerce")
    df["src_bytes"] = pd.to_numeric(df["sbytes"], errors="coerce")
    df["total_bytes"] = df["src_bytes"] + pd.to_numeric(df["dbytes"], errors="coerce")

    df["fwd_pkts"] = pd.to_numeric(df["spkts"], errors="coerce")
    df["bwd_pkts"] = pd.to_numeric(df["dpkts"], errors="coerce")
    df["fwd_bytes"] = df["src_bytes"]
    df["bwd_bytes"] = pd.to_numeric(df["dbytes"], errors="coerce")

    # Audit G4/W5: UNSW-NB15 provides no per-packet TCP flag counts (Argus reports connection
    # `state` and two handshake-completion timers, not flag tallies), so these are NOT the same
    # measurement as CIC's per-flow SYN/ACK/FIN/RST/PSH/URG packet counts. Rather than leaving
    # all six at a constant zero (which the audit flagged as the most PS-relevant gap -- the
    # problem statement singles out TCP flag ratios), derive what `state`/`synack`/`ackdat`
    # genuinely support, for TCP flows only, and leave the rest honestly at zero:
    #   - `synack` (seconds from SYN to SYN-ACK) > 0  => a SYN and a SYN-ACK were both observed.
    #     Treated as one SYN-equivalent packet per flow (a completed TCP handshake has exactly
    #     one initial SYN by definition -- not an invented count, a structural fact about TCP).
    #   - `ackdat` (seconds from SYN-ACK to the first data ACK) > 0 => the handshake's final ACK
    #     was observed => one ACK-equivalent packet per flow.
    #   - `state == "FIN"` => the flow was seen to close normally => one FIN-equivalent packet.
    #   - `state == "RST"` => the flow was reset => one RST-equivalent packet.
    #   - PSH and URG have no derivable signal anywhere in UNSW-NB15's schema (no push/urgent
    #     timers or counts of any kind) -- left at zero and documented, not invented.
    is_tcp_row = df["proto"] == "tcp"
    synack = pd.to_numeric(df["synack"], errors="coerce").fillna(0.0)
    ackdat = pd.to_numeric(df["ackdat"], errors="coerce").fillna(0.0)
    state = df["state"].astype("string").str.strip().str.upper()

    df["syn_cnt"] = np.where(is_tcp_row & (synack > 0), 1.0, 0.0)
    df["ack_cnt"] = np.where(is_tcp_row & (ackdat > 0), 1.0, 0.0)
    df["fin_cnt"] = np.where(is_tcp_row & (state == "FIN"), 1.0, 0.0)
    df["rst_cnt"] = np.where(is_tcp_row & (state == "RST"), 1.0, 0.0)
    df["psh_cnt"] = 0.0
    df["urg_cnt"] = 0.0

    # Sintpkt/Dintpkt are mean inter-packet times in MILLISECONDS; CIC's iat_mean/std/max (which
    # build_flow_windows expects, see pipeline/packet_features.py's own µs conversion for the same
    # reason) are in MICROSECONDS. Audit G4: this was never converted, making mean_iat ~1000x low
    # on top of whatever residual scale difference remains between the two datasets' own
    # measurement methodologies (documented, not hidden, in the regenerated report below).
    # No per-flow variance is available in UNSW-NB15 at all, so iat_std/iat_max are still
    # conservatively zero-filled rather than invented, same convention pipeline/adapters/ctu13.py
    # uses for CTU-13.
    MS_TO_US = 1000.0
    df["iat_mean"] = (
        pd.to_numeric(df["sintpkt"], errors="coerce").fillna(0.0)
        + pd.to_numeric(df["dintpkt"], errors="coerce").fillna(0.0)
    ) / 2.0 * MS_TO_US
    df["iat_std"] = 0.0
    df["iat_max"] = 0.0

    df["is_tcp"] = (df["protocol"] == 6).astype(float)
    df["is_udp"] = (df["protocol"] == 17).astype(float)

    df["bidir_ratio"] = np.where(
        df["total_bytes"] > 0,
        np.minimum(df["src_bytes"], df["total_bytes"] - df["src_bytes"]) / df["total_bytes"],
        0.0,
    )

    numeric_cols = [
        "total_pkts", "total_bytes", "src_bytes", "duration_s",
        "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
        "iat_mean", "iat_std", "iat_max", "is_tcp", "is_udp", "bidir_ratio",
    ]
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0)

    df = df.dropna(subset=["timestamp", "protocol", "src_ip", "dst_ip"])
    df["has_ip_data"] = 1.0  # every UNSW-NB15 row carries real IPs -- unlike 9/10 CIC-IDS-2018 days

    return df.reset_index(drop=True)


def load_unsw_nb15_file(path: str | Path) -> pd.DataFrame:
    """Load and normalize one raw UNSW-NB15_<n>.csv file (no header row)."""

    path = Path(path)
    df = pd.read_csv(path, header=None, names=RAW_COLUMNS, low_memory=False)
    df["source_file"] = path.name
    return _normalize_columns(df)


def load_unsw_nb15_directory(directory: str | Path) -> pd.DataFrame:
    """Load and normalize every UNSW-NB15_<n>.csv in ``directory`` (non-recursive -- the
    "Training and Testing Sets" subfolder holds the pre-split, no-IP files and must be skipped)."""

    directory = Path(directory)
    files = sorted(directory.glob("UNSW-NB15_[0-9]*.csv"))
    if not files:
        raise FileNotFoundError(
            f"No UNSW-NB15_<n>.csv files found directly in {directory} "
            "(expected UNSW-NB15_1.csv .. _4.csv)."
        )

    frames = []
    for path in files:
        print(f"Loading: {path}")
        try:
            df = load_unsw_nb15_file(path)
            frames.append(df)
            print(f"  Rows: {len(df):,}")
        except Exception as exc:
            print(f"  ERROR: {exc}")

    if not frames:
        raise RuntimeError("No UNSW-NB15 files could be loaded.")

    result = pd.concat(frames, ignore_index=True)
    return result.sort_values(["src_ip", "timestamp"]).reset_index(drop=True)
