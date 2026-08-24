"""Packet-level features from raw PCAP, via Scapy.

Flow-level features (flow_features.py) capture aggregate behaviour (a SYN flood). Packet-level
features expose timing/sequencing patterns a flow-level view smooths over — TTL variance across a
session, a port scan's near-one-packet-per-port signature, retransmissions. PCAP input is optional:
windowing.py falls back to flow-only features when no PCAP is available for a given capture window.
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
from scapy.all import IP, TCP, UDP, PcapReader

TCP_PROTO = 6
UDP_PROTO = 17


def load_pcap(path: str | Path) -> pd.DataFrame:
    """Parse a PCAP into one row per IP packet. Non-IP packets are skipped."""
    rows = []
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            if IP not in pkt:
                continue
            ip = pkt[IP]
            row = {
                "timestamp": pd.to_datetime(float(pkt.time), unit="s"),
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "ttl": ip.ttl,
                "is_frag": bool(ip.flags.MF) or ip.frag > 0,
                "payload_size": len(bytes(ip.payload)),
                "src_port": np.nan,
                "dst_port": np.nan,
                "window_size": np.nan,
                "seq": np.nan,
                "protocol": "OTHER",
            }
            if TCP in pkt:
                tcp = pkt[TCP]
                row.update(
                    src_port=int(tcp.sport), dst_port=int(tcp.dport),
                    window_size=int(tcp.window), seq=int(tcp.seq), protocol="TCP",
                )
            elif UDP in pkt:
                udp = pkt[UDP]
                row.update(src_port=int(udp.sport), dst_port=int(udp.dport), protocol="UDP")
            rows.append(row)
    if not rows:
        raise ValueError(f"No IP packets found in {path}")
    return pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)


def _retransmit_ratio(group: pd.DataFrame) -> float:
    tcp_pkts = group[group["protocol"] == "TCP"]
    if len(tcp_pkts) == 0:
        return 0.0
    keys = tcp_pkts[["src_ip", "dst_ip", "src_port", "dst_port", "seq"]]
    duplicate_count = len(keys) - len(keys.drop_duplicates())
    return duplicate_count / len(tcp_pkts)


def _port_scan_score(group: pd.DataFrame) -> float:
    total_pkts = len(group)
    if total_pkts == 0:
        return 0.0
    unique_ports = group["dst_port"].nunique(dropna=True)
    return float(np.clip(unique_ports / total_pkts, 0.0, 1.0))


def compute_packet_window_features(df: pd.DataFrame, window_seconds: int) -> pd.DataFrame:
    """Aggregate per-packet rows into per (src_ip, window_start) packet-level state features."""
    df = df.copy()
    df["window_start"] = df["timestamp"].dt.floor(f"{window_seconds}s")

    out = []
    for (src_ip, window_start), group in df.groupby(["src_ip", "window_start"]):
        payload = group["payload_size"]
        out.append({
            "src_ip": src_ip,
            "window_start": window_start,
            "mean_ttl": group["ttl"].mean(),
            "var_ttl": group["ttl"].var(ddof=0) or 0.0,
            "mean_window_size": group["window_size"].mean(skipna=True) or 0.0,
            "frag_ratio": group["is_frag"].mean(),
            "mean_payload_size": payload.mean(),
            "std_payload_size": payload.std(ddof=0) or 0.0,
            "port_scan_score": _port_scan_score(group),
            "retransmit_ratio": _retransmit_ratio(group),
        })
    return pd.DataFrame(out)
