"""Packet-level features from raw PCAP / PCAPNG, via Scapy.

Flow-level features (flow_features.py) capture aggregate behaviour (a SYN flood). Packet-level
features expose timing/sequencing patterns a flow-level view smooths over — TTL variance across a
session, a port scan's near-one-packet-per-port signature, retransmissions. PCAP input is optional
when a flow CSV is also present: windowing.py falls back to flow-only features when no PCAP is
available for a given capture window. When PCAP is the ONLY input (audit S4), build_flow_records
below derives flow-level records directly from these same per-packet rows, so a capture needs no
companion CSV at all.

PCAPNG note: scapy's `PcapReader` class dispatches on the file's magic bytes, not its extension —
it already reads both classic pcap (`\\xd4\\xc3\\xb2\\xa1` et al.) and pcapng (`\\x0a\\x0d\\x0d\\x0a`)
transparently (see scapy.utils.rdpcap, which relies on the same dispatch). Verified against a real
PcapNgWriter-produced file. The historical ".pcapng rejected" behaviour (audit S4) was the
uploader's `type="pcap"` restriction in the since-retired Streamlit UI, not a parsing limitation
here — both extensions are accepted by the current upload path
(`app/server.py::upload_file`, which allows .pcap/.pcapng/.csv).
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
from scapy.all import IP, TCP, UDP, PcapReader

TCP_PROTO = 6
UDP_PROTO = 17

# Scapy's TCP.flags is a bitmask; these are the standard single-letter membership checks it
# supports directly ("S" in flags, etc.) rather than hand-rolling the bit values.
_TCP_FLAG_LETTERS = {"syn": "S", "ack": "A", "fin": "F", "rst": "R", "psh": "P", "urg": "U"}


def load_pcap(path: str | Path) -> pd.DataFrame:
    """Parse a PCAP or PCAPNG file into one row per IP packet. Non-IP packets are skipped."""
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
                "l4_payload_size": 0,
                "src_port": np.nan,
                "dst_port": np.nan,
                "window_size": np.nan,
                "seq": np.nan,
                "protocol": "OTHER",
                **{f"flag_{name}": 0 for name in _TCP_FLAG_LETTERS},
            }
            if TCP in pkt:
                tcp = pkt[TCP]
                row.update(
                    src_port=int(tcp.sport), dst_port=int(tcp.dport),
                    window_size=int(tcp.window), seq=int(tcp.seq), protocol="TCP",
                    l4_payload_size=len(bytes(tcp.payload)),
                    **{f"flag_{name}": int(letter in tcp.flags) for name, letter in _TCP_FLAG_LETTERS.items()},
                )
            elif UDP in pkt:
                udp = pkt[UDP]
                row.update(src_port=int(udp.sport), dst_port=int(udp.dport), protocol="UDP",
                           l4_payload_size=len(bytes(udp.payload)))
            rows.append(row)
    if not rows:
        raise ValueError(f"No IP packets found in {path}")
    return pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)


def build_flow_records(packet_df: pd.DataFrame) -> pd.DataFrame:
    """Aggregate per-packet rows (load_pcap's output) into per-flow records in the SAME
    already-normalized schema pipeline.flow_features.clean_and_normalize produces from a
    CICFlowMeter CSV -- so the result feeds pipeline.windowing.build_flow_windows directly, no
    CSV required (audit S4: PCAP-only input).

    Flow key: the unordered {src_ip, src_port} <-> {dst_ip, dst_port} pair plus protocol -- both
    directions of one TCP/UDP conversation merge into ONE flow record, matching CICFlowMeter's own
    flow definition. "Forward" is the direction of the first packet observed for that flow (also
    matching CICFlowMeter). Unlike CICFlowMeter, no inactivity timeout splits a long-idle
    conversation into multiple flows -- a documented simplification for a bounded demo capture,
    not fabricated data: every field below is a genuine aggregate of the packets that arrived.
    ICMP and other non-TCP/UDP traffic is dropped (no ports to key a flow on).
    """
    df = packet_df[packet_df["protocol"].isin(["TCP", "UDP"])].copy()
    if df.empty:
        raise ValueError("No TCP/UDP packets to build flow records from (only ICMP/other seen).")

    endpoint_a = df["src_ip"] + ":" + df["src_port"].astype(int).astype(str)
    endpoint_b = df["dst_ip"] + ":" + df["dst_port"].astype(int).astype(str)
    df["flow_key"] = df["protocol"] + "|" + np.minimum(endpoint_a, endpoint_b) + "<->" + np.maximum(endpoint_a, endpoint_b)

    records = []
    for flow_key, group in df.groupby("flow_key", sort=False):
        group = group.sort_values("timestamp")
        first = group.iloc[0]
        forward = (group["src_ip"] == first["src_ip"]) & (group["src_port"] == first["src_port"])
        fwd_pkts, bwd_pkts = int(forward.sum()), int((~forward).sum())
        # CICFlowMeter's TotLen Fwd/Bwd Pkts counts L4 payload bytes only (no TCP/UDP header) --
        # `payload_size` above is the whole IP payload, so use l4_payload_size to match the CSV path.
        fwd_bytes = float(group.loc[forward, "l4_payload_size"].sum())
        bwd_bytes = float(group.loc[~forward, "l4_payload_size"].sum())

        iats = group["timestamp"].diff().dt.total_seconds().dropna()
        duration_s = (group["timestamp"].iloc[-1] - group["timestamp"].iloc[0]).total_seconds()

        records.append({
            "timestamp": first["timestamp"],
            "src_ip": first["src_ip"],
            "dst_ip": first["dst_ip"],
            "src_port": int(first["src_port"]),
            "dst_port": int(first["dst_port"]),
            "label": "BENIGN",  # unlabeled live capture -- see load_flow_csv(require_label=False)
            "has_ip_data": 1.0,  # a PCAP always carries real IPs, unlike 9/10 CIC-IDS-2018 days
            "total_pkts": fwd_pkts + bwd_pkts,
            "total_bytes": fwd_bytes + bwd_bytes,
            "duration_s": max(duration_s, 0.0),
            "syn_cnt": float(group["flag_syn"].sum()),
            "ack_cnt": float(group["flag_ack"].sum()),
            "fin_cnt": float(group["flag_fin"].sum()),
            "rst_cnt": float(group["flag_rst"].sum()),
            "psh_cnt": float(group["flag_psh"].sum()),
            "urg_cnt": float(group["flag_urg"].sum()),
            # CICFlowMeter's Flow IAT Mean/Std/Max are in MICROSECONDS (clean_and_normalize carries
            # them through unchanged, and the model was trained on that scale). total_seconds()
            # is seconds, so scale by 1e6 -- without this every PCAP-only upload fed the model
            # IAT features 10^6x too small (audit G5). duration_s stays in seconds, matching
            # clean_and_normalize's duration_us / 1e6.
            "iat_mean": float(iats.mean()) * 1e6 if len(iats) else 0.0,
            "iat_std": float(iats.std(ddof=0)) * 1e6 if len(iats) else 0.0,
            "iat_max": float(iats.max()) * 1e6 if len(iats) else 0.0,
            "is_tcp": float(first["protocol"] == "TCP"),
            "is_udp": float(first["protocol"] == "UDP"),
            "bidir_ratio": (min(fwd_pkts, bwd_pkts) / (fwd_pkts + bwd_pkts)) if (fwd_pkts + bwd_pkts) else 0.0,
        })

    return pd.DataFrame(records).sort_values("timestamp").reset_index(drop=True)


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
