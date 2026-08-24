"""Generate a small synthetic CICFlowMeter-shaped CSV + matching PCAP so the pipeline, models,
and demo can run end-to-end before the real (tens-of-GB) CIC-IDS-2018 download is in place.

This is NOT real attack data — a narrative attack chain across a handful of source IPs, built
purely to exercise every stage in the MITRE label space (including `exfiltration`, which no real
CIC-IDS-2018 label maps to — see pipeline/mitre_mapping.py). The Streamlit demo must say clearly
when it's running on this synthetic sample instead of real data.

Usage:
    python -m scripts.make_synthetic_sample --config configs/default.yaml
"""
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
from scapy.all import IP, TCP, wrpcap

from common.config import load_config, resolve_path

RNG = np.random.default_rng(42)
BASE_TIME = pd.Timestamp("2026-01-01 00:00:00")

BENIGN_IPS = ["10.0.0.5", "10.0.0.12"]
ATTACKER_IP = "10.0.0.9"
VICTIM_IP = "10.0.0.50"
INTERNAL_HOSTS = ["10.0.0.60", "10.0.0.70", "10.0.0.80"]
C2_IP = "203.0.113.9"
EXFIL_IP = "198.51.100.7"


def _flow_row(t: pd.Timestamp, src_ip, dst_ip, src_port, dst_port, protocol, duration_us,
              fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes, syn, ack, fin, rst, psh, urg,
              iat_mean, iat_std, iat_max, label) -> dict:
    return dict(
        **{"Src IP": src_ip, "Src Port": src_port, "Dst IP": dst_ip, "Dst Port": dst_port,
           "Protocol": protocol, "Timestamp": t, "Flow Duration": duration_us,
           "Tot Fwd Pkts": fwd_pkts, "Tot Bwd Pkts": bwd_pkts,
           "TotLen Fwd Pkts": fwd_bytes, "TotLen Bwd Pkts": bwd_bytes,
           "SYN Flag Cnt": syn, "ACK Flag Cnt": ack, "FIN Flag Cnt": fin, "RST Flag Cnt": rst,
           "PSH Flag Cnt": psh, "URG Flag Cnt": urg,
           "Flow IAT Mean": iat_mean, "Flow IAT Std": iat_std, "Flow IAT Max": iat_max,
           "Label": label},
    )


def _benign_phase(start_s: int, end_s: int) -> list[dict]:
    rows = []
    for src_ip in BENIGN_IPS:
        t = start_s
        while t < end_s:
            dst_ip = f"93.184.216.{RNG.integers(1, 254)}"
            rows.append(_flow_row(
                BASE_TIME + pd.Timedelta(seconds=t), src_ip, dst_ip,
                int(RNG.integers(1024, 65535)), int(RNG.choice([80, 443, 53])), 6,
                int(RNG.uniform(50_000, 2_000_000)),
                int(RNG.integers(3, 40)), int(RNG.integers(3, 40)),
                int(RNG.integers(200, 20000)), int(RNG.integers(200, 20000)),
                1, int(RNG.integers(3, 30)), 1, 0, int(RNG.integers(1, 10)), 0,
                float(RNG.uniform(1000, 50000)), float(RNG.uniform(100, 5000)), float(RNG.uniform(50000, 200000)),
                "BENIGN",
            ))
            t += int(RNG.uniform(2, 8))
    return rows


def _recon_phase(start_s: int, end_s: int) -> list[dict]:
    """Attacker port-scans the victim. Flow-level label stays BENIGN (CIC-IDS-2018 has no recon
    label) — reconnaissance is derived later from packet-level port_scan_score, see
    pipeline/windowing.py:apply_reconnaissance_heuristic."""
    rows = []
    ports = list(range(1, 151))
    t = start_s
    for port in ports:
        if t >= end_s:
            break
        rows.append(_flow_row(
            BASE_TIME + pd.Timedelta(seconds=t), ATTACKER_IP, VICTIM_IP,
            int(RNG.integers(40000, 65000)), port, 6,
            int(RNG.uniform(500, 5000)), 1, 0, 40, 0,
            1, 0, 0, 1, 0, 0,
            0.0, 0.0, 0.0, "BENIGN",
        ))
        t += (end_s - start_s) / len(ports)
    return rows


def _bruteforce_phase(start_s: int, end_s: int) -> list[dict]:
    rows = []
    t = start_s
    while t < end_s:
        rows.append(_flow_row(
            BASE_TIME + pd.Timedelta(seconds=t), ATTACKER_IP, VICTIM_IP,
            int(RNG.integers(40000, 65000)), 22, 6,
            int(RNG.uniform(20_000, 200_000)),
            int(RNG.integers(2, 6)), int(RNG.integers(1, 4)),
            int(RNG.integers(60, 400)), int(RNG.integers(60, 400)),
            1, int(RNG.integers(0, 3)), 0, int(RNG.integers(0, 2)), 0, 0,
            float(RNG.uniform(500, 5000)), float(RNG.uniform(50, 500)), float(RNG.uniform(5000, 20000)),
            "SSH-Bruteforce",
        ))
        t += int(RNG.uniform(1, 4))
    return rows


def _lateral_movement_phase(start_s: int, end_s: int) -> list[dict]:
    rows = []
    t = start_s
    while t < end_s:
        dst_ip = RNG.choice(INTERNAL_HOSTS)
        rows.append(_flow_row(
            BASE_TIME + pd.Timedelta(seconds=t), ATTACKER_IP, dst_ip,
            int(RNG.integers(40000, 65000)), int(RNG.choice([445, 3389, 139, 22])), 6,
            int(RNG.uniform(100_000, 900_000)),
            int(RNG.integers(5, 30)), int(RNG.integers(5, 30)),
            int(RNG.integers(500, 8000)), int(RNG.integers(500, 8000)),
            1, int(RNG.integers(2, 20)), int(RNG.integers(0, 2)), 0, int(RNG.integers(0, 5)), 0,
            float(RNG.uniform(2000, 20000)), float(RNG.uniform(200, 2000)), float(RNG.uniform(20000, 80000)),
            "Infilteration",
        ))
        t += int(RNG.uniform(3, 10))
    return rows


def _c2_phase(start_s: int, end_s: int) -> list[dict]:
    """Regular, low-variance beacon interval — the signature C2 pattern."""
    rows = []
    t = start_s
    beacon_interval = 5
    while t < end_s:
        rows.append(_flow_row(
            BASE_TIME + pd.Timedelta(seconds=t), ATTACKER_IP, C2_IP,
            int(RNG.integers(40000, 65000)), 443, 6,
            int(RNG.uniform(10_000, 30_000)),
            2, 2, int(RNG.integers(100, 300)), int(RNG.integers(100, 300)),
            1, 2, 1, 0, 1, 0,
            float(beacon_interval * 1_000_000), float(RNG.uniform(10, 100)), float(beacon_interval * 1_100_000),
            "Bot",
        ))
        t += beacon_interval
    return rows


def _exfiltration_phase(start_s: int, end_s: int) -> list[dict]:
    rows = []
    t = start_s
    while t < end_s:
        rows.append(_flow_row(
            BASE_TIME + pd.Timedelta(seconds=t), ATTACKER_IP, EXFIL_IP,
            int(RNG.integers(40000, 65000)), 443, 6,
            int(RNG.uniform(1_000_000, 5_000_000)),
            int(RNG.integers(50, 200)), int(RNG.integers(5, 20)),
            int(RNG.integers(500_000, 3_000_000)), int(RNG.integers(1000, 5000)),
            1, int(RNG.integers(10, 50)), int(RNG.integers(0, 2)), 0, int(RNG.integers(20, 80)), 0,
            float(RNG.uniform(5000, 20000)), float(RNG.uniform(500, 3000)), float(RNG.uniform(30000, 100000)),
            "SYNTH-Exfiltration",
        ))
        t += int(RNG.uniform(5, 15))
    return rows


def _recon_packets(start_s: int, end_s: int) -> list:
    """PCAP packets matching the recon flow phase: one SYN per port to the victim — this is what
    gives that window a high port_scan_score in pipeline/packet_features.py."""
    packets = []
    ports = list(range(1, 151))
    for i, port in enumerate(ports):
        t = start_s + i * (end_s - start_s) / len(ports)
        pkt = IP(src=ATTACKER_IP, dst=VICTIM_IP, ttl=64) / TCP(sport=int(RNG.integers(40000, 65000)), dport=port, flags="S")
        pkt.time = (BASE_TIME + pd.Timedelta(seconds=t)).timestamp()
        packets.append(pkt)
    return packets


def _benign_packets(start_s: int, end_s: int) -> list:
    packets = []
    t = start_s
    while t < end_s:
        for src_ip in BENIGN_IPS:
            dst_ip = f"93.184.216.{RNG.integers(1, 254)}"
            pkt = IP(src=src_ip, dst=dst_ip, ttl=int(RNG.choice([64, 128]))) / TCP(
                sport=int(RNG.integers(1024, 65535)), dport=443, flags="PA",
                window=int(RNG.integers(4000, 65000)),
            )
            pkt /= b"x" * int(RNG.integers(50, 1400))
            pkt.time = (BASE_TIME + pd.Timedelta(seconds=t)).timestamp()
            packets.append(pkt)
        t += int(RNG.uniform(2, 8))
    return packets


def _bruteforce_packets(start_s: int, end_s: int) -> list:
    """Includes deliberate duplicate (seq, port) packets to exercise retransmit_ratio."""
    packets = []
    t = start_s
    last_seq = 1000
    while t < end_s:
        sport = int(RNG.integers(40000, 65000))
        pkt = IP(src=ATTACKER_IP, dst=VICTIM_IP, ttl=64) / TCP(sport=sport, dport=22, flags="S", seq=last_seq)
        pkt.time = (BASE_TIME + pd.Timedelta(seconds=t)).timestamp()
        packets.append(pkt)
        if RNG.random() < 0.3:  # simulate a retransmission
            retry = IP(src=ATTACKER_IP, dst=VICTIM_IP, ttl=64) / TCP(sport=sport, dport=22, flags="S", seq=last_seq)
            retry.time = (BASE_TIME + pd.Timedelta(seconds=t + 0.5)).timestamp()
            packets.append(retry)
        last_seq += 1
        t += int(RNG.uniform(1, 4))
    return packets


def _lateral_movement_packets(start_s: int, end_s: int) -> list:
    packets = []
    t = start_s
    while t < end_s:
        dst_ip = str(RNG.choice(INTERNAL_HOSTS))
        port = int(RNG.choice([445, 3389, 139, 22]))
        pkt = IP(src=ATTACKER_IP, dst=dst_ip, ttl=64) / TCP(
            sport=int(RNG.integers(40000, 65000)), dport=port, flags="PA",
            window=int(RNG.integers(4000, 65000)),
        )
        pkt /= b"x" * int(RNG.integers(100, 2000))
        pkt.time = (BASE_TIME + pd.Timedelta(seconds=t)).timestamp()
        packets.append(pkt)
        t += int(RNG.uniform(2, 6))
    return packets


def _c2_packets(start_s: int, end_s: int) -> list:
    """Regular beacon interval, matching _c2_phase's flow-level pattern."""
    packets = []
    t = start_s
    beacon_interval = 5
    while t < end_s:
        pkt = IP(src=ATTACKER_IP, dst=C2_IP, ttl=64) / TCP(
            sport=int(RNG.integers(40000, 65000)), dport=443, flags="PA",
            window=int(RNG.integers(4000, 8000)),
        )
        pkt /= b"x" * int(RNG.integers(100, 300))
        pkt.time = (BASE_TIME + pd.Timedelta(seconds=t)).timestamp()
        packets.append(pkt)
        t += beacon_interval
    return packets


def _exfiltration_packets(start_s: int, end_s: int) -> list:
    packets = []
    t = start_s
    while t < end_s:
        pkt = IP(src=ATTACKER_IP, dst=EXFIL_IP, ttl=64) / TCP(
            sport=int(RNG.integers(40000, 65000)), dport=443, flags="PA",
            window=int(RNG.integers(4000, 65000)),
        )
        pkt /= b"x" * int(RNG.integers(1000, 1400))
        pkt.time = (BASE_TIME + pd.Timedelta(seconds=t)).timestamp()
        packets.append(pkt)
        t += int(RNG.uniform(1, 3))
    return packets


def main(config_path: str = "configs/default.yaml") -> None:
    config = load_config(config_path)
    flow_dir = resolve_path(config, "raw_flow_dir")
    pcap_dir = resolve_path(config, "raw_pcap_dir")
    flow_dir.mkdir(parents=True, exist_ok=True)
    pcap_dir.mkdir(parents=True, exist_ok=True)

    # One narrative attack cycle (recon -> bruteforce -> lateral movement -> C2 -> exfiltration,
    # bookended by benign traffic) repeated across the timeline so every chronological train/val/test
    # split — not just one — actually contains attack examples. A single non-repeating cycle put every
    # attack phase in the train split and left val/test entirely benign, which is a synthetic-data
    # artifact, not something the real (much larger, multi-day) CIC-IDS-2018 dataset would exhibit.
    cycle_length = 900
    n_cycles = 4
    rows = []
    packets = []
    for cycle in range(n_cycles):
        offset = cycle * cycle_length
        phases = [
            (offset + 0, offset + 300, _benign_phase),
            (offset + 300, offset + 375, _recon_phase),
            (offset + 375, offset + 450, _bruteforce_phase),
            (offset + 450, offset + 600, _lateral_movement_phase),
            (offset + 600, offset + 750, _c2_phase),
            (offset + 750, offset + 825, _exfiltration_phase),
            (offset + 825, offset + 900, _benign_phase),
        ]
        for start, end, fn in phases:
            rows.extend(fn(start, end))

        # PCAP coverage alternates by WHOLE CYCLE, not by attack phase. Every cycle contains the
        # same phase progression (benign -> recon -> bruteforce -> lateral -> C2 -> exfil ->
        # benign), so an every-other-cycle capture gap — simulating a sensor that periodically
        # drops, e.g. a rotating/rebooting capture appliance — is independent of the attack label.
        # Earlier this only ever captured the first three phases of every cycle, which made
        # `has_packet_features` a near-perfect proxy for "early vs late attack" — the same leak
        # class a competing SIH team found and fixed on CTU-13's PCAP. See
        # tests/test_windowing.py::test_has_packet_features_not_a_near_perfect_label_proxy_on_synthetic_sample.
        if cycle % 2 == 0:
            packets.extend(_benign_packets(offset + 0, offset + 300))
            packets.extend(_recon_packets(offset + 300, offset + 375))
            packets.extend(_bruteforce_packets(offset + 375, offset + 450))
            packets.extend(_lateral_movement_packets(offset + 450, offset + 600))
            packets.extend(_c2_packets(offset + 600, offset + 750))
            packets.extend(_exfiltration_packets(offset + 750, offset + 825))
            packets.extend(_benign_packets(offset + 825, offset + 900))

    flow_df = pd.DataFrame(rows).sort_values("Timestamp")
    csv_path = flow_dir / "synthetic_sample.csv"
    flow_df.to_csv(csv_path, index=False)
    print(f"Wrote {len(flow_df)} synthetic flows -> {csv_path}")

    packets.sort(key=lambda p: p.time)
    pcap_path = pcap_dir / "synthetic_sample.pcap"
    wrpcap(str(pcap_path), packets)
    print(f"Wrote {len(packets)} synthetic packets -> {pcap_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/default.yaml")
    args = parser.parse_args()
    main(args.config)
