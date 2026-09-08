"""Adds synthetic large-but-legitimate benign traffic to the real CIC-IDS-2018 raw flow directory.

Fixes a robustness failure found by scripts/check_robustness.py: the trained model flagged a big
legitimate transfer (long-lived, low SYN ratio, single sustained connection) at 100% infiltration
probability. Root cause traced (see docs/04-evaluation-real.md discussion / session notes):
total_bytes for that capture pegs at the FeatureScaler's +6 std clip ceiling — a raw-volume range
that, in the real CIC-IDS-2018 training data, is almost exclusively attack traffic (e.g. DDoS
floods), so the model learned "extreme volume = attack" as a shortcut instead of looking at flow
shape (SYN ratio, destination diversity, flow count).

This generates several distinct legitimate high-volume archetypes spanning that same extreme
volume range, all labeled BENIGN:
  - backup / bulk transfer: one destination, very few large flows per window (the exact shape
    check_robustness.py exercises)
  - video / media streaming: one or two destinations, sustained duration
  - database replication: one destination, TCP, high throughput
  - patch / software distribution: MANY destinations and MANY flows per window, each individually
    modest — a deliberately different benign-high-volume shape (high flow_count, high destination
    diversity) so the model doesn't just learn a new shortcut ("low flow_count = benign")
  - cloud sync / large file share: a handful of destinations, high throughput

Output is written as one more CICFlowMeter-shaped CSV into the real raw flow directory
(data/raw/flows_real/), so it flows through the exact same pipeline.build_dataset path as the real
CIC-IDS-2018 files — no special-casing needed downstream. Each synthetic host gets a genuine
src_ip (like the one real per-host CIC-IDS-2018 day), so windowing.py treats it as a normal host,
not a network-wide pseudo-host.

Usage:
    python -m scripts.augment_benign_high_volume
"""
from __future__ import annotations

import argparse

import numpy as np
import pandas as pd

from common.config import load_config, resolve_path

RNG = np.random.default_rng(42)  # distinct from check_robustness.py's RNG(7) — independent traffic,
                                  # not a copy of the held-out check's exact scenario.
OUTPUT_NAME = "Synthetic-BenignHighVolume_TrafficForML_CICFlowMeter.csv"
WINDOW_SECONDS = 10


def _host_capture(
    host_ip: str,
    n_windows: int,
    base_time: pd.Timestamp,
    n_destinations: int,
    flows_per_window: tuple[int, int],
    fwd_bytes_range: tuple[float, float],
    dst_ports: list[int],
    is_udp: bool = False,
) -> list[dict]:
    """One synthetic host's worth of large-but-legitimate flows across n_windows time windows."""
    rows = []
    dest_ips = [f"10.50.{RNG.integers(0, 255)}.{RNG.integers(1, 255)}" for _ in range(n_destinations)]
    protocol = 17 if is_udp else 6
    for w in range(n_windows):
        window_start = base_time + pd.Timedelta(seconds=w * WINDOW_SECONDS)
        n_flows = int(RNG.integers(flows_per_window[0], flows_per_window[1] + 1))
        for _ in range(n_flows):
            dst = dest_ips[RNG.integers(0, len(dest_ips))]
            fwd_pkts = int(RNG.integers(500, 30000))
            bwd_pkts = int(RNG.integers(100, 15000))
            fwd_bytes = float(RNG.uniform(*fwd_bytes_range))
            bwd_bytes = fwd_bytes * float(RNG.uniform(0.05, 0.3))
            total_pkts = fwd_pkts + bwd_pkts
            ts = window_start + pd.Timedelta(seconds=float(RNG.uniform(0, WINDOW_SECONDS)))
            rows.append({
                "Src IP": host_ip,
                "Src Port": int(RNG.integers(30000, 65000)),
                "Dst IP": dst,
                "Dst Port": int(RNG.choice(dst_ports)),
                "Protocol": protocol,
                "Timestamp": ts.strftime("%d/%m/%Y %H:%M:%S"),
                "Flow Duration": int(RNG.uniform(1_000_000, 9_500_000)),
                "Tot Fwd Pkts": fwd_pkts,
                "Tot Bwd Pkts": bwd_pkts,
                "TotLen Fwd Pkts": int(fwd_bytes),
                "TotLen Bwd Pkts": int(bwd_bytes),
                "SYN Flag Cnt": 1,
                "ACK Flag Cnt": int(total_pkts * RNG.uniform(0.80, 0.99)),
                "FIN Flag Cnt": int(RNG.integers(0, 2)),
                "RST Flag Cnt": 0,
                "PSH Flag Cnt": int(RNG.integers(20, 500)),
                "URG Flag Cnt": 0,
                "Flow IAT Mean": float(RNG.uniform(50, 2000)),
                "Flow IAT Std": float(RNG.uniform(5, 300)),
                "Flow IAT Max": float(RNG.uniform(500, 8000)),
                "Label": "BENIGN",
            })
    return rows


# (archetype name, count, n_windows range, n_destinations range, flows_per_window range,
#  fwd_bytes range, dst_ports, is_udp)
ARCHETYPES = [
    ("backup", 10, (60, 150), (1, 1), (1, 3), (2_000_000, 45_000_000), [443, 22, 873], False),
    ("stream", 10, (80, 200), (1, 2), (1, 2), (1_000_000, 15_000_000), [443, 8443], False),
    ("replication", 8, (60, 140), (1, 1), (1, 2), (3_000_000, 50_000_000), [3306, 5432, 443], False),
    ("patch_distribution", 8, (40, 100), (10, 30), (10, 40), (200_000, 2_000_000), [443, 80], False),
    ("cloud_sync", 8, (60, 150), (2, 5), (2, 5), (1_500_000, 20_000_000), [443, 8443, 22], False),
]


def build_augmentation_df() -> pd.DataFrame:
    base_time = pd.Timestamp("2018-04-01 00:00:00")
    all_rows: list[dict] = []
    host_counter = 0
    for name, count, n_windows_range, n_dest_range, flows_range, byte_range, ports, is_udp in ARCHETYPES:
        for i in range(count):
            host_counter += 1
            host_ip = f"10.90.{host_counter // 255}.{host_counter % 255 + 1}"
            n_windows = int(RNG.integers(*n_windows_range))
            n_dest = int(RNG.integers(n_dest_range[0], n_dest_range[1] + 1))
            host_start = base_time + pd.Timedelta(hours=host_counter)  # stagger hosts, no real reason it matters
            all_rows.extend(_host_capture(
                host_ip, n_windows, host_start, n_dest, flows_range, byte_range, ports, is_udp,
            ))
    df = pd.DataFrame(all_rows)
    print(f"Generated {len(df)} synthetic benign high-volume flows across {host_counter} hosts "
          f"({', '.join(f'{name}={count}' for name, count, *_ in ARCHETYPES)}).")
    return df


def main(config_path: str = "configs/real_data.yaml") -> None:
    config = load_config(config_path)
    raw_flow_dir = resolve_path(config, "raw_flow_dir")
    raw_flow_dir.mkdir(parents=True, exist_ok=True)

    df = build_augmentation_df()
    out_path = raw_flow_dir / OUTPUT_NAME
    df.to_csv(out_path, index=False)
    print(f"Wrote {out_path} ({out_path.stat().st_size / 1024:.0f} KB)")
    print("Rebuild the dataset to pick this up: python -m pipeline.build_dataset --config "
          f"{config_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/real_data.yaml")
    args = parser.parse_args()
    main(args.config)
