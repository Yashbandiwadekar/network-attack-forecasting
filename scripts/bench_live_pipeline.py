"""Throughput of the live pipeline, stage by stage (docs/11). READ-ONLY on the capture it is given.

    python -m scripts.bench_live_pipeline --pcap V:/Datasets/CTU-13-pcaps/1/botnet-capture-20110810-neris.pcap
    python -m scripts.bench_live_pipeline --synthetic-pps 1000 --seconds 180      # no capture needed

For a capture it reports: frame-length facts (captured vs wire vs IP total length, so truncation and
padding are visible), why frames were skipped, then the time of each stage on the whole file -- raw read,
header parse, flow assembly, windowing, graph features, GraphSAGE embedding, batched rollout -- and an
end-to-end LiveEngine replay at maximum speed. The synthetic mode drives the engine with a fixed packet
rate in 1-second slices and reports the per-tick cost (the docs/09 A3 success test is tick p95 < 2 s at
1,000 packets/s). Nothing here opens a network interface or writes next to the capture.
"""
from __future__ import annotations

import argparse
import json
import platform
import struct
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _hw() -> dict:
    info = {"platform": platform.platform(), "python": sys.version.split()[0], "logical_cpus": None, "cpu": None}
    try:
        import os
        info["logical_cpus"] = os.cpu_count()
    except Exception:
        pass
    try:
        if sys.platform == "win32":
            import subprocess
            out = subprocess.run(["powershell", "-NoProfile", "-Command",
                                  "(Get-CimInstance Win32_Processor | Select-Object -First 1).Name"],
                                 capture_output=True, text=True, timeout=20).stdout.strip()
            info["cpu"] = out or None
        else:
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.startswith("model name"):
                    info["cpu"] = line.split(":", 1)[1].strip()
                    break
    except Exception:
        pass
    try:
        import psutil
        info["ram_gb"] = round(psutil.virtual_memory().total / 2**30, 1)
    except Exception:
        pass
    return info


def frame_facts(path: Path) -> dict:
    """Captured vs wire length, IP total length vs captured, and skip reasons. Pure reading."""
    from scapy.utils import RawPcapReader
    n = trunc = ip_len_mismatch = padded = 0
    skip: Counter = Counter()
    proto: Counter = Counter()
    sum_cap_pay = sum_ip_pay = 0
    with RawPcapReader(str(path)) as r:
        is_ng = type(r).__name__ == "RawPcapNgReader"
        for data, meta in r:
            n += 1
            if meta.wirelen > len(data):
                trunc += 1
            if len(data) < 34:
                skip["short"] += 1
                continue
            et = struct.unpack_from(">H", data, 12)[0]
            if et == 0x8100:
                skip["802.1Q VLAN"] += 1
            elif et == 0x86DD:
                skip["IPv6"] += 1
            elif et == 0x0806:
                skip["ARP"] += 1
            elif et != 0x0800:
                skip[f"ethertype 0x{et:04x}"] += 1
            else:
                ihl = (data[14] & 15) * 4
                tot = struct.unpack_from(">H", data, 16)[0]
                p = data[23]
                proto[p] += 1
                if tot + 14 != len(data):
                    ip_len_mismatch += 1
                if tot + 14 < len(data):
                    padded += 1
                if p in (6, 17):
                    hdr = ((data[14 + ihl + 12] >> 4) * 4) if p == 6 and len(data) >= 14 + ihl + 13 else 8
                    sum_cap_pay += max(len(data) - 14 - ihl - hdr, 0)
                    sum_ip_pay += max(tot - ihl - hdr, 0)
                if p not in (6, 17):
                    skip[f"IP proto {p} (not TCP/UDP: parsed, then ignored by the flow builder)"] += 1
    return {"frames": n, "format": "pcapng" if is_ng else "pcap", "truncated_frames_caplen_lt_wirelen": trunc,
            "frames_where_ip_total_length_plus_14_ne_caplen": ip_len_mismatch,
            "frames_with_ethernet_padding": padded, "ip_protocols": {str(k): v for k, v in proto.most_common()},
            "skipped_or_ignored": dict(skip), "l4_payload_bytes_by_captured_length": int(sum_cap_pay),
            "l4_payload_bytes_by_ip_total_length": int(sum_ip_pay),
            "phantom_bytes_removed_by_ip_length_fix": int(sum_cap_pay - sum_ip_pay)}


def stage_times(path: Path, config_path: str, flow_timeout: float) -> dict:
    from scapy.utils import RawPcapReader
    from app import service
    from models.forecast import ForecastEngine, latest_sequences_batch
    from pipeline import fast_packet_windows as F
    from pipeline.graph_embedding_features import build_graph_embedding_window_features
    from pipeline.graph_features import build_graph_window_features
    from pipeline.windowing import (apply_reconnaissance_heuristic, build_flow_windows, merge_graph_embedding_features,
                                    merge_graph_features, merge_packet_features)
    from common.config import feature_columns
    out: dict = {}
    t = time.perf_counter()
    buf = []
    with RawPcapReader(str(path)) as r:
        is_ng = type(r).__name__ == "RawPcapNgReader"
        lt = None
        for data, meta in r:
            if lt is None:
                lt = meta.linktype if is_ng else r.linktype
            buf.append((data, ((meta.tshigh << 32) | meta.tslow) / meta.tsresol if is_ng else meta.sec + meta.usec / 1e6))
    out["read_s"] = time.perf_counter() - t
    t = time.perf_counter()
    cols = F._parse_chunk(buf, F._LINK_HEADER[lt], F._ETHERTYPE_OFFSET[lt])
    out["parse_s"] = time.perf_counter() - t
    n_frames, n_pk = len(buf), len(cols["ts"])
    del buf
    t = time.perf_counter()
    fl = F.assemble_flows(cols, timeout_s=flow_timeout)
    out["assemble_s"] = time.perf_counter() - t
    config, model, scaler, _ = service.load_backend(config_path)
    fdf = fl.drop(columns=["timestamp_s", "src_ip", "dst_ip"]).copy()
    fdf["timestamp"] = pd.to_datetime(fl["timestamp_s"].to_numpy(), unit="s")
    fdf["src_ip"] = F.ip_to_str(fl["src_ip"]).to_numpy()
    fdf["dst_ip"] = F.ip_to_str(fl["dst_ip"]).to_numpy()
    fdf["label"] = "BENIGN"
    t = time.perf_counter()
    w = build_flow_windows(fdf, config)
    out["windowing_s"] = time.perf_counter() - t
    t = time.perf_counter()
    gw = build_graph_window_features(fdf, config)
    out["graph_features_s"] = time.perf_counter() - t
    t = time.perf_counter()
    ew = build_graph_embedding_window_features(fdf, config)
    out["graph_embedding_s"] = time.perf_counter() - t
    w = merge_graph_embedding_features(merge_graph_features(merge_packet_features(w, None, config), gw, config), ew, config)
    w = apply_reconnaissance_heuristic(w, config)
    engine = ForecastEngine(model, scaler, config)
    t = time.perf_counter()
    hosts, seqs = latest_sequences_batch(w, feature_columns(config), int(config["windowing"]["sequence_length"]))
    batch = engine.rollout_batch(hosts, seqs) if hosts else None
    out["score_s"] = time.perf_counter() - t
    out.update(frames=n_frames, parsed_packets=n_pk, flows=int(len(fl)), windows=int(len(w)), hosts_scored=len(hosts),
               capture_span_s=float(cols["ts"].max() - cols["ts"].min()))
    out["read_frames_per_s"] = n_frames / out["read_s"]
    out["parse_frames_per_s"] = n_frames / out["parse_s"]
    out["assemble_packets_per_s"] = n_pk / out["assemble_s"]
    out["assemble_flows_per_s"] = len(fl) / out["assemble_s"]
    front = out["read_s"] + out["parse_s"] + out["assemble_s"]
    out["read_parse_assemble_packets_per_s"] = n_pk / front
    feat = out["windowing_s"] + out["graph_features_s"] + out["graph_embedding_s"]
    out["whole_file_batch_total_s"] = front + feat + out["score_s"]
    out["whole_file_batch_packets_per_s"] = n_pk / out["whole_file_batch_total_s"]
    del batch
    return out


def engine_replay(path: Path, config_path: str, flow_timeout: float, slice_s: float) -> dict:
    from app import service
    from app.live import LiveEngine, LiveSettings, ReplaySource
    from models.forecast import ForecastEngine
    config, model, scaler, _ = service.load_backend(config_path)
    le = LiveEngine(ForecastEngine(model, scaler, config), config, LiveSettings(flow_timeout_s=flow_timeout),
                    publish=lambda s: None, source_name="bench", mode="REPLAY")
    t = time.perf_counter()
    src = ReplaySource(le, [path], speed=0, slice_s=slice_s)
    src.run()
    wall = time.perf_counter() - t
    st = le.status()
    lat = sorted(le._lat)
    return {"wall_s": wall, "packets": st["packets_total"], "flows": st["flows_total"], "windows": st["windows_processed"],
            "packets_per_s": st["packets_total"] / wall, "flows_per_s": st["flows_total"] / wall,
            "ticks": len(lat), "tick_p50_s": lat[len(lat) // 2] if lat else None,
            "tick_p95_s": lat[int(len(lat) * 0.95)] if lat else None, "tick_max_s": lat[-1] if lat else None,
            "error": st["error"], "hosts_scored": st["hosts_scored"], "hosts_warming": st["hosts_warming_up"],
            "buffer_packets_at_end": st["caps"]["buffer_packets_now"], "slice_s": slice_s}


def synthetic_cols(pps: int, seconds: int, n_hosts: int, seed: int = 1, base: float = 1_760_000_000.0) -> dict:
    """pps packets/s as flows of 8 packets (SYN, SYN-ACK, ACK, 3 data both ways, FIN) between n_hosts clients
    and 20 servers, vectorised so generating 300k packets takes well under a second."""
    rng = np.random.default_rng(seed)
    n_flows = pps * seconds // 8
    start = np.sort(rng.random(n_flows) * seconds) + base
    cli = rng.integers(1, n_hosts + 1, n_flows)
    srv = rng.integers(1, 21, n_flows)
    sport = (10000 + np.arange(n_flows) % 50000).astype(np.int64)
    dport = rng.choice([22, 80, 443, 8080], n_flows)
    offs = np.array([0.0, 0.01, 0.02, 0.2, 0.25, 0.8, 0.85, 1.0])
    fwd = np.array([1, 0, 1, 1, 0, 1, 0, 1], dtype=bool)
    flags = np.array([0x02, 0x12, 0x10, 0x18, 0x18, 0x18, 0x10, 0x11], dtype=np.uint8)
    pay = np.array([0, 0, 0, 200, 600, 100, 0, 0], dtype=float)
    ts = (start[:, None] + offs[None, :]).ravel()
    c_ip = ((10 << 24) | cli).astype(np.uint32)
    s_ip = ((10 << 24) | (1 << 8) | srv).astype(np.uint32)
    F = np.tile(fwd, n_flows)
    src = np.where(F, np.repeat(c_ip, 8), np.repeat(s_ip, 8))
    dst = np.where(F, np.repeat(s_ip, 8), np.repeat(c_ip, 8))
    sp = np.where(F, np.repeat(sport, 8), np.repeat(dport, 8))
    dp = np.where(F, np.repeat(dport, 8), np.repeat(sport, 8))
    order = np.argsort(ts, kind="stable")
    n = len(ts)
    cols = {
        "ts": ts, "src": src, "dst": dst, "ttl": np.full(n, 64.0), "frag": np.zeros(n), "pay": np.tile(pay, n_flows) + 40,
        "sport": sp, "dport": dp, "win": np.full(n, 8192.0), "seq": np.arange(n, dtype=np.int64), "is_tcp": np.ones(n, dtype=bool),
        "flags": np.tile(flags, n_flows), "l4pay": np.tile(pay, n_flows), "proto": np.full(n, 6, dtype=np.uint8),
    }
    return {k: v[order] for k, v in cols.items()}


def synthetic_run(pps: int, seconds: int, n_hosts: int, config_path: str, flow_timeout: float) -> dict:
    from app import service
    from app.live import LiveEngine, LiveSettings
    from models.forecast import ForecastEngine
    config, model, scaler, _ = service.load_backend(config_path)
    le = LiveEngine(ForecastEngine(model, scaler, config), config, LiveSettings(flow_timeout_s=flow_timeout),
                    publish=lambda s: None, source_name="synthetic", mode="REPLAY")
    cols = synthetic_cols(pps, seconds, n_hosts)
    t0 = float(cols["ts"][0])
    ticks = []
    a = 0
    for sec in range(seconds):
        b = int(np.searchsorted(cols["ts"], t0 + sec + 1))
        piece = {k: v[a:b] for k, v in cols.items()}
        a = b
        t = time.perf_counter()
        le.ingest(piece)
        ticks.append(time.perf_counter() - t)
    ticks_s = sorted(ticks)
    st = le.status()
    return {"pps": pps, "seconds": seconds, "hosts": n_hosts, "packets": int(len(cols["ts"])), "flow_timeout_s": flow_timeout,
            "tick_p50_s": ticks_s[len(ticks_s) // 2], "tick_p95_s": ticks_s[int(len(ticks_s) * 0.95)], "tick_max_s": ticks_s[-1],
            "tick_mean_s": float(np.mean(ticks)), "keeps_up_realtime": bool(ticks_s[int(len(ticks_s) * 0.95)] < 1.0),
            "hosts_scored": st["hosts_scored"], "windows": st["windows_processed"],
            "buffer_packets_at_end": st["caps"]["buffer_packets_now"], "flows_final": st["flows_total"]}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--pcap", type=Path, default=None)
    ap.add_argument("--synthetic-pps", type=int, default=None)
    ap.add_argument("--seconds", type=int, default=180)
    ap.add_argument("--hosts", type=int, default=30)
    ap.add_argument("--config", default="configs/real_data_v2_converged_seed1.yaml")
    ap.add_argument("--bundle", default=None, help="model bundle directory (overrides --config)")
    ap.add_argument("--flow-timeout", type=float, default=30.0)
    ap.add_argument("--slice", type=float, default=10.0, help="engine tick size in capture seconds for --pcap")
    ap.add_argument("--out", type=Path, default=None, help="write the JSON here (default: dist/bench/live_<host>.json)")
    args = ap.parse_args()
    if not args.pcap and not args.synthetic_pps:
        ap.error("give --pcap and/or --synthetic-pps")
    config = args.config
    if args.bundle:
        from app.server import resolve_config_choice
        config = resolve_config_choice(args.bundle)
    res: dict = {"hardware": _hw(), "config": config, "flow_timeout_s": args.flow_timeout}
    if args.pcap:
        res["capture"] = {"file": args.pcap.name, "size_mb": round(args.pcap.stat().st_size / 2**20, 1)}
        res["frame_facts"] = frame_facts(args.pcap)
        res["stages"] = stage_times(args.pcap, config, args.flow_timeout)
        res["engine_replay_max_speed"] = engine_replay(args.pcap, config, args.flow_timeout, args.slice)
    if args.synthetic_pps:
        res["synthetic"] = synthetic_run(args.synthetic_pps, args.seconds, args.hosts, config, args.flow_timeout)
    out = args.out or (PROJECT_ROOT / "dist" / "bench" / f"live_{platform.node()}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=2, default=float), encoding="utf-8")
    print(json.dumps(res, indent=2, default=float))
    print(f"\nwritten to {out}")


if __name__ == "__main__":
    main()
