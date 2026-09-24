"""Extract per-(src_ip, 10 s window) packet-level features from a directory tree of captures, in parallel.

    python -m scripts.extract_packet_windows --src "V:/Datasets/UNSW NB15/pcap files" \
        --out data/processed_unsw_pkt/packet_windows --workers 12

Writes one parquet per capture file (skips files already done, so a restart resumes). See
pipeline/fast_packet_windows.py for exactly what is computed and its limits.
"""
from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path

import numpy as np

from pipeline.fast_packet_windows import output_name, process_many


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--window-seconds", type=int, default=10)
    ap.add_argument("--glob", default=None, help="file pattern, e.g. '*' for extension-less captures (CIC-IDS-2018)")
    ap.add_argument("--keep-at-sender", action="store_true",
                    help="host-based captures named like cap<HOST>-<a.b.c.d>: keep each packet only in its sender's capture")
    args = ap.parse_args()

    if args.glob:
        files = sorted(p for p in Path(args.src).rglob(args.glob) if p.is_file())
    else:
        files = sorted(Path(args.src).rglob("*.pcap")) + sorted(Path(args.src).rglob("*.pcapng"))
    out = Path(args.out)
    done = {p.name for p in out.glob("*.parquet")} if out.exists() else set()
    todo = [f for f in files if output_name(f) not in done]
    total_gb = sum(f.stat().st_size for f in todo) / 1e9
    print(f"{len(files)} captures found, {len(todo)} to do ({total_gb:.1f} GB), {args.workers} workers", flush=True)
    rules = None
    if args.keep_at_sender:
        def ip_of(p: Path) -> int:
            a, b, c, d = map(int, re.search(r"(\d+)\.(\d+)\.(\d+)\.(\d+)$", p.name).groups())
            return (a << 24) | (b << 16) | (c << 8) | d
        captured = np.array(sorted({ip_of(f) for f in files}), dtype=np.uint32)
        rules = {str(f): (ip_of(f), captured) for f in todo}
        print(f"keep-at-sender: {len(captured)} captured machines", flush=True)
    t0 = time.time()
    stats = process_many(todo, out, args.window_seconds, args.workers, rules)
    dt = time.time() - t0
    frames = sum(s["frames"] for s in stats)
    summary = {"files": len(stats), "frames": frames, "seconds": dt, "gb": total_gb,
               "aggregate_frames_per_s": frames / max(dt, 1e-9), "gb_per_hour": total_gb / max(dt, 1e-9) * 3600}
    (out / "_run_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
