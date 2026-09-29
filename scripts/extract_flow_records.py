"""Flow records (CICFlowMeter-style) from a directory of host-based captures, in parallel, kept at the initiator.

    python -m scripts.extract_flow_records --src "V:/Datasets/CIC-IDS-2018/Wednesday-14-02-2018/pcap" --glob "*" \
        --out data/processed_cic_pkt/flow_records --workers 8

One parquet per capture (resumable). Uses pipeline.fast_packet_windows.assemble_flows; see its docstring for the flow
definition and its documented approximations (120 s timeout, no FIN-termination split).
"""
from __future__ import annotations

import argparse
import json
import re
import time
from multiprocessing import Pool
from pathlib import Path

import numpy as np

from pipeline.fast_packet_windows import assemble_flows, output_name, read_all_frames


def _ip_of(name: str) -> int:
    a, b, c, d = map(int, re.search(r"(\d+)\.(\d+)\.(\d+)\.(\d+)$", name).groups())
    return (a << 24) | (b << 16) | (c << 8) | d


def _work(job: tuple[str, str, int, np.ndarray]) -> dict:
    path, out_dir, host_ip, captured = job
    t0 = time.time()
    cols = read_all_frames(path)
    flows = assemble_flows(cols, captured, host_ip)
    flows.to_parquet(Path(out_dir) / output_name(path), index=False)
    return {"file": Path(path).name, "packets": int(len(cols["ts"])), "flows": int(len(flows)), "seconds": time.time() - t0}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--glob", default="*")
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()
    files = sorted(p for p in Path(args.src).rglob(args.glob) if p.is_file())
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    done = {p.name for p in out.glob("*.parquet")}
    todo = [f for f in files if output_name(f) not in done]
    captured = np.array(sorted({_ip_of(f.name) for f in files}), dtype=np.uint32)
    print(f"{len(files)} captures, {len(todo)} to do, {len(captured)} captured machines, {args.workers} workers", flush=True)
    t0, stats = time.time(), []
    with Pool(args.workers) as pool:
        for s in pool.imap_unordered(_work, [(str(f), str(out), _ip_of(f.name), captured) for f in todo]):
            stats.append(s)
    summary = {"files": len(stats), "packets": sum(s["packets"] for s in stats), "flows": sum(s["flows"] for s in stats),
               "seconds": time.time() - t0}
    (out / "_run_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
