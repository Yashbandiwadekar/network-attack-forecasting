"""W23: how long does the deployed pipeline actually take?

The project claims a 60-second forecast and publishes no latency figure at all, so "is this
real-time?" currently has no answer. This measures the real deployed path -- the same functions
`POST /api/v1/analysis/upload` and `POST /api/v1/forecast/predict` call -- on real captured
traffic.

**Real traffic, not generated noise.** The input is a slice of an actual CIC-IDS-2018 capture
day. A latency benchmark that times an untrained model on `np.random.randn` inputs measures nothing
useful; that failure mode is avoided here by construction, and the capture's provenance is recorded
in the output.

Stages are timed separately because they have wildly different costs and different meanings:
ingestion happens once per uploaded capture, while the per-host stages run on every dashboard
interaction. Pass counts differ per stage for the same reason -- parsing a 40 MB capture 20 times
would dominate the runtime while telling you nothing new -- and each stage records its own count
rather than implying a single uniform protocol.

    python -m scripts.benchmark_latency
    python -m scripts.benchmark_latency --rows 60000 --passes 30
"""
from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from pathlib import Path

import numpy as np
import torch

from app import service
from common.config import resolve_path
from models.explain import gradient_input_attribution
from models.forecast import ForecastEngine, latest_sequence

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUT_JSON = PROJECT_ROOT / "docs" / "latency_benchmark.json"
DEFAULT_CAPTURE = PROJECT_ROOT / "data" / "raw" / "flows_real" / "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv"


def _timed(fn, passes: int, warmups: int) -> dict:
    for _ in range(warmups):
        fn()
    samples = []
    for _ in range(passes):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    samples.sort()
    return {
        "passes": passes,
        "warmups": warmups,
        "p50_ms": round(statistics.median(samples), 2),
        "p95_ms": round(samples[min(len(samples) - 1, int(0.95 * len(samples)))], 2),
        "mean_ms": round(statistics.mean(samples), 2),
        "sd_ms": round(statistics.stdev(samples), 2) if len(samples) > 1 else 0.0,
        "min_ms": round(samples[0], 2),
        "max_ms": round(samples[-1], 2),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/real_data.yaml")
    parser.add_argument("--capture", type=Path, default=DEFAULT_CAPTURE)
    parser.add_argument("--rows", type=int, default=120000)
    parser.add_argument("--passes", type=int, default=20)
    args = parser.parse_args()

    if not args.capture.exists():
        raise SystemExit(f"Capture not found: {args.capture}")

    import pandas as pd
    import tempfile

    print(f"[*] slicing {args.rows:,} rows from {args.capture.name}")
    df = pd.read_csv(args.capture, nrows=args.rows, low_memory=False)
    label_mix = {str(k): int(v) for k, v in df["Label"].value_counts().items()} if "Label" in df else {}
    tmp = Path(tempfile.mkdtemp(prefix="latency_")) / "capture.csv"
    df.to_csv(tmp, index=False)
    capture_mb = tmp.stat().st_size / (1024 * 1024)

    config, model, scaler, _ = service.load_backend(args.config)
    if model is None:
        raise SystemExit(f"No checkpoint for {args.config}")
    engine = ForecastEngine(model, scaler, config)
    feature_cols = service.feature_cols_for(config)
    seq_len = int(config["windowing"]["sequence_length"])
    stages: dict[str, dict] = {}

    # --- Ingestion: parse + window + graph/packet features. Once per uploaded capture. Expensive,
    #     so fewer passes; the count is recorded rather than the protocol being implied uniform.
    print("[*] timing ingestion (parse + feature build)...")
    stages["ingestion_parse_and_features"] = _timed(
        lambda: service.process_uploads(tmp, None, config), passes=3, warmups=1
    )
    flow_df, windows = service.process_uploads(tmp, None, config)

    # --- Scoring every host: one batched K-step rollout. Runs on every upload and refresh.
    print("[*] timing batched scoring (all hosts)...")
    stages["score_all_hosts_batched_rollout"] = _timed(
        lambda: service.score_all_hosts(engine, windows, feature_cols, seq_len),
        passes=args.passes, warmups=3,
    )
    batch = service.score_all_hosts(engine, windows, feature_cols, seq_len)
    host_ip = batch.host_ids[0]
    seq = latest_sequence(windows, feature_cols, host_ip, seq_len)

    # --- Per-host stages: what the dashboard calls when an analyst drills into one host.
    print("[*] timing single-host rollout...")
    stages["single_host_rollout_k6"] = _timed(lambda: engine.rollout(seq), passes=args.passes, warmups=3)

    print("[*] timing explainability (gradient x input)...")
    scaled = scaler.transform(seq[None, ...])[0]
    stages["explainability_gradient_x_input"] = _timed(
        lambda: gradient_input_attribution(model, scaled, feature_cols), passes=args.passes, warmups=3
    )

    # --- Batch scaling. The capture above yields a single host, so the batched figure alone says
    #     nothing about a realistic multi-host load. This replicates that host's REAL feature
    #     sequence to N rows and times the batched rollout: the per-row content is genuine
    #     measured traffic, only the row count is synthetic, and it is the row count this stage's
    #     cost depends on. Labelled as replicated so it is never read as N distinct hosts.
    print("[*] timing batched rollout at increasing host counts (replicated real sequence)...")
    scaling = {}
    for n_hosts in (1, 100, 1000, 5000):
        seqs = np.repeat(seq[None, ...], n_hosts, axis=0)
        ids = [f"host{i}" for i in range(n_hosts)]
        st = _timed(lambda: engine.rollout_batch(ids, seqs), passes=max(5, args.passes // 2), warmups=2)
        st["hosts"] = n_hosts
        st["ms_per_host"] = round(st["p50_ms"] / n_hosts, 4)
        scaling[str(n_hosts)] = st
        print(f"      {n_hosts:>5} hosts: {st['p50_ms']:>8.1f}ms P50  ({st['ms_per_host']:.4f} ms/host)")

    try:
        tmp.unlink()
        tmp.parent.rmdir()
    except OSError:
        pass

    interactive = (stages["single_host_rollout_k6"]["p50_ms"]
                   + stages["explainability_gradient_x_input"]["p50_ms"])

    result = {
        "_comment": (
            "Wall-clock latency of the deployed pipeline on real CIC-IDS-2018 traffic. Generated "
            "by scripts/benchmark_latency.py. Inputs are a real capture slice, never synthetic "
            "noise. Pass counts differ per stage and are recorded per stage."
        ),
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "platform": {
            "os": f"{platform.system()} {platform.release()}",
            "machine": platform.machine(),
            "python": sys.version.split()[0],
            "torch": torch.__version__,
            "device": "cuda" if torch.cuda.is_available() else "cpu",
        },
        "capture": {
            "file": args.capture.name,
            "dataset": "CIC-IDS-2018",
            "rows_read": args.rows,
            "size_mb": round(capture_mb, 2),
            "label_mix": label_mix,
            "flows_parsed": int(len(flow_df)),
            "windows_built": int(len(windows)),
            "hosts_scored": len(batch.host_ids),
        },
        "model": {
            "config": args.config,
            "horizon_k": int(config["windowing"]["forecast_horizon"]),
            "window_seconds": int(config["windowing"]["window_seconds"]),
            "sequence_length": seq_len,
            "n_features": len(feature_cols),
            "checkpoint_kb": round(
                (resolve_path(config, "checkpoint_dir") / "world_model_best.pt").stat().st_size / 1024, 1
            ),
        },
        "stages": stages,
        "batch_scaling_replicated_sequence": scaling,
        "derived": {
            "interactive_drilldown_p50_ms": round(interactive, 2),
            "note": (
                "interactive_drilldown = single-host rollout + explainability, i.e. what an "
                "analyst waits for after clicking a host. Ingestion is excluded because it runs "
                "once per uploaded capture, not per interaction."
            ),
        },
    }
    OUT_JSON.write_text(json.dumps(result, indent=1), encoding="utf-8")

    print(f"\n{'stage':<38} {'P50':>10} {'P95':>10} {'mean±sd':>18} {'n':>4}")
    for name, st in stages.items():
        print(f"{name:<38} {st['p50_ms']:>8.1f}ms {st['p95_ms']:>8.1f}ms "
              f"{st['mean_ms']:>10.1f}±{st['sd_ms']:<6.1f} {st['passes']:>4}")
    print(f"\ninteractive drill-down (rollout + explain), P50: {interactive:.1f} ms")
    print(f"wrote {OUT_JSON.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
