"""CPU-only latency benchmark for a model bundle (docs/09 A2 go/no-go, docs/10).

    python -m scripts.bench_cpu --bundle dist/models/seed1

Forces CPU (CUDA_VISIBLE_DEVICES='' is set BEFORE torch is imported, and every tensor goes on
torch.device('cpu')), sets the torch thread count from os.cpu_count() and reports it, then measures
with warm-up:

  * model load: torch import, bundle verification (SHA256 + schema + encoder), checkpoint load
  * single-host forecast: full K-step rollout, p50/p95/p99
  * batched rollout for N hosts (default 1, 10, 50, 200): p50/p95, throughput
  * explain call: gradient x input alone, and the whole /explainability/attribution computation
  * peak resident memory of this process

Inputs are SYNTHETIC raw feature sequences drawn around the bundle's own scaler (mean +/- std), labelled
as such in the output: a bundle carries no traffic and the laptop has no data/. Inference cost does not
depend on the values. Output is written to <out-dir>/bench_cpu_<hostname>.json/.md (hostname in the name
so a laptop run never overwrites this PC's).
"""
from __future__ import annotations

import os

# Must precede the first torch import anywhere in this process. Windows treats setting an env var to ""
# as deleting it (CUDA then stays visible), so there "-1" (no valid device ordinal) is used instead.
os.environ["CUDA_VISIBLE_DEVICES"] = "-1" if os.name == "nt" else ""

import argparse
import json
import platform
import socket
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TICK_BUDGET_MS = 2000.0      # docs/09 A2 success test: tick p95 < 2 s
DEMO_WINDOW_MS = 10_000.0    # docs/07: one 10 s window


def cpu_model_name() -> str:
    try:
        if sys.platform.startswith("linux"):
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
        if sys.platform == "win32":
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as k:
                return str(winreg.QueryValueEx(k, "ProcessorNameString")[0]).strip()
    except Exception:
        pass
    return platform.processor() or "unknown"


def total_ram_gb() -> float | None:
    try:
        if sys.platform.startswith("linux"):
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemTotal"):
                    return round(int(line.split()[1]) / 1024 / 1024, 1)
        if sys.platform == "win32":
            import ctypes

            class MEMSTATUS(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("sullAvailExtendedVirtual", ctypes.c_ulonglong)]
            st = MEMSTATUS(); st.dwLength = ctypes.sizeof(MEMSTATUS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st))
            return round(st.ullTotalPhys / 1024 ** 3, 1)
    except Exception:
        pass
    return None


def peak_rss_mb() -> float | None:
    """Peak resident set of this process. Linux: ru_maxrss (KiB). Windows: PeakWorkingSetSize."""
    try:
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes

            class PMC(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                            ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                            ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
            k32, psapi = ctypes.windll.kernel32, ctypes.windll.psapi
            k32.GetCurrentProcess.restype = wintypes.HANDLE
            psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PMC), wintypes.DWORD]
            pmc = PMC(); pmc.cb = ctypes.sizeof(PMC)
            if not psapi.GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb):
                return None
            return round(pmc.PeakWorkingSetSize / 1024 ** 2, 1)
        import resource
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round((rss / 1024 ** 2) if sys.platform == "darwin" else (rss / 1024), 1)
    except Exception:
        return None


def pct(sorted_samples: list[float], q: float) -> float:
    return sorted_samples[min(len(sorted_samples) - 1, int(np.ceil(q * len(sorted_samples))) - 1)]


def timed(fn, iters: int, warmup: int) -> dict:
    for _ in range(warmup):
        fn()
    s = []
    for _ in range(iters):
        t0 = time.perf_counter()
        fn()
        s.append((time.perf_counter() - t0) * 1000.0)
    s.sort()
    return {"iters": iters, "warmup": warmup, "p50_ms": round(statistics.median(s), 3),
            "p95_ms": round(pct(s, 0.95), 3), "p99_ms": round(pct(s, 0.99), 3),
            "mean_ms": round(statistics.mean(s), 3), "min_ms": round(s[0], 3), "max_ms": round(s[-1], 3)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", required=True, help="model bundle directory (see scripts/make_model_bundle.py)")
    ap.add_argument("--out-dir", default=str(PROJECT_ROOT / "dist" / "bench"))
    ap.add_argument("--threads", type=int, default=None, help="torch threads (default os.cpu_count())")
    ap.add_argument("--single-iters", type=int, default=300)
    ap.add_argument("--batch-iters", type=int, default=30)
    ap.add_argument("--explain-iters", type=int, default=200)
    ap.add_argument("--warmup", type=int, default=20)
    ap.add_argument("--hosts", default="1,10,50,200", help="comma list of batch sizes")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args(argv)

    t_start = time.perf_counter()
    t0 = time.perf_counter()
    import torch
    t_import = time.perf_counter() - t0
    assert not torch.cuda.is_available(), "CUDA is still visible; this benchmark must run on CPU"
    n_cpu = os.cpu_count() or 1
    threads = args.threads or n_cpu
    torch.set_num_threads(threads)
    cpu = torch.device("cpu")

    from app import service
    from common.bundle import verify_bundle
    from common.config import feature_columns, load_config
    from models.dataset import FeatureScaler
    from models.explain import gradient_input_attribution, summarize_attention
    from models.forecast import ForecastEngine, load_world_model

    bundle = Path(args.bundle).resolve()
    t0 = time.perf_counter()
    status = verify_bundle(bundle)
    t_verify = time.perf_counter() - t0
    config = load_config(bundle / "config.yaml")
    t0 = time.perf_counter()
    model, _ = load_world_model(bundle / "checkpoint" / "world_model_best.pt", cpu)
    scaler = FeatureScaler.load(bundle / "processed" / "scaler.npz")
    t_load = time.perf_counter() - t0
    device = str(next(model.parameters()).device)
    assert device == "cpu", f"model is on {device}"
    engine = ForecastEngine(model, scaler, config)
    names = feature_columns(config)
    seq_len = int(config["windowing"]["sequence_length"])
    horizon = int(config["windowing"]["forecast_horizon"])

    rng = np.random.default_rng(args.seed)

    def synth(n: int) -> np.ndarray:
        return (scaler.mean + scaler.std * rng.standard_normal((n, seq_len, len(names)))).astype(np.float32)

    one = synth(1)[0]
    res: dict = {}

    def single() -> dict:
        return timed(lambda: engine.rollout(one), args.single_iters, args.warmup)

    res["single_host_rollout"] = single()
    torch.set_num_threads(1)
    res["single_host_rollout_1thread"] = single()
    torch.set_num_threads(threads)

    scaled = scaler.transform(one[None, ...])[0]
    res["explain_gradient_x_input"] = timed(
        lambda: gradient_input_attribution(model, scaled, names, target="logit"), args.explain_iters, args.warmup)

    def explain_endpoint():  # the computation behind POST /api/v1/explainability/attribution
        gradient_input_attribution(model, scaler.transform(one[None, ...])[0], names, target="logit")
        r = engine.rollout(one)
        summarize_attention(np.asarray(r.attentions)[0], seq_len)
    res["explain_endpoint_equivalent"] = timed(explain_endpoint, args.explain_iters, args.warmup)

    batches = {}
    for n in [int(x) for x in args.hosts.split(",")]:
        seqs, ids = synth(n), [f"host{i}" for i in range(n)]
        st = timed(lambda: engine.rollout_batch(ids, seqs), args.batch_iters, max(3, args.warmup // 4))
        st.update(hosts=n, ms_per_host_p50=round(st["p50_ms"] / n, 4),
                  hosts_per_second_p50=round(n / (st["p50_ms"] / 1000.0), 1))
        batches[str(n)] = st
    res["batched_rollout"] = batches

    hardware = {
        "hostname": socket.gethostname(), "cpu_model": cpu_model_name(), "logical_cpus": n_cpu,
        "total_ram_gb": total_ram_gb(), "os": platform.platform(), "machine": platform.machine(),
    }
    out = {
        "what": "CPU-only inference benchmark of a model bundle on SYNTHETIC inputs (scaler mean +/- std); "
                "parser/ingestion is NOT measured here.",
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "hardware": hardware,
        "software": {"python": platform.python_version(), "torch": torch.__version__,
                     "numpy": np.__version__, "torch_threads": threads, "os_cpu_count": n_cpu,
                     "cuda_available": torch.cuda.is_available(), "model_device": device,
                     "CUDA_VISIBLE_DEVICES": os.environ.get("CUDA_VISIBLE_DEVICES")},
        "bundle": {"name": status["name"], "manifest_sha256": status["manifest_sha256"],
                   "checksums_ok": status["checksums_ok"], "n_features": status["n_features"],
                   "sequence_length": seq_len, "forecast_horizon": horizon},
        "model_load_seconds": {"import_torch": round(t_import, 3), "verify_bundle": round(t_verify, 3),
                               "load_checkpoint_and_scaler": round(t_load, 3),
                               "note": "measured in this fresh process; verify_bundle includes SHA256 of every file "
                                       "and the graph-encoder fingerprint"},
        "peak_rss_mb": peak_rss_mb(),
        "results": res,
        "budget_check": {
            "tick_budget_ms (docs/09: tick p95 < 2 s)": TICK_BUDGET_MS,
            "demo_window_ms (docs/07: 10 s window)": DEMO_WINDOW_MS,
            "worst_inference_p95_ms (200-host batch or explain endpoint)": max(
                [batches[k]["p95_ms"] for k in batches] + [res["explain_endpoint_equivalent"]["p95_ms"]]),
        },
        "total_benchmark_seconds": round(time.perf_counter() - t_start, 1),
    }
    worst = out["budget_check"]["worst_inference_p95_ms (200-host batch or explain endpoint)"]
    out["budget_check"]["margin_vs_tick_budget_x"] = round(TICK_BUDGET_MS / worst, 1) if worst else None

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"bench_cpu_{hardware['hostname']}"
    (out_dir / f"{stem}.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    (out_dir / f"{stem}.md").write_text(render_markdown(out), encoding="utf-8")
    print(render_markdown(out))
    print(f"[+] wrote {out_dir / (stem + '.json')} and .md")
    return 0


def render_markdown(o: dict) -> str:
    h, s, r = o["hardware"], o["software"], o["results"]
    f = lambda d: f"{d['p50_ms']:.2f} | {d['p95_ms']:.2f} | {d['p99_ms']:.2f} | {d['iters']}"
    lines = [
        f"# CPU benchmark: {o['bundle']['name']} on {h['hostname']}", "",
        f"- CPU: **{h['cpu_model']}**, {h['logical_cpus']} logical CPUs, {h['total_ram_gb']} GB RAM, {h['os']}",
        f"- torch {s['torch']} (python {s['python']}), threads = {s['torch_threads']} (os.cpu_count() = {s['os_cpu_count']}), "
        f"cuda_available = {s['cuda_available']}, model on `{s['model_device']}`",
        f"- Bundle manifest sha256 `{o['bundle']['manifest_sha256']}`, checksums_ok = {o['bundle']['checksums_ok']}",
        f"- Inputs: SYNTHETIC ({o['bundle']['sequence_length']}x{o['bundle']['n_features']} per host, scaler mean +/- std). "
        f"Parser/ingestion is not measured.", "",
        "| Stage | p50 ms | p95 ms | p99 ms | iters |", "|---|---|---|---|---|",
        f"| Single host, full K={o['bundle']['forecast_horizon']} rollout ({s['torch_threads']} threads) | {f(r['single_host_rollout'])} |",
        f"| Single host, full rollout (1 thread) | {f(r['single_host_rollout_1thread'])} |",
        f"| Explain: gradient x input only | {f(r['explain_gradient_x_input'])} |",
        f"| Explain endpoint equivalent (attribution + rollout + attention) | {f(r['explain_endpoint_equivalent'])} |", "",
        "| Batched rollout, hosts | p50 ms | p95 ms | p99 ms | ms/host (p50) | hosts/s (p50) |", "|---|---|---|---|---|---|",
    ]
    for k, b in r["batched_rollout"].items():
        lines.append(f"| {k} | {b['p50_ms']:.2f} | {b['p95_ms']:.2f} | {b['p99_ms']:.2f} | {b['ms_per_host_p50']} | {b['hosts_per_second_p50']} |")
    m = o["model_load_seconds"]
    lines += ["", f"- Load: import torch {m['import_torch']} s, verify bundle {m['verify_bundle']} s, "
                  f"load checkpoint+scaler {m['load_checkpoint_and_scaler']} s",
              f"- Peak RSS of the benchmark process: {o['peak_rss_mb']} MB",
              f"- Worst inference p95 {o['budget_check']['worst_inference_p95_ms (200-host batch or explain endpoint)']} ms vs the "
              f"2000 ms tick budget: margin {o['budget_check']['margin_vs_tick_budget_x']}x", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
