# Latency benchmark (W23)

**Run 2026-09-30.** `scripts/benchmark_latency.py`. Raw output: `docs/latency_benchmark.json`.

Measured on the real deployed path — the same functions `POST /api/v1/analysis/upload` and
`POST /api/v1/forecast/predict` call — using a **real CIC-IDS-2018 capture slice**
(Friday 02-03-2018, 120,000 flows: 99,707 Bot, 20,293 Benign), never generated noise.

**Platform:** Windows 10, AMD64, Python 3.11, PyTorch, **CUDA**. Checkpoint 436 KB.

## Results

| Stage | P50 | P95 | mean ± SD | passes | When it runs |
|---|---|---|---|---|---|
| Ingestion (parse + windowing + graph/packet features) | **2,004 ms** | 2,112 ms | 2,038 ± 65 ms | 3 | once per uploaded capture |
| Batched scoring, all hosts | 7.1 ms | 7.3 ms | 7.1 ± 0.1 ms | 20 | every upload / refresh |
| Single-host K=6 rollout | 6.6 ms | 6.9 ms | 6.6 ± 0.1 ms | 20 | per host drill-down |
| Explainability (gradient × input) | 3.4 ms | 3.9 ms | 3.4 ± 0.2 ms | 20 | per host drill-down |

**Interactive drill-down (rollout + explainability): 9.9 ms P50.** That is what an analyst waits
for after clicking a host. Ingestion is excluded because it runs once per capture, not per click.

Ingestion gets 3 passes rather than 20 deliberately: parsing 40 MB twenty times would dominate
the runtime without changing the estimate. Each stage records its own pass count rather than
implying a uniform protocol.

## Batch scaling

The capture above yields a single host, so the batched figure alone says nothing about a
realistic multi-host load. This replicates that host's **real** feature sequence to N rows — the
per-row content is genuine measured traffic, only the row count is synthetic, and the row count
is what this stage's cost depends on.

| Hosts | P50 | per host |
|---|---|---|
| 1 | 6.2 ms | 6.21 ms |
| 100 | 7.0 ms | 0.071 ms |
| 1,000 | 13.0 ms | 0.013 ms |
| **5,000** | **60.1 ms** | **0.012 ms** |

Cost is dominated by fixed per-call overhead up to ~100 hosts, then scales close to linearly at
~0.012 ms/host. **Scoring 5,000 hosts takes 60 ms**, so a full K=6, 60-second forecast for every
host on a mid-sized network completes well inside one 10-second window — the batching added under
audit G10 is what makes this hold.

## How this compares — carefully

`muthukkumaranb/ShadowCat` publishes 1,630.87 ms P50 per 30-window evaluation. **These numbers are
not comparable**, and quoting a speedup would be wrong:

- Their measurement is CPU (`PyTorch 2.10.0+cpu`); this one is CUDA.
- Their P50 bundles feature extraction (561 ms), PCA, a **37-fold LSTM ensemble** (197 ms), graph
  traversal (367 ms) and lineage hashing. This project runs a single model and has no graph
  traversal stage.
- The denominators differ: theirs is per 30-window evaluation, this is per capture (ingestion) and
  per host (inference).

The honest statement is that this project now publishes measured latency at all, on real traffic,
with the stages and platform named — not that it is faster than anyone.

## Limitations

- CUDA only. No CPU-only figure is published, and CPU is the likelier deployment target for an
  offline appliance. Re-running with `CUDA_VISIBLE_DEVICES=""` would give it; not done here.
- One capture, one day, one machine. No cold-start, concurrency or sustained-load measurement.
- Ingestion at 2.0 s covers 120,000 flows. It is roughly linear in flow count, but that was not
  measured across sizes.
- The server holds one capture in memory globally (see `app/server.py::_State`), so these are
  single-session numbers; concurrent users are not modelled.

## Reproduce

```bash
python -m scripts.benchmark_latency --rows 120000 --passes 20
```
