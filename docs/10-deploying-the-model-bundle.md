# Deploying the model bundle (docs/09 A2)

A **model bundle** is a ~440 KiB folder that carries everything inference needs, so the served model
runs on a machine with no `data/` folder, no `V:` drive and no GPU. It is built from a config and
verified on every load. Weights are never committed (`/dist/` is gitignored) and nothing is uploaded
anywhere; how it gets to a machine (scp, USB) is the owner's call.

## What is in it

```
seed1/
  MANIFEST.json                    file list, sizes, SHA256, model name, feature_names, n_features,
                                   git commit (+ dirty flag), created time, torch version,
                                   graph-encoder fingerprint
  config.yaml                      configs/real_data_v2_converged_seed1.yaml, copied verbatim
  checkpoint/world_model_best.pt   447,271 B
  processed/scaler.npz             1,084 B
  processed/metadata.json          1,338 B   (the flow-only guard, G11, reads this)
  state/                           created at run time (audit ledger); not in the manifest
```

Deliberately left out: `shap_background.npy` (the API never uses it, QC-20: every caller of
`service.load_backend` discards that value), `train/val/test.npz`, `window_graphs.pkl`. The
graph-embedding features need no file: the frozen GraphSAGE encoder is re-derived from a fixed seed
at inference time, so the manifest stores a numeric fingerprint of those weights and the loader
recomputes it. A torch build that drew different "random" weights would otherwise shift every
`graph_embed_*` column silently.

## On load the server checks, and refuses to start if any fails

1. every manifest file exists with the recorded size and SHA256;
2. the feature list agrees, by name and order, between the manifest, `config.yaml`,
   `processed/metadata.json` and the checkpoint's `feature_names`, and the widths agree with the
   scaler and `checkpoint["n_features"]`;
3. the graph-encoder fingerprint matches the one recorded at build time.

Failure aborts `scripts/serve.py` with exit code 2 and a message naming the file. A bundle config is
pinned to its own folder: the global `PHOENIX_*_DIR` overrides (QC-11) are ignored for it, so it can
never load someone else's weights. Verification runs at startup and when the model is first loaded;
a file changed while the server runs is not noticed until restart.

The audit ledger is written to `<bundle>/state/audit_ledger.jsonl` (override: `PHOENIX_STATE_DIR`),
outside the manifest, so using the server never invalidates the checksums.

## Build (on the dev PC)

```
python -m scripts.make_model_bundle --config configs/real_data_v2_converged_seed1.yaml --out dist/models/seed1 --archive
```

Writes `dist/models/seed1/` and `dist/models/seed1.tar.gz` and prints the archive SHA256. The build
refuses to run if any `PHOENIX_*_DIR` override is set (it would copy the wrong files) or if the output
folder is non-empty. `python -m common.bundle <dir>` re-verifies a bundle by hand.

## Install on the Debian laptop

Prerequisite: the code that understands bundles (`--bundle`, `common/bundle.py`) must be in the
commit you clone. It was written after `a66fa99` and is uncommitted on this branch as I write this, so
commit and push it first (or copy the working tree). The manifest records `git_dirty: true` for the
same reason.

```
# 1. copy the archive (from the dev PC) and check it
scp dist/models/seed1.tar.gz USER@LAPTOP:~/            # or USB
sha256sum ~/seed1.tar.gz                               # compare with the SHA256 printed by --archive

# 2. system packages and Python. Debian 12 ships python3.11; on Debian 11 (3.9) install 3.11 another way.
python3 --version
sudo apt install python3-venv python3-pip git

# 3. code + venv
git clone <repo> naf && cd naf && git checkout <commit with bundle support>
python3 -m venv .venv && . .venv/bin/activate
pip install --upgrade pip
pip install torch --index-url https://download.pytorch.org/whl/cpu    # FIRST, so pip does not pick the CUDA wheel
pip install -r requirements.txt

# 4. unpack the bundle
mkdir -p ~/models && tar -xzf ~/seed1.tar.gz -C ~/models

# 5. serve (API; the dashboard is served too if frontend/dist exists, otherwise API-only)
python -m scripts.serve --bundle ~/models/seed1 --host 0.0.0.0 --port 8000
```

`frontend/dist` is not in git. Without it (and without npm) the server runs API-only; copy
`frontend/dist` across or `npm run build --prefix frontend` if the dashboard is needed. The host
firewall must allow TCP 8000 for other machines.

Install order matters: if the torch version differs from the one the bundle was built with
(`built_with_torch` in the health output) the encoder fingerprint is still compared numerically and
only a real difference aborts startup.

## Verify

```
curl -s http://LAPTOP:8000/api/v1/health | python3 -m json.tool
```

Expect `"checkpoint_loaded": true`, `"model_name": "seed1"`, `"device": "cpu"` and a `bundle` block
with `"checksums_ok": true`, `"schema_ok": true`, `"encoder_fingerprint_ok": true`, the manifest
SHA256 and `n_files: 4`. Compare `manifest_sha256` with the dev PC's:
`6751ca5734731058f5b5d88356894bc5f441712a5278a47c533c6a5a92c67df0` (this build; it changes if the
bundle is rebuilt, because the manifest carries a timestamp).

## CPU benchmark

Run on the laptop (it forces CPU, picks threads from `os.cpu_count()`, and writes
`dist/bench/bench_cpu_<hostname>.json` and `.md`, so it will not overwrite the dev PC's):

```
python -m scripts.bench_cpu --bundle ~/models/seed1
python -m scripts.bench_cpu --bundle ~/models/seed1 --threads 1     # optional: tiny model, 1-2 threads can win
```

### Results on THIS PC (not the laptop)

Measured 2026-10-17 on **AMD Ryzen 9 9950X3D 16-Core Processor** (32 logical CPUs, 31.1 GB RAM,
Windows 11, torch 2.11.0+cu128 with `CUDA_VISIBLE_DEVICES=-1`, `cuda_available=False`, model on `cpu`,
32 torch threads). Inputs are synthetic (scaler mean +/- std); parsing is not included.

| Stage | p50 ms | p95 ms | p99 ms | iters |
|---|---|---|---|---|
| Single host, full K=6 rollout (32 threads) | 3.52 | 4.49 | 5.04 | 300 |
| Single host, full rollout (1 thread) | 4.28 | 4.40 | 4.45 | 300 |
| Explain: gradient x input only | 2.39 | 3.01 | 3.42 | 200 |
| Explain endpoint equivalent (attribution + rollout + attention) | 6.32 | 7.78 | 8.23 | 200 |
| Batched rollout, 1 host | 3.60 | 4.66 | 4.93 | 30 |
| Batched rollout, 10 hosts | 4.88 | 6.00 | 6.04 | 30 |
| Batched rollout, 50 hosts | 8.59 | 10.10 | 10.20 | 30 |
| Batched rollout, 200 hosts | 18.09 | 19.07 | 19.79 | 30 |

Model load: `import torch` 1.28 s, bundle verification 0.015 s, checkpoint + scaler 0.015 s. Peak RSS
of the benchmark process 786 MB (mostly the Python imports: torch, pandas, shap, scapy; the model is
447 KB). Full output: `dist/bench/bench_cpu_DESKTOP-5DDFOST.json` / `.md` (gitignored).

### What the demo needs, and what this says

- docs/09 A2 success test: tick p95 < 2 s at 1,000 pps. The demo window is 10 s and docs/07 estimates
  25-45 s end to end (capture, parse, features, forecast, display), dominated by waiting for windows
  to fill rather than compute.
- **Model inference** (the part this benchmark measures): worst p95 here is 19 ms (200-host batch),
  about 100x under the 2 s tick budget and about 500x under one 10 s window. Even a laptop 20x slower
  than this CPU would stay under 0.4 s for 200 hosts. On this PC the model is not the bottleneck.
- A 16-core Zen 5 desktop says little about an old laptop's absolute numbers; only the laptop run
  settles that. A small model also does not scale across 32 threads (1 thread had the tighter tail),
  so try `--threads 1` and `2` on the laptop.
- **Not covered, and decisive for the live go/no-go:** the packet parser and flow assembly
  (`read_all_frames` + `assemble_flows`) at 1,000 pps. It is unmeasured here (the CTU-13 PCAP folder was
  deliberately not touched) and docs/04 puts ingestion of 120k flows at about 2 s on this PC with
  CUDA irrelevant (it is CPU work). This benchmark therefore supports "model inference will not block a
  live demo", not "the live demo is a go".

## Not verified

- Everything on the laptop: install, health check, benchmark numbers, whether its CPU runs the
  current torch CPU wheel (check `grep -o -m1 avx2 /proc/cpuinfo`; torch falls back to older kernels
  but that was not tested), and the Python version it ships.
- Parser throughput on any CPU.
- Behaviour of `scripts/serve.py --bundle` on Linux (tested on Windows only; the code paths are
  platform-neutral and the CPU benchmark has a Linux branch for RSS and CPU model that was not run).
