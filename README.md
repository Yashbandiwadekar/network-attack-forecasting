# AI-Based Network Attack Forecasting

A world-model AI system — a digital twin of network behaviour — that learns network traffic
dynamics from flow and packet telemetry, forecasts attacker progression K steps ahead, maps
predicted behaviour to MITRE ATT&CK stages, and explains every prediction — built for SIH problem
statement 26153 (full text in `docs/problem-statement.md`, project framing in
`docs/00-project-overview.md`).

Rather than classifying each flow in isolation (the traditional approach the problem statement
explicitly wants moved beyond), the core model learns `P(S_t+1 | S_t-L..S_t)` over windowed
network-state sequences and rolls that forward K steps to simulate whether the current trajectory
is heading toward compromise — before it completes.

Everything runs offline. No cloud APIs, no network calls at inference time.

## Quick start (synthetic sample, ~2 minutes)

```bash
# 1. Create a Python 3.11 virtual environment and install dependencies
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt      # Windows
# source .venv/bin/activate && pip install -r requirements.txt   # macOS/Linux

# 2. Generate the synthetic sample (so everything below runs immediately, no dataset download needed)
python -m scripts.make_synthetic_sample

# 3. Build the windowed sequence dataset
python -m pipeline.build_dataset

# 4. Train the world model (GPU used automatically if available)
python -m models.train

# 5. Benchmark against the baselines
python -m eval.benchmark

# 6. Build the dashboard and run everything as one service
python -m scripts.serve            # http://127.0.0.1:8000
python -m scripts.serve --lan      # also reachable from other devices on the network
```

`scripts/serve.py` builds the dashboard if needed and serves it from the same uvicorn process as
the API. One process, one port: the browser and the API share an origin, so there is no CORS to
configure and no build-time API address to set. `--lan` binds `0.0.0.0` and prints the LAN URL to
open on another machine. If a device on the network cannot connect, the host firewall is almost
always the cause -- allow inbound TCP on the port.

The dashboard starts with no hosts: upload a PCAP/PCAPNG or a CICFlowMeter CSV from the UI (or
`curl -F "file=@data/raw/flows/synthetic_sample.csv" http://127.0.0.1:8000/api/v1/analysis/upload`)
and it parses the capture, scores every host and forecasts 60 seconds ahead.

**Two constraints worth knowing before you capture something yourself**, because either one
produces an upload that succeeds and then shows no hosts:

- **At least 2 minutes of traffic from the same source IP.** A host is scored only once it has
  12 consecutive 10-second windows (`sequence_length` x `window_seconds`). A 30-second Wireshark
  capture parses fine and scores nothing; the response says so (`"status": "partial"`).
- **CSVs must use the CICFlowMeter schema.** The required fields are `dst_port`, `protocol`,
  `timestamp`, `duration_us`, `fwd_pkts`, `bwd_pkts`, `fwd_bytes`, `bwd_bytes`, `syn_cnt`,
  `ack_cnt`, `fin_cnt`, `rst_cnt`, `psh_cnt`, `urg_cnt`, `iat_mean`, `iat_std`, `iat_max`,
  `label` (several common CIC/Zeek spellings are auto-renamed). A CSV with other columns is
  rejected with 422 and the list of what is missing.

PCAP has no schema requirement -- flow records are derived from the packets directly, so an
ordinary Wireshark/tcpdump capture works, subject to the 2-minute rule above.

### Development (hot reload)

For frontend work, run the two halves separately so Vite can hot-reload:

```bash
python -m uvicorn app.server:app --port 8000
npm run dev --prefix frontend      # http://localhost:5173
```

Here the UI and API are different origins, so CORS applies and the frontend needs the API's
address -- `frontend/.env.development` sets it, and the API's default CORS allowlist already
covers the Vite ports. Nothing extra to configure.

### Configuration

All optional; the defaults run a complete local demo.

| Variable | Default | Purpose |
|---|---|---|
| `PHOENIX_HOST` / `PHOENIX_PORT` | `127.0.0.1` / `8000` | Bind address and port (`--lan`/`--port` set these for you). |
| `PHOENIX_CORS_ORIGINS` | Vite dev ports | Only needed for the split dev setup, or a separately-hosted frontend. Irrelevant in the single-port deployment. |
| `PHOENIX_REQUIRE_AUTH` | off | `1` enforces `Authorization: Bearer <PHOENIX_API_TOKEN>` on every endpoint. |
| `PHOENIX_API_TOKEN` | — | The bearer token, required when auth is enforced. |
| `PHOENIX_DEMO_USER` / `PHOENIX_DEMO_PASSWORD` | — | Credentials for `/api/v1/auth/login`; without them login returns 503 rather than accepting anything. |
| `VITE_API_BASE_URL` | relative | Frontend build-time override. Leave unset for the single-port deployment. |

GPU note: install torch from the CUDA index (`pip install torch --index-url
https://download.pytorch.org/whl/cu128`) — the default PyPI wheel is CPU-only.

## Running on real CIC-IDS-2018

Drop the CIC-IDS-2018 CSVs into `data/raw/flows_real/` (see `docs/02-dataset-and-features.md`
for the download), then pass `configs/real_data.yaml` to every step:

```bash
python -m pipeline.build_dataset --config configs/real_data.yaml
python -m models.train          --config configs/real_data.yaml
python -m models.train          --config configs/real_data.yaml --arch lstm   # LSTM baseline
python -m eval.benchmark        --config configs/real_data.yaml
```

Optional extras:

```bash
python -m scripts.augment_benign_high_volume        # synthetic high-volume BENIGN traffic (see below)
python -m scripts.check_robustness                  # stays calm on unusual-but-legitimate traffic?
python -m scripts.check_adversarial_robustness      # PGD-style evasion attack on the infiltration head
# NOTE: both checks currently fail on the 41-feature schema — see "Known limitations"
python -m models.train_joint --config configs/real_data.yaml    # jointly-trained GNN variant
python -m eval.benchmark --train-config configs/real_data.yaml \
                         --test-config  configs/ctu13.yaml      # zero-shot cross-dataset eval
```

## Project layout

| Path | Purpose |
|---|---|
| `pipeline/` | Flow + packet feature extraction, graph features and GraphSAGE embeddings, MITRE stage mapping, time-windowing, sequence building, dataset builds (CIC-IDS-2018 + CTU-13) |
| `models/world_model.py`, `models/train.py` | The Transformer world model (next-state + stage + infiltration heads) and its training loop |
| `models/forecast.py` | K-step autoregressive rollout, batched host scoring, MC-dropout uncertainty, one-step reconstruction error |
| `models/explain.py` | Attention summaries, gradient×input attribution, KernelSHAP |
| `models/baseline_lr.py`, `models/lstm_model.py`, `models/markov_baseline.py` | Baselines: last-window LR, stacked-window LR, LSTM, Markov chain, label persistence |
| `models/world_model_joint.py`, `models/train_joint.py`, `models/graph_encoder.py` | Jointly-trained GNN variant (negative result — see `docs/06-gnn-ablation.md`) |
| `models/narrative.py`, `models/response.py` | Template-based attack narrative and MITRE-stage → first-response playbook |
| `models/audit_ledger.py` | Blockchain-style SHA-256 hash chain, tamper-evident log of dashboard alerts. Same core tamper-evidence primitive as a blockchain (each entry's hash depends on the previous entry's, so altering or deleting a past entry breaks every hash after it, detectably) — a single-writer chain rather than a distributed ledger, which was the deliberate scope for an offline demo. |
| `models/compliance.py`, `models/cve_lookup.py` | CERT-In-style incident report generator and offline CVE/NVD enrichment |
| `eval/metrics.py`, `eval/benchmark.py` | F1/precision/recall/FPR, fixed-FPR thresholds, lead-time metric, single- and cross-dataset benchmarks |
| `app/server.py`, `app/service.py` | REST API for the React dashboard (forecast, explainability, narrative, CERT-In report, audit ledger) and the headless pipeline behind it |
| `frontend/` | React + Vite dashboard: alert table, 60-second forecast timeline, explainability, 3D network field |
| `scripts/` | Synthetic sample generation, benign-traffic augmentation, robustness and adversarial checks, one-off data-inspection scripts |
| `configs/` | `default.yaml` (synthetic), `real_data.yaml` (CIC-IDS-2018, v1), `real_data_v2_converged_seed1.yaml` (served model), `ctu13*.yaml` — windowing, features and hyperparameters |
| `docs/` | Problem statement, architecture, dataset notes, MITRE mapping, evaluation reports, related work, audit |

## Tests

```bash
pytest tests/       # 542 tests (541 pass; one, test_adapter_prepare's flows_real guard case, fails when
                    # data/raw/flows_real is a symlink to another drive, as on the dev machine)
```

## Results (real CIC-IDS-2018)

**Headline, on a leakage-free split, averaged over three seeds** — this is the number to quote
(`docs/04-evaluation-real-v2-seeds.md`):

| Metric | Value |
|---|---|
| F1 @ 0.5 | **0.481 ± 0.033** |
| Precision @ 0.5 | 0.931 ± 0.024 |
| Recall @ 0.5 | 0.325 ± 0.029 |
| AUROC | **0.794 ± 0.043** |
| AUPRC | 0.646 ± 0.035 |

Day-disjoint split (no attack session appears in both train and test), 7,191 test sequences,
three independent training runs. The model is consistently *conservative*: precision holds at 0.93
across seeds while recall sits at 0.33 — what it flags is almost always right, but it misses most
attack windows on an honest split.

**The model the server loads by default is one of those three runs, not the mean.** It is the
seed-1 checkpoint (`configs/real_data_v2_converged_seed1.yaml` ->
`checkpoints_real_v2_converged/seed1/world_model_best.pt`), chosen because it has the lowest
validation loss of the three seeds (0.7579 vs 0.8327 and 0.8555), a rule fixed before looking at
test results. Its own test metrics, on the same 7,191 sequences, are F1 0.466, precision 0.903,
recall 0.314, AUROC 0.800, AUPRC 0.651 (`docs/v2_converged_seed_results.json`, row `seed1`); the
numbers in the table above are the 3-seed mean. `/api/v1/health` names the served model, and
`/api/v1/eval/metrics` and the dashboard show its own row separately from the mean. The earlier
unseeded checkpoint (F1 0.370 / AUROC 0.706) is still on disk and selectable with
`--config v2-unseeded`.

### Why an earlier, higher number is not quoted

| Split | F1 @ 0.5 | AUROC | Status |
|---|---|---|---|
| Per-host chronological (v1) | 0.917 | 0.9995 | **Not valid** — train and test shared attack sessions |
| Day-disjoint, single unseeded run | 0.370 | 0.706 | Superseded — a low-tail draw |
| **Day-disjoint, 3 seeds** | **0.481 ± 0.033** | **0.794 ± 0.043** | **Current** |

The 0.917 came from a split that shared attack sessions between train and test — data snooping in
the sense of Arp et al. (USENIX Security 2022). It was found by this project's own audit
(`docs/AUDIT.md`, E1) and corrected. On the fixed split the baselines were re-measured too; full
tables, including the label-oracle references (persistence and a Markov chain, which read the
current window's true label and are therefore not deployable), are in
`docs/04-evaluation-real-v2.md` and `docs/04-evaluation-real.md`.

### Generalisation to unseen attacks

Measured, and negative — see `docs/04-evaluation-lofo-seeds.md`. Leave-one-attack-family-out,
three seeds per fold:

| Held-out family | AUROC (mean ± SD) |
|---|---|
| initial_access | 0.685 ± 0.087 |
| lateral_movement | 0.528 ± 0.129 |
| command_and_control | 0.646 ± 0.131 |
| impact (DDoS) | 0.819 ± 0.128 |

Only `impact` is distinguishable from chance, and only marginally. With three seeds the test is
low-powered, so the honest reading is *no statistically supported evidence of transfer to held-out
families*, not *proven no transfer*. The three failing families are precisely those with no real
per-host data in CIC-IDS-2018 (see E7) — the limitation is the dataset's structure, not a broken
model.

Zero-shot on CTU-13 (trained on CIC-IDS-2018, never fine-tuned): **the model does not transfer.**
After the CTU-13 label fix (D-1), the day-disjoint v2 checkpoint `checkpoints_real_v2/` (not the
served seed-1 model) scores AUROC 0.7804 on CTU-13, but this is **detection of ongoing botnet C2
traffic, not forecasting**: AUPRC is only 0.070, F1 at the 0.5 threshold is about 0, the corrected
test set contains no benign-to-attack onsets, and a stacked logistic regression trained natively
on CTU-13 gets 0.7811, so it does not beat a shallow in-domain baseline
(`docs/04-evaluation-ctu13_cross_from_real_data_v2_postD1.md`). The v1 checkpoint is at chance (AUROC about 0.52) on both the old and the corrected labels; the
earlier headline CTU-13 AUROC in this README came from that v1 checkpoint on pre-fix labels and is
superseded. An even earlier version of this README
quoted F1 0.534; that number came from a 33-feature checkpoint and dataset build that no longer
exist and is withdrawn (see `docs/AUDIT.md` G1). Generalising across different network topologies
and packet-capture tools remains a significant challenge. The served seed-1 model has not been
scored on CTU-13.

## What this system does not do

Stated here, next to the results, rather than only in `docs/AUDIT.md`. Every figure is measured
and links to the report it comes from.

- **It misses most attacks.** Recall 0.325 ± 0.029 at the 0.5 threshold — roughly two in three
  attack windows go unflagged. Precision is the strong side (0.931 ± 0.024): what it flags is
  almost always real. Use it as a second signal beside existing detection, not as sole coverage.
  (`docs/04-evaluation-real-v2-seeds.md`)
- **Early warning is not demonstrated.** The earlier lead-time figures (measured on 628
  benign-to-attack transitions, which come from about 15 episodes on 3 pseudo-hosts) used a
  definition of "early" that has since been tightened (audit QC-3) and were measured on a
  different checkpoint than the one now served. Lead-time numbers are **pending re-run under the
  QC-3 definition** on the served model and are not quoted here. (`docs/04-evaluation-real-v2.md`
  holds the old measurement.)
- **The headline is a t+1 number.** F1 0.481 / AUROC 0.794 measure **one step — 10 seconds —
  ahead**, not 60. The evaluation path runs a single forward pass.
  (`docs/04-evaluation-frozen-state-ablation.md`)
- **The 60-second rollout is not better than reusing the first step.** Holding the t+1 estimate
  for the whole minute scores *higher* than advancing the model's state (AUROC 0.785 vs 0.755 at
  t+60s, consistent across three seeds, not statistically established at n=3). The rollout
  produces the trajectory, stages and what-if path; it does not improve infiltration ranking.
  (`docs/04-evaluation-frozen-state-ablation.md`)
- **No demonstrated generalisation to unseen attack families or datasets.** Leave-one-family-out
  is chance-level on three of four families; zero-shot CTU-13 is detection only (AUROC 0.7804, AUPRC 0.070, no better than a native LR at 0.7811).
  (`docs/04-evaluation-lofo-seeds.md`, `docs/AUDIT.md` G1)
- **Single dataset, single network.** Trained on CIC-IDS-2018 only. Cross-network transfer is a
  known-hard problem in this literature and this project is a textbook instance of the collapse,
  not an exception (`docs/04-evaluation-ctu13_cross_from_real_data.md`,
  `docs/04-evaluation-unsw_cross_from_real_data_v2.md`).

Speed is not the constraint: interactive drill-down is **9.9 ms** and scoring 5,000 hosts takes
**60 ms** (`docs/04-latency-benchmark.md`).

## Known limitations

These are documented rather than hidden. `docs/AUDIT.md` is the full list with measurements.

- **The v1 per-host split leaked; the headline no longer uses it.** The original split cut
  train/val/test per host in time order, so test windows came from the same attack sessions as
  training — data snooping in the sense of Arp et al. That is what produced the withdrawn F1
  0.917. The reported headline is now the **day-disjoint** split (no attack session appears in
  both), which is where F1 0.481 / AUROC 0.794 come from. The older split survives only in
  `docs/04-evaluation-real.md`, marked as superseded.
- **Lead-time metric rests on narrow events.** The day-disjoint re-measure covers 628
  benign-to-attack transitions (the earlier "32 transitions" figure predates it), but they come
  from 3 network-wide pseudo-hosts with 96% from a single day, so the sample is wide in count and
  narrow in origin. False alarms are counted (audit E3). The resulting lead-time and alarm-precision
  figures are pending re-run under the QC-3 definition (see above).
- **3 of 5 MITRE stages on real data.** CIC-IDS-2018 has no Reconnaissance or Exfiltration labels.
  DoS/DDoS is mapped to `impact`, which is excluded from the 5-way stage task.
- **Flow-only in practice.** Packet-level features are implemented, but no CIC-IDS-2018 PCAP is
  downloaded (37 GB/day), so the real-data model is trained with them zero-filled.
- **Demo input.** The upload path accepts a flow CSV (labelled or unlabelled), a PCAP/PCAPNG on its
  own (flow records are derived from the packets; fixed in audit S4), or both. A PCAP-only upload
  has no ground-truth labels, so the observed stage is reported as unknown.
- **Fabricated benign traffic.** The earlier v2 runs (`docs/04-evaluation-real-v2.md`'s first
  version) had val/test sets with 17-27% fabricated benign traffic from an augment script. The
  converged config behind the headline above drops those fabricated days (04-01, 04-02) from val
  and test entirely.
- **Adversarial evasion works, but only under a specific threat model (audit W11, measured
  2026-09-23 on a 41-feature checkpoint other than the one now served).** A white-box PGD attack that perturbs only
  the most recent window's raw features drives the t+1 infiltration probability from 0.9975 to
  0.0000 within an epsilon=1.5-std budget (`scripts/check_adversarial_robustness.py`). **What this
  attack actually requires, stated precisely rather than left implicit:** the top perturbed
  features are `flow_count`, `total_packets`, `total_bytes` (all pushed sharply down) and
  `has_ip_data`/`mean_duration` (pushed up) — the model has learned "volume = attack", and evading
  it means the attacker must genuinely send less traffic that looks less voluminous. For a flood
  (DDoS, brute-force at scale), that defeats the attack's own purpose — an attacker who
  successfully evades this way has, by construction, stopped flooding. **It is a real threat only
  for a low-and-slow intrusion** that was never volume-heavy to begin with, where suppressing
  volume features costs the attacker little. Claiming this is "unfixed" without that qualification
  overstates the risk for the traffic class (DDoS/brute-force) this project's real-IP data
  actually covers (E7), and understates it for the low-and-slow case it doesn't have real examples
  of.
  - **A second, independent gate helps.** `models/forecast.py::one_step_reconstruction_error`
    (does the observed window match what the model's own dynamics predicted from the L windows
    before it, independent of the trained probability head?) is now combined with the probability
    threshold via `models/forecast.py::or_gate_alarm` inside
    `scripts/check_adversarial_robustness.py`: alarm if infiltration probability **or**
    reconstruction error crosses its own threshold (the latter calibrated to the 99th percentile
    of the val split's own currently-benign one-step errors). On this specific evasion case the
    OR-gate **recovers the alarm** (reconstruction error 5.53 -> 9.77 against an 8.26 threshold,
    while probability drops to 0.0000) at a measured added false-positive cost of **1.06%** on the
    test split's own currently-benign windows — close to the 1% the calibration targets, so it
    generalises from val to test reasonably well here. This is not deployed as the app's alerting
    logic (that would need its own tuning and a wider evaluation than one synthetic attack
    capture); it is reported here as evidence for the threat model above, not as a claim the
    vulnerability is closed.
- **Robustness scripts: code fixed, not re-run on the served model.** `scripts/check_robustness.py`
  and `scripts/check_adversarial_robustness.py` used to build their windows without the 8
  `graph_embed_*` columns and raised `KeyError` against the 41-feature checkpoints; both now call
  `merge_graph_embedding_features`. The adversarial numbers quoted above were measured on
  2026-09-23 on a checkpoint that is not the served seed-1 model, and have not been re-run on it.

## Deliverables checklist (per problem statement)

- [x] Feature extraction pipeline (flow-level + packet-level + graph) — `pipeline/`
- [x] Trained world model with reproducible training config — `models/world_model.py`, `models/train.py`, `configs/real_data.yaml`
- [x] Trained on real CIC-IDS-2018 (10 days, ~16M flows) — `checkpoints_real/`, `docs/04-evaluation-real.md`
- [x] K-step infiltration prediction engine with MITRE stage mapping — `models/forecast.py`
- [x] Explainability (attention + gradient×input + SHAP) — `models/explain.py`
- [x] Offline demo interface — `frontend/` (React) over `app/server.py`
- [x] Benchmark vs logistic regression and three further baselines, at default and fixed-FPR thresholds — `eval/benchmark.py`, `docs/04-evaluation-real.md`
- [x] Lead-time metric ("before compromise completes") — `eval/metrics.py::lead_time_metrics`
- [x] Cross-dataset generalisation evaluation (CIC-IDS-2018 → CTU-13) — `docs/04-evaluation-ctu13_cross_from_real_data.md`
- [x] Robustness check against out-of-distribution-but-benign traffic — `scripts/check_robustness.py`
- [x] Adversarial evasion testing — `scripts/check_adversarial_robustness.py`
- [x] Attack narrative, response playbook, tamper-evident audit ledger, CERT-In report, CVE enrichment — `models/`
- [x] Architecture document (≤2 pages) — `docs/01-architecture.md`
- [ ] Demo video (≤2 min) and technical presentation (≤5 slides) — **not produced yet.** A prior
  commit added `docs/demo.mp4` and `docs/presentation.pdf` as 0-byte placeholders and checked this
  item off; both were removed (audit H4/W16) since an empty file makes an open item look closed.

## License

The source code is released under the [Apache License 2.0](LICENSE) (see also [NOTICE](NOTICE)).

Two things the licence does **not** cover:

- **Datasets.** The models were trained and evaluated on CIC-IDS-2018, UNSW-NB15 and CTU-13, which have
  their own terms. Check them before any use beyond research, especially commercial use.
- **Dependencies keep their own licences.** In particular, Scapy (used for PCAP parsing) is
  GPL-2.0-only. This repository only imports it and does not bundle it, but anyone *distributing* a
  product that includes Scapy needs to comply with the GPL for that component.
