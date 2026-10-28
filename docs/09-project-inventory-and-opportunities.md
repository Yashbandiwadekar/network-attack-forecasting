# 09 - Project inventory and what we can make next

**Written 2026-10-17** on branch `test/session-2026-10-10` (HEAD `65c3bf2`). This was a read-and-report
pass. No existing file was edited. Nothing was trained, evaluated or built, and the GPU was not used.

The only things executed were:

- `pytest --collect-only`
- md5 and metadata reads of the checkpoints (on CPU)
- directory listings on `V:`
- three read-only label/timestamp counting scripts over the CTU-13 `.binetflow` files and the
  CIC-IDS-2017 CSVs. These live in the session scratchpad, not in the repo. No PCAP was opened, and
  the scenario-10 download was not touched.

Each claim below is tagged:

- **[measured today]**: I ran it.
- **[read]**: from a file, with the path given.
- **[from doc]**: quoted from a project document I did not re-verify.

---

## 0. The six things to know first

1. **The dashboard serves a different model from the one whose numbers it shows.** [measured today]
   - `app/server.py:133` defaults to `configs/real_data_v2_converged.yaml`, which loads
     `checkpoints_real_v2_converged/world_model_best.pt`.
   - That file's md5 (`03e957…`) matches none of the three seed checkpoints (`seed1..3/`)
     [measured today].
   - `docs/04-evaluation-real-v2-seeds.md:6,30` says the seeds were written to `seed<N>/` and "the
     previously shipped unseeded checkpoint was not touched". That checkpoint scores **F1 0.3697,
     AUROC 0.7058** [read].
   - `/api/v1/eval/metrics` (`app/server.py:1110`) reports the **3-seed mean 0.481 / 0.794** next
     to it.
   - The same file also has **no `feature_names`**, so the W19 schema guard is inert on exactly the
     default model. The seed checkpoints do carry them. AUDIT I1 is still open for the one model
     that matters.
2. **A clean clone cannot start the default server.** [read]
   - The only tracked weights are `checkpoints_real/world_model_best.pt` plus
     `data/processed_real/scaler.npz` (v1, the leaky split).
   - The v2_converged checkpoint is gitignored (`*.pt`). Its scaler lives under
     `data/processed_real_v2_converged`, which is an NTFS junction into `V:\Datasets\NAF-processed`.
   - `check_model_artifacts` refuses to start without them. The Debian laptop, or a judge cloning
     the repo, therefore gets a startup error.
   - `master` still serves v1 (`self.config_path = "configs/real_data.yaml"`).
3. **There are very few forecastable events, but a few more than docs/05 counts.** [measured
   today] These come from read-only counts over the raw labels. Each row uses a different
   definition, so **the rows do not add up**.

   | Source | Definition used | Onsets | Distinct hosts | Notes |
   |---|---|---|---|---|
   | CIC-2018 (docs/05 D-3) | benign now, attack within k=1..6 | ~15 episodes (upper bound) | 3 pseudo-hosts | All network-wide aggregates. |
   | CIC-2017, keyed on source | 60 s windows; ≥12 benign non-empty windows before the onset; history resets after a gap of more than 10 min | 12 | 9 | 7 are **Bot** onsets on internal hosts that had real benign history. |
   | CIC-2017, keyed on victim | same | 18 | 7 | **12 of the 18 hit one victim** (192.168.10.50). Includes **4 PortScan (real reconnaissance)** onsets. The Bot onsets appear in both the source and victim counts. |
   | CTU-13, C2→ICMP DDoS per bot (needs relabelling, B2) | first ICMP flood flow after earlier botnet-only activity | 13 bots: scen. 10 ×10, scen. 4 ×1, scen. 11 ×2 | 13 | Pre-flood history is sparse. Scen. 10 bots have 6-12 non-empty 10 s windows spread over 1.2-1.7 h; scen. 11 bots have 2-3. **Only ~2 bots** (scen. 10 .165 with exactly 12 windows, scen. 4 with 131) qualify under the current `sequence_length: 12`. |

   - **Realistic total:** about 25-30 distinct onsets across the datasets. They are heavily
     concentrated on a few hosts, and CTU-13 adds only ~2 unless sequences can be shorter or
     gap-aware.
   - **CTU-13 under its own per-IP labels:** every infected IP is labelled botnet from its very
     first flow (0 s lead, 0 earlier benign flows, in all 13 scenarios). So, under these labels, no
     benign→infected sequence can be built from either the binetflow files or the mixed PCAPs.
   - **Why the C2→DDoS progressions are invisible today:** `ctu13_label_to_stage` maps
     `From-Botnet-*-ICMP` to `command_and_control`.
4. **The live-demo engine is half-built on an unmerged branch.** [read]
   - `live-deployment-2026-10-10` has `scripts/live_forecast.py` (event-time windows, PCAP-dir and
     CSV-replay sources) and `scripts/demo_dos_forecast.py`. It is local only, with no remote.
   - It does not feed the dashboard; it writes JSONL.
   - Its DoS-forecast numbers were not regenerated after its own off-by-one fix (`90bbd1c`).
5. **README is stale in at least six places** (§2.3), and **the PS deliverables are still missing**:
   the ≤2-minute video and the ≤5-slide deck. The architecture doc is 1,579 words, likely over the
   2-page limit.
6. **Test suite: 537 tests collected** [measured today, collect-only, not run this session]. README
   still says 157.

---

## 1. Inventory: what is there

Status key:

- **W** = working (tests exist, code path exercised in recent commits)
- **P** = partial
- **B** = broken
- **D** = dead or superseded
- **U** = unverified

### 1.1 Code components

| Component | Files | Status | Evidence / note |
|---|---|---|---|
| Flow feature extraction (CICFlowMeter CSV) | `pipeline/flow_features.py`, `windowing.py`, `window_features.py` | W | 19 flow features, 10 s windows, 12-window sequences, K=6 targets. `tests/test_windowing.py`, `test_flow_features.py`. |
| Graph features + frozen GraphSAGE embeddings | `pipeline/graph_features.py`, `graph_builder.py`, `graph_embedding_features.py` | W (value ~none) | 5 graph features + 8 random-init embedding dims. `docs/06-gnn-ablation.md` measured no benefit. On CIC the graph is mostly one pseudo-host. |
| Packet features (TTL, window, frag, payload, scan score, retransmits) | `pipeline/packet_features.py` (Scapy), `fast_packet_windows.py` (struct parser) | P | Implemented and tested. Zero-filled for every shipped real-data checkpoint (`app/service.py::is_flow_only_model`). Payload bytes use **captured length** (`fast_packet_windows.py:65`), which is wrong on truncated captures (the CTU-13 `mixed/` files). IPv4 TCP/UDP only, so ICMP is dropped. |
| MITRE mapping | `pipeline/mitre_mapping.py` | W, with known design limits | D-1 fixed (`de6efe9`). CIC-2017 map added. CTU-13 botnet labels all go to C2 (including ICMP floods and spam). |
| Recon heuristic | `windowing.py::apply_reconnaissance_heuristic`, `forecast.py::_heuristic_stage_override` | P | Needs `port_scan_score`, which is zero-filled on flow-only checkpoints, so **recon cannot fire** on the served model (AUDIT H5, docs/07 D6). |
| Dataset builders | `pipeline/build_dataset.py`, `build_ctu13_dataset.py`, `build_unsw_dataset.py`, `build_cic_pkt_dataset.py`, `build_unsw_pkt_dataset.py` | W | `require_contiguous_windows` exists (QC-1, `windowing.py:512`), but **no config sets it** and no dataset was built with it. |
| Dataset adapter toolkit | `pipeline/adapters/*` (registry, base, validation, prepare, sidecar; adapters for cicids2017/2018, ctu13, unsw_nb15, netflow_v2, generic_cicflowmeter, pcap), `scripts/validate_dataset.py`, `scripts/prepare_dataset.py` | W / U | Validator run on 6 real datasets (`data/adapter_reports/*.md`). Unverified: the NF-v2, PCAP and generic adapters have seen fixtures only. `prepare_dataset` has only been run on row-capped prefixes. |
| World model | `models/world_model.py`, `train.py` | W | Transformer, d_model 64, multi-task. **Trains only on `future_stages[:, 0]` / `infiltration[:, 0]`** (`train.py:52,59`), so the k=2..6 targets are built and discarded. |
| Rollout / forecast engine | `models/forecast.py` | W | K-step rollout, MC-dropout, one-step reconstruction error, OR-gate. The rollout does **not** beat holding the t+1 estimate (AUROC 0.755 vs 0.785 at t+60 s, `docs/04-evaluation-frozen-state-ablation.md`). |
| Explainability | `models/explain.py` | W | Attention, gradient×input, KernelSHAP. The `has_ip_data` provenance driver is separated out (`f4558d8`). |
| Baselines | `models/baseline_lr.py`, `lstm_model.py`, `markov_baseline.py` | W | Unpickler allowlists added (QC-2). Persistence and Markov are label oracles and are captioned as such. |
| Joint GNN variant | `models/world_model_joint.py`, `train_joint.py`, `graph_encoder.py` | D (negative result) | Kept for the ablation only. |
| Narrative, playbook, CERT-In report, CVE, PDF, audit ledger | `models/narrative.py`, `response.py`, `compliance.py`, `cve_lookup.py`, `report_pdf.py`, `audit_ledger.py` | W | Ledger hardened (lock, atomic save, corrupt → not intact; QC-5). |
| Evaluation | `eval/benchmark.py`, `metrics.py`, `lofo.py`, `pilot_packet_compare.py` | W | QC-3 changed lead time: an alarm must come strictly before onset. **Every published lead-time figure predates this.** Stage macro metrics now cover only the classes present. |
| REST API + service | `app/server.py`, `app/service.py` | W | v2 default, `PHOENIX_CONFIG`, fails loudly if artefacts are missing, "Unlabelled" observed stage (docs/07 D1 fixed). See §0.1 for the checkpoint mismatch. |
| Webhook service | `app/api.py` | D (hardened, unused) | Off unless `NAF_API_ENABLED=1`. Nothing consumes it. |
| Frontend | `frontend/` (React + Vite, `dist/` built, 6 Vitest files) | W / P | Polls every 5 s. Hard-coded fallback token `phoenix_demo_jwt_token_2026_secured` still in `frontend/src/api/client.js:15,50` and `Login.jsx:33` (docs/07 D9 open). No LIVE / REPLAY badge. |
| Streaming consumer | `scripts/stream_consumer.py` | D | Batches per 100 rows (docs/07 D2/D3). Superseded by `live_forecast.py` on the other branch. |
| Live forecaster | `scripts/live_forecast.py`, `scripts/demo_dos_forecast.py`, `docs/06-live-deployment.md` | P, **unmerged** | Only on branch `live-deployment-2026-10-10`. Uses the Scapy path (`build_flow_records`), not the fast parser. Output goes to JSONL, not the dashboard. |
| Robustness / adversarial checks | `scripts/check_robustness.py`, `check_adversarial_robustness.py` | W (per code) | Both now call `merge_graph_embedding_features`. README still says "broken" (stale). |
| Latency benchmark | `scripts/benchmark_latency.py` | W (GPU only) | No CPU figure exists. The laptop is CPU-only. |
| Misc. one-off inspect scripts | `scripts/inspect_*.py`, `check_chronology.py`, `fix_sequence_chronology.py`, `visualize_topology.py`, `survey_competitors.py`, `build_idea_docx.js` | D / one-off | Not part of the product. Candidates for `scripts/archive/`. |
| Tests | `tests/` (51 files) | **537 collected** | Collect-only, not run this session. |

### 1.2 Checkpoints [measured today: md5 + metadata keys]

| Directory | What it is | `feature_names` | Status |
|---|---|---|---|
| `checkpoints/` | Synthetic-pipeline model (`configs/default.yaml`), plus LSTM and joint-GNN | yes | Demo/synthetic only. |
| `checkpoints_real/` | **v1**, per-host chronological (leaky) split. F1 0.917 withdrawn. Has `audit_ledger.jsonl`. | yes | **The only real checkpoint in git**, and `master`'s default. Do not quote. |
| `checkpoints_real_v2/` | v2 day-disjoint, 15 epochs, batch 64. Source of the post-D-1 CTU-13 AUROC 0.7804. | yes | Superseded by converged. Its config no longer reproduces it (`configs/real_data_v2.yaml` header). |
| `checkpoints_real_v2_converged/world_model_best.pt` | v2, 30 epochs, **unseeded** run (F1 0.370 / AUROC 0.706) | **no** | **Served by default.** Not the quoted model. |
| `checkpoints_real_v2_converged/seed{1,2,3}/` | The three seeds behind 0.481 ± 0.033 / 0.794 ± 0.043 | yes | The quoted numbers. None is served. |
| `checkpoints_real_v2_lofo/<family>/seed{1..3}` | Leave-one-family-out folds | (not checked) | Results in `docs/04-evaluation-lofo-seeds.md`. |
| `checkpoints_real_v2_scaleinv/` | Scale-invariance augmentation, truncated run | **no** | Partial (BUILD_REPORT W11 part 3). Evasion still succeeds. |
| `checkpoints_cic_pkt{,_flowonly}/seed{1..3}` | Packet-aware pilot, CIC Wed 14-02 PCAP day | (not checked) | **AUROC 1.000 with recall 0**: defect D-2, undiagnosed. Do not quote. |
| `checkpoints_unsw_pkt{,_flowonly}/seed{1..3}` | Packet-aware UNSW pilot | (not checked) | Unverified (AUDIT H.8). |
| `checkpoints_ctu13/`, `checkpoints_unsw/` | Referenced by configs | **do not exist** | The dashboard's CTU-13 and UNSW dropdown entries cannot load a native model. |

### 1.3 Datasets on disk [measured today: listings and `du`; nothing parsed except the label counts in §0.3]

| Path | Size | Content | Status |
|---|---|---|---|
| `V:\Datasets\CIC-IDS-2018-flows` (= `data/raw/flows_real`) | 6.5 GB | 10 CICFlowMeter day CSVs plus the synthetic augment CSV | Used. 9/10 days have no IPs. |
| `V:\Datasets\CIC-IDS-2018` | 110 GB | Raw PCAPs for **2 days only**: `Wednesday-14-02-2018/pcap` (449 per-host files, 46 GB) and `Friday-23-02-2018/pcap` (446 files, 65 GB) plus `labels.csv` (1,048,576 lines, Excel-truncated, no IP columns) | Wed was used for the cic_pkt pilot. Fri has no documented use (`processed_cic_fri_pkt` provenance unverified, docs/05 D-4). The per-host file names (`UCAP172.31.69.x`, `capDESKTOP-…`) are victim-side captures. |
| `V:\Datasets\CIC-IDS-2017` | 1.2 GB | 8 TrafficLabelling CSVs, **real IPs every day**, minute-resolution timestamps | Validated (WARN), not prepared. PortScan 158,930 rows, Bot 1,966, Infiltration **36**. |
| `V:\Datasets\CTU-13` (= `data/raw/ctu13`) | 2.6 GB | 13 `.binetflow` files | Used. Processed splits rebuilt after D-1, but **before** the ICMP-drop fix (`docs/08` §6). |
| `V:\Datasets\CTU-13-pcaps/<1..13>` | 30 GB total | Botnet-only PCAPs. Scenario 4 includes a 5.2 GB ICMP-DoS file. Scenario 9 also has a 2.6 MB `normal-capture`. | Downloaded and sha256-manifested (`MANIFEST.md`). **Scenario 10 is still downloading** (9.2 GB so far, mtime today). Its MANIFEST row says "skipped", which is now out of date. Not touched. |
| `V:\Datasets\CTU-13-pcaps/mixed/<1..13>` | ~11 GB compressed | `*.truncated.pcap.bz2`: full background + botnet traffic, header-truncated | Downloaded (`MANIFEST_mixed.md`). Needs bz2 streaming and a captured-length fix (§1.1) before use. Not parsed. |
| `V:\Datasets\UNSW NB15` | 71 GB | CSV (688 MB), Argus, Bro, **PCAPs 68 GB** (two days), reports | CSVs used. PCAPs not used. **No `data/raw/unsw_nb15` junction**, so `configs/unsw_nb15*.yaml`'s `raw_flow_dir` does not resolve. |
| `V:\Datasets\NAF-processed` | 34 GB | All `data/processed*` except `processed_real` | Junctioned. `processed/` is 23 GB (CIC-synthetic and ctu13 splits). |
| `data/processed_real` (local) | small | v1 scaler + metadata (tracked) | Needed for v1 only. |
| `demo/demo-capture-cicids2018-bot-02mar2018.csv` | 14 MB | Bot-day pseudo-host replay | Gitignored; regenerate with `scripts/make_demo_capture.py`. |

### 1.4 Docs

| Doc | Status |
|---|---|
| `docs/problem-statement.md` | Current. Source for §3. |
| `README.md` | **Stale.** See §2.3. |
| `BUILD_REPORT.md` | Historical log up to 2026-09-30. Fine as a log, not a status page. |
| `docs/00`-`03` | 01 (architecture) is 1,579 words, likely over the PS's 2-page limit. |
| `docs/04-evaluation-*.md` (14 files) | Mixed. Current: `real-v2-seeds`, `lofo-seeds`, `frozen-state-ablation`, `ctu13_cross_from_real_data_v2_postD1` (header only; the generated "Interpretation" boilerplate below it still says the result "demonstrates genuine generalisation", which contradicts the header). Stale: `ctu13`, `ctu13_cross_from_real_data`, `unsw_*`, `real` (v1), and every lead-time section. |
| `docs/05` roadmap | Current as of 10-10. D-1 is now fixed. D-2 open. D-3's CTU-13 row is superseded by §0.3 here. References `docs/04-dos-forecast-demo.md`, which exists only on the unmerged branch. |
| `docs/07` live-demo plan | Mostly current. **D1 (unlabelled stage) and D4 (v1 default) are now fixed**; T1/T2 are effectively done. Assumes an isolated LAN and a Kali VM (see §5 decisions). |
| `docs/08` adapter guide | Current. |
| `docs/AUDIT.md` | Current through Part I. I1 is still open for the served checkpoint. |
| `docs/CipherWraiths-Project-Report.pdf` | Not reviewed. |

**Git state** [measured today]:

- The working tree is clean.
- Local `test/session-2026-10-10` is **1 commit ahead of origin** (`65c3bf2`, not pushed) and 3 ahead
  of `master`.
- `live-deployment-2026-10-10` exists locally only.

---

## 2. Current honest capability

### 2.1 What can be claimed today

- **An end-to-end offline system.** It takes a CSV or a PCAP (PCAP-only upload was fixed in S4) and
  produces 41-feature windows, a Transformer world model, a 6-step rollout, a stage label,
  attributions, a narrative, a CERT-In-style report and a hash-chained ledger.
- **CIC-IDS-2018 day-disjoint, t+1 (10 s ahead), 3 seeds:**
  - F1 0.481 ± 0.033, precision 0.931, recall 0.325, AUROC 0.794 ± 0.043, AUPRC 0.646
    (`docs/v2_converged_seed_results.json`; 7,191 test sequences, 1,482 positive).
  - Caveat: val and test contain 17-27% fabricated benign traffic (README).
  - **The served checkpoint scores F1 0.370 / AUROC 0.706.**
- **Leave-one-family-out:** only `impact` is above chance (0.819 ± 0.128). The other three are
  0.53-0.69.
- **The rollout is a trajectory and what-if view, not a better predictor:** 0.755 vs 0.785 frozen at
  t+60 s.
- **CTU-13 zero-shot after the D-1 fix** (`checkpoints_real_v2`, not converged):
  - AUROC 0.7804, AUPRC 0.070, F1 ≈ 0 at every threshold.
  - A native stacked LR gets 0.7811.
  - This is detection of ongoing C2 with zero onsets in the test set, so it is **not forecasting
    evidence**, and it does not beat a native shallow baseline.
- **Latency on GPU:** 9.9 ms drill-down; 60 ms for 5,000 hosts. **There is no CPU number.**

### 2.2 Numbers that are stale and must be re-run or re-labelled before quoting

| Number | Why stale |
|---|---|
| Lead time −0.5 s mean / 0 s median, 93.5% missed, 1.5% alarm precision (628 transitions) | QC-3 redefined "early". The 628 transitions are ~15 episodes on 3 pseudo-hosts (D-3). |
| CTU-13 AUROC 0.517 (README) | Pre-D-1 labels, v1 checkpoint. |
| UNSW zero-shot 0.424 / 0.443 | Built before the protocol-drop fix (12.2% of non-benign rows were dropped). |
| All CTU-13 / UNSW processed splits | Built before the ICMP and other-protocol drop fixes (+34.9% CTU positives once rebuilt). |
| DoS demo "0 of 12 forecast attempts, 56% in-progress detection" | On the unmerged branch, and not regenerated after the off-by-one fix. |
| Adversarial 0.9975 → 0.0000 | Measured 09-23 on a checkpoint that is not the served one. Re-run on whatever becomes the served model. |

### 2.3 Retracted or never to be quoted

- F1 0.917 / AUROC 0.9995 (v1 leaky split).
- CTU-13 F1 0.534.
- AUROC 1.000 for the packet pilots (D-2).

**README stale items:**

- "157 tests" (537 are collected).
- CTU-13 0.517.
- "Both robustness scripts are broken".
- "PCAP cannot yet be used on its own".
- The lead-time figures.
- The deliverables checklist ticks the cross-dataset eval against the pre-fix report.

---

## 3. Gaps against the problem statement (`docs/problem-statement.md`)

| PS requirement | Status | Gap / what closes it |
|---|---|---|
| Represent network state as vectors or graphs | Met | 41-feature window vector plus graph features. |
| Learn P(S_t+1 \| S_t) with a sequence model | Met | Transformer next-state head; LSTM variant. |
| Supervised dynamics from attack-timeline annotations | Met, thin | Only ~15 onset episodes on CIC-2018 (D-3). §0.3 finds about 12-18 more in CIC-2017, plus about 2 in CTU-13 (up to 13 with relabelling and shorter sequences). |
| **Generalise to unseen attack patterns** | **Not shown** | LOFO near chance except DoS. CTU-13 detection 0.78 equals native LR. Options 4.B1-B3 are the only honest route. |
| Flow-level features | Met | Native on CIC. CTU zero-fills 6 flag ratios and 3 IAT; UNSW approximates flags. |
| **Packet-level features, "combination required"** | **Partial** | Implemented, but every served model is flow-only. Packet pilots are unverified (D-2, H.8). The CTU-13 botnet PCAPs are the first second-dataset source of real packet features (4.B2). |
| K-step forward simulation | Met (mechanically) | The rollout exists. It adds nothing over frozen t+1 (ablation). R-6 is the fix to try. |
| Time-series infiltration probability over K windows | Met | Dashboard 60 s curve. |
| **MITRE stage: Recon, Initial Access, Lateral, C2, Exfil** | **Partial** | Real labels exist for Initial Access, C2 and a little Lateral (CIC-2018), plus **Recon via CIC-2017 PortScan** (mapped, never trained on). Exfil has no real labels anywhere. Recon cannot fire on the served model (D6). |
| Driving features via attention / SHAP | Met | |
| Pipeline ingesting CIC-2018 / CTU-13 CSVs and/or PCAP via Scapy/PyShark | Met | Plus the adapter toolkit. |
| Training scripts, weights, reproducible config | **Partial** | The default model's weights and scaler are not in the repo (§0.2). `real_data_v2.yaml` reproduces neither v2 checkpoint. |
| Engine output: probability, stage, top features | Met | |
| Demo interface accepting PCAP or CSV, offline | Met | No live mode yet (docs/07). |
| Benchmark vs LR (F1, P, R, FPR) showing improvement | Met on paper | World model beats LR on CIC day-disjoint t+1, but not CTU-13 native stacked LR. The "temporal dynamics" claim is weakened by the frozen-state ablation. |
| README with setup | **Stale** | §2.3. |
| Architecture doc ≤ 2 pages | **At risk** | 1,579 words; needs a 2-page cut. |
| **Demo video ≤ 2 min** | **Missing** | |
| **Technical presentation ≤ 5 slides** | **Missing in repo** | Owner has a draft outside the repo (memory note; not verified). |
| Permitted datasets / knowledge bases | Met / partial | CIC-2018, CTU-13 and UNSW used. CIC-2017 on disk, unused for training. No CAPEC. |
| Enterprise / CII applicability | Partial | CERT-In report exists. No live or enterprise-like validation; that is what the lab demo would add. |

---

## 4. What we can make: ranked build options

Effort assumes one person and excludes GPU queue time. "Onset ceiling" is the number of independent
benign→attack (or stage→stage) episodes the option can ever be scored on. Every forecasting claim
must print it.

### 4.A Demo-critical before SIH

**A1. Truth-and-consistency pass (served model = quoted model)** (rank 1)

- **What:**
  - Pick the served checkpoint by a rule fixed before looking at test, e.g. lowest val loss among
    seeds 1-3, not best test AUROC. Point `checkpoints_real_v2_converged/world_model_best.pt` (or the
    config) at it.
  - Make `/eval/metrics` show both the served seed's own numbers and the 3-seed mean.
  - Run `scripts/backfill_feature_names.py` on the served file.
  - Fix the README items in §2.3.
  - Mark the lead-time figures "pending re-run under QC-3".
  - Fix the post-D-1 doc's boilerplate "Interpretation" section.
- **Why:** a judge who asks "which model is this?" currently gets an inconsistent answer. That is
  the cheapest credibility loss to remove.
- **Data:** none new.
- **Effort:** 3-5 h.
- **Risk:** low.
- **Success test:** `GET /api/v1/health` names a checkpoint whose md5 matches a row in
  `v2_converged_seed_results.json`. `validate_feature_names` runs (not skips) on it. `grep -n "157
  tests\|0.517" README.md` returns nothing.

**A2. Deployable artefact bundle + laptop CPU benchmark** (rank 2, gates everything live)

- **What:**
  - A `scripts/package_model.py` or release asset carrying the served `.pt`, `scaler.npz`,
    `metadata.json` and `shap_background.npy` (small files, no `V:` dependency).
  - Install on the Debian laptop.
  - Run `CUDA_VISIBLE_DEVICES="" python -m scripts.benchmark_latency`, plus parser throughput
    (`read_all_frames` + `assemble_flows`) on a CTU-13 botnet PCAP, e.g. scenario 6 at 5 MB or
    scenario 1 at 58 MB.
- **Why:** docs/07 T9. No CPU number exists, and the live demo is impossible if a tick takes over 2 s.
  32 GB RAM removes the memory caveats in docs/07 §3.3.
- **Data:** small CTU-13 botnet PCAPs as a parser workload.
- **Effort:** 4-6 h.
- **Risk:** low-medium (old CPU).
- **Success test:** a clean clone plus the bundle passes `/api/v1/health` on the laptop.
  CPU latency and parser pkt/s are recorded in `docs/04-latency-benchmark.md`, with tick p95 < 2 s at
  1,000 pps.

**A3. Live pipeline, built by merging and extending `live_forecast.py`** (rank 3)

- **What:**
  - Merge `live-deployment-2026-10-10`.
  - Swap its Scapy flow path for `fast_packet_windows` (keep the event-time watermark).
  - Run it as a thread in `scripts/serve.py` that swaps `STATE.batch` atomically.
  - Add `/api/v1/live/status` and a LIVE / REPLAY / UPLOAD badge (docs/07 T3-T5).
  - Add a replay mode first, as insurance.
- **Why:** it is the owner's "live log feed" idea and the PS's "ingest network traffic" made
  visible.
- **Data:** a lab capture; CTU-13 botnet PCAPs and the Bot-day CSV as replay fixtures.
- **Effort:** 2-3 days (down from docs/07's 14-18 h + 4 h + 5-6 h, because event-time windowing
  already exists).
- **Risk:** medium (train/serve skew from the flow timeout; docs/07 §1.4).
- **Success test:** docs/07 T3's golden test. Replay of `data/raw/pcap/synthetic_sample.pcap` gives
  window features equal to the batch upload path (max abs diff < 1e-6). No duplicate
  `(src_ip, window_start)` rows. The badge flips to STALE after 30 s of no input.

**A4. Lab rehearsal + threshold calibration on the owner's own machines** (rank 4)

- **What:**
  - Follow the existing plan in docs/07 §2 (storyline, safety rules, calibration). This report does
    not restate it.
  - Record benign-only and scripted sessions with a ground-truth event log.
  - Build `scripts/calibrate_live.py` (docs/07 T6): one threshold, chosen as the 99th percentile of
    benign peaks.
  - Drop any phase that does not fire in at least 2 of 3 runs.
- **Why:**
  - The model was trained on CIC-2018 aggregates (`has_ip_data` confound, docs/07 D5), so whether
    it fires on lab traffic is unknown.
  - Finding that out before the judges do is the whole point.
  - It also produces the replay recording that A3's fallback needs.
- **Data:** the owner's lab captures only.
- **Effort:** 1.5-2 days, mostly wall-clock.
- **Risk:** **high** that some phases never fire. The mitigation is honesty plus replay, never
  fabrication.
- **Success test:** a `docs/` calibration table with, per phase, the detection rate, the
  onset-to-alarm delay and the benign false alarms per hour. Every phase kept in the live script
  fired in at least 2 of 3 runs.
- **Setup caveats (see §5):**
  - The home LAN is not isolated, so docs/07's safety rule 2 cannot be met as written.
  - A Windows attacker using WSL2 NAT collapses the source IP, so it needs mirrored or bridged
    networking. Verify this.

**A5. Reconnaissance specialist: the defensible part of the MoE idea** (rank 5)

- **What:**
  - A small, separate recon detector built only on features that are native in **both** CIC-2017
    and UNSW: `unique_dst_ports`, `unique_dst_ips`, `flow_count`, `total_packets`.
  - UNSW's flag ratios are 0/1 values derived from connection state. Using them would make the
    cross-dataset test measure the adapter mismatch rather than recon skill.
  - Rebuild the UNSW split first. The current `processed_unsw_v2` predates the fix that stopped the
    adapter dropping 15.2% of Reconnaissance rows (docs/08 §6).
  - Train it on **CIC-2017 PortScan** (158,930 real-labelled flows).
  - Test it on **UNSW-NB15 Reconnaissance** (2,022 windows), and then on lab traffic.
  - Expose it as a disclosed second stage source beside the world model: a two-expert router that
    takes the recon expert's label when its score crosses its own calibrated threshold.
- **Why:**
  - Recon is the first PS stage, and it **cannot fire on the served model** (D6).
  - This is the one place where a "specialist" fills a real hole, rather than splitting already
    scarce data.
- **Data:** CIC-2017 PortScan; UNSW recon; lab captures.
- **Effort:** 1.5-2 days.
- **Risk:** medium.
  - CIC-2017 has one PortScan attacker (NAT 172.16.0.1) and documented label errors (Lanvin et al.
    2023).
  - Cross-dataset transfer has failed before in this project.
  - It is detection, not forecasting, and must be described that way.
- **Success test:** on the rebuilt UNSW split, which the model never trained on, it reaches recall
  ≥ 0.7 at a threshold chosen on CIC-2017 val for 1% FPR. Report the FPR it actually achieves on
  UNSW, and report AUROC alongside. On a lab recording, it labels the scan window
  "reconnaissance (specialist)".

**A6. PS deliverables: video, ≤5 slides, 2-page architecture doc** (rank 6)

- **What:**
  - A 2-minute screen recording of a real replay or rehearsal run, captioned as such.
  - 5 slides, with a limitations slide built from §2.
  - Cut `docs/01-architecture.md` to 2 pages.
- **Why:** these are mandatory evaluation deliverables. Two are missing outright.
- **Effort:** 1 day.
- **Risk:** low.
- **Success test:**
  - The files are non-empty and in the repo.
  - The video is ≤ 120 s.
  - The deck has ≤ 5 slides.
  - Every number in the deck appears in §2.1.

### 4.B Research upside (makes the forecasting claim real or honestly refutes it)

**B1. R-2: onset-conditioned, episode-level evaluation across three datasets** (rank 7; do it before any model change)

- **What:**
  - Score only sequences that are benign now and have a positive at step k. Report per k with
    `impact` excluded, and with episode-level bootstrap CIs.
  - Print the episode count beside every figure.
  - Re-run lead time under QC-3 and the frozen-state ablation under this protocol.
- **Why:** this is the yardstick for B2-B6. Without it, every "improvement" is window-level and
  dominated by persistence.
- **Data and onset ceilings:**

  | Source | Ceiling (see §0.3 for the definitions) |
  |---|---|
  | CIC-2018 | ~15 episodes, an upper bound, on 3 pseudo-hosts (D-3) |
  | CIC-2017 | 12 source-keyed (9 hosts) and 18 victim-keyed (7 hosts). These overlap, and 12 of the victim onsets are on one host. |
  | CTU-13 C2→DDoS | ~2 under `sequence_length: 12`; up to 13 with shorter or gap-aware sequences (after B2) |
  | **Realistic total** | **~25-30 distinct onsets, concentrated on few hosts** |

  Before using these numbers, recount the CIC-2017 rows under B1's own onset definition (k = 1..6).

- **Effort:** 1-2 days.
- **Risk:** CIs may be too wide to separate models. If so, report that rather than a point estimate.
- **Success test:** a table of AUROC/AUPRC at k = 1..6 with n_episodes and 95% CIs, for the
  served model and for frozen t+1.

**B2. CTU-13 intra-botnet progression (C2 → Impact) with real packet features** (rank 8)

- **What:**
  - Owner decision: in `ctu13_label_to_stage`, map `From-Botnet-*-ICMP` (flood) to `impact`
    instead of `command_and_control`.
  - Optionally map `*-SPAM` and the TCP-Attempt families to separate stages.
  - Rebuild CTU-13 with the ICMP-drop fix.
  - Score the per-bot C2→DDoS onsets. There are 13 bots in total:

    | Scenario | Bots | Non-empty windows before the flood |
    |---|---|---|
    | 10 | 10 | 6-12, spread over 1.2-1.7 h |
    | 4 | 1 | 131 |
    | 11 | 2 | 2-3 |

  - **Only ~2 of the 13 qualify** under the current 12-window sequence rule. The rest need a
    shorter-history or gap-aware variant.
  - Then derive packet features for the same bots from the **botnet-only PCAPs**: scenarios 4 and
    11 are on disk, scenario 10 is still downloading.
- **Why:**
  - It gives the first real-IP, per-host, label-backed **stage progression** in the project: the
    IRC command precedes the flood.
  - It gives the first second-dataset packet-level features.
- **Data:** `V:\Datasets\CTU-13`; `CTU-13-pcaps/{4,10,11}`.
- **Effort:** 2-3 days (plus the scenario-10 download).
- **Risk:** medium-high.
  - The pre-flood history is sparse: 6-12 non-empty windows spread over an hour. Most sequences fail
    `sequence_length: 12`, and all fail `require_contiguous_windows`. A shorter-history or
    time-gap-aware variant may be needed.
  - The botnet-only PCAPs must be parsed with ICMP support (`fast_packet_windows` is TCP/UDP only).
- **Success test:** a B1-protocol table on these onsets for (a) zero-shot v2 and (b) a CTU-trained
  model, with n_episodes printed. Any AUROC claim needs a CI that excludes 0.5.
- **What it will NOT do:** produce benign→infected sequences. The mixed captures carry the same
  per-IP labels, and every infected IP is botnet-labelled from its first flow. The mixed PCAPs are
  therefore worth using only for packet-level background-traffic statistics (after the
  captured-length fix), not for onsets.

**B3. CIC-IDS-2017 multi-day, victim- and source-keyed training** (rank 9)

- **What:**
  - Prepare CIC-2017 with a **60 s window config** (its timestamps are minute-resolution, so 10 s
    windows are invalid), using a curated day split.
  - Train a native checkpoint.
  - Evaluate on the 12 source-keyed (7 Bot, 2 Infiltration, …) and 18 victim-keyed (4 PortScan,
    3 slowloris, Patator, web, …) onsets under B1.
- **Why:**
  - It is the only in-hand dataset with real IPs every day, internal hosts that turn into bots after
    a benign history, and real recon labels.
  - It is the best route to "multi-stage" evidence.
- **Effort:** 3-4 days.
- **Risk:** medium-high.
  - The "multi-stage" structure is a lab **schedule** (one NAT'd attacker, sessions on different
  days), not one adversary's kill chain.
  - The AM/PM heuristic is unverified.
  - Label noise is documented (Engelen 2021; Lanvin 2023).
  - 12 onsets land on one victim (192.168.10.50), so the episodes are not independent.
- **Success test:** B1 table on CIC-2017 test days, with stage macro-F1 including
  `reconnaissance`, reported against LR and frozen-t+1 under the same protocol.

**B4. R-6: multi-horizon head** (rank 10)

- **What:** train on all six target columns with a horizon embedding. `train.py:52,59` uses only
  column 0. Keep the rollout for the trajectory and what-if views.
- **Why:** it is the only direct attack on the project's largest negative result (rollout < frozen).
- **Effort:** 2-3 days plus GPU.
- **Risk:** it may just reproduce frozen t+1. That is a cheap and publishable negative.
- **Success test:** beats frozen t+1 at k = 4 and 6 under B1, with non-overlapping episode CIs.

**B5. Retrain with `require_contiguous_windows`** (rank 11)

- **What:**
  - First, count how many sequences and onsets survive the flag on CIC-2018 and CIC-2017. This is
    read-only, about 1 h.
  - Only retrain if retention is acceptable and B1 shows that gaps hurt.
- **Why:** it makes "k steps" mean k × 10 s (QC-1).
- **Effort:** 1 day plus a GPU rebuild.
- **Risk:** it may delete most onsets. It kills every CTU-13 onset in B2.
- **Success test:** a retention table first. After retraining, no regression on B1.

**B6. Mixture-of-Experts / per-attack specialists with a learned router (full version)** (rank 12)

- **Honest assessment:** low expected value now.
  - The bottleneck is onset data, not model capacity.
  - Each specialist would see only a fraction of ~25-30 onsets.
  - A router that must know the attack type *before* it happens is circular for forecasting.
  - LOFO already shows that per-family knowledge does not transfer.
- **What to build instead:** A5 (a recon expert where the generalist is structurally blind), plus
  an optional volume (impact) expert. Present this as a "detector ensemble beside the world model",
  not as an MoE forecaster.
- **Effort:** 3-5 days.
- **Risk:** high.
- **Falsifiable test:** if attempted, it must beat the single model on LOFO held-out families
  **and** on B1 onsets. Otherwise drop it.

**Also worth doing** (each 1 h - 1 day):

- R-5: score a `flow_count` z-score rule on the cic_pkt split to explain AUROC 1.000 (D-2).
- R-4: report infiltration AUROC three ways (all / impact-only / impact-excluded).
- Merge the DoS demo, then regenerate `docs/04-dos-forecast-demo.md` after `90bbd1c`.
- Remove the hard-coded frontend token (docs/07 T12).
- Add a `data/raw/unsw_nb15` junction.
- Rebuild CTU-13 and UNSW processed splits with the drop fixes, then re-run their zero-shot docs.
- Optional new data: CIC-2018 infiltration-day PCAPs (02-28, 03-01). These are the only CIC-2018
  days where internal victims turn hostile, giving per-host lateral-movement onsets. Tens of GB,
  and the labels are known to be noisy.

---

## 5. Recommended 2-week plan

| Day | Work | Depends on |
|---|---|---|
| 1 | A1 truth pass. Push `65c3bf2`. Decide the served checkpoint (rule fixed in advance). | — |
| 1-2 | A2 bundle + Debian install + CPU benchmark (**go/no-go for live**) | A1 |
| 2 | B1 protocol code + QC-3 lead-time re-run on the served model (CPU or GPU, owner's call) | A1 |
| 3-5 | A3 live pipeline: merge the branch, fast parser, `STATE` hook, badge, replay first | A2 |
| 5-6 | A5 recon specialist (CIC-2017 PortScan → UNSW recon) | B1 harness (for reporting) |
| 6-8 | A4 lab rehearsal and calibration; record the replay | A3, A5, owner's network decision |
| 8-9 | A6 video, deck, 2-page architecture doc; README final pass | A4 results |
| 10-12 | Research slot. B2 (CTU-13 C2→DDoS) if the owner approves the mapping change and scenario 10 has finished; otherwise B3 (CIC-2017) | B1 |
| 13-14 | B4 multi-horizon head if B1 shows headroom; write up results with episode counts | B1, GPU |

If A2 shows that the laptop cannot keep up, A3 becomes replay-only on the laptop with the live
capture on the dev PC. Decide on day 2.

### Open decisions for the owner

1. **Served checkpoint.** Which rule selects it (val-loss-best seed is recommended)? Should the
   dashboard show that seed's own metrics, the 3-seed mean, or both?
2. **Network for the demo.**
   - The home LAN has internet and household devices, which conflicts with docs/07's isolation rule.
   - Choose a separate isolated segment (travel router or switch with no uplink), or a written,
     narrower rule set with a hard target allowlist.
   - At the venue, is replay-only acceptable?
3. **Attacker setup on Windows.** Native tools, WSL2 with mirrored networking, or a bridged VM?
   WSL2 NAT would hide the source IP.
4. **CTU-13 label change.** May `From-Botnet-*-ICMP` become `impact`, and may SPAM / Attempt become
   separate stages? This edits `pipeline/mitre_mapping.py` and invalidates the CTU-13 numbers again.
5. **Which research track:** B2 (CTU-13, waits on the scenario-10 download) or B3 (CIC-2017, ready
   now)?
6. **Merge `live-deployment-2026-10-10`** into this branch, and **when to merge this branch into
   `master`**. Judges see `master`, which still serves v1.
7. **Artefact distribution.** Git LFS, a GitHub release asset, or a manual copy for the v2 weights
   and scaler?
8. **MoE scope.** Accept A5 (recon expert) as the MoE deliverable and park B6?
9. **Fabricated benign traffic in v2 val/test** (17-27%). Keep it and disclose it, or rebuild
   without it?
