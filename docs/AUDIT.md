# Project Audit: AI-Based Network Attack Forecasting (SIH PS 26153)

**Audit date:** 2026-09-19 (revised 2026-09-20 for the problem statement's added "Dataset Link" section)
**Audited state:** commit `de75a3b` (branch head), real-data checkpoint `checkpoints_real/world_model_best.pt` (41 features), processed data `data/processed_real/` (rebuilt 2026-09-19).
**Scope:** code, trained models, evaluation reports, documentation, and the problem statement itself.
**Method:** read-only. The test suite was run, and every number marked "measured" was recomputed with a separate script against the checkpoint and splits on disk, without re-running `eval/benchmark.py` (which would overwrite the reports being audited).

## Severity key

| Level | Meaning |
|---|---|
| **Critical** | Invalidates or seriously misrepresents a headline claim. A judge who finds it can discount the result. |
| **High** | A problem-statement requirement is unmet, or a reported number is misleading. |
| **Medium** | A real flaw with limited blast radius, or a disclosure gap. |
| **Low** | Hygiene, staleness, or polish. |

---

## Part A: Summary

> Status values in this table were edited by the builder agent on 2026-09-23. **Part G** holds the
> independent verification of those statuses and takes precedence where the two disagree.

| # | Finding | Severity | Area | Status |
|---|---|---|---|---|
| E1 | Train/val/test are split per host in time order, so test attacks are the *same attack sessions* seen in training. The data cannot support any "unseen attacks" claim. | **Critical** | Evaluation | **IN PROGRESS** — day-disjoint split + v2 checkpoint built (`configs/real_data_v2.yaml`, `docs/04-evaluation-real-v2.md`); leave-one-family-out results now exist (see S8) and are negative except for DDoS. Not FIXED: this is honest new evidence *against* generalisation, not a resolution. See BUILD_REPORT.md. |
| E2 | Lead-time metric: the 32 "transitions" are 2 pseudo-hosts, 30 of them re-onsets of one DDoS day. 0 of 32 are PS-stage attacks. | **Critical** | Evaluation | **Substantially addressed** — the day-disjoint split alone produces 628 real transitions across many hosts/days (`docs/04-evaluation-real-v2.md`), vs. the original 32. 93.5% are missed at the same operating point. |
| E3 | Lead-time metric ignores false alarms. At the same threshold the rollout raises 2,922 false early warnings against 32 true transitions (≈1% alarm precision). | **Critical** | Evaluation | **FIXED (code)** — `eval/metrics.py::lead_time_metrics` now reports `false_alarm_rate`/`alarm_precision` in every report. Re-measured on the day-disjoint split: alarm precision 1.5%, closely matching this finding's own hand-measured number. |
| E4 | Stage macro-F1 is labelled "5-way" but test contains 4 classes, including benign. The 3 attack classes each come from a single day-level pseudo-host. | **High** | Evaluation | **FIXED** — `eval/metrics.py::stage_metrics` reports actual `n_classes_present`/per-class `support`; report headers are generated from these instead of hard-coded; added an attack-classes-only macro-F1 column. |
| E5 | The "5% FPR budget" operating point is not 5% (1.4% achieved), and it hides the model's real low-FPR performance (F1 0.918 at 0.1% FPR vs reported 0.535). | **High** | Evaluation | **FIXED** — added 1% and 0.1% FPR budget tables plus an AUROC/AUPRC table alongside the original 5% table (kept, with a caveat note). |
| E6 | Persistence and Markov baselines read the ground-truth label of the current window. They are oracles, not deployable baselines, and the report doesn't say so. | **High** | Evaluation | **FIXED** — both now labelled `[ORACLE -- reads true current label, not deployable]` everywhere they appear; added `models/baseline_lr.py::PersistenceOnPredictedLabel`, a real deployable baseline (predicts current label from features first). Measured gap: oracle F1 0.878 vs deployable 0.153. |
| E7 | All per-host (real-IP) attack data is DDoS. Every non-DDoS attack exists only as a whole-day network aggregate (9 pseudo-hosts in total). | **High** | Data | Open — kept open per project owner's explicit decision; UNSW-NB15 added for D1 but not yet used to close this specific gap. |
| E8 | No gap between splits. Sliding windows (L=12, K=6) overlap at every train/val/test boundary. | Medium | Evaluation | **FIXED** — `pipeline/build_dataset.py::day_disjoint_split` drops any sequence whose input-to-target span crosses into a different calendar day. |
| E9 | The CTU-13 cross-dataset report was produced by code that fitted the native baselines' scaler on the test split. | Medium | Evaluation | **Regenerated**, not yet swapped in — `docs/04-evaluation-ctu13_cross_from_real_data_REGEN.md` (original left untouched pending confirmation). LR rows changed as expected; the World Model row *also* changed unexpectedly, for a reason not fully diagnosed (see BUILD_REPORT.md) — flagging this rather than presenting it as a clean drop-in fix. |
| E10 | No confidence intervals, seeds, or repeated runs. The GNN ablation draws conclusions from 0.003–0.03 F1 differences. | Medium | Evaluation | Open — not started. |
| E11 | README points to `docs/04-evaluation.md`, which holds **synthetic** results (72 test sequences), not real-data results. | Medium | Docs | Open — not started. |
| S1 | Uploading an unlabeled flow CSV crashed the demo | High | App | **Fixed** `de75a3b` |
| S2 | Alert cache keyed on host count only (stale alerts across uploads) | Medium | App | **Fixed** `de75a3b` |
| S3 | Test-split scaler leak in the cross-dataset benchmark | Medium | Eval code | **Fixed** `de75a3b` |
| S4 | No PCAP-only input; `.pcapng` rejected; no PCAP→flow conversion | High | PS compliance | **FIXED** — `.pcapng` rejection was purely the uploader's `type=` restriction (scapy already parsed it correctly, verified with a genuine pcapng-magic file); fixed. `pipeline/packet_features.py::build_flow_records` derives flow-level records directly from packets, so a PCAP/PCAPNG alone (no CSV) now drives the full pipeline. |
| S5 | Uploads only run through the synthetic-data model | High | PS compliance | **FIXED** — upload widgets unified across both data-source branches; an upload is now scored by whichever model is selected, with an explicit "Scored by: \<model\>" caption on every result. |
| S6 | Recon and Exfiltration never appear in real data; the model never predicts them | High | PS compliance | **Mitigated, not eliminated** — `models/forecast.py::_heuristic_stage_override` derives Reconnaissance from `port_scan_score` at inference time (same signal already used for training labels), disclosed in the UI as a heuristic. Still zero-fires on the real bundled dataset (no PCAP), same documented limitation as before; now genuinely usable on PCAP-only uploads (S4). Exfiltration now carries an explicit "synthetic, demo-only" caption wherever shown. |
| S7 | DoS/DDoS ("impact") is predicted as Command & Control 570 of 684 times | High | Model/UI | **FIXED** — the same heuristic overrides extreme flow-volume + low destination diversity to `impact`, disclosed as a heuristic override, and rendered as its own badge outside the 5-way stepper. |
| S8 | No leave-one-attack-family-out test for "generalise to unseen attacks" | High | PS compliance | **Addressed (evaluation exists)** — all 4 folds run (`eval/lofo.py`, `docs/lofo_results_v2.json`). Result is negative: AUROC 0.612/0.432/0.531/0.872 for initial_access/lateral_movement/command_and_control/impact respectively — only DDoS (the one family with abundant real per-host data, see E7) generalises. This is the honest answer to S8, not a fix to what it measures. |
| S9 | App loads the full train split (~1.7 GB) to sample 20 SHAP background rows | Low | App | Open — not started. |
| S10 | Jointly-trained GNN model is built but unused by the app, and shows no benefit | Low | Scope | Open — not started. |
| S11 | README checklist is stale; repo root is cluttered with untracked logs and scripts | Low | Docs | Open — not started. |
| S12 | Demo video and 5-slide deck are not in the repo | Low | Deliverables | Open — not started. |
| S13 | Both robustness scripts (`check_robustness.py`, `check_adversarial_robustness.py`) raise `KeyError` on the 41-feature schema — they never build the `graph_embed_*` columns. Neither has run since the GNN work landed. | **High** | Scripts | **FIXED** — both now build the missing `graph_embed_*` columns and run cleanly on `configs/real_data.yaml`. Re-measured: the PGD evasion finding reproduces on the current 41-feature checkpoint (0.9975 -> 0.0000). |
| D1 | The PS's "Dataset Link" section permits 6 datasets; the project uses 2, and uses no authentication-log telemetry (LANL) at all. Unused datasets are the cheapest route out of E1. | Medium | Data scope | **IN PROGRESS** — UNSW-NB15 added (`pipeline/adapters/unsw_nb15.py`, real per-host IPs/timestamps, includes genuine Reconnaissance), zero-shot cross-dataset eval run. Result is also negative (AUROC 0.443 on the v2 checkpoint) — independent confirmation of E1/S8, not a win. CICIoT2023 investigated and ruled out (no IPs/timestamps in its CSVs; raw PCAPs are ~548 GB). |
| D2 | The PS names CAPEC alongside ATT&CK and CVE/NVD. The project maps to ATT&CK stages and enriches with CVE/NVD, but has no CAPEC linkage. | Low | PS compliance | Open — not started. |

**Builder progress note (2026-09-23):** see `BUILD_REPORT.md` for full detail, evidence, and honest caveats behind every status above. Nothing above has been swapped in as the project's primary checkpoint/report yet — all new artefacts (`*_v2`, `*_REGEN`, `*_unsw`) sit alongside the originals pending review.

---

## Part B: Evaluation reports vs code

Reports audited: `docs/04-evaluation-real.md` (primary), `docs/04-evaluation-ctu13_cross_from_real_data.md`, `docs/04-evaluation.md`, `docs/06-gnn-ablation.md`.
Code audited: `eval/benchmark.py`, `eval/metrics.py`, `models/baseline_lr.py`, `models/markov_baseline.py`, `pipeline/build_dataset.py::chronological_split`.

### B.0 Reproduction: the reported numbers are genuine

The code does compute what the tables show. The recomputed world-model figures match `04-evaluation-real.md` exactly:

| Metric | Reported | Measured |
|---|---|---|
| F1 / P / R @ 0.5 | 0.917 / 0.943 / 0.892 | 0.9171 / 0.9434 / 0.8923 |
| F1 / P / R / FPR @ "5% budget" | 0.535 / 0.365 / 0.999 / 0.014 | 0.5347 / 0.3650 / 0.9993 / 0.0138 |
| Persistence F1 @ 0.5 | 0.988 | 0.9879 |
| Lead time (transitions, missed, early, mean, median) | 32, 0, 46.9%, +6.9s, +0.0s | 32, 0, 46.9%, +6.875s, 0.0s |

**No fabrication or copy errors.** The problems below are about what those numbers *mean*, not whether they were computed correctly.

### E1 (Critical): the "chronological" split puts the same attack sessions in train and test

`configs/real_data.yaml` says `chronological: true`. `pipeline/build_dataset.py:84-130` implements this as a 70/15/15 time-ordered cut **within each `src_ip` group**, not a global cut in time. Because 9 of 10 CIC-IDS-2018 days are one pseudo-host per day (`NETWORK-<date>`), every day is sliced three ways.

Measured, per split:

- All three splits span the same dates: train 2018-02-14 → 04-02, val 02-14 → 04-02, test 02-14 → 04-02.
- Every attack day contributes to both train and test. Examples: `NETWORK-2018-03-02` (Bot, the C2 class) has 1,092 positives in train and 468 in test (all 470 test windows are positive). `NETWORK-2018-02-14` (brute force) has 546 in train and 196 in test.

**Consequence:** the test set measures "can the model keep recognising an attack session it has already watched for 70% of its length". That's close to the persistence task, which is why persistence wins (E6). There is no evidence the model generalises to an attack it hasn't seen, and the PS explicitly requires that ("Generalise to unseen attack patterns — not merely memorize signatures"). The CTU-13 cross-dataset run is the only real out-of-distribution evidence in the project.

**What a defensible split looks like:** hold out whole days (each CIC-IDS-2018 day is roughly one attack family), plus a leave-one-attack-family-out rotation.

### E2 (Critical): the lead-time metric is measured on almost no independent events

The report presents "32 benign-to-attack transitions, 0 missed, 46.9% detected early" as direct evidence for the PS's "before compromise completes".

Measured breakdown of the 32 transitions:

| Property | Value |
|---|---|
| Distinct hosts | **2**: `NETWORK-2018-02-21` (30), `NETWORK-2018-03-02` (2) |
| Stage at onset | **30 × `impact` (DDoS)**, 2 × command_and_control |
| Onset step within horizon | step 1: 17, step 2: 8, step 3: 7, steps 4–6: 0 |
| Distinct onset events on 02-21 | 16, one roughly every 50–70 seconds from 10:27 to 10:42 |

The 02-21 "transitions" are the on/off gaps of **one continuous DDoS run**, not 30 separate attack starts. The whole metric rests on about 2 real episodes. Neither is a PS stage (Reconnaissance → Exfiltration): one is DDoS, which the project itself excludes from stage classification. The other is the Bot/C2 session that E1 shows already appears in training.

**Definition issue in `eval/metrics.py:97`:** `lead = onset_step − first_alarm_step` compares two steps *inside the same forecast issued at time t*. Every alarm in a rollout is raised at time t, so any correct alarm is already `(onset_step + 1) × 10s` ahead of the attack. "Median lead time 0.0s" therefore means "first flagged at the same future step the attack begins", which still delivers ≥10 s of warning. The metric understates warning time for detected cases and gives no picture of how early, in wall-clock time, a host was first flagged. A per-host measure over consecutive forecasts (earliest alarm before each onset, in seconds) would match the PS framing.

### E3 (Critical): the lead-time metric never counts false alarms

`lead_time_metrics` only looks at sequences that do transition. It never asks how often the rollout alarms on sequences that stay benign.

Measured, same threshold (0.0075), same K=6 rollout:

| | Count |
|---|---|
| Benign-now sequences that stay benign for all 6 steps | 193,065 |
| …of which the rollout raises an alarm | **2,922 (1.51%)** |
| True transitions detected | 32 |

A defender acting on these early warnings would get about **1 real warning per 90 false ones**. With a threshold that low, "0 missed" follows almost automatically. Report the alarm precision and false-alarm rate alongside the lead time, or the metric can't be defended.

### E4 (High): stage macro-F1 is not "5-way" and mostly measures which day it is

The report header reads "MITRE stage classification (5-way, `impact`-mapped windows excluded)". `eval/metrics.py::stage_metrics` macro-averages over **the classes present in `y_true`**.

Measured test stage labels: benign 193,100 · initial_access 196 · lateral_movement 184 · command_and_control 468 · (impact 684, excluded). That's **4 classes, and one of them is benign**. Reconnaissance and exfiltration have **zero** examples in train, val and test.

Each of the 3 attack classes comes from **a single day-level pseudo-host** (02-14, 02-28 and 03-02 respectively). "Stage classification" is therefore largely "which day's aggregate is this", and with E1 the model has already seen 70% of each of those days. The 0.820 macro-F1 is also pulled up by the near-perfect benign class.

The header should read "4 classes present (3 attack + benign)", the report should state the per-class support, and it should report macro-F1 over the attack classes only.

### E5 (High): the "fixed 5% FPR budget" table understates the model and isn't 5%

- `TARGET_FPR = 0.05` (`eval/benchmark.py:61`), but the threshold picked on val (0.0075) gives **1.38%** FPR on test. The table's title and its FPR column disagree, with no explanation.
- At 0.8% prevalence, a 5% FPR budget allows ~9,700 false positives against ~1,530 positives, so the threshold has to fall near zero. That's why F1 collapses from 0.917 to 0.535.
- Measured at stricter budgets: **0.1% FPR → F1 0.918** (P 0.934, R 0.903, test FPR 0.05%). A 1% budget lands on the same threshold as 5% (F1 0.535).
- The best-F1 threshold on val (0.475) gives F1 0.917 on test.

A judge reading the 0.535 table concludes the model is weak at a realistic operating point, when the opposite is true. Report 0.1% and 1% budgets and the achieved FPR, and add AUPRC (measured **0.965**; AUROC 0.9995).

The same pattern shows in `06-gnn-ablation.md`, which draws "F1 @ 5% FPR" conclusions (0.503 vs 0.535) from this degenerate operating point.

### E6 (High): persistence and Markov are label oracles, presented as "no learning" baselines

`models/baseline_lr.py::PersistenceBaseline.predict` returns `ds.current_infiltration`, and `models/markov_baseline.py` indexes on `ds.current_stage`. Both are **ground-truth labels** of the last input window. A deployed system never has those; producing them is the classification problem itself.

The report calls persistence "no learning" and the benchmark docstring says "If the world model can't beat this, it isn't learning real dynamics". Read literally, the project's own benchmark says its model fails its own bar (0.917 vs 0.988). The existing "honest caveat" explains *why* persistence is strong but never says it is an oracle.

Recommended framing: rename it "Label-persistence oracle (upper reference, not deployable)". A fair persistence baseline would apply persistence to a *predicted* current label, for example the LR last-window classifier's output.

### E7 (High): only DDoS has per-host data

Measured: in train, **2,617 of 2,617** positives on real-IP hosts are `impact` (DDoS). Every brute-force, infiltration and bot positive comes from one of 9 `NETWORK-<date>` aggregates. Only the 02-20 DDoS day kept per-host IP columns.

The PS asks for "attacker progression" through kill-chain stages. On real data, the model never sees a single host progress through non-DDoS stages. Stage transitions in the data are transitions of a whole network's daily aggregate. This is disclosed in `docs/02` for feature extraction, but none of the evaluation reports carry it through to what it means for the stage and progression claims.

### E8 (Medium): overlapping sequences at split boundaries

`chronological_split` cuts sorted sequence indices with no embargo. Each sequence covers 12 input windows plus 6 target windows, so the last ~17 train sequences of every host share windows with the first val sequences, and the same holds between val and test. With per-host splitting (E1) this repeats at 2 boundaries × ~9,150 hosts. The effect on aggregate numbers is small compared with E1, but it is textbook leakage and easy to fix: drop `L + K − 1` sequences at each boundary.

### E9 (Medium): CTU-13 cross-dataset report predates the scaler fix

`docs/04-evaluation-ctu13_cross_from_real_data.md` (last touched `c5a4882`) was produced while `eval/benchmark.py` fitted the **native CTU-13 baselines'** scaler on the CTU-13 **test** split (fixed in `de75a3b`). The world-model row is unaffected: it uses the CIC scaler. The LR rows (0.014 / 0.002 at 0.5; 0.045 at budget) need regenerating before they're quoted.

The report also opens with "strongest available evidence against signature memorisation". That's reasonable for the binary signal, but its own stage-transfer result (macro-F1 0.328) should sit right next to that claim.

### E10 (Medium): single runs, no uncertainty

Every table comes from one training run with one seed. There are no bootstrap confidence intervals. Given E1, E2 and E7, the effective number of independent attack episodes in test is very small (single digits per class). Differences such as the GNN ablation's −0.003 / +0.032 / −0.021 are almost certainly inside run-to-run noise. `06-gnn-ablation.md` correctly concludes "no measurable benefit", but it should say the comparison has no power to detect one. Lead time being "numerically identical" in both runs shows how coarse that metric is.

### E11 (Medium): report hygiene

- The README deliverables checklist says benchmark "results in `docs/04-evaluation.md`". That file is the **synthetic** run: 72 test sequences, no transitions. Real results are in `04-evaluation-real.md`.
- `04-evaluation-real-before-graph-embed.md` is a frozen snapshot with no header saying it's historical.
- The single-dataset benchmark calls `build_datasets`, which **overwrites `scaler.npz`** on every run (`models/dataset.py:104`). That's the same file the demo app loads. Today it is deterministic, but a benchmark run against a rebuilt dataset silently changes the scaler the production checkpoint is served with. The scaler belongs inside the checkpoint.

---

## Part C: System audit (earlier in this session)

### Health

- Test suite: **157 passed**, before and after fixes.
- Checkpoint/data consistency: the real checkpoint (trained 2026-09-17) still matches the data rebuilt 2026-09-19. Measured test AUROC is 0.9995.
- K-step rollout, scored against true future labels per step: F1 0.962 → 0.961 → 0.961 → 0.956 → 0.954 → 0.951 (steps 1–6, first 40k test sequences). The rollout doesn't drift, but given E1 and E6 this mostly reflects label persistence.
- CVE lookup, compliance report and narrative generation are fully offline. PS requirement met.

### Fixed in `de75a3b`

- **S1:** `pipeline/flow_features.py::load_flow_csv` required a `Label` column, so any real, unlabeled capture crashed the demo. Added `require_label=False` for the upload path. Verified end to end.
- **S2:** `app/streamlit_app.py` score cache keyed on `(config_path, host_count)`, so a different upload with the same host count reused stale alerts and skipped the audit-ledger write. The key now includes input identity.
- **S3:** `eval/benchmark.py::run_cross_dataset` fitted the native-baseline scaler on the test split. It now uses the train split (see E9).

### Open

- **S4 (High):** the PS requires the demo to accept "a PCAP **or** CSV". The flow CSV is mandatory, and a PCAP only adds to it. There's no PCAP→flow conversion, even though the PS names Scapy/PyShark for exactly this. The uploader's `type="pcap"` also rejects `.pcapng`.
- **S5 (High):** uploaded files are scored only by the synthetic-data model. The real-data model can only replay the bundled dataset.
- **S6 (High):** real data has zero Reconnaissance and zero Exfiltration labels (the latter exists only in the synthetic generator), and the model never predicts either on real data. Only 3 of the PS's 5 stages are exercised.
- **S7 (High):** DoS/DDoS windows (label `impact`, excluded from stage training) come out as command_and_control 570 / 684 times. The dashboard shows floods as C2.
- **S8 (High):** no leave-one-attack-family-out evaluation. See E1.
- **S13 (High, found 2026-09-20):** `scripts/check_robustness.py:80-82` and `scripts/check_adversarial_robustness.py:147-149` call `build_flow_windows` + `merge_graph_features` + `merge_packet_features`, but never `merge_graph_embedding_features`. Since the GNN Phase-3 commit (`ed065b6`, 2026-09-17) added 8 `graph_embed_*` columns, both scripts fail with `KeyError: ['graph_embed_0', ...] not in index` against `configs/real_data.yaml`. Reproduced 2026-09-20. Consequences: (a) the robustness fix that motivated `scripts/augment_benign_high_volume.py` is no longer verified against the shipped checkpoint; (b) the adversarial-evasion finding (99.98% → 0.00%) was measured on the 33-feature model and has not been re-measured on the 41-feature one, so quoting it as a current result is unsupported. The app's `_process_uploads` does call `merge_graph_embedding_features`, which is why the demo still works — the drift is script-only.

- **S9 (Low):** `_load_backend` scales the full train split (~877k × 12 × 41 floats) only to draw 20 SHAP background rows.
- **S10 (Low):** the joint GNN (`models/world_model_joint.py`) is trained but not exposed in the app, and its ablation showed no benefit. Either present it as a documented negative result or leave it out of the pitch.
- **S11 (Low):** the README checklist still shows "[ ] Trained on full CIC-IDS-2018" and doesn't mention the GNN, CVE, compliance, ledger or lead-time work. The repo root has untracked `*.log` files, `certin_directions.txt`, `configs/_ctu13_build_tmp.yaml`, and loose `inspect_*.py` / `fix_sequence_chronology.py` / `check_chronology.py`.
- **S12 (Low):** the demo video (≤2 min) and the technical presentation (≤5 slides) aren't in the repo. `docs/01-architecture.md` is ~1,045 words, which fits the 2-page limit only with little room for diagrams.

---

## Part D: Problem statement compliance matrix

| PS requirement | Status | Evidence / gap |
|---|---|---|
| Represent network state as feature vectors or graphs | ✅ Met | 41-feature window vector plus graph-level features and a GraphSAGE embedding |
| Learn P(S_t+1 \| S_t) with a sequence model | ✅ Met | Transformer next-state head plus LSTM variant |
| Supervised dynamics learning from attack timeline annotations | ✅ Met | Next-state + stage + infiltration multi-task loss |
| Generalise to unseen attack patterns | ❌ **Not shown** | E1: test is a continuation of training sessions. CTU-13 transfer is partial (binary yes, stage no). |
| Flow-level features (flags, IAT, bytes, ratios…) | ✅ Met | `pipeline/flow_features.py`, `windowing.py` |
| Packet-level features (TTL, window size, frags, scan signature, retransmits) | ⚠️ Partial | Implemented, but the real model is trained flow-only (all packet features zero-filled). The PS says "the combination of both levels is required". |
| K-step forward simulation | ✅ Met | `ForecastEngine.rollout` |
| Time-series infiltration probability over next K windows | ✅ Met | Dashboard timeline |
| MITRE stage mapping (Recon, Initial Access, Lateral Movement, C2, Exfil) | ⚠️ Partial | 3 of 5 stages on real data (S6); DDoS mislabelled as C2 (S7) |
| Driving features via attention / SHAP | ✅ Met | Attention + gradient×input + KernelSHAP |
| Pipeline ingesting CIC-IDS-2018 / CTU-13 CSVs and/or PCAP | ⚠️ Partial | CSV yes; PCAP only as a supplement (S4) |
| Trained model + weights + reproducible config | ✅ Met | Checkpoints, configs and training scripts present |
| Demo accepting PCAP or CSV, fully offline | ⚠️ Partial | S4, S5; offline requirement met |
| Displays probability timeline, flagged flows, stage annotations | ✅ Met | "Flagged flows" lists every flow in the window, not flows the model individually flagged |
| Benchmark vs logistic regression (F1, P, R, FPR) showing measurable improvement | ⚠️ Met on paper | Beats both LR baselines, but see E1, E5 and E6 for how the comparison reads |
| README with setup | ✅ Met | Stale in places (S11, E11) |
| Architecture doc ≤2 pages | ⚠️ Check | ~1,045 words |
| Demo video ≤2 min, deck ≤5 slides | ❌ Not in repo | S12 |
| Datasets from the permitted list (CIC-IDS2017/2018, UNSW-NB15, CTU-13, CICIoT2023, LANL auth, DARPA) | ⚠️ Partial | CIC-IDS-2018 (trained) + CTU-13 (cross-dataset eval). UNSW-NB15, CICIoT2023, LANL and DARPA unused — see D1 |
| Public knowledge bases (MITRE ATT&CK, CAPEC, CVE/NVD) | ⚠️ Partial | ATT&CK stage mapping + offline CVE/NVD snapshot; no CAPEC (D2) |
| Applicability to enterprise and Critical Information Infrastructure; NCIIPC contact given | ⚠️ Partial | CERT-In-style compliance report exists (`models/compliance.py`); no CII-specific validation, and the NCIIPC contact route was not used |

---

## Part E: Weaknesses in the problem statement itself

These aren't project defects. They are places where the PS is ambiguous or can't be fully met with the data it recommends. Stating them up front protects the submission.

1. **Stage vocabulary vs dataset labels.** The PS asks for five ATT&CK stages and recommends CIC-IDS-2018 / CTU-13, neither of which labels Reconnaissance (as a campaign phase) or Exfiltration. Any team claiming all five on real data is using heuristics or synthetic labels.
2. **"Before compromise" has no metric.** It asks for pre-compromise prediction but only lists F1/P/R/FPR, all of which reward detecting an attack during it. There's no defined lead-time or early-warning measure.
3. **The required baseline is too weak.** Only logistic regression is required. On 10-second windows of long contiguous attacks, a label-persistence reference beats every learned model, so "beats LR" doesn't show temporal learning.
4. **"Unseen attack patterns" has no protocol.** Neither a held-out attack family nor a cross-dataset test is specified.
5. **Flow + packet "required", but PCAP isn't practical.** CIC-IDS-2018 PCAP is about 37 GB per day. The PS demands both levels without acknowledging that the recommended CSVs are flow-only.
6. **The "world model" definition is loose.** It requires P(S_t+1 | S_t) but doesn't say whether infiltration and stage must be predicted *from the imagined state*, or can come from separate heads. K (number of steps and their duration) is also left undefined.
7. **The dataset list postdates the main text.** The "Dataset Link" section permits authentication logs (LANL) and IoT traffic (CICIoT2023), but Section 1 still mandates flow-level *and* packet-level features as described for NetFlow/PCAP — which an authentication log cannot supply. A team using LANL cannot satisfy Section 1 literally.
8. **Known label noise.** CIC-IDS-2018 has documented labelling error rates of about 6.7–7.5% (over 75% for some classes; Cantone et al. 2024). The PS treats its annotations as ground truth for "supervised dynamics learning".

---

## Part F: Recommended remediation order

Ranked by how much each changes what a judge concludes. None of this has been implemented.

1. **Re-split by day / attack family and add a leave-one-family-out evaluation** (E1, S8). This is the only way to make any generalisation claim, and it will likely lower headline numbers. Do this before the numbers go in slides. The PS's dataset list makes a second route available: a zero-shot evaluation on **UNSW-NB15 or CICIoT2023** would reuse the existing `run_cross_dataset` path (D1) and give unseen-attack evidence that doesn't depend on re-splitting CIC-IDS-2018 at all.
2. **Rework the lead-time section** (E2, E3). Measure wall-clock warning time per host over consecutive forecasts, report the false-alarm rate and alarm precision, count distinct episodes rather than re-onsets, and break results down by stage.
3. **Fix the operating-point reporting** (E5). Use 0.1% and 1% FPR budgets, show the achieved FPR, and add AUPRC.
4. **Relabel persistence and Markov as label oracles** (E6), and add a deployable persistence-on-predicted-label baseline.
5. **Correct the stage-metric labelling** (E4). Report actual class count and per-class support, and give macro-F1 over attack classes only.
6. **Regenerate the CTU-13 cross-dataset report** (E9).
7. **Close the PS compliance gaps** S4, S5 and S7 (PCAP-only input, real-model uploads, separate Impact stage in the UI).
8. **Add split embargo, seeds and bootstrap CIs** (E8, E10). Store the scaler in the checkpoint (E11).
9. **Documentation cleanup** (E11, S11, S12).

---

## Part G: Branch review — `builder/audit-fixes-2026-09-23` (`db49ea0`)

**Review date:** 2026-09-23. **Reviewed:** the builder's single commit on
`builder/audit-fixes-2026-09-23`, its `BUILD_REPORT.md`, and the status edits it made to Part A
above. **Method:** read-only. `pytest` was run (194 passed). Every number below was recomputed in
a scratch directory against the artefacts on disk; `eval/benchmark.py`, `eval/lofo.py` and the
`build_*` pipelines were NOT run, so no report, checkpoint or scaler was overwritten.

Part A's status column was edited by the builder and is left as it stands. This part is the
independent verification of those statuses; where the two disagree, this part is the audit's
position.

### G.0 What holds up

| Builder claim | Verdict | Evidence |
|---|---|---|
| S13 fixed; both robustness scripts run on the 41-feature schema | **Verified** | Ran `scripts.check_robustness` against `configs/real_data.yaml`: completes, OOD-benign peak 0.0369, PASS. |
| 194 tests pass | **Verified** | `pytest` → 194 passed. |
| Protected artefacts untouched | **Verified** | mtimes unchanged: `checkpoints_real/world_model_best.pt` 09-17 17:44, `data/processed_real/scaler.npz` 09-19 15:39, `docs/04-evaluation-real.md` 09-19 15:40, original CTU-13 report 09-11 14:22. |
| v2 next-step F1 @0.5 = 0.431 | **Verified** | Recomputed: 0.4305. |
| E1's direction: the old headline numbers depended on session overlap | **Verified** | v2 (day-disjoint) test AUROC 0.7791 vs v1's 0.9995. Holds after removing every synthetic row (real-only AUROC 0.7784), so it is not an artefact of G6 below. |
| E9 regeneration is correct and the branch did not change inference | **Verified** | Independent recompute of the CTU-13 world-model row on current data: F1@0.5 = 0.0065, matching the REGEN's 0.006, not the original's 0.001. The builder's "unexplained" flag is resolved — see G1. |
| E3–E6 honest-metric changes implemented | **Verified (code + tests)** | `false_alarm_rate`/`alarm_precision`, `n_classes_present`/`support`, 1%/0.1% FPR tables, `[ORACLE ...]` labels and `PersistenceOnPredictedLabel` all present, with tests. |
| Stage metrics are not contaminated by the new S6/S7 heuristic | **Verified** | `eval/benchmark.py::_world_model_predictions` uses the raw softmax; the override lives only in `ForecastEngine`. Reported stage-F1 is still the trained classifier's. |
| S4/S5 verified live in the browser (upload widgets, "Scored by" caption) | **Not verified** | Not re-run here. The builder states it did not inject a file through the browser either, relying on a direct-call integration test. The code path is reviewed in G11 below. |
| S6 recon heuristic usable on PCAP-only uploads | **Not verified** | Never fires on the bundled flow-only data; exercising it needs a port-scan PCAP, which the repo does not contain. |
| LOFO AUROC values (0.612 / 0.432 / 0.531 / 0.872) | **Not re-run** | Taken from `docs/lofo_results_v2.json` as produced by the builder; re-running means retraining 4 folds. Fold sizes were checked — see the notes below. |
| D1 UNSW-NB15 build (108,372 sequences, label mapping) | **Partially verified** | The processed split exists and loads with 41 features; the adapter's feature fidelity is the subject of G4. |

Honest reporting in `BUILD_REPORT.md` is, on the whole, good: the negative LOFO and UNSW results
are stated plainly rather than spun, the 1-epoch smoke result was withheld from quotation, and an
earlier `threshold_at_fpr` claim was retracted. The findings below are about significance missed
and numbers that don't survive recomputation, not about dishonesty.

### G1 (Critical, NEW): the project's flagship cross-dataset number is stale and does not hold for the shipped checkpoint

`docs/04-evaluation-ctu13_cross_from_real_data.md` has been the submission's headline evidence for
zero-shot generalisation: **"F1 0.534 at a calibrated operating point vs 0.045 for CTU-13-native
LR."** That number is quoted in `README.md`, in Part B/E9 of this audit, and in the project's
working notes.

Recomputed against the current checkpoint and the current CTU-13 data, following exactly the
procedure the report describes (CIC scaler, threshold tuned on the CTU-13 val split at a 5% FPR
budget):

| Quantity | Original report | Recomputed (2026-09-23) | Builder's REGEN |
|---|---|---|---|
| F1 @ 0.5 | 0.001 | **0.0065** | 0.006 |
| F1 @ 5% FPR budget | **0.534** | **0.0086** | 0.009 |
| Test AUROC | not reported | **0.5172** | — |
| Val AUROC | not reported | **0.4965** | — |

AUROC 0.517 on test and 0.497 on val is **chance**. A recall of 0.651 at 2.8% FPR, as the original
table claims, is arithmetically incompatible with a chance-level ranking — the original row cannot
be reproduced from any current artefact.

The cause is established by file dates, not inferred: the report is dated 2026-09-11, while the
current checkpoint was trained 2026-09-17 and the CTU-13 data was rebuilt 2026-09-19 (adding the 8
`graph_embed_*` columns). The report was therefore necessarily produced by a different, 33-feature
checkpoint against a 33-feature CTU-13 build — a self-consistent pair that no longer exists on
disk. Whether 0.534 was valid for that older pair cannot now be verified. Either way it does not
describe anything the project currently ships, and it is **not quotable**.

This is a correction to my own earlier work as well: E9 states "the world-model row is unaffected:
it uses the CIC scaler." That was wrong. The scaler was not the only thing that went stale, and I
did not recompute the row when I wrote it.

**Consequence.** The evidence for generalisation is now clearly negative, but the strands are not
equally clean. The **LOFO folds are the sound evidence** (AUROC 0.612 / 0.432 / 0.531, DDoS 0.872):
they stay within CIC-IDS-2018 and use no adapter. The UNSW-NB15 transfer (AUROC 0.443) and the
corrected CTU-13 result (AUROC 0.517) point the same way but are both confounded by the adapter
zero-fills described in G4, so they should be cited as consistent with the LOFO finding, not as
independent confirmations of it. **`README.md` currently quotes 0.534 as a headline result and must
be corrected before this is shown to anyone.**

### G2 (High, NEW): "628 real transitions across many hosts/days" is not what the data contains

Part A's E2 row, as edited by the builder, says the day-disjoint split "produces 628 real
transitions across many hosts/days". Recomputed on `data/processed_real_v2/test.npz`:

| Property | Value |
|---|---|
| Transitions as the metric counts them | 628 |
| Distinct hosts | **3** — all `NETWORK-` day aggregates, no real-IP hosts |
| Concentration | **604 of 628 (96%) on a single day**, 2018-02-23; 12 each on 02-16 and 03-01 |
| Distinct episodes (contiguous runs collapsed) | **181** |
| Stage at onset | 604 initial_access, 12 lateral_movement, 12 impact |

This is a genuine improvement over the original 32 (3 hosts not 2, 181 episodes not ~2, and PS
stages rather than pure DDoS), so E2 is **partially** addressed. But the row's wording repeats the
exact error E2 was raised about: counting re-onsets as independent events and describing 3
pseudo-hosts as "many hosts". The "93.5% missed" figure is measured over those same re-onsets and
is dominated by one day. Reword to "628 transition windows across 181 episodes on 3 day-level
pseudo-hosts, 96% from 2018-02-23".

### G3 (High, NEW): the v1 to v2 comparison changes three things at once

`configs/real_data_v2.yaml` differs from `configs/real_data.yaml` in more than the split:

| Setting | v1 | v2 |
|---|---|---|
| split | per-host chronological | day-disjoint |
| `batch_size` | 64 | **512** |
| `epochs` | 30 | **15** |

The learning rate is unchanged at 3e-4 while the batch grew 8x, epochs were halved, and the
builder's own note records that the best validation loss came at the **final** epoch with the loss
oscillating 0.9–1.25 throughout — that model is not converged. Train is also 98% one DDoS day.

So "F1 0.917 -> 0.431 confirms E1" cannot separate split leakage from undertraining and a changed
training mix. The direction is independently supported (G.0, AUROC 0.9995 -> 0.778), but the
*magnitude* is not attributable to leakage alone. To make this claim cleanly, retrain v2 at v1's
batch size and epoch count, or train v1's split under v2's hyperparameters, and compare like with
like. As E1 is my own finding, this is the place to be strictest.

### G4 (High, NEW): the UNSW-NB15 adapter feeds the model 9 systematically wrong features

`pipeline/adapters/unsw_nb15.py` zero-fills every TCP flag count (lines 73–75) because UNSW-NB15
reports Argus state rather than flag tallies, and zero-fills `iat_std`/`iat_max`. Measured across
the UNSW test split under the CIC scaler, against the CIC test split:

| Feature | UNSW mean | CIC mean | Status in UNSW |
|---|---|---|---|
| syn_ratio, ack_ratio, fin_ratio, rst_ratio, psh_ratio, urg_ratio | 0 | 0.037, 0.224, 0.006, 0.012, 0.039, 0.047 | **constant zero** |
| var_iat, max_iat | 0 | 3.2e13, 1.2e7 | **constant zero** |
| mean_iat (median) | 11.7 | 34,760 | **~3,000x low** |

The `mean_iat` gap is a unit bug: the adapter's own comment notes `Sintpkt`/`Dintpkt` are in
**milliseconds**, but no conversion to the **microseconds** the CIC features use is applied.

The six flag ratios are precisely the features the problem statement singles out ("TCP flag
bitmask (SYN, ACK, FIN, RST, PSH, URG)", "the pattern in which SYN flags precede ACK floods"). A
CIC-trained model that relied on them is handed constant zeros. **AUROC 0.443 is therefore not
clean evidence about generalisation** — it confounds domain shift with adapter defects. Fix the
millisecond-to-microsecond conversion, and either derive flag counts from UNSW's `state` field
where possible or exclude the flag features from the transfer comparison and say so. The same
zero-fill convention is inherited from the CTU-13 adapter, so G1's CTU-13 numbers carry a similar
caveat.

### G5 (High, NEW): the new PCAP-only path reports IAT in seconds where the model expects microseconds

`pipeline/packet_features.py::build_flow_records` (new in this branch, the S4 feature) computes
`iat_mean`/`iat_std`/`iat_max` via `.dt.total_seconds()` — seconds. The CSV path carries CIC's
`Flow IAT Mean/Std/Max` straight through in **microseconds** (`clean_and_normalize` converts only
`duration_us`). Demonstrated with a controlled 3-packet flow spaced exactly 1 second apart:

```
PCAP path                 : iat_mean = 1.0
CSV/CIC path would report : iat_mean = 1000000
```

Every PCAP-only upload therefore presents `mean_iat`, `var_iat` and `max_iat` about **10^6 times
too small** to a model trained on microseconds. The demo will run and produce confident-looking
output on 3 of 41 features that are wrong by six orders of magnitude. `duration_s` is handled
correctly; only the IAT family is affected. Multiply the three IAT fields by 1e6 in
`build_flow_records`, and add a test asserting the CSV and PCAP paths agree on identical traffic —
the existing `tests/test_packet_features.py` checks flow merging but never compares units against
the CSV path, and `data/raw/pcap/synthetic_sample.pcap` cannot catch this because every flow in it
is a single packet (0 multi-packet flows out of 944).

### G6 (Medium, NEW): fabricated benign traffic is 27% of the v2 validation split

The `2018-04-01` / `2018-04-02` "days" in the v2 split are not CIC-IDS-2018 captures. CIC-IDS-2018
has no April data. They are `scripts/augment_benign_high_volume.py`'s synthetic hosts
(`base_time = 2018-04-01`, hosts `10.90.0.x`), generated to teach the v1 model that high volume is
not automatically an attack.

| Split | Sequences | Synthetic share |
|---|---|---|
| train | 1,239,090 | **0%** |
| val | 9,110 | **26.6%** (2,425) |
| test | 8,731 | **17.6%** (1,540) |

`docs/04-evaluation-real-v2.md` presents itself as a real-CIC-IDS-2018 evaluation while a sixth of
its test set, and a quarter of the split its operating threshold is tuned on, are fabricated
traffic. That must be disclosed in the report, and ideally the synthetic days should be spread
across all three splits or dropped from v2 entirely and the numbers re-measured.

**What this is not.** The day-disjoint split put all of the augmentation in val/test and none in
train, so the obvious worry is that v2 never learned high-volume benign traffic and the v1
robustness fix was undone. Tested, and it is not so: `scripts.check_robustness --config
configs/real_data_v2.yaml` **passes** on v2, with the large legitimate transfer scoring 0.0000 at
every step (v1 scores 0.0369). The distributional gap is real — v2 assigns synthetic benign
windows a mean probability of 0.245 against 0.029 for real benign — but it does not translate into
more false alarms: at the reported operating threshold v2 flags **27.5%** of synthetic benign
windows versus **38.2%** of *real* benign ones, so the fabricated rows are the easier negatives,
not the harder ones. The finding here is the disclosure gap, not a regression.

### G7 (Medium, NEW): the stage override is not gated on infiltration probability

`models/forecast.py::_heuristic_stage_override` promotes any window with volume z > 4 and low
destination diversity to `impact`, regardless of what the model thinks the window is. Reproduced
by the project's own robustness script, whose OOD case is explicitly a *legitimate* large transfer:

```
OOD-benign capture (large legitimate transfer, 10.0.0.201 -> 203.0.113.200):
  peak: 0.0369 at step 0 (predicted stage: impact)
  PASS - peak stays below 0.3 despite unusual volume
```

The same window is simultaneously "benign, 3.7% probability" and "stage: impact" (a DDoS in
progress). A demo user backing up a database sees an Impact badge. Gate the override on the
infiltration probability crossing an alert threshold, so stage annotations cannot contradict the
score they sit beside. Note the override did *not* misfire on the v2 model's own synthetic benign
windows (0 of 60), because v2's scaler std is inflated by its DDoS-heavy training day — the
behaviour is scaler-dependent, which is itself a reason not to leave it ungated.

Related: the training-time recon label requires a high port-scan score *preceding a real attack*,
while the inference override drops that qualifier. On flow-only data neither fires, so nothing is
currently wrong in production — but the two definitions should be stated as different.

### G8 (Medium, NEW): the v2 operating threshold does not transfer across days

The threshold tuned for a 5% false-positive budget on the v2 val split (0.0101) yields a
false-positive rate of **35.9%** on the v2 test split ((424 + 2,180) / 7,249 benign windows).
Fitting the threshold on real (non-synthetic) val rows only gives 0.016, and with it a test FPR of
**33.8%** overall, or **35.6%** on real test rows alone — the instability is not an artefact of the
synthetic rows. Every operating-point number in
`docs/04-evaluation-real-v2.md` — including alarm precision 1.5% — rests on a threshold that is
off by roughly 7x once the day changes. Report the achieved FPR next to every budgeted row (E5's
fix does this for the budget tables; the lead-time section still needs it), and treat cross-day
threshold instability as a finding in its own right: it is a deployment-relevant result, not a
reporting nit.

### G9 (Low, NEW): `BUILD_REPORT.md`'s own summary table contradicts the rest of the file

The findings table near the top still reports E1/E8/S8 as "IN PROGRESS", the v2 model as "NOT yet
retrained", and "E2–E7, E9–E11, S4–S7, S9–S12, D1, D2" as "NOT STARTED" — while later sections of
the same file document E3–E6, S4–S7, S8, E9 and D1 as done with measured results. A reader who
trusts the summary table gets the wrong picture in both directions. Regenerate the table from the
sections below it.

### G10 (Low, carried forward): unbatched inference in `eval/benchmark.py`

The builder found and fixed an OOM caused by an unbatched forward pass in `eval/lofo.py`, and
correctly reported that `eval/benchmark.py::_world_model_predictions` has the same pattern
unfixed. Confirmed present. Harmless on today's test splits (<200k sequences), and it would fail
the same way on a larger one. Left open, correctly scoped and disclosed.

### G11 (High, NEW): a PCAP upload feeds the real model 9 features it was never trained on

`app/streamlit_app.py::_process_uploads` computes packet-level features whenever a PCAP is
supplied and merges them unconditionally:

```python
packet_windows = None
if packet_df is not None:
    packet_windows = compute_packet_window_features(packet_df, ...)
windows = merge_packet_features(flow_windows, packet_windows, config)
```

There is no check on which model is selected. Before S5 this was harmless, because uploads only
ever reached the synthetic-data model, which is trained *with* packet features. S5 deliberately
removed that restriction, so a PCAP can now be scored by the real CIC-IDS-2018 checkpoint — which
was trained flow-only (`data/processed_real/metadata.json`: `"flow_only": true`,
`"packet_features_available": false`, and `mean_ttl`/`var_ttl`/`mean_window_size`/`frag_ratio`/
`mean_payload_size`/`std_payload_size`/`port_scan_score`/`retransmit_ratio` all constant zero in
its training data).

A PCAP upload therefore hands that model non-zero values in all 8 packet features plus
`has_packet_features = 1`, a combination it has never seen — 9 of 41 features out of distribution,
compounding G5's 10^6 unit error on the 3 IAT features. This is on the demo path a judge is most
likely to exercise. Either zero-fill packet features when the selected checkpoint was trained
flow-only (detectable from its own metadata), or state in the UI that the real model ignores them.

### G12 (Medium, NEW): checkpoints and baselines are loaded with arbitrary-code deserialization

`models/forecast.py:123`, `models/lstm_model.py:57` and `models/train_joint.py:199` all call
`torch.load(..., weights_only=False)`; `models/baseline_lr.py:88` calls `pickle.load` on a saved
baseline. Both execute arbitrary code from the file being loaded. `models/dataset.py:57` uses
`np.load(..., allow_pickle=True)` on the processed splits for the same reason.

Practical risk today is low: every checkpoint and split is produced locally by this project and
never downloaded. But the project's own engineering rules require "no unpickling untrusted files",
this is a security product whose code will be read as one, and the fix is cheap — pass
`weights_only=True` and store the config beside the tensors as JSON rather than pickling it into
the checkpoint. Flagged because a reviewer grepping for unsafe deserialization will find it in
under a minute, not because an exploit path exists in the current workflow.

### Notes on items that are fine

- **E8 (embargo).** "0 sequences dropped" is correct but vacuous: with one pseudo-host per calendar
  day, a sequence cannot span two days, so the only hosts that could trip the embargo are the
  real-IP ones (02-20 and the synthetic days). The protection comes from day-disjointness, not
  from the embargo. Worth stating plainly rather than presenting the embargo as load-bearing.
- **LOFO fold sizes are wildly uneven.** Measured from each fold's `train.npz`: `impact` trains on
  **16,416** sequences, while `initial_access`, `lateral_movement` and `command_and_control` train
  on **1,239,747 / 1,242,869 / 1,246,522** — a 75x difference, because holding out `impact` removes
  02-20, which is 98% of the corpus. The four AUROC values are therefore not like-for-like, and the
  ranking between families should not be read as one. Note also that the headline AUROC understates
  the `initial_access` fold in one respect: at the 0.5 threshold it reaches precision 0.981 at
  recall 0.374 (`docs/lofo_results_v2.json`), i.e. what it does flag on an unseen family is mostly
  correct, even though its overall ranking is weak.

### G.12 Recommended order

1. **Correct the CTU-13 number everywhere it appears** (G1) — `README.md` first, then this audit's
   E9 text and the project notes. This is the only finding that currently misinforms a reader.
2. **Fix the demo's input correctness before the demo is shown** — G5 (PCAP IAT units) and G11
   (packet features fed to a flow-only model) both corrupt the new PCAP path, and G4's millisecond
   bug must be fixed before anyone cites the UNSW AUROC of 0.443.
3. **Reword the E2 status row** (G2) and disclose the synthetic share of the v2 splits (G6).
4. **Retrain v2 at v1's hyperparameters** (G3) so the leakage claim is clean, and redistribute or
   drop the synthetic days (G6) in the same rebuild.
5. **Gate the stage override on infiltration probability** (G7).
6. Report achieved FPR in the lead-time section (G8); regenerate `BUILD_REPORT.md`'s table (G9).
