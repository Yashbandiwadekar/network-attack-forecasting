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

| # | Finding | Severity | Area | Status |
|---|---|---|---|---|
| E1 | Train/val/test are split per host in time order, so test attacks are the *same attack sessions* seen in training. The data cannot support any "unseen attacks" claim. | **Critical** | Evaluation | Open |
| E2 | Lead-time metric: the 32 "transitions" are 2 pseudo-hosts, 30 of them re-onsets of one DDoS day. 0 of 32 are PS-stage attacks. | **Critical** | Evaluation | Open |
| E3 | Lead-time metric ignores false alarms. At the same threshold the rollout raises 2,922 false early warnings against 32 true transitions (≈1% alarm precision). | **Critical** | Evaluation | Open |
| E4 | Stage macro-F1 is labelled "5-way" but test contains 4 classes, including benign. The 3 attack classes each come from a single day-level pseudo-host. | **High** | Evaluation | Open |
| E5 | The "5% FPR budget" operating point is not 5% (1.4% achieved), and it hides the model's real low-FPR performance (F1 0.918 at 0.1% FPR vs reported 0.535). | **High** | Evaluation | Open |
| E6 | Persistence and Markov baselines read the ground-truth label of the current window. They are oracles, not deployable baselines, and the report doesn't say so. | **High** | Evaluation | Open |
| E7 | All per-host (real-IP) attack data is DDoS. Every non-DDoS attack exists only as a whole-day network aggregate (9 pseudo-hosts in total). | **High** | Data | Open |
| E8 | No gap between splits. Sliding windows (L=12, K=6) overlap at every train/val/test boundary. | Medium | Evaluation | Open |
| E9 | The CTU-13 cross-dataset report was produced by code that fitted the native baselines' scaler on the test split. | Medium | Evaluation | Code fixed in `de75a3b`; **report not regenerated** |
| E10 | No confidence intervals, seeds, or repeated runs. The GNN ablation draws conclusions from 0.003–0.03 F1 differences. | Medium | Evaluation | Open |
| E11 | README points to `docs/04-evaluation.md`, which holds **synthetic** results (72 test sequences), not real-data results. | Medium | Docs | Open |
| S1 | Uploading an unlabeled flow CSV crashed the demo | High | App | **Fixed** `de75a3b` |
| S2 | Alert cache keyed on host count only (stale alerts across uploads) | Medium | App | **Fixed** `de75a3b` |
| S3 | Test-split scaler leak in the cross-dataset benchmark | Medium | Eval code | **Fixed** `de75a3b` |
| S4 | No PCAP-only input; `.pcapng` rejected; no PCAP→flow conversion | High | PS compliance | Open |
| S5 | Uploads only run through the synthetic-data model | High | PS compliance | Open |
| S6 | Recon and Exfiltration never appear in real data; the model never predicts them | High | PS compliance | Open |
| S7 | DoS/DDoS ("impact") is predicted as Command & Control 570 of 684 times | High | Model/UI | Open |
| S8 | No leave-one-attack-family-out test for "generalise to unseen attacks" | High | PS compliance | Open (see E1) |
| S9 | App loads the full train split (~1.7 GB) to sample 20 SHAP background rows | Low | App | Open |
| S10 | Jointly-trained GNN model is built but unused by the app, and shows no benefit | Low | Scope | Open |
| S11 | README checklist is stale; repo root is cluttered with untracked logs and scripts | Low | Docs | Open |
| S12 | Demo video and 5-slide deck are not in the repo | Low | Deliverables | Open |
| S13 | Both robustness scripts (`check_robustness.py`, `check_adversarial_robustness.py`) raise `KeyError` on the 41-feature schema — they never build the `graph_embed_*` columns. Neither has run since the GNN work landed. | **High** | Scripts | Open |
| D1 | The PS's "Dataset Link" section permits 6 datasets; the project uses 2, and uses no authentication-log telemetry (LANL) at all. Unused datasets are the cheapest route out of E1. | Medium | Data scope | Open |
| D2 | The PS names CAPEC alongside ATT&CK and CVE/NVD. The project maps to ATT&CK stages and enriches with CVE/NVD, but has no CAPEC linkage. | Low | PS compliance | Open |

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
