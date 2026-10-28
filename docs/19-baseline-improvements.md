# 19 - Improving the classical baselines under the LODO protocol (docs/16 actions 4 and 5, docs/18 gate)

**Branch** `test/session-2026-10-10`, nothing committed. **Section 0 below was written before any candidate (any feature variant other than the
docs/18 anchor, any tuned or non-HGB model, any secondary label, any calibrator) was fitted or scored, and is reproduced unchanged in the final
document.** Code and data produced by this step: `models/features_v5.py` (causal features), `models/baseline_export_v5.py` (pickle-free HGB / ExtraTrees / RandomForest / LR export; `models/tree_export.py` from the previous step is reused unchanged),
`eval/baselines_v5.py`, `eval/baselines_v5_run.py`, `eval/baselines_v5_stages.py`, `eval/baselines_v5_report.py`, `eval/baselines_v5_secondary.py`, `eval/baselines_v5_robust.py`, `eval/baselines_v5_final.py`, `eval/baselines_v5_render.py`, `eval/secondary_labels.py`,
tests `tests/test_features_v5.py`, `tests/test_baseline_export_v5.py`, `tests/test_baselines_v5.py`, `data/processed_adapter/baselines_v5/` (per-day feature caches), `checkpoints_baselines_v5/` (OOF scores, exported models), `docs/lodo_v5/`
(raw result JSON, `feature_names.json` = the exact columns of every variant, `tables.md`). Nothing existing was modified: not the server, dashboard, served model, production, `checkpoints*`, `data/processed*`,
configs; `docs/17`, `docs/18` and `eval/lodo_v4*.py` are read and imported only; the uncommitted work of the previous step is intact.

## 0. Pre-registration (fixed before any candidate result existed)

### 0.1 Protocol: inherited unchanged from docs/18 section 0

* Data: the 7 non-test CIC-2018 days (02-14, 02-15, 02-20, 02-21, 02-22, 02-28, 03-02), the same cached sequences
  (`data/processed_adapter/lodo_v4`, read only), the same 70,000-row seed-0 sample of 02-20 in the training pool, the same 9 outer folds (6 whole-day
  folds + 3 host-group folds of 02-20), the same unit-of-evidence rule (days; 02-20 pooled over its groups counts as one day), the same
  leakage assertions (`eval.lodo_v4.assert_no_leakage`, `assert_sealed`).
* **The CIC-2018 test days 02-16, 02-23, 03-01 are spent** (docs/18 section 3). No code of this step reads `test.npz`, the raw CSVs of those days,
  or `docs/lodo_v4/test_sealed.json` as data; the raw-CSV reader of `eval/secondary_labels.py` refuses them; `test_sealed.json` is neither modified
  nor bypassed. Nothing is scored on them.
* Selection metric: mean over the 7 days of the out-of-fold within-day AUROC. Gate: `eval.diagnostics.core.baseline_gate` (paired per-day gain
  against the paired MDE with SD = max(0.0245, observed SD), 80% power, two-sided 5%, day-bootstrap CI printed and not part of the verdict), on the
  7 days (headline) and on the 6 pseudo-host days (02-20 removed; removing the identity features is expected to cost 02-20 its 1.000, which is
  not a loss of transfer, so the 6-day line is reported beside every 7-day line).
* Reference arms (read from the docs/18 OOF files and `docs/lodo_v4/selection.json`, not refitted for the gate): `HGB_stacked` (current, 0.818),
  `HGB_last`, `LR_last`, `flow_count` (0.812), Transformer single (0.744, nested epoch) and 5-seed ensemble (0.715 nested). **Anchor:** this step
  re-fits `HGB_stacked` from its own feature cache and must reproduce the docs/18 OOF scores (per-day AUROC to 3 decimals) before any
  variant is interpreted; if it does not, the step stops.
* Rows with a causal context warm-up (section 0.2) keep NaN features; no row is dropped from any score.

### 0.2 Feature variants (item 1, 2, 3), cumulative recipes, all stacked over the 12 windows

Every variant is a function of the row's 12 windows plus (S6, S7 only) the earlier windows of the same unit. Definitions are in
`models/features_v5.py` (`VARIANTS`); the number of columns and the names are printed in the results.

| id | recipe |
|---|---|
| S0_stacked41 | all 41 raw features x {last, mean, std, d1, d6, max} (= the current HGB_stacked; anchor) |
| S1_no_zero9 | S0 without the 9 always-zero packet features (`mean_ttl` ... `has_packet_features`) |
| S2_no_ident | S1 without `has_ip_data`, `unique_dst_ips`, 5 graph, 8 graph_embed features (17 behavioural features) |
| S3_log | S2 with log1p on `flow_count`, `unique_dst_ports`, `total_bytes`, `total_packets`, `mean_duration`, `mean_iat`, `var_iat`, `max_iat` before stacking (trees are invariant to a monotone map of one feature; it changes the deltas/std/mean and the LR) |
| S4_ratio | S3 + per-window ratios: log bytes/packet, log packets/flow, log bytes/flow, ports/flow, syn_ratio-ack_ratio, rst_ratio+fin_ratio (`flows/s` is `flow_count`/10 s and adds nothing, so it is not a separate column; `syn_ratio` already exists as a feature) |
| S5_temporal | S4 + causal in-sequence features on the 5 log volume features (flow_count, ports, bytes, packets, duration): z of the last window vs the earlier 11 (SD floored at 0.1 log units), jump (last minus median of the earlier 11 = log volume ratio), OLS slope over 12, burst (max of last 3 minus mean of earlier 9); plus spike count (# windows > 3x the 12-window median flow_count), seconds since the last "quiet" window (a window with flow_count <= the 12-window median; the label-free reading of "time since last alert-free"), the gap between the last two windows and the 12-window span in seconds (02-20 windows are irregular: only 49% of host gaps are 10 s) |
| S6_context | S5 + z and difference of the last window of the 5 volume features against the **unit's rolling baseline of the previous 120 sequences** (mean and SD of their last windows; strictly earlier time; NaN until 12 earlier windows exist). The unit is the host on 02-20 and the whole-network pseudo-host on the other days. This is the "per-host / per-day normalisation from data available at prediction time" |
| S7_relative | S6 without the absolute LEVEL blocks (last, mean, max) of flow_count, ports, bytes, packets, bytes/flow, packets/flow: a model that sees volume only through ratios, deltas, SD, slopes and z-scores (the shift-robust arm) |

**Causality rules (tested, `tests/test_features_v5.py`).** (a) No label of any kind is an input: not `current_infiltration`, not past
`infiltration`, not stage (that would be the persistence oracle, 0.947). (b) The rolling baseline of a row uses only rows of the same unit with
strictly smaller last-window time, computed on the FULL unit series (all of 02-20's hosts) before the 70,000-row training sample is drawn.
(c) Time-based quantities use the window timestamps, not row offsets. (d) Warm-up = NaN (HistGradientBoosting handles it natively; ET/RF/LR impute
the training median). (e) The tests perturb or delete every row after a cut time and assert bit-identical features before it, assert row-order
invariance, and check the rolling statistics against a brute-force reference including equal-time ties.

### 0.3 Models and the pre-registered grids (item 4)

* HGB = sklearn `HistGradientBoostingClassifier(max_iter=200, early_stopping=False, random_state=0)` + grid parameters. **Default C0** =
  `learning_rate 0.1, max_leaf_nodes 31, min_samples_leaf 20, l2 0, class_weight None` (the docs/18 setting). **Tuning grid:** C0 first, then
  12 configurations drawn without replacement (`numpy.default_rng(0)`) from the 32-point factorial {learning_rate 0.05, 0.15} x {max_leaf_nodes 8, 31}
  x {min_samples_leaf 20, 300} x {l2 0, 10} x {class_weight None, balanced}: 13 configurations in `eval.baselines_v5.hgb_grid()`.
  `early_stopping` stays off (its random validation split would leak neighbouring windows of the same day).
* ExtraTrees and RandomForest: 150 trees, `max_features sqrt`, `random_state 0`, grid {min_samples_leaf 5, 50} x {class_weight None,
  balanced_subsample} = 4 configurations each. LR: standardised (train mean/SD), clipped at +/-6, NaN -> train median, `max_iter 500`, grid
  {C 0.01, 0.1, 1} x {class_weight None, balanced} = 6 configurations.
* lightgbm / xgboost are not installed and nothing is installed; whether they would matter is discussed in the conclusions, not tested.

**Stages (the order is fixed):**

* **A. Feature variants** S0..S7 with the default C0, 9 outer folds. 8 arms.
* **B. HGB tuning** (13-configuration grid, nested inner LODO, section 0.4) on the **two best non-anchor variants of stage A by 7-day OOF mean
  AUROC** (rule fixed now; ties to the lower variant number). 2 arms.
* **C. Other model families** on the **best non-anchor variant of stage A** (same rule): ExtraTrees, RandomForest, LR, each tuned by nested
  inner LODO. 3 arms.
* **D. Calibration and operating point** of the best stage-B arm: Platt (logistic regression on the logit of the score) and isotonic regression,
  each fitted ONLY on the inner out-of-fold scores of the outer-training days (day-balanced weights), applied to the outer held-out scores.
  Calibration is monotone, so within-day AUROC cannot improve (isotonic can only add ties): its benefit is judged by threshold transfer, Brier
  score and per-day expected calibration error (10 bins) and **no AUROC gain is claimed from it**.
* **13 registered arms in total** (8 + 2 + 3), plus the references. The number of arms tried is reported next to every "best" number.

### 0.4 Nested tuning and the arm-selection claim

* **Inner loop (HGB, ET, RF, LR tuning).** Inside every outer fold the outer-train rows form the inner folds: each remaining pseudo-host day held out
  whole, and the 02-20 training sample (minus any held-out host group) held out whole as one inner fold; the inner model trains on the remaining
  outer-train rows. A configuration's inner score = mean over inner folds of within-fold AUROC. The configuration with the highest inner score is
  refitted on all outer-train rows and scored on the outer held-out day/group. Ties go to the earlier grid entry. The outer held-out day never
  enters any inner fit or any inner score.
* **Nested arm selection (the claim).** Picking the best of 13 arms on the 7 OOF days and reporting its OOF mean is optimistic (docs/18 hit the
  same problem with the epoch). The reported claim is therefore the **nested arm selection**: every day d is read from the arm with the highest
  mean AUROC over the OTHER six days (ties: lower arm index). The un-nested best arm is printed beside it and labelled optimistic. The other
  days' arm scores were produced by models that saw d in training; this is the same limited nesting as docs/18's nested epoch and is stated as
  such.
* **Success definition.** An improvement is **demonstrated** only if the nested-selection per-day AUROCs beat `HGB_stacked` (current) with gate
  PASS on the 7 days (paired mean gain > paired MDE). Beating `flow_count` is a second, separate line. A gain inside the MDE is called **not
  demonstrated**, whatever its sign and bootstrap CI, and is not described as an improvement.

### 0.5 Threshold transfer (item 3), leave-one-day-out

docs/18 chose one threshold from the OOF scores of all 7 days, so every day helped set its own threshold. Here, for outer fold d the threshold
comes from **inner out-of-fold scores of the other days** only (models that were trained without that day and without the scored day), by
`day_balanced_threshold` at 1% (and 5%) day-balanced FPR, and is applied to the outer held-out scores of d. For the 3 host-group folds of 02-20 each
group has its own threshold and the day-level FPR/recall pool the three groups. Reported per day: realised FPR, recall, alarm rate; per arm: the
min-max and the mean absolute log-ratio of realised FPR to the 1% target over days with at least 100 negatives, and the number of days whose
FPR lies within a factor of 3 of the target (0.33%-3%). Arms: `HGB_stacked` default (S0), the best arm, its Platt and isotonic versions,
`flow_count` (threshold from the raw scores of the other days), and a **label-free adaptive rule** on the 6 pseudo-host days only: alarm when the
score is >= the 99th percentile of the scores of the previous 360 sequences of the same day (needs 60 earlier scores; none before that); 02-20 is
excluded from the adaptive rule (it is per-host, not one series). The OOF thresholds of docs/18 are not reused.

### 0.6 Secondary label definitions (item 5), alongside the primary label, never replacing it

The primary label stays "any attack flow in the next 10 s window" and is the only one used for the headline, the selection and the gate.
Per-window attack-flow and all-flow counts of the TARGET window are rebuilt from the raw CSVs of the six pseudo-host LODO days (02-20 keeps
the primary label only: per-host windows of a volumetric DDoS, 7.9M rows) and **verified against the primary label before use**: the rebuilt
`n_attack > 0` must match `infiltration[:, 0]` on >= 99% of sequences per day or the step stops (`eval/secondary_labels.py`).

* **S_fix:** window positive iff attack flows >= 5 and attack share >= 5% (docs/16 action 5a).
* **S_train(k, s):** for each outer fold, `k` = ceil of the 10th percentile and `s` = 10th percentile of the attack-flow count and of the attack
  share over the primary-positive windows of the outer-TRAIN pseudo-host days (each day's positives weighted equally), floored at k >= 2 and s >= 1%.
  `k` and `s` come from training-day counts only and are printed per fold.
* **S_run6:** a window is positive iff it lies in a run of >= 6 consecutive primary-positive windows of its day (docs/16 action 5c).
* Windows that are primary-positive but fail the rule are **dropped from scoring** ("ambiguous"), not relabelled negative; counts are printed.
  Primary-negative windows stay negative.
* **Training stays on the primary label.** Scores of the primary-trained models are evaluated against each secondary label. One additional arm
  trains the best candidate on S_train (ambiguous rows dropped from training) and is evaluated on S_train; it is reported as a separate row and is
  not part of the 13 registered arms or the selection. Reported per pseudo-host day for flow_count, HGB_stacked (current), the best candidate:
  AUROC, positives remaining, and (02-22) how the sparse windows behave. The 02-23 day is not available (spent).

### 0.7 Robustness checks of the best candidate (item 6)

All on the LODO OOF folds, no test day. (1) **Mean-ablation of `flow_count`**: the raw `flow_count` column is set to the training mean in all 12
windows of the held-out rows BEFORE feature construction, so every derived column (log, ratios, rolling statistics, z-scores, deltas, context)
is rebuilt from the ablated input; the model is not refitted. Also a **joint volume ablation** (flow_count, unique_dst_ports, total_bytes,
total_packets). Reported per day for the best candidate and for `HGB_stacked` (current) with the same ablation; "02-16-style dependence" (docs/16:
0.989 -> 0.078) cannot be measured on 02-16 (spent), so it is read on the volumetric LODO days 02-14, 02-15, 02-21 (and 02-20). Success test
inherited from docs/16 action 4: ablation moves every volumetric day's AUROC by < 0.05. (2) **Range and clip rates** per held-out day: the share
of held-out feature values outside the training min-max (the tree analogue; trees do not clip) and, for the LR path, the share beyond +/-6
training SD (the Transformer scaler's clip, for comparison on the old 41 raw features). (3) **Per-day spread** (SD over days, min, max), (4) the
gate of the best candidate and of the nested selection against `flow_count`, `HGB_stacked`, `HGB_last`, `LR_last`, Transformer single (nested epoch)
and ensemble-5 (nested epoch), on 7 and 6 days.

### 0.8 Cross-dataset (secondary, never used for selection)

The exported-recipe model (trained on all 7 days, hyper-parameters from a full 7-day inner LODO, section 0.9) is applied zero-shot to CTU-13,
UNSW-NB15 (unit-balanced and host-mean AUROC; the docs/16 weighting definitions) and CIC-2017 60 s (host-mean), with `flow_count` and the
current `HGB_stacked` (fitted on the same 7 days) beside it. These sets have 10 / 4 / 10 positive hosts; no claim follows from them (docs/16 F4).
The read-only loaders and splits of docs/16 are used; no PCAP folder and nothing on `V:\Datasets\CTU-13-pcaps` or any CIC-2017 pcap folder is touched.

### 0.9 Export

The best arm, retrained on all 7 days (same 87,058 rows) with the configuration chosen by a full inner LODO over the 7 days (6 pseudo-host days +
the 02-20 sample as one fold), is exported without pickle to `checkpoints_baselines_v5/`: HGB via `models/tree_export.py` (flat arrays, round
trip tested); if the best arm is ExtraTrees / RandomForest / LR a generic exporter with the same property is added with its own round-trip
test. The feature recipe is recorded in `meta_json` (variant id, column names, constants). No `.pt` file is written there. The full test suite is run
with counts.

### 0.10 Not done / out of scope by design

Transformer retraining; any change to the served model, `app/`, the dashboard, `common/bundle.py`; new packages; the CIC-2018 test days;
re-extraction from PCAPs (causal windows, docs/16 action 12); a re-draw of folds.

### 0.11 Clarifications written after stage A had run and before stage B / C / D produced any number

Stage A (the 8 variants with the default HGB) had been computed when this paragraph was written: S0 anchor reproduced docs/18 exactly (max score
difference 3e-8, per-day AUROC identical, mean 0.8185) and no non-anchor variant was above it. Nothing in sections 0.1-0.10 was changed by that
result; the following only closes ambiguities that the result exposed.

* **"Best candidate"** (robustness 0.7, secondary-label training arm 0.6, export 0.9, cross-dataset 0.8) = the best **non-anchor** registered arm
  by un-nested 7-day OOF mean AUROC (ties: lower arm index), because the anchor is the incumbent being compared against. The incumbent
  (`HGB_stacked`, S0) gets the same robustness checks as the comparison row. If no non-anchor arm is demonstrably better, that is the headline,
  and the exported candidate is exported as a candidate, not as a replacement.
* **Best stage-B arm** for calibration (0.3 D) = the better of the two tuned HGB arms by 7-day OOF mean.
* The tuned stage-B arms are selected from stage A's two best non-anchor variants by the fixed rule: S1_no_zero9 and S3_log (their stage-A means
  0.8115 and 0.8101). Stage C runs on S1_no_zero9 (the best non-anchor of stage A).
* Exploratory additions (anything not in sections 0.1-0.10, e.g. score averaging) are listed separately and are excluded from the registered
  arm count, the nested selection and every verdict.

## 1. What was run, and the deviations (all disclosed)

* **Run order and cost.** anchor -> stage A (8 variants x 9 outer folds) -> stage B (2 tuned arms: 13 configurations x 6-7 inner folds x 9 outer folds
  = 1,638 inner fits + 18 refits) -> stage C (ET, RF, LR with 4 / 4 / 6 configurations, nested) -> tables -> thresholds / calibration -> secondary labels
  -> robustness -> full-7-day tuning, export, cross-dataset. Fits take seconds to tens of seconds on the 32-core CPU; the whole step is about 2 hours of CPU compute, no GPU. Fold construction and the leakage assertions are the docs/18 functions and ran before every fit.
* **Anchor passed exactly.** The cached S0 features are byte-identical to `eval.baseline_gate.stack_features` and the refitted `HGB_stacked` reproduces
  the docs/18 OOF scores to 3e-8 (float32 rounding), per-day AUROC identical, mean 0.8185 (`docs/lodo_v5/anchor.json`).
* **Deviation 1 (stage A was seen before 0.11 was written).** The ambiguity of "best candidate" was resolved after the stage-A table was visible (S0 on top, no variant above it). The resolution (best NON-anchor arm) was written before stages B, C, D were computed
  and cannot favour a particular arm; stage C then decided the candidate (RF on S1), which stage A alone would not have suggested.
* **Deviation 2 (a duplicate launch).** Stage B was started twice by a tooling slip (the first launch was not terminated when its shell call returned); the first process tree was killed within minutes. Both write identical deterministic files (random_state 0, no subsampling), so no
  result differs; the cost was wasted CPU.
* **Deviation 3 (small model budgets).** ET/RF use 150 trees with `max_features=sqrt` (registered), a deliberately small forest; more trees would reduce variance and cannot be ruled out as a small gain. One random state (0) for every model: no seed spread was measured, so a
  difference the size of a forest's seed noise (not measured here) is below what this design can see.
* **Deviation 4 (thresholds from inner scores).** The inner models are trained on fewer rows than the outer model, so their score distribution is slightly less confident than the outer one; the leave-one-day-out threshold inherits that mismatch. It is leakage-free, not exactly matched.
* **Deviation 5 (02-22 secondary).** Every secondary definition leaves 02-22 with zero positive windows (section 3, item 8), so the question "how do the sparse windows behave" is answered by "they do not qualify", not by an AUROC. 02-23 is spent.
* **Deviation 6 (nested arm selection reuses OOF scores).** As in docs/18's nested epoch, the other days' arm scores came from models that saw the held-out day in training; the inner tuning, the inner-OOF thresholds and the inner-OOF calibrators do not have this issue.
* **Deviation 7 (evaluation-only arms added to the threshold-transfer table after the first threshold run).** The first threshold run listed the incumbent, the best non-anchor arm and tuned S3; it omitted the normalised/temporal variants that item 3 is about. S5_temporal, S6_context and S7_relative (their stage-A inner OOF scores already existed) were then added to the table
  and the stage re-run. They are evaluation-only: not new arms, not part of the 13, not used in any selection or gate. Likewise a **post-hoc** row (S3_log with the default HGB fitted on the 7 days) was added to the cross-dataset table to back the S3 remark of section 4; it is secondary and not for selection.
* **Not done.** The Transformer was not retrained or changed; lightgbm/xgboost are not installed (section 4); the label arms were not used for training except the single S_train arm of 0.6; per-host/per-day normalisation was done only through the causal context block of S6/S7 (no scaler refit per day); no seed-spread run; `monotonic_cst` was not tried.
* **Tests.** New: `tests/test_features_v5.py` (16: rolling statistics against a brute-force reference including ties, **future-perturbation / deletion / one-by-one canary tests proving no row at or before t changes when later rows are replaced or removed**, row-order invariance for every variant, no label argument anywhere, column counts, ablation rebuilds every derived column),
  `tests/test_baseline_export_v5.py` (4: HGB / ET / RF / LR numpy predictor equals sklearn, no pickle, recipe in `meta_json`), `tests/test_baselines_v5.py` (7: grids, nested selection never reads the held-out day, adaptive alarm causality, secondary rules, raw-CSV alignment guard, sealed days refused).
  **Python suite: 792 passed, 0 failed** (4 warnings, 116.7 s; the run before `tests/test_baselines_v5.py` was added gave 785 passed, so 785 + 7 = 792). Frontend suite (run in `frontend/`, unchanged by this step): 8 files, 31 tests passed. No `.pt` file was written under `checkpoints_baselines_v5/`, so `test_checkpoint_io`'s scan of `checkpoints*/` is unaffected.

## 2. Results

(The feature columns of every variant are listed in `docs/lodo_v5/feature_names.json`.) Everything below is the output of `eval/baselines_v5_render.py` (from `docs/lodo_v5/*.json`), reproduced verbatim; interpretation is in section 3. Arm names: `A_<variant>` = stage A (default HGB), `B_<variant>_HGBtuned` = stage B, `C_<variant>_<family>` = stage C. "nested arm selection" = section 0.4. References are the docs/18 numbers
(read from `docs/lodo_v4/selection.json`; Transformer rows at their nested epoch).

## Generated tables (eval/baselines_v5_render.py from docs/lodo_v5/*.json)

### Feature variants

| variant | columns | base features / blocks | recipe |
|---|---|---|---|
| S0_stacked41 | 246 | 41 raw/window features x 6 stack blocks  | current HGB_stacked: all 41 raw features x 6 stack blocks (anchor, reproduces docs/18) |
| S1_no_zero9 | 192 | 32 raw/window features x 6 stack blocks  | S0 without the 9 always-zero packet features |
| S2_no_ident | 102 | 17 raw/window features x 6 stack blocks  | S1 without has_ip_data, unique_dst_ips, 5 graph features, 8 graph_embed features (17 behavioural features) |
| S3_log | 102 | 17 raw/window features x 6 stack blocks  | S2 with log1p on count/volume/duration/IAT features before stacking |
| S4_ratio | 138 | 17 raw/window features x 6 stack blocks +6 ratios | S3 + per-window ratio/rate features (bytes/packet, packets/flow, bytes/flow, ports/flow, syn-ack, rst+fin) |
| S5_temporal | 162 | 17 raw/window features x 6 stack blocks +6 ratios +temporal block | S4 + causal in-sequence features (z / jump / slope / burst vs the earlier 11 windows, spike count, seconds since quiet, gaps) |
| S6_context | 172 | 17 raw/window features x 6 stack blocks +6 ratios +temporal block +context block | S5 + z / difference of the last window against the unit's rolling baseline of the previous 120 sequences (causal) |
| S7_relative | 154 | 17 raw/window features x 6 stack blocks +6 ratios +temporal block +context block (level blocks of volume dropped) | S6 without the absolute LEVEL blocks (last/mean/max) of the volume features: only relative / shape information about volume |

### Anchor

S0 + default HGB reproduces docs/18 `HGB_stacked`: ok=True, max abs score difference 3.0e-08, mean AUROC 0.8185 vs 0.8185.

### Per-day OOF within-day AUROC of every registered arm


| arm | 02-14 | 02-15 | 02-20 | 02-21 | 02-22 | 02-28 | 03-02 | mean 7 [95% day-boot CI] | mean 6 pseudo | SD (7) | min | max |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A_S0_stacked41 | 0.992 | 0.600 | 1.000 | 0.941 | 0.588 | 0.716 | 0.892 | **0.818** [0.695, 0.935] | 0.788 | 0.180 | 0.588 | 1.000 |
| A_S1_no_zero9 | 0.994 | 0.567 | 1.000 | 0.945 | 0.578 | 0.709 | 0.888 | **0.812** [0.681, 0.935] | 0.780 | 0.190 | 0.567 | 1.000 |
| A_S2_no_ident | 0.941 | 0.502 | 1.000 | 0.934 | 0.600 | 0.742 | 0.916 | **0.805** [0.670, 0.928] | 0.773 | 0.193 | 0.502 | 1.000 |
| A_S3_log | 0.923 | 0.586 | 1.000 | 0.926 | 0.618 | 0.720 | 0.898 | **0.810** [0.697, 0.917] | 0.778 | 0.166 | 0.586 | 1.000 |
| A_S4_ratio | 0.820 | 0.564 | 1.000 | 0.947 | 0.566 | 0.687 | 0.909 | **0.785** [0.663, 0.902] | 0.749 | 0.181 | 0.564 | 1.000 |
| A_S5_temporal | 0.957 | 0.564 | 1.000 | 0.953 | 0.574 | 0.698 | 0.901 | **0.807** [0.679, 0.929] | 0.775 | 0.189 | 0.564 | 1.000 |
| A_S6_context | 0.949 | 0.510 | 1.000 | 0.941 | 0.593 | 0.687 | 0.895 | **0.796** [0.663, 0.923] | 0.763 | 0.196 | 0.510 | 1.000 |
| A_S7_relative | 0.627 | 0.332 | 1.000 | 0.937 | 0.566 | 0.599 | 0.802 | **0.695** [0.537, 0.848] | 0.644 | 0.233 | 0.332 | 1.000 |
| B_S1_no_zero9_HGBtuned | 0.720 | 0.642 | 1.000 | 0.947 | 0.613 | 0.684 | 0.888 | **0.785** [0.682, 0.892] | 0.749 | 0.157 | 0.613 | 1.000 |
| B_S3_log_HGBtuned | 0.823 | 0.705 | 1.000 | 0.936 | 0.592 | 0.716 | 0.862 | **0.805** [0.708, 0.900] | 0.772 | 0.143 | 0.592 | 1.000 |
| C_S1_no_zero9_ET | 0.974 | 0.474 | 1.000 | 0.624 | 0.582 | 0.708 | 0.911 | **0.753** [0.616, 0.893] | 0.712 | 0.208 | 0.474 | 1.000 |
| C_S1_no_zero9_LR | 0.533 | 0.340 | 1.000 | 0.640 | 0.563 | 0.675 | 0.926 | **0.668** [0.515, 0.825] | 0.613 | 0.229 | 0.340 | 1.000 |
| C_S1_no_zero9_RF | 0.989 | 0.564 | 1.000 | 0.882 | 0.635 | 0.715 | 0.932 | **0.817** [0.697, 0.931] | 0.786 | 0.177 | 0.564 | 1.000 |
| *references (docs/18)* | | | | | | | | | | | | |
| flow_count | 0.944 | 0.801 | 0.992 | 0.963 | 0.604 | 0.640 | 0.740 | **0.812** [0.702, 0.918] | 0.782 | 0.159 | 0.604 | 0.992 |
| LR_last | 0.568 | 0.625 | 0.999 | 0.877 | 0.506 | 0.559 | 0.888 | **0.717** [0.591, 0.853] | 0.671 | 0.198 | 0.506 | 0.999 |
| HGB_last | 0.925 | 0.484 | 1.000 | 0.927 | 0.546 | 0.613 | 0.731 | **0.746** [0.609, 0.886] | 0.704 | 0.207 | 0.484 | 1.000 |
| HGB_stacked | 0.992 | 0.600 | 1.000 | 0.941 | 0.588 | 0.716 | 0.892 | **0.818** [0.695, 0.935] | 0.788 | 0.180 | 0.588 | 1.000 |
| Transformer_single_nested | 0.670 | 0.348 | 1.000 | 0.924 | 0.608 | 0.711 | 0.948 | **0.744** [0.577, 0.889] | 0.701 | 0.232 | 0.348 | 1.000 |
| Transformer_ens5_nested | 0.736 | 0.345 | 1.000 | 0.899 | 0.534 | 0.662 | 0.826 | **0.715** [0.560, 0.859] | 0.667 | 0.224 | 0.345 | 1.000 |
| **nested arm selection (the claim)** | 0.823 | 0.564 | 1.000 | 0.882 | 0.588 | 0.716 | 0.892 | **0.781** [0.671, 0.888] | 0.744 | | | |
| nested selection, anchor excluded | 0.823 | 0.564 | 1.000 | 0.882 | 0.578 | 0.715 | 0.888 | 0.778 | 0.742 | | | |
| arm chosen per day (nested) | B S3 log HGBtuned | C S1 no zero9 RF | A S0 stacked41 | C S1 no zero9 RF | A S0 stacked41 | A S0 stacked41 | A S0 stacked41 | | | | | |

Best non-anchor arm (un-nested): **C_S1_no_zero9_RF**; best arm overall (un-nested): A_S0_stacked41. Chosen configuration per fold: see the tuning table.

### Gate, 7 days

| candidate | reference | days | mean paired gain | MDE | day-bootstrap 95% CI | days won | verdict |
|---|---|---|---|---|---|---|---|
| nested_selection | HGB_stacked | 7 | -0.038 | 0.079 | [-0.086, -0.005] | 0/7 | **FAIL** |
| nested_selection | flow_count | 7 | -0.031 | 0.164 | [-0.121, +0.054] | 3/7 | **FAIL** |
| nested_selection | HGB_last | 7 | +0.034 | 0.115 | [-0.028, +0.095] | 5/7 | **FAIL** |
| nested_selection | LR_last | 7 | +0.063 | 0.139 | [-0.005, +0.144] | 6/7 | **FAIL** |
| nested_selection | Transformer_single_nested | 7 | +0.037 | 0.133 | [-0.028, +0.113] | 4/7 | **FAIL** |
| nested_selection | Transformer_ens5_nested | 7 | +0.066 | 0.097 | [+0.020, +0.121] | 6/7 | **FAIL** |
| nested_selection_non_anchor | HGB_stacked | 7 | -0.040 | 0.077 | [-0.088, -0.007] | 0/7 | **FAIL** |
| nested_selection_non_anchor | flow_count | 7 | -0.034 | 0.162 | [-0.121, +0.052] | 3/7 | **FAIL** |
| nested_selection_non_anchor | HGB_last | 7 | +0.032 | 0.113 | [-0.030, +0.092] | 5/7 | **FAIL** |
| nested_selection_non_anchor | LR_last | 7 | +0.061 | 0.139 | [-0.007, +0.142] | 6/7 | **FAIL** |
| nested_selection_non_anchor | Transformer_single_nested | 7 | +0.034 | 0.135 | [-0.030, +0.111] | 4/7 | **FAIL** |
| nested_selection_non_anchor | Transformer_ens5_nested | 7 | +0.064 | 0.098 | [+0.019, +0.120] | 5/7 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | HGB_stacked | 7 | -0.002 | 0.048 | [-0.027, +0.024] | 2/7 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | flow_count | 7 | +0.005 | 0.170 | [-0.092, +0.089] | 5/7 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | HGB_last | 7 | +0.070 | 0.100 | [+0.017, +0.124] | 6/7 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | LR_last | 7 | +0.099 | 0.204 | [+0.005, +0.222] | 6/7 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | Transformer_single_nested | 7 | +0.073 | 0.175 | [-0.010, +0.175] | 5/7 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | Transformer_ens5_nested | 7 | +0.102 | 0.130 | [+0.036, +0.174] | 5/7 | **FAIL** |

### Gate, 6 pseudo-host days

| candidate | reference | days | mean paired gain | MDE | day-bootstrap 95% CI | days won | verdict |
|---|---|---|---|---|---|---|---|
| nested_selection | HGB_stacked | 6 | -0.044 | 0.094 | [-0.096, -0.006] | 0/6 | **FAIL** |
| nested_selection | flow_count | 6 | -0.038 | 0.200 | [-0.140, +0.063] | 2/6 | **FAIL** |
| nested_selection | HGB_last | 6 | +0.040 | 0.139 | [-0.034, +0.108] | 4/6 | **FAIL** |
| nested_selection | LR_last | 6 | +0.074 | 0.165 | [-0.004, +0.164] | 5/6 | **FAIL** |
| nested_selection | Transformer_single_nested | 6 | +0.043 | 0.162 | [-0.033, +0.130] | 3/6 | **FAIL** |
| nested_selection | Transformer_ens5_nested | 6 | +0.077 | 0.111 | [+0.026, +0.142] | 5/6 | **FAIL** |
| nested_selection_non_anchor | HGB_stacked | 6 | -0.047 | 0.091 | [-0.098, -0.009] | 0/6 | **FAIL** |
| nested_selection_non_anchor | flow_count | 6 | -0.040 | 0.198 | [-0.141, +0.061] | 2/6 | **FAIL** |
| nested_selection_non_anchor | HGB_last | 6 | +0.037 | 0.138 | [-0.036, +0.105] | 4/6 | **FAIL** |
| nested_selection_non_anchor | LR_last | 6 | +0.071 | 0.166 | [-0.007, +0.161] | 5/6 | **FAIL** |
| nested_selection_non_anchor | Transformer_single_nested | 6 | +0.040 | 0.164 | [-0.038, +0.129] | 3/6 | **FAIL** |
| nested_selection_non_anchor | Transformer_ens5_nested | 6 | +0.075 | 0.112 | [+0.023, +0.139] | 5/6 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | HGB_stacked | 6 | -0.002 | 0.059 | [-0.033, +0.028] | 2/6 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | flow_count | 6 | +0.004 | 0.210 | [-0.112, +0.103] | 4/6 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | HGB_last | 6 | +0.082 | 0.113 | [+0.020, +0.141] | 5/6 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | LR_last | 6 | +0.116 | 0.241 | [+0.007, +0.248] | 5/6 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | Transformer_single_nested | 6 | +0.085 | 0.209 | [-0.013, +0.198] | 4/6 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | Transformer_ens5_nested | 6 | +0.119 | 0.144 | [+0.047, +0.194] | 5/6 | **FAIL** |

### Gate of every registered arm against the incumbent and against flow_count (7 days / 6 days)

| candidate | reference | days | mean paired gain | MDE | day-bootstrap 95% CI | days won | verdict |
|---|---|---|---|---|---|---|---|
| A_S1_no_zero9 | HGB_stacked | 7 | -0.007 | 0.031 | [-0.016, +0.000] | 2/7 | **FAIL** |
| A_S1_no_zero9 | flow_count | 7 | -0.001 | 0.151 | [-0.088, +0.071] | 4/7 | **FAIL** |
| A_S2_no_ident | HGB_stacked | 7 | -0.013 | 0.057 | [-0.047, +0.014] | 3/7 | **FAIL** |
| A_S2_no_ident | flow_count | 7 | -0.007 | 0.188 | [-0.117, +0.083] | 3/7 | **FAIL** |
| A_S3_log | HGB_stacked | 7 | -0.008 | 0.039 | [-0.032, +0.011] | 3/7 | **FAIL** |
| A_S3_log | flow_count | 7 | -0.002 | 0.146 | [-0.086, +0.071] | 4/7 | **FAIL** |
| A_S4_ratio | HGB_stacked | 7 | -0.034 | 0.081 | [-0.083, -0.001] | 2/7 | **FAIL** |
| A_S4_ratio | flow_count | 7 | -0.027 | 0.163 | [-0.117, +0.058] | 3/7 | **FAIL** |
| A_S5_temporal | HGB_stacked | 7 | -0.012 | 0.031 | [-0.025, +0.001] | 3/7 | **FAIL** |
| A_S5_temporal | flow_count | 7 | -0.005 | 0.152 | [-0.095, +0.069] | 4/7 | **FAIL** |
| A_S6_context | HGB_stacked | 7 | -0.022 | 0.045 | [-0.048, -0.002] | 2/7 | **FAIL** |
| A_S6_context | flow_count | 7 | -0.016 | 0.172 | [-0.120, +0.065] | 4/7 | **FAIL** |
| A_S7_relative | HGB_stacked | 7 | -0.124 | 0.179 | [-0.227, -0.035] | 0/7 | **FAIL** |
| A_S7_relative | flow_count | 7 | -0.117 | 0.249 | [-0.261, +0.000] | 2/7 | **FAIL** |
| B_S1_no_zero9_HGBtuned | HGB_stacked | 7 | -0.034 | 0.136 | [-0.118, +0.018] | 3/7 | **FAIL** |
| B_S1_no_zero9_HGBtuned | flow_count | 7 | -0.027 | 0.159 | [-0.116, +0.055] | 4/7 | **FAIL** |
| B_S3_log_HGBtuned | HGB_stacked | 7 | -0.014 | 0.102 | [-0.076, +0.037] | 2/7 | **FAIL** |
| B_S3_log_HGBtuned | flow_count | 7 | -0.007 | 0.110 | [-0.066, +0.052] | 3/7 | **FAIL** |
| C_S1_no_zero9_ET | HGB_stacked | 7 | -0.065 | 0.153 | [-0.156, -0.000] | 1/7 | **FAIL** |
| C_S1_no_zero9_ET | flow_count | 7 | -0.059 | 0.250 | [-0.192, +0.065] | 4/7 | **FAIL** |
| C_S1_no_zero9_LR | HGB_stacked | 7 | -0.150 | 0.239 | [-0.284, -0.032] | 1/7 | **FAIL** |
| C_S1_no_zero9_LR | flow_count | 7 | -0.144 | 0.318 | [-0.313, +0.023] | 3/7 | **FAIL** |
| C_S1_no_zero9_RF | HGB_stacked | 7 | -0.002 | 0.048 | [-0.027, +0.024] | 2/7 | **FAIL** |
| C_S1_no_zero9_RF | flow_count | 7 | +0.005 | 0.170 | [-0.092, +0.089] | 5/7 | **FAIL** |

| candidate | reference | days | mean paired gain | MDE | day-bootstrap 95% CI | days won | verdict |
|---|---|---|---|---|---|---|---|
| A_S1_no_zero9 | HGB_stacked | 6 | -0.008 | 0.035 | [-0.019, +0.000] | 2/6 | **FAIL** |
| A_S1_no_zero9 | flow_count | 6 | -0.002 | 0.186 | [-0.103, +0.086] | 3/6 | **FAIL** |
| A_S2_no_ident | HGB_stacked | 6 | -0.016 | 0.070 | [-0.054, +0.017] | 3/6 | **FAIL** |
| A_S2_no_ident | flow_count | 6 | -0.009 | 0.231 | [-0.138, +0.097] | 2/6 | **FAIL** |
| A_S3_log | HGB_stacked | 6 | -0.010 | 0.048 | [-0.035, +0.013] | 3/6 | **FAIL** |
| A_S3_log | flow_count | 6 | -0.004 | 0.180 | [-0.102, +0.083] | 3/6 | **FAIL** |
| A_S4_ratio | HGB_stacked | 6 | -0.039 | 0.097 | [-0.094, -0.000] | 2/6 | **FAIL** |
| A_S4_ratio | flow_count | 6 | -0.033 | 0.199 | [-0.134, +0.067] | 2/6 | **FAIL** |
| A_S5_temporal | HGB_stacked | 6 | -0.014 | 0.035 | [-0.029, +0.002] | 2/6 | **FAIL** |
| A_S5_temporal | flow_count | 6 | -0.007 | 0.187 | [-0.112, +0.080] | 3/6 | **FAIL** |
| A_S6_context | HGB_stacked | 6 | -0.026 | 0.053 | [-0.056, -0.002] | 2/6 | **FAIL** |
| A_S6_context | flow_count | 6 | -0.019 | 0.211 | [-0.141, +0.076] | 3/6 | **FAIL** |
| A_S7_relative | HGB_stacked | 6 | -0.144 | 0.203 | [-0.256, -0.046] | 0/6 | **FAIL** |
| A_S7_relative | flow_count | 6 | -0.138 | 0.294 | [-0.300, -0.002] | 1/6 | **FAIL** |
| B_S1_no_zero9_HGBtuned | HGB_stacked | 6 | -0.039 | 0.166 | [-0.136, +0.022] | 3/6 | **FAIL** |
| B_S1_no_zero9_HGBtuned | flow_count | 6 | -0.033 | 0.195 | [-0.134, +0.063] | 3/6 | **FAIL** |
| B_S3_log_HGBtuned | HGB_stacked | 6 | -0.016 | 0.126 | [-0.086, +0.047] | 2/6 | **FAIL** |
| B_S3_log_HGBtuned | flow_count | 6 | -0.010 | 0.135 | [-0.079, +0.059] | 2/6 | **FAIL** |
| C_S1_no_zero9_ET | HGB_stacked | 6 | -0.076 | 0.183 | [-0.182, -0.000] | 1/6 | **FAIL** |
| C_S1_no_zero9_ET | flow_count | 6 | -0.070 | 0.304 | [-0.223, +0.074] | 3/6 | **FAIL** |
| C_S1_no_zero9_LR | HGB_stacked | 6 | -0.175 | 0.276 | [-0.321, -0.044] | 1/6 | **FAIL** |
| C_S1_no_zero9_LR | flow_count | 6 | -0.169 | 0.378 | [-0.360, +0.024] | 2/6 | **FAIL** |
| C_S1_no_zero9_RF | HGB_stacked | 6 | -0.002 | 0.059 | [-0.033, +0.028] | 2/6 | **FAIL** |
| C_S1_no_zero9_RF | flow_count | 6 | +0.004 | 0.210 | [-0.112, +0.103] | 4/6 | **FAIL** |

### Tuned configurations per fold

| arm | fold | chosen configuration |
|---|---|---|
| B_S1_no_zero9_HGBtuned | 2018-02-14 | {"learning_rate": 0.15, "max_leaf_nodes": 31, "min_samples_leaf": 300, "l2_regularization": 0.0, "class_weight": "balanced"} |
| B_S1_no_zero9_HGBtuned | 2018-02-15 | {"learning_rate": 0.05, "max_leaf_nodes": 8, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": null} |
| B_S1_no_zero9_HGBtuned | 2018-02-20#g0 | {"learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": "balanced"} |
| B_S1_no_zero9_HGBtuned | 2018-02-20#g1 | {"learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": "balanced"} |
| B_S1_no_zero9_HGBtuned | 2018-02-20#g2 | {"learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": "balanced"} |
| B_S1_no_zero9_HGBtuned | 2018-02-21 | {"learning_rate": 0.15, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": null} |
| B_S1_no_zero9_HGBtuned | 2018-02-22 | {"learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": null} |
| B_S1_no_zero9_HGBtuned | 2018-02-28 | {"learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": null} |
| B_S1_no_zero9_HGBtuned | 2018-03-02 | {"learning_rate": 0.05, "max_leaf_nodes": 8, "min_samples_leaf": 300, "l2_regularization": 10.0, "class_weight": null} |
| B_S3_log_HGBtuned | 2018-02-14 | {"learning_rate": 0.15, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": null} |
| B_S3_log_HGBtuned | 2018-02-15 | {"learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": null} |
| B_S3_log_HGBtuned | 2018-02-20#g0 | {"learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": null} |
| B_S3_log_HGBtuned | 2018-02-20#g1 | {"learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": null} |
| B_S3_log_HGBtuned | 2018-02-20#g2 | {"learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": null} |
| B_S3_log_HGBtuned | 2018-02-21 | {"learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": "balanced"} |
| B_S3_log_HGBtuned | 2018-02-22 | {"learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": "balanced"} |
| B_S3_log_HGBtuned | 2018-02-28 | {"learning_rate": 0.15, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": null} |
| B_S3_log_HGBtuned | 2018-03-02 | {"learning_rate": 0.05, "max_leaf_nodes": 8, "min_samples_leaf": 300, "l2_regularization": 10.0, "class_weight": null} |
| C_S1_no_zero9_ET | 2018-02-14 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_ET | 2018-02-15 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_ET | 2018-02-20#g0 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_ET | 2018-02-20#g1 | {"min_samples_leaf": 5, "class_weight": "balanced_subsample"} |
| C_S1_no_zero9_ET | 2018-02-20#g2 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_ET | 2018-02-21 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_ET | 2018-02-22 | {"min_samples_leaf": 50, "class_weight": null} |
| C_S1_no_zero9_ET | 2018-02-28 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_ET | 2018-03-02 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_LR | 2018-02-14 | {"C": 0.01, "class_weight": "balanced"} |
| C_S1_no_zero9_LR | 2018-02-15 | {"C": 0.01, "class_weight": "balanced"} |
| C_S1_no_zero9_LR | 2018-02-20#g0 | {"C": 0.01, "class_weight": "balanced"} |
| C_S1_no_zero9_LR | 2018-02-20#g1 | {"C": 0.01, "class_weight": "balanced"} |
| C_S1_no_zero9_LR | 2018-02-20#g2 | {"C": 0.01, "class_weight": "balanced"} |
| C_S1_no_zero9_LR | 2018-02-21 | {"C": 0.01, "class_weight": null} |
| C_S1_no_zero9_LR | 2018-02-22 | {"C": 0.01, "class_weight": "balanced"} |
| C_S1_no_zero9_LR | 2018-02-28 | {"C": 0.01, "class_weight": null} |
| C_S1_no_zero9_LR | 2018-03-02 | {"C": 0.01, "class_weight": "balanced"} |
| C_S1_no_zero9_RF | 2018-02-14 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_RF | 2018-02-15 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_RF | 2018-02-20#g0 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_RF | 2018-02-20#g1 | {"min_samples_leaf": 5, "class_weight": "balanced_subsample"} |
| C_S1_no_zero9_RF | 2018-02-20#g2 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_RF | 2018-02-21 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_RF | 2018-02-22 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_RF | 2018-02-28 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_RF | 2018-03-02 | {"min_samples_leaf": 5, "class_weight": null} |

### Exploratory (not registered, excluded from every verdict): mean probability of the incumbent and the best non-anchor arm

7-day mean 0.827; per day 02-14 0.991, 02-15 0.563, 02-20 1.000, 02-21 0.934, 02-22 0.649, 02-28 0.719, 03-02 0.935; vs HGB_stacked gain +0.009, MDE 0.042, verdict FAIL.

### Threshold transfer

#### Realised FPR / recall per day, leave-one-day-out threshold, target 1% (threshold from inner OOF scores of the other days)

| arm | 02-14 | 02-15 | 02-20 | 02-21 | 02-22 | 02-28 | 03-02 | FPR min-max | mean abs log(FPR/target) | days within x3 of target |
|---|---|---|---|---|---|---|---|---|---|---|
| flow_count | 0.62% / 4.16% | 1.24% / 9.68% | 0.00% / 0.00% | 0.29% / 48.90% | 3.73% / 4.27% | 0.42% / 4.14% | 1.64% / 3.11% | 0.00%-3.73% | 2.10 | 4/7 |
| A_S0_stacked41 | 0.00% / 22.30% | 1.89% / 0.00% | 0.00% / 99.57% | 0.57% / 45.96% | 6.18% / 16.46% | 1.62% / 3.88% | 0.64% / 13.61% | 0.00%-6.18% | 2.54 | 4/7 |
| C_S1_no_zero9_RF | 0.00% / 0.09% | 0.20% / 0.00% | 0.11% / 99.09% | 3.45% / 45.59% | 0.00% / 0.00% | 1.89% / 4.01% | 0.82% / 14.00% | 0.00%-3.45% | 1.97 | 2/7 |
| B_S3_log_HGBtuned | 0.00% / 3.27% | 1.92% / 1.76% | 0.00% / 90.23% | 0.57% / 45.59% | 3.83% / 9.15% | 1.00% / 4.51% | 1.09% / 18.39% | 0.00%-3.83% | 2.36 | 4/7 |
| A_S5_temporal | 0.00% / 16.46% | 1.14% / 0.00% | 0.00% / 99.89% | 0.57% / 45.96% | 0.42% / 1.22% | 2.16% / 7.39% | 1.09% / 19.92% | 0.00%-2.16% | 2.32 | 5/7 |
| A_S6_context | 0.00% / 29.82% | 1.47% / 0.59% | 0.00% / 99.87% | 0.57% / 45.59% | 1.16% / 4.88% | 2.47% / 6.27% | 1.09% / 19.53% | 0.00%-2.47% | 1.90 | 5/7 |
| A_S7_relative | 0.66% / 9.91% | 0.13% / 0.00% | 0.00% / 99.89% | 0.00% / 11.40% | 0.16% / 0.61% | 0.69% / 1.13% | 0.64% / 4.04% | 0.00%-0.69% | 1.92 | 3/7 |
| B_S3_log_HGBtuned+platt | 0.00% / 3.27% | 1.92% / 1.76% | 0.00% / 90.23% | 0.57% / 45.59% | 3.83% / 9.15% | 1.00% / 4.51% | 1.09% / 18.39% | 0.00%-3.83% | 2.36 | 4/7 |
| B_S3_log_HGBtuned+isotonic | 0.00% / 0.62% | 1.92% / 1.76% | 0.00% / 89.77% | 0.57% / 45.59% | 3.96% / 9.15% | 0.46% / 1.38% | 1.09% / 17.95% | 0.00%-3.96% | 2.47 | 4/7 |

#### Realised FPR / recall per day, leave-one-day-out threshold, target 5% (threshold from inner OOF scores of the other days)

| arm | 02-14 | 02-15 | 02-20 | 02-21 | 02-22 | 02-28 | 03-02 | FPR min-max | mean abs log(FPR/target) | days within x3 of target |
|---|---|---|---|---|---|---|---|---|---|---|
| flow_count | 4.93% / 45.58% | 11.04% / 44.28% | 0.00% / 0.00% | 0.29% / 48.90% | 14.51% / 22.56% | 2.59% / 7.02% | 5.92% / 21.50% | 0.00%-14.51% | 1.89 | 5/7 |
| A_S0_stacked41 | 0.57% / 52.74% | 3.81% / 1.47% | 0.00% / 99.95% | 20.40% / 94.12% | 24.83% / 32.93% | 2.86% / 14.29% | 1.64% / 20.76% | 0.00%-24.83% | 2.69 | 2/7 |
| C_S1_no_zero9_RF | 0.43% / 49.65% | 0.98% / 0.29% | 0.26% / 99.79% | 3.45% / 48.90% | 4.05% / 7.32% | 3.63% / 20.30% | 1.09% / 17.65% | 0.26%-4.05% | 1.36 | 3/7 |
| B_S3_log_HGBtuned | 0.00% / 40.18% | 5.60% / 11.73% | 0.05% / 99.89% | 12.64% / 78.31% | 15.05% / 25.61% | 3.09% / 14.29% | 1.28% / 23.32% | 0.00%-15.05% | 1.98 | 3/7 |
| A_S5_temporal | 0.09% / 47.96% | 2.25% / 1.76% | 0.00% / 99.92% | 19.25% / 94.49% | 8.94% / 17.07% | 14.09% / 33.33% | 1.82% / 41.52% | 0.00%-19.25% | 2.43 | 4/7 |
| A_S6_context | 0.38% / 49.03% | 3.13% / 2.64% | 0.01% / 99.97% | 8.33% / 76.47% | 11.16% / 23.17% | 12.85% / 30.08% | 2.37% / 39.60% | 0.01%-12.85% | 1.79 | 5/7 |
| A_S7_relative | 2.80% / 45.40% | 1.63% / 0.00% | 0.10% / 100.00% | 0.00% / 18.75% | 8.01% / 12.80% | 8.68% / 10.15% | 1.18% / 17.85% | 0.00%-8.68% | 1.67 | 3/7 |
| B_S3_log_HGBtuned+platt | 0.00% / 40.18% | 5.60% / 11.73% | 0.05% / 99.89% | 12.64% / 78.31% | 15.05% / 25.61% | 3.09% / 14.29% | 1.28% / 23.32% | 0.00%-15.05% | 1.98 | 3/7 |
| B_S3_log_HGBtuned+isotonic | 0.00% / 0.62% | 1.92% / 1.76% | 0.02% / 90.33% | 0.57% / 45.59% | 9.62% / 17.68% | 2.12% / 11.40% | 1.09% / 17.95% | 0.00%-9.62% | 2.42 | 3/7 |

#### Label-free adaptive rule (adaptive_q99): realised FPR / recall per pseudo-host day

| arm | 02-14 | 02-15 | 02-21 | 02-22 | 02-28 | 03-02 | FPR min-max | mean abs log ratio | within x3 |
|---|---|---|---|---|---|---|---|---|---|
| flow_count | 1.09% / 2.21% | 1.17% / 2.35% | 0.00% / 0.37% | 1.22% / 3.05% | 1.12% / 2.13% | 1.28% / 1.53% | 0.00%-1.28% | 0.46 | 5/6 |
| A_S0_stacked41 | 1.47% / 6.02% | 1.60% / 3.81% | 0.00% / 6.99% | 1.87% / 4.88% | 1.58% / 2.26% | 1.64% / 4.44% | 0.00%-1.87% | 0.73 | 5/6 |
| C_S1_no_zero9_RF | 1.09% / 4.34% | 1.69% / 3.23% | 0.00% / 8.82% | 2.03% / 3.66% | 1.78% / 3.38% | 2.00% / 4.88% | 0.00%-2.03% | 0.75 | 5/6 |
| B_S3_log_HGBtuned | 1.57% / 3.19% | 1.76% / 6.16% | 0.57% / 17.28% | 2.09% / 4.88% | 1.47% / 3.38% | 1.18% / 5.37% | 0.57%-2.09% | 0.48 | 6/6 |
| A_S5_temporal | 1.47% / 4.16% | 1.73% / 5.57% | 0.00% / 2.21% | 2.32% / 6.71% | 1.24% / 2.88% | 2.28% / 5.67% | 0.00%-2.32% | 0.79 | 5/6 |
| A_S6_context | 1.52% / 3.45% | 1.40% / 7.33% | 0.00% / 8.09% | 2.57% / 5.49% | 1.24% / 2.76% | 1.82% / 5.03% | 0.00%-2.57% | 0.74 | 5/6 |
| A_S7_relative | 2.32% / 2.21% | 2.12% / 3.23% | 0.57% / 1.10% | 1.80% / 4.88% | 1.81% / 1.88% | 2.64% / 4.44% | 0.57%-2.64% | 0.72 | 6/6 |

#### Label-free adaptive rule (adaptive_q95): realised FPR / recall per pseudo-host day

| arm | 02-14 | 02-15 | 02-21 | 02-22 | 02-28 | 03-02 | FPR min-max | mean abs log ratio | within x3 |
|---|---|---|---|---|---|---|---|---|---|
| flow_count | 4.89% / 10.09% | 4.95% / 10.85% | 0.00% / 5.51% | 5.66% / 4.88% | 4.94% / 6.52% | 5.37% / 7.00% | 0.00%-5.66% | 0.63 | 5/6 |
| A_S0_stacked41 | 4.84% / 16.64% | 4.95% / 11.73% | 0.57% / 12.50% | 6.34% / 14.02% | 5.44% / 10.65% | 4.64% / 13.46% | 0.57%-6.34% | 0.43 | 5/6 |
| C_S1_no_zero9_RF | 4.51% / 12.83% | 5.50% / 9.97% | 0.57% / 12.87% | 7.56% / 10.37% | 4.75% / 11.78% | 4.19% / 12.38% | 0.57%-7.56% | 0.50 | 5/6 |
| B_S3_log_HGBtuned | 6.12% / 11.33% | 5.89% / 14.37% | 0.86% / 20.22% | 6.40% / 12.80% | 4.98% / 9.02% | 4.28% / 10.95% | 0.86%-6.40% | 0.42 | 5/6 |
| A_S5_temporal | 5.65% / 13.01% | 5.05% / 14.37% | 0.00% / 5.15% | 6.92% / 15.24% | 4.82% / 7.89% | 5.10% / 13.02% | 0.00%-6.92% | 0.68 | 5/6 |
| A_S6_context | 5.27% / 12.48% | 5.21% / 13.78% | 1.72% / 16.18% | 7.17% / 14.63% | 5.36% / 7.64% | 5.37% / 12.28% | 1.72%-7.17% | 0.28 | 6/6 |
| A_S7_relative | 6.36% / 7.79% | 6.38% / 4.99% | 1.44% / 5.51% | 6.53% / 10.37% | 6.33% / 5.64% | 5.92% / 9.66% | 1.44%-6.53% | 0.40 | 5/6 |

#### Calibration of B_S3_log_HGBtuned (outer held-out; Brier / ECE-10 per day; calibrators fitted on inner OOF scores of the other days only)

| score | 02-14 | 02-15 | 02-20 | 02-21 | 02-22 | 02-28 | 03-02 | mean Brier | mean AUROC |
|---|---|---|---|---|---|---|---|---|---|
| raw | 0.231 / 0.266 | 0.102 / 0.090 | 0.000 / 0.001 | 0.099 / 0.050 | 0.152 / 0.200 | 0.215 / 0.210 | 0.443 / 0.482 | 0.1774 | 0.8047 |
| platt | 0.187 / 0.183 | 0.115 / 0.087 | 0.001 / 0.015 | 0.102 / 0.071 | 0.197 / 0.341 | 0.162 / 0.032 | 0.323 / 0.370 | 0.1551 | 0.8047 |
| isotonic | 0.205 / 0.182 | 0.124 / 0.101 | 0.001 / 0.014 | 0.108 / 0.087 | 0.197 / 0.338 | 0.169 / 0.027 | 0.350 / 0.371 | 0.1647 | 0.7711 |

### Secondary labels

| day | k, s (train-derived) | definition | positives kept | dropped as ambiguous | median attack flows in primary-positive windows |
|---|---|---|---|---|---|
| 02-14 | 2, 0.010 | primary | 1130 | 0 | 340.0 |
| 02-14 | 2, 0.010 | S_fix(k>=5,s>=5%) | 1130 | 0 | 340.0 |
| 02-14 | 2, 0.010 | S_train(k>=2,s>=0.010) | 1130 | 0 | 340.0 |
| 02-14 | 2, 0.010 | S_run6 | 1129 | 1 | 340.0 |
| 02-15 | 2, 0.010 | primary | 341 | 0 | 37.0 |
| 02-15 | 2, 0.010 | S_fix(k>=5,s>=5%) | 302 | 39 | 37.0 |
| 02-15 | 2, 0.010 | S_train(k>=2,s>=0.010) | 339 | 2 | 37.0 |
| 02-15 | 2, 0.010 | S_run6 | 340 | 1 | 37.0 |
| 02-21 | 2, 0.010 | primary | 272 | 0 | 21.0 |
| 02-21 | 2, 0.010 | S_fix(k>=5,s>=5%) | 255 | 17 | 21.0 |
| 02-21 | 2, 0.010 | S_train(k>=2,s>=0.010) | 266 | 6 | 21.0 |
| 02-21 | 2, 0.010 | S_run6 | 237 | 35 | 21.0 |
| 02-22 | 18, 0.100 | primary | 164 | 0 | 2.0 |
| 02-22 | 18, 0.100 | S_fix(k>=5,s>=5%) | 0 | 164 | 2.0 |
| 02-22 | 18, 0.100 | S_train(k>=18,s>=0.100) | 0 | 164 | 2.0 |
| 02-22 | 18, 0.100 | S_run6 | 0 | 164 | 2.0 |
| 02-28 | 2, 0.010 | primary | 798 | 0 | 52.0 |
| 02-28 | 2, 0.010 | S_fix(k>=5,s>=5%) | 782 | 16 | 52.0 |
| 02-28 | 2, 0.010 | S_train(k>=2,s>=0.010) | 796 | 2 | 52.0 |
| 02-28 | 2, 0.010 | S_run6 | 798 | 0 | 52.0 |
| 03-02 | 2, 0.010 | primary | 2028 | 0 | 90.0 |
| 03-02 | 2, 0.010 | S_fix(k>=5,s>=5%) | 2006 | 22 | 90.0 |
| 03-02 | 2, 0.010 | S_train(k>=2,s>=0.010) | 2027 | 1 | 90.0 |
| 03-02 | 2, 0.010 | S_run6 | 2027 | 1 | 90.0 |

AUROC on each label definition (scores from the primary-trained arms; ambiguous windows dropped from scoring):

| day | score | primary | S_fix(k>=5,s>=5%) | S_train(k>=2,s>=0.010) | S_run6 |
|---|---|---|---|---|---|
| 02-14 | flow_count | 0.944 | 0.944 | 0.944 | 0.945 |
| 02-14 | HGB_stacked(current) | 0.992 | 0.992 | 0.992 | 0.992 |
| 02-14 | best=C_S1_no_zero9_RF | 0.989 | 0.989 | 0.989 | 0.990 |
| 02-15 | flow_count | 0.801 | 0.800 | 0.804 | 0.803 |
| 02-15 | HGB_stacked(current) | 0.600 | 0.607 | 0.603 | 0.602 |
| 02-15 | best=C_S1_no_zero9_RF | 0.564 | 0.580 | 0.564 | 0.565 |
| 02-21 | flow_count | 0.963 | 0.965 | 0.964 | 0.977 |
| 02-21 | HGB_stacked(current) | 0.941 | 0.943 | 0.943 | 0.948 |
| 02-21 | best=C_S1_no_zero9_RF | 0.882 | 0.889 | 0.887 | 0.901 |
| 02-22 | flow_count | 0.604 | n/a | n/a | n/a |
| 02-22 | HGB_stacked(current) | 0.588 | n/a | n/a | n/a |
| 02-22 | best=C_S1_no_zero9_RF | 0.635 | n/a | n/a | n/a |
| 02-28 | flow_count | 0.640 | 0.638 | 0.640 | 0.640 |
| 02-28 | HGB_stacked(current) | 0.716 | 0.713 | 0.716 | 0.716 |
| 02-28 | best=C_S1_no_zero9_RF | 0.715 | 0.713 | 0.715 | 0.715 |
| 03-02 | flow_count | 0.740 | 0.740 | 0.740 | 0.740 |
| 03-02 | HGB_stacked(current) | 0.892 | 0.897 | 0.892 | 0.892 |
| 03-02 | best=C_S1_no_zero9_RF | 0.932 | 0.937 | 0.932 | 0.932 |

Trained on S_train (ambiguous dropped from training), evaluated on S_train, against the primary-trained arm on the same rows:

| day | arm | primary-trained | S_train-trained |
|---|---|---|---|
| 02-14 | HGB_stacked(current) | 0.992 | 0.885 |
| 02-14 | best=C_S1_no_zero9_RF | 0.989 | 0.986 |
| 02-15 | HGB_stacked(current) | 0.603 | 0.565 |
| 02-15 | best=C_S1_no_zero9_RF | 0.564 | 0.508 |
| 02-21 | HGB_stacked(current) | 0.943 | 0.934 |
| 02-21 | best=C_S1_no_zero9_RF | 0.887 | 0.693 |
| 02-22 | HGB_stacked(current) | n/a | n/a |
| 02-22 | best=C_S1_no_zero9_RF | n/a | n/a |
| 02-28 | HGB_stacked(current) | 0.716 | 0.702 |
| 02-28 | best=C_S1_no_zero9_RF | 0.715 | 0.713 |
| 03-02 | HGB_stacked(current) | 0.892 | 0.833 |
| 03-02 | best=C_S1_no_zero9_RF | 0.932 | 0.937 |

Alignment check (raw-CSV rebuilt label vs primary): 02-14 100.00% match, 100.0% of primary positives recovered, 02-15 100.00% match, 100.0% of primary positives recovered, 02-21 99.68% match, 99.3% of primary positives recovered, 02-22 100.00% match, 100.0% of primary positives recovered, 02-28 100.00% match, 100.0% of primary positives recovered, 03-02 100.00% match, 100.0% of primary positives recovered

### Robustness

| arm | ablation | 02-14 | 02-15 | 02-20 | 02-21 | 02-22 | 02-28 | 03-02 | max drop (volumetric days 02-14, 02-15, 02-21) |
|---|---|---|---|---|---|---|---|---|---|
| HGB_stacked(current) | none | 0.992 | 0.600 | 1.000 | 0.941 | 0.588 | 0.716 | 0.892 | |
| HGB_stacked(current) | flow_count | 0.945 (+0.047) | 0.631 (-0.031) | 1.000 (-0.000) | 0.944 (-0.003) | 0.575 (+0.014) | 0.681 (+0.035) | 0.871 (+0.021) | +0.047 |
| HGB_stacked(current) | volume4 | 0.950 (+0.042) | 0.724 (-0.124) | 1.000 (+0.000) | 0.895 (+0.046) | 0.571 (+0.017) | 0.626 (+0.091) | 0.830 (+0.062) | +0.046 |
| best=C_S1_no_zero9_RF | none | 0.989 | 0.564 | 1.000 | 0.882 | 0.635 | 0.715 | 0.932 | |
| best=C_S1_no_zero9_RF | flow_count | 0.986 (+0.003) | 0.590 (-0.026) | 1.000 (+0.000) | 0.877 (+0.005) | 0.589 (+0.046) | 0.679 (+0.036) | 0.924 (+0.009) | +0.005 |
| best=C_S1_no_zero9_RF | volume4 | 0.929 (+0.060) | 0.456 (+0.108) | 1.000 (+0.000) | 0.520 (+0.361) | 0.449 (+0.186) | 0.652 (+0.063) | 0.865 (+0.067) | +0.361 |

Share of held-out feature values outside the fold-training range / beyond 6 training SD (per day):

| features | 02-14 | 02-15 | 02-20 | 02-21 | 02-22 | 02-28 | 03-02 |
|---|---|---|---|---|---|---|---|
| HGB_stacked(current) (outside range) | 0.00% | 0.00% | 0.00% | 1.22% | 0.00% | 0.00% | 0.05% |
| HGB_stacked(current) (> 6 SD) | 0.01% | 0.02% | 0.22% | 2.47% | 0.07% | 0.15% | 0.06% |
| best=C_S1_no_zero9_RF (outside range) | 0.00% | 0.00% | 0.00% | 1.57% | 0.00% | 0.00% | 0.06% |
| best=C_S1_no_zero9_RF (> 6 SD) | 0.02% | 0.02% | 0.28% | 3.17% | 0.10% | 0.19% | 0.07% |
| raw 41 last-window features, Transformer-scaler analogue (> 6 SD) | 0.01% | 0.01% | 0.29% | 2.49% | 0.04% | 0.04% | 0.02% |

Clean re-score check (max abs difference to the stored OOF score): HGB_stacked(current) 3.0e-08, best=C_S1_no_zero9_RF 3.0e-08

### Export and secondary cross-dataset (zero-shot, not used for selection)

Best non-anchor arm **C_S1_no_zero9_RF** (variant S1_no_zero9, family RF), configuration chosen by the full 7-day inner LODO: `{"min_samples_leaf": 5, "class_weight": null}`; 1% day-balanced FPR threshold from the inner OOF scores 0.4800; export `checkpoints_baselines_v5\final\C_S1_no_zero9_RF.npz`; numpy-vs-sklearn max abs difference on 5,000 rows 2.2e-16.

| dataset (sequences / positive) | score | pooled sequence AUROC | unit-balanced (scenario,ip) | unit-balanced (ip) | host-mean AUROC (hosts / positive hosts) |
|---|---|---|---|---|---|
| CTU-13 (355302 / 21066) | flow_count | 0.488 | 0.724 | 0.871 | 0.907 (311 / 10) |
| CTU-13 (355302 / 21066) | HGB_stacked(current) | 0.278 | 0.615 | 0.529 | 0.792 (311 / 10) |
| CTU-13 (355302 / 21066) | candidate=C_S1_no_zero9_RF | 0.241 | 0.453 | 0.210 | 0.205 (311 / 10) |
| CTU-13 (355302 / 21066) | S3_log default HGB (post-hoc) | 0.398 | 0.647 | 0.739 | 0.850 (311 / 10) |
| UNSW-NB15 (96299 / 9997) | flow_count | 0.292 | 0.229 | 0.229 | 0.500 (19 / 4) |
| UNSW-NB15 (96299 / 9997) | HGB_stacked(current) | 0.081 | 0.082 | 0.082 | 0.067 (19 / 4) |
| UNSW-NB15 (96299 / 9997) | candidate=C_S1_no_zero9_RF | 0.142 | 0.113 | 0.113 | 0.000 (19 / 4) |
| UNSW-NB15 (96299 / 9997) | S3_log default HGB (post-hoc) | 0.013 | 0.037 | 0.037 | 0.100 (19 / 4) |
| CIC-2017 60s (41713 / 901) | flow_count | 0.710 | 0.898 | 0.898 | 0.995 (473 / 10) |
| CIC-2017 60s (41713 / 901) | HGB_stacked(current) | 0.784 | 0.854 | 0.854 | 0.984 (473 / 10) |
| CIC-2017 60s (41713 / 901) | candidate=C_S1_no_zero9_RF | 0.714 | 0.842 | 0.842 | 0.989 (473 / 10) |
| CIC-2017 60s (41713 / 901) | S3_log default HGB (post-hoc) | 0.844 | 0.939 | 0.939 | 0.995 (473 / 10) |

## 3. Reading the results (what improved, what did not)

**Headline: no improvement over the current `HGB_stacked` (0.818) or over `flow_count` (0.812) is demonstrated. Every one of the 13 registered arms is a gate FAIL
against both, on the 7 days and on the 6 pseudo-host days. The nested-selection claim (0.781) is lower than the incumbent, not higher.**

1. **Feature hygiene (item 1): no gain, no demonstrated loss.** Dropping the 9 always-zero features (S1) gives 0.812 (-0.007 vs the incumbent, MDE 0.031), dropping all identity features too (S2) 0.805
   (-0.013, MDE 0.057), adding log1p (S3) 0.810 (-0.008, MDE 0.039). All three are inside the MDE in both directions: the data cannot separate them from the incumbent, and they are not better. What
   they buy is not accuracy: 192 / 102 / 102 columns instead of 246 and no dependence on `has_ip_data` / graph / graph_embed identity columns. Single days move in opposite directions: removing identity helps
   02-22 (S2 +0.012, S3 +0.030), 02-28 (S2 +0.026) and 03-02 (S2 +0.024) and hurts 02-14 (0.992 -> 0.941 for S2) and 02-15 (0.600 -> 0.502). Ratio features (S4) are worse (-0.034, CI [-0.083, -0.001]; 02-14 falls to 0.820).
2. **Causal temporal and context features (items 2, 3): no gain.** S5 (in-sequence z / jump / slope / burst / spike count / seconds since quiet / gaps) 0.807 (-0.012, CI [-0.025, +0.001]), S6 (adds the unit's rolling baseline) 0.796 (-0.022,
   CI [-0.048, -0.002]), S7 (no absolute volume level, relative information only) 0.695 (-0.124, CI [-0.227, -0.035]): the volume level is the signal on 02-14, 02-15 and 02-28 (S7: 0.627, 0.332, 0.599), while the
   flood-like days 02-21 and 03-02 survive without it (0.937, 0.802). The normalised / temporal variants do change the operating-point behaviour modestly (descriptive, 7 days, no test): at the 1% leave-one-day-out budget the realised FPR range is 0.00%-6.18% for S0, 0.00%-2.16% for S5, 0.00%-2.47% for S6 (the 02-22 FPR falls from 6.18% to 0.42% / 1.16%), 0.00%-0.69% for S7;
   mean |log(FPR/target)| 2.54 -> 2.32 / 1.90 / 1.92 and days within a factor of 3 of the target 4/7 -> 5/7 / 5/7 / 3/7; at the 5% budget the S0 range 0.00%-24.8% becomes 0.00%-19.3% / 0.01%-12.9% / 0.00%-8.7% and 2/7 -> 4/7 / 5/7 / 3/7. That is a narrower spread, not a controlled rate: several days remain at 0.00% FPR or far below the target, S7 reaches its narrow range by under-alarming (recall 0-11% on every day except 02-20), and recall at
   the threshold is not higher (02-22: 16.5% for S0 against 1.2% / 4.9% / 0.6%). The AUROC did not improve, so the narrower FPR spread is not bought back as detection. The features
   are causal by construction and by test; being causal did not make them informative here.
3. **Tuning (item 4): nested tuning of HGB made it worse, not better.** S1 tuned 0.785 (default 0.812), S3 tuned 0.805 (default 0.810); against the incumbent -0.034 (MDE 0.136) and -0.014 (MDE 0.102). The inner LODO (6-7 inner days,
   13 configurations) picks different configurations in different outer folds (the S1 arm chose `class_weight=balanced, min_samples_leaf=300` for the 02-14 fold, and the held-out 02-14 AUROC fell from 0.994 to 0.720). The selection noise of an inner criterion
   with 6-7 independent days is of the size of the differences between configurations. Tuning on this data is not a source of gain.
4. **Other families (item 4).** RandomForest on S1: 0.817 (-0.002 vs `HGB_stacked`, MDE 0.048; +0.005 vs `flow_count`, MDE 0.170), a tie with a different day profile (better on 02-22 0.635 and 03-02 0.932, worse on 02-21
   0.882 and 02-15 0.564). ExtraTrees 0.753 (02-21 collapses to 0.624) and the regularised LR 0.668 (02-14 0.533, 02-15 0.340) are worse; LR confirms that the signal is not linear in these features. The RF is the best non-anchor arm and is
   what was exported (section 2, last table), as a candidate and not as a replacement.
5. **Selection across arms is the trap docs/18 predicted.** The best arm by 7-day mean is the incumbent itself (A_S0, 0.818). The nested claim, each day read from the arm that wins on the other six days, is **0.781**
   (6 pseudo-host days 0.744): 0.038 below the incumbent (CI [-0.086, -0.005], 0 of 7 days won, MDE 0.079). The nested rule picked the incumbent on 4 days, the RF on 2 and tuned S3 on 02-14 (0.823 against the incumbent's 0.992 on that day).
   The gate verdict is FAIL (improvement not demonstrated); the CI says that searching these 13 arms lost accuracy relative to keeping the incumbent, which is what selection noise looks like.
6. **Against the other references.** The best non-anchor arm (RF) is +0.070 over `HGB_last` (MDE 0.100, CI [+0.017, +0.124]), +0.099 over `LR_last`, +0.073 over the single Transformer and +0.102 over the 5-seed ensemble (MDE 0.130, CI [+0.036, +0.174]): all FAIL by the MDE, although the
   Transformer-ensemble CI excludes zero. This restates docs/18 (trees beat the Transformer on the OOF protocol) with a slightly different tree; it is not a new improvement because the same holds for the incumbent.
   Exploratory only (not registered, excluded from every verdict): the mean probability of the incumbent and the RF gives 0.827 (+0.009, MDE 0.042, FAIL).
7. **Threshold transfer (item 3 evaluation).** With the threshold chosen leave-one-day-out (inner OOF scores of the other days), the realised FPR at the 1% budget is 0.00%-6.18% for the incumbent (02-22: 6.18%), 0.00%-3.45% for the RF, 0.00%-3.83% for tuned S3
   and 0.00%-3.73% for `flow_count` (02-20: thresholds taken from pseudo-host days sit above every 02-20 host, FPR 0% and recall 0%); only 2-4 of 7 days land within a factor of 3 of the target. Recall at that threshold is 0-22% except 02-21 (46%) and 02-20 (90-100%).
   Platt scaling is monotone, so with the threshold chosen by the FPR rule on the same inner scores it produces **the same alarms as the raw score** (identical rows in the table); isotonic regression only adds ties (mean AUROC 0.805 -> 0.771). Calibration lowers the mean Brier (0.177 raw, 0.155 Platt,
   0.165 isotonic) on 02-14, 02-28, 03-02 and raises it on 02-15, 02-21, 02-22; ECE on 02-22 rises (0.200 -> 0.341): a calibrator fitted on other days encodes their prevalence. **A fixed probability threshold is not a controlled false-alarm rate under any of these arms.** The label-free
   adaptive rule (alarm above the 99th percentile of the previous 360 sequences' scores) keeps FPR within a factor of 3 on 5-6 of 6 pseudo-host days (mean |log ratio| 0.46-0.75 against 1.97-2.54 for fixed thresholds), but that is an alarm-rate cap by construction: its recall is 0.4-17%, and on 02-21 (45% positive) it reaches 0.0-0.6% FPR because the
   attack itself sets the quantile. It controls the alarm budget; it does not detect more.
8. **Secondary labels (item 5).** The rebuilt label matches the primary on 99.68-100.00% of sequences on all six days (02-21: two windows differ). On the volumetric days (02-14, 02-15, 02-21, 02-28, 03-02) the three rules change AUROC by at most 0.02 for any score: the positive windows there hold tens to hundreds of attack flows, so the
   ambiguity dropped is 0-39 windows per day (S_fix; S_run6 drops 35 on 02-21) and the ranking of the arms is unchanged. **02-22, the sparse day, has zero positive windows under every definition** (median 2 attack flows; the train-derived rule gives k = 18, s = 10% for that fold because the other five days' positives are large; S_run6 finds no run of 6). The sparse windows
   are therefore not "harder positives" under any registered rule: they are excluded, and nothing about 02-22 (or the spent 02-23) becomes detectable. Training on S_train instead of the primary label lowered AUROC on all 5 defined days for the incumbent (by 0.009-0.107) and on 4 of 5 for the RF (by 0.002-0.194; RF on 02-21 0.887 -> 0.693),
   RF on 03-02 +0.005: no gain. The train-derived (k, s) is also unstable (k = 2, s = 1% floor in five folds, k = 18, s = 10% in the fold where the sparse day is held out), which is a reason not to adopt it.
9. **Robustness (item 6).** `flow_count` mean-ablation (every derived column rebuilt): the incumbent loses at most 0.047 on the volumetric days (02-14), the RF 0.005; both pass the docs/16 test (< 0.05).
   The joint volume ablation (flow_count, ports, bytes, packets) is the real test: the incumbent moves +0.042 / -0.124 / +0.046 on 02-14 / 02-15 / 02-21 (02-15 IMPROVES from 0.600 to 0.724 when volume is removed: volume points the wrong way on the slow DoS), the RF loses 0.060 / 0.108 / **0.361** (02-21 0.882 -> 0.520), so
   **the RF depends more on joint volume than the incumbent does**. Clip analogue: on the engineered S1 features 3.17% of 02-21 values lie beyond 6 training SD (incumbent S0 2.47%, the raw 41 last-window features the Transformer scaler sees 2.49%) and 0.0-0.3% on every other day, so 02-21 still exceeds the docs/16 "< 1% on every day" criterion for every feature
   set; the share of values outside the training min-max is 0.00-0.06% on the other days and 1.2-1.6% on 02-21. The per-day SD across the 7 days is 0.14-0.20 for every top arm: the days, not the arm, dominate.
10. **Cross-dataset (secondary, not used for selection).** The candidate is not better than the incumbent or `flow_count`: CTU-13 host-mean 0.205 (10 bot IPs of 311) against 0.792 (incumbent) and 0.907 (`flow_count`); UNSW 0.000 against 0.067 and 0.500 (4 attackers of 19 hosts; the docs/16 volume sign flip applies to every volume-using score);
   CIC-2017 60 s host-mean 0.989 against 0.984 and 0.995 (10 of 473). Unit-balanced (scenario|ip) values are 0.453 / 0.113 / 0.842 for the candidate. With 10, 4 and 10 positive hosts these rows say nothing about transfer (docs/16 F4); they do show that volume-using models still invert on UNSW and that the RF (which keeps the identity columns, S1) is not a more transferable detector.

## 4. Recommendation

* **Keep `HGB_stacked` (S0) as the best-supported detector in the repo, or the zero-training `flow_count` score it ties. No baseline of this step is demonstrably better.** The only arm whose mean matches the incumbent (RF on S1, 0.817) has a different day profile and a larger joint-volume dependence, so
  it is exported for inspection and not recommended for use. If a model without identity columns is wanted (docs/16 action 4), S3_log (17 behavioural features, 102 columns, 0.810, -0.008 vs the incumbent, inside the MDE) is the cleanest choice; state it as "not distinguishable in accuracy, fewer shortcuts by construction", not as an improvement and not as a portability claim: the one post-hoc look at it (default HGB, 7 days, cross-dataset, not for selection) gives CTU-13 host-mean 0.850 (incumbent 0.792), UNSW 0.100 (0.067, still inverted), CIC-2017 0.995 (0.984), unit-balanced 0.647 / 0.037 / 0.939 (0.615 / 0.082 / 0.854), on 10 / 4 / 10 positive hosts, which supports no inference.
* **Do not claim from this step:** an improvement from any feature family, tuning, ET/RF/LR, calibration or the secondary labels; a controlled false-alarm rate from any fixed threshold (the leave-one-day-out FPR at a 1% budget is 0-6%); better cross-network behaviour.
* **What would change the answer is data, not another model in this stack:** more independent days (7 here, six of them one series each), untruncated days, per-host series from other networks, and flow-level labels for the sparse web-attack days (02-22 has no windows that survive any secondary rule). A rolling alarm-budget rule is a cheap, label-free
  way to cap alarms per day; it does not raise recall.
* **lightgbm / xgboost** are not expected to change this: the top seven arms lie within 0.013 of each other, the paired SD across days is 0.1-0.2, and the limits (sparse windows, 7 days) are not model-capacity limits. Where they could matter is monotone constraints on the volume
  features (the volume sign flips on 02-15 and on UNSW), which sklearn's `HistGradientBoostingClassifier(monotonic_cst=...)` already offers and which was **not tested** here (it was not pre-registered).

## 5. What remains unfixed / limits

* 7 days (six single-series pseudo-host days, one real-IP day), 5 of the 7 partial (truncated at 1,048,575 rows); per-day AUROC SD 0.14-0.20; the gate's MDE is 0.03-0.25 depending on the pair (floor SD 0.0245). Small differences cannot be resolved, large ones were not found.
* The sealed test is spent and nothing here was scored on it. The nested arm selection reuses OOF scores of models that saw the held-out day in training (the docs/18 limitation); the inner tuning and the leave-one-day-out thresholds do not.
* No seed spread for ET/RF, 150 trees only; the inner tuning criterion (mean of 6-7 inner AUROCs) is noisy; the HGB grid is a 12-of-32 random subset plus the default.
* Causal windows (docs/16 action 12: windows keyed by flow start, 120 s timeout) are untouched: the "next 10 s" claim still uses flows that would not have ended in a live setting.
* 02-20 is host-disjoint, not day-disjoint, and is 1.000 for every arm (volume alone suffices); it does not discriminate between arms, which is why the 6-day line is printed beside every 7-day line.
* `checkpoints_baselines_v5/oof` (about 660 MB: OOF and inner OOF scores) and `data/processed_adapter/baselines_v5` (about 6 GB of feature caches) are regenerable and can be deleted.

## 6. Reproduce

```text
python -m scripts.build_lodo_v4                    # docs/18 cache (read only here)
python -m eval.baselines_v5_run prep               # causal context + feature caches of the 8 variants (data/processed_adapter/baselines_v5)
python -m eval.baselines_v5_run anchor             # S0 + default HGB must reproduce docs/18 (stops otherwise)
python -m eval.baselines_v5_run A ; python -m eval.baselines_v5_run B ; python -m eval.baselines_v5_run C
python -m eval.baselines_v5_stages tables          # nested selection, gates -> docs/lodo_v5/tables.json
python -m eval.baselines_v5_stages threshold       # leave-one-day-out thresholds, calibration, adaptive rule
python -m eval.baselines_v5_stages secondary       # needs V:\Datasets\CIC-IDS-2018-flows (the six LODO days only)
python -m eval.baselines_v5_stages robust
python -m eval.baselines_v5_final                  # full 7-day tuning, export to checkpoints_baselines_v5/final, cross-dataset
python -m eval.baselines_v5_render                 # docs/lodo_v5/tables.md
python -m pytest tests -q
```
