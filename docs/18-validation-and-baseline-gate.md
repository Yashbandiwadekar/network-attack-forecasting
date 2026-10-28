# 18 - Leave-one-day-out validation and the baseline gate (docs/16 actions 2 and 3)

**Branch** `test/session-2026-10-10` (base `734d47b`), nothing committed. **Section 0 (the protocol) was written to this file before the first
out-of-fold model was trained and is reproduced unchanged in the final document**; results follow it. No existing checkpoint, `data/processed*`,
config or the server default was modified; the served model stays `checkpoints_real_v2_converged/seed1`. New artefacts only:
`data/processed_adapter/lodo_v4/` (per-day cache of the train+val days), `checkpoints_lodo_v4/` (OOF scores, final-recipe weights),
`docs/lodo_v4/` (selection, results), code `eval/lodo_v4.py`, `eval/lodo_v4_run.py`, `eval/lodo_v4_select.py`, `eval/baseline_gate.py`,
`eval/diagnostics/core.py` (+`paired_mde`, `baseline_gate`), `eval/benchmark.py` (+ baseline-gate section), tests `tests/test_lodo_v4.py`,
`tests/test_baseline_gate.py`.

## 0. Protocol (fixed before any LODO result was computed)

### 0.1 Data and units

* **Source.** The 7 non-test days of CIC-IDS-2018 from the existing `data/processed_real_v2_converged/{train,val}.npz` (read only, the sealed
  `test.npz` is not opened by any LODO stage): 02-14, 02-15, 02-20, 02-21, 02-22, 02-28, 03-02. Sequences are the existing ones
  (12 x 10 s input windows, target = `infiltration[:, 0]`, i.e. "is any flow of the next 10 s window an attack flow"). Copied per day to
  `data/processed_adapter/lodo_v4/<day>/<key>.npy` by `scripts/build_lodo_v4.py`.
* **Sealed test days** 02-16, 02-23, 03-01 (7,191 sequences, 12 onset episodes) never enter training, fold construction, epoch choice,
  threshold choice or baseline fitting. `eval.lodo_v4.assert_sealed` refuses them in every fold builder; the final stage opens `test.npz`
  once (0.8).
* **Truncated source days.** The CIC-2018 processed CSVs on AWS stop at 1,048,575 rows on 7 of 10 days (local files are byte-identical to the
  official bucket). Of the LODO days 02-14, 02-15, 02-21, 02-22 and 03-02 are therefore **partial days** (a prefix of unknown extent); 02-20 and
  02-28 are complete. Of the sealed test days 02-16 and 02-23 are partial and 03-01 is complete. Every per-day number below is a statement about the
  available slice, not about a full day (02-21 has 620 sequences, 02-16 has 483).
* **Independent units** are days (n = 7: six pseudo-host days, each ONE network-wide series, plus 02-20, the only day with real source IPs:
  6,810 hosts, 10 attackers). Sequences within a day overlap by 11 of 12 windows and are not independent; all intervals resample days or hosts.

### 0.2 Folds (`eval/lodo_v4.py`, tested by `tests/test_lodo_v4.py`)

* **Day folds (6):** 02-14, 02-15, 02-21, 02-22, 02-28, 03-02. The whole day is held out; no row of it is in training.
* **02-20 host-group folds (3):** the 6,810 hosts are partitioned into 3 groups (`assign_host_groups`, seeded hash, the 10 attackers dealt first so
  the groups hold 4 / 3 / 3 of them; no host is in two groups). A fold holds out one group's hosts (all of their sequences) and trains on the other six
  days plus the other two groups. These folds are **host-disjoint, not day-disjoint**: the 02-20 campaign (one DDoS family on one day) is still seen
  through other hosts. They are labelled as such everywhere. The 02-20 OOF scores of the three folds are pooled and count as **one day** in the
  day mean.
* **Family-aware:** every fold records whether its attack family is still represented in the training days (`family_coverage`). Families:
  initial_access 02-14, 02-22; impact 02-15, 02-20, 02-21; lateral_movement 02-28; command_and_control 03-02. Two folds therefore measure transfer to
  an UNSEEN family and are reported separately: 02-28 (the only other lateral-movement day, 03-01, is sealed) and 03-02 (C2 has one day). The
  headline mean is over all 7 days; the 5 family-covered days, and the 6 pseudo-host days (02-20 is near 1.0 for every arm), are printed beside it.
  A strict leave-family-out design (also withholding 02-14 when 02-22 is held out, 02-15/02-21 when 02-20 is) is NOT used because it would leave
  1-2 impact days; the existing leave-one-family-out results (docs/04 lofo) cover that question.
* **Training rows per fold:** all rows of the training days except 02-20, which is represented by a fixed uniform random sample of **70,000** of its
  1,228,717 sequences (seed 0, drawn once; the B recipe of docs/15 used the same scale). This is a deliberate change of the training mix relative
  to the served seed 1 (whose train set is 99.2% 02-20) and keeps a fold at about 87k rows (about 6 s/epoch on the GPU). Scalers
  (`FeatureScaler`) are fitted **per fold on that fold's training rows only**, in memory; no scaler on disk is touched.

### 0.3 Models

* **Transformer recipe** = `configs/real_data_v2_converged_seed1.yaml` unchanged: `WorldModel`, 41 features, d_model 64, 4 heads, 3 layers, d_ff 128,
  dropout 0.1, Adam lr 3e-4, batch size 64, loss = MSE(next state) + CE(stage) + BCE(infiltration) exactly as `models/train.py::_step_loss`
  (the GPU-resident loop in `eval/lodo_v4_run.py` only removes the DataLoader). Same architecture and features as the served model; no feature
  removal (docs/16 action 4 is out of scope). Epoch cap **20** (30 in the config; every earlier run's val loss bottomed at epoch 1-3, so 20 is a cap
  and not a target). **Seeds 1-5** for every fold.
* **Baselines on the same folds, same training rows, same raw (unscaled) features, no tuning:** `flow_count` (last window, no fit), `LR_last`
  (standardized last window, `max_iter` 1000), `HGB_last` and `HGB_stacked` (`HistGradientBoostingClassifier(max_iter=200, early_stopping=False,
  random_state=0)`; stacked = last, mean, std, 1-step and 6-step delta, max over the 12 windows). Persistence (label oracle) is shown as an
  upper reference only; it is not deployable and is not gated.

### 0.4 Selection metric and the epoch rule (decided before any OOF number was seen)

* **Metric.** For a fold set and epoch e, the out-of-fold within-day AUROC of each day (02-20 pooled over its groups), averaged **unweighted over
  days**. Validation loss is never used. AUPRC is reported beside it but is not used to select.
* **Single model:** `curve_single[e]` = mean over days of (mean over seeds of the per-seed within-day AUROC at epoch e). `E*_single` = argmax,
  ties to the earlier epoch.
* **Ensemble (mean probability of seeds 1-5, and of seeds 1-3 for comparison):** `curve_ens[e]` = mean over days of the within-day AUROC of the
  seed-averaged probability. `E*_ens` = argmax, ties to the earlier epoch. The seed-averaged probability is formed epoch by epoch (all members
  at the same epoch).
* **Nested (honest) per-day numbers.** Picking one epoch from the same days that are then reported is optimistic and HGB has no tuned epoch, so
  for the gate each day d is read at the epoch chosen from the OTHER six days' mean curve (`nested_epoch_selection`). The un-nested number is
  printed beside it. The recipe that is finally retrained uses the global `E*`.

### 0.5 Operating point

Alert threshold from OOF probabilities at `E*` only: the smallest score whose **day-balanced** false-positive rate over OOF negatives is <= 1%
(every day's negatives carry total weight 1, so 02-20's 1.2M sequences do not decide it; `day_balanced_threshold`). Also computed at 5%. The
realised per-day FPR / recall at that threshold on the OOF predictions is reported with the day spread. Then it is applied unchanged to the sealed test.

### 0.6 Gate (`eval.diagnostics.core.baseline_gate`)

For the Transformer (single, ensemble) against each of `flow_count`, `LR_last`, `HGB_last`, `HGB_stacked`: paired per-day within-day AUROC
differences over the LODO days (nested epoch). **PASS iff the mean paired gain exceeds the paired minimum detectable effect** `(t_{0.975,n-1} +
t_{0.8,n-1}) * SD / sqrt(n)` with `SD = max(0.0245 (docs/16), observed SD of the per-day differences)` (fixed this way so a noisy comparison cannot
shrink its own bar), n = 7 days (n = 6 pseudo-host days as a robustness line). A day-bootstrap 95% CI of the mean gain is printed and is not part of
the verdict. Success test inherited from docs/16 action 2: the selected recipe must beat the HGB-LODO mean and `flow_count` by more than the MDE.
If HGB is at least as good, that is stated as the result.

### 0.7 Budget

Measured: about 5-7 s per epoch per run (87k rows, batch 64, RTX 5080), so 20 epochs about 2 min. 9 folds x 5 seeds = 45 runs about 90 min; the final
stage trains 5 seeds on all 7 days about 10 min. GPU seconds of every run are logged to `docs/lodo_v4/oof_timing.jsonl`. Total expected well under the
~6 h allowance.

### 0.8 Sealed test

After `select` writes `docs/lodo_v4/selection.json` (epochs, thresholds, the list of recipes), `final` trains the selected recipes on all 7 days
(same 70k sample of 02-20), scores `test.npz` **once**, and writes `docs/lodo_v4/test_sealed.json`; it refuses to run if that file exists. Nothing
about the test set is looked at before this. The test results are reported with per-day AUROC/AUPRC, episode counts and the OOF-derived threshold's
realised FPR/recall, and are not used to change anything.



## 1. What was run (as stated in section 0, plus the deviations disclosed here)

* 9 folds x 5 seeds = 45 Transformer runs and 9 baseline fits, 20 epochs each, OOF probabilities stored for every epoch
  (`checkpoints_lodo_v4/oof/`, `docs/lodo_v4/oof_timing.jsonl`). Fold construction and the no-leakage assertions run before every fit
  (`eval.lodo_v4.assert_no_leakage`: held-out day absent from train, no 02-20 host on both sides, no sealed day anywhere).
* GPU time: **1.81 h** summed over the 46 logged runs (about 2.4 min each; three worker processes shared the one GPU, wall clock about 65 min) plus 8.6 min for the
  final stage. Well under the ~6 h allowance; nothing had to be cut.
* **Deviation 1 (code bug, caught before the test was opened).** The first `select` run indexed the nested-epoch column one epoch too early (a 0-based/1-based mix-up in
  `eval/lodo_v4_select.py`). It was visible because the "nested" and "global epoch" columns disagreed although the rule picked the same epoch for every day. It was fixed and `select`
  re-run; the epoch choices (single 1, ensemble-5 9, ensemble-3 15) and the thresholds did not change, only the nested columns and the gates built on them. All tables below are the corrected ones.
* **Deviation 2.** Fold 02-21 seed 4 was trained twice by two worker processes (the second write won; the GPU-time log therefore has 46 rows). Same seed and fold, so it is a re-draw
  of GPU non-determinism, not a data change.
* **Deviation 3.** The `eval.benchmark` baseline section was first run with a uniform 200,000-row subsample of the seed-1 train split and then with all rows; both gave HGB_last
  a mean per-day AUROC of only 0.65 / 0.56 on the v2 test, because that split is 99.2% one day (02-20) and the tree learns that day's identity-like features. It now uses the docs/16 rule
  "at most 30,000 rows per day" (`per_day_cap_indices`), which reproduces the docs/16 numbers (HGB_last 0.962 / 0.593 / 0.706). The two discarded variants are reported here, not hidden:
  **the strength of the HGB baseline depends strongly on the training mix, and so does the Transformer's** (the served seed 1 was trained on the 99.2% one-day mix).
  In the LODO the Transformer and every baseline see identical rows by construction.

* **Deviation 4 (what "sealed" means here).** Before this work docs/16 had already published per-day test AUROC for the existing checkpoints and for default HGB/LR/`flow_count` fitted on the seed-1 rows, and docs/17
  (action 1, run while the OOF jobs were training) added seed 2/3 and the joint_v3 models. No LODO rule (folds, epoch rule, threshold rule, gate rule, seeds) was set or changed using those numbers, and none of the 3 test days entered
  any fit of the new recipes; "sealed" refers to the new recipes and baselines, which were scored on `test.npz` once.
* **Deviation 5 (code changed after scoring).** The five seeds' final snapshots (`checkpoints_lodo_v4/final/seed*/ep*.pt`) were re-serialised into the repo's safe checkpoint format (config as JSON, scaler as tensors) AFTER
  `test_sealed.json` was written, because `tests/test_checkpoint_io.py` loads every `.pt` under `checkpoints*/` with `weights_only=True`. The conversion asserted `torch.equal` on every tensor of `model_state`
  (weights bit-identical), and `stage_final` was then changed to read them through `load_checkpoint`; the repo code is therefore not byte-for-byte the code that produced the sealed numbers, the weights are.
* **Deviation 6.** The OOF thresholds of `HGB_last`, `HGB_stacked` and `LR_last` (section 0.5 names only the Transformer thresholds) were added to the `select` stage before it ran; same rule (day-balanced 1% and 5% FPR on their OOF scores).

## 2. Results: leave-one-day-out (OOF), 7 days

Selected epochs (1-based, by OOF day-mean within-day AUROC, ties to the earlier epoch): single **1**, ensemble of 5 seeds **9**, ensemble of 3 seeds **15**. Validation loss was not used.


| held-out day | family (in train?) | seq | pos | episodes | **single (5-seed mean), nested epoch** | single, global epoch | **ensemble-5, nested** | ensemble-3, nested | flow_count | LR_last | HGB_last | HGB_stacked | label oracle |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 02-14 * | initial_access (yes) | 3,238 | 1,130 | 2 | **0.670** | 0.670 | **0.736** | 0.768 | 0.944 | 0.568 | 0.925 | 0.992 | 0.999 |
| 02-15 * | impact (yes) | 3,412 | 341 | 5 | **0.348** | 0.348 | **0.345** | 0.263 | 0.801 | 0.625 | 0.484 | 0.600 | 0.992 |
| 02-20 | impact (yes) | 1,228,717 | 3,745 | 0 | **1.000** | 1.000 | **1.000** | 1.000 | 0.992 | 0.999 | 1.000 | 1.000 | 1.000 |
| 02-21 * | impact (yes) | 620 | 272 | 2 | **0.924** | 0.924 | **0.899** | 0.932 | 0.963 | 0.877 | 0.927 | 0.941 | 0.961 |
| 02-22 * | initial_access (yes) | 3,273 | 164 | 9 | **0.608** | 0.608 | **0.534** | 0.574 | 0.604 | 0.506 | 0.546 | 0.588 | 0.678 |
| 02-28 | lateral_movement (**NO**) | 3,389 | 798 | 2 | **0.711** | 0.711 | **0.662** | 0.686 | 0.640 | 0.559 | 0.613 | 0.716 | 0.999 |
| 03-02 * | command_and_control (**NO**) | 3,126 | 2,028 | 2 | **0.948** | 0.948 | **0.826** | 0.925 | 0.740 | 0.888 | 0.731 | 0.892 | 0.999 |
| **mean, all 7 days** | | | | | 0.744 (sd 0.23) | 0.744 (sd 0.23) | 0.715 (sd 0.22) | 0.736 (sd 0.26) | 0.812 (sd 0.16) | 0.717 (sd 0.20) | 0.746 (sd 0.21) | 0.818 (sd 0.18) | 0.947 (sd 0.12) |
| mean, 6 pseudo-host days (without 02-20) | | | | | 0.701 (sd 0.22) | 0.701 (sd 0.22) | 0.667 (sd 0.20) | 0.692 (sd 0.25) | 0.782 (sd 0.15) | 0.671 (sd 0.17) | 0.704 (sd 0.19) | 0.788 (sd 0.18) | 0.938 (sd 0.13) |
| mean, 5 family-covered days | | | | | 0.710 (sd 0.26) | 0.710 (sd 0.26) | 0.703 (sd 0.27) | 0.708 (sd 0.30) | 0.861 (sd 0.16) | 0.715 (sd 0.21) | 0.776 (sd 0.24) | 0.824 (sd 0.21) | 0.926 (sd 0.14) |


`*` = partial source day (CSV truncated at 1,048,575 rows). 02-20 = the three host-group folds pooled (host-disjoint, not day-disjoint). 'nested' = each day read at the epoch chosen from the other six days.


### AUPRC (secondary)

| held-out day | single AUPRC (nested) | ensemble-5 AUPRC (nested) | flow_count | LR_last | HGB_last | HGB_stacked | positive rate |
|---|---|---|---|---|---|---|---|
| 02-14 * | 0.637 | 0.716 | 0.827 | 0.375 | 0.891 | 0.982 | 0.349 |
| 02-15 * | 0.184 | 0.182 | 0.324 | 0.301 | 0.152 | 0.117 | 0.100 |
| 02-20 | 0.985 | 0.999 | 0.281 | 0.791 | 0.999 | 1.000 | 0.003 |
| 02-21 * | 0.900 | 0.871 | 0.960 | 0.838 | 0.932 | 0.927 | 0.439 |
| 02-22 * | 0.082 | 0.064 | 0.074 | 0.058 | 0.060 | 0.086 | 0.050 |
| 02-28 | 0.409 | 0.384 | 0.351 | 0.259 | 0.371 | 0.446 | 0.235 |
| 03-02 * | 0.969 | 0.900 | 0.796 | 0.918 | 0.838 | 0.931 | 0.649 |

### OOF day-mean within-day AUROC by epoch (the selection curve)

| epoch | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| single (5-seed mean) | 0.744 | 0.716 | 0.703 | 0.712 | 0.714 | 0.700 | 0.703 | 0.708 | 0.714 | 0.696 | 0.715 | 0.701 | 0.684 | 0.690 | 0.698 | 0.715 | 0.699 | 0.702 | 0.701 | 0.687 |
| ensemble-5 | 0.757 | 0.721 | 0.706 | 0.721 | 0.728 | 0.726 | 0.716 | 0.752 | 0.757 | 0.732 | 0.734 | 0.731 | 0.721 | 0.713 | 0.756 | 0.738 | 0.751 | 0.752 | 0.731 | 0.716 |
| ensemble-3 | 0.761 | 0.718 | 0.706 | 0.712 | 0.725 | 0.725 | 0.718 | 0.715 | 0.730 | 0.725 | 0.745 | 0.711 | 0.719 | 0.705 | 0.764 | 0.737 | 0.753 | 0.753 | 0.733 | 0.709 |


Nested epoch per held-out day (single): 02-14 * -> 1, 02-15 * -> 1, 02-20 -> 1, 02-21 * -> 1, 02-22 * -> 1, 02-28 -> 1, 03-02 * -> 1.

Nested epoch per held-out day (ensemble-5): 02-14 * -> 1, 02-15 * -> 1, 02-20 -> 9, 02-21 * -> 15, 02-22 * -> 9, 02-28 -> 15, 03-02 * -> 8.


### Baseline gate, all 7 LODO days (primary)

| comparison (model minus baseline) | days | mean paired gain | MDE | day-bootstrap 95% CI | days won | verdict |
|---|---|---|---|---|---|---|
| single Transformer vs flow_count | 7 | -0.068 | 0.282 | [-0.231, +0.072] | 4/7 | **FAIL** |
| single Transformer vs LR_last | 7 | +0.027 | 0.180 | [-0.082, +0.103] | 6/7 | **FAIL** |
| single Transformer vs HGB_last | 7 | -0.002 | 0.196 | [-0.114, +0.101] | 4/7 | **FAIL** |
| single Transformer vs HGB_stacked | 7 | -0.074 | 0.188 | [-0.181, +0.016] | 2/7 | **FAIL** |
| ensemble-5 vs flow_count | 7 | -0.097 | 0.232 | [-0.232, +0.012] | 3/7 | **FAIL** |
| ensemble-5 vs LR_last | 7 | -0.003 | 0.181 | [-0.108, +0.085] | 5/7 | **FAIL** |
| ensemble-5 vs HGB_last | 7 | -0.032 | 0.127 | [-0.104, +0.033] | 3/7 | **FAIL** |
| ensemble-5 vs HGB_stacked | 7 | -0.104 | 0.133 | [-0.172, -0.039] | 0/7 | **FAIL** |
| ensemble-3 vs flow_count | 7 | -0.076 | 0.292 | [-0.252, +0.059] | 3/7 | **FAIL** |
| ensemble-3 vs LR_last | 7 | +0.018 | 0.227 | [-0.119, +0.119] | 6/7 | **FAIL** |
| ensemble-3 vs HGB_last | 7 | -0.011 | 0.176 | [-0.107, +0.081] | 5/7 | **FAIL** |
| ensemble-3 vs HGB_stacked | 7 | -0.083 | 0.177 | [-0.185, -0.000] | 1/7 | **FAIL** |
| HGB_last vs flow_count (is the tree better than the one-liner?) | 7 | -0.066 | 0.143 | [-0.152, -0.012] | 1/7 | **FAIL** |
| HGB_stacked vs flow_count (is the tree better than the one-liner?) | 7 | +0.006 | 0.139 | [-0.073, +0.074] | 4/7 | **FAIL** |

### Baseline gate, 6 pseudo-host days only (02-20 removed)

| comparison (model minus baseline) | days | mean paired gain | MDE | day-bootstrap 95% CI | days won | verdict |
|---|---|---|---|---|---|---|
| single Transformer vs flow_count | 6 | -0.081 | 0.344 | [-0.267, +0.086] | 3/6 | **FAIL** |
| single Transformer vs LR_last | 6 | +0.031 | 0.221 | [-0.097, +0.113] | 5/6 | **FAIL** |
| single Transformer vs HGB_last | 6 | -0.003 | 0.242 | [-0.131, +0.115] | 3/6 | **FAIL** |
| single Transformer vs HGB_stacked | 6 | -0.087 | 0.226 | [-0.206, +0.019] | 2/6 | **FAIL** |
| ensemble-5 vs flow_count | 6 | -0.115 | 0.277 | [-0.269, +0.013] | 2/6 | **FAIL** |
| ensemble-5 vs LR_last | 6 | -0.003 | 0.222 | [-0.128, +0.099] | 4/6 | **FAIL** |
| ensemble-5 vs HGB_last | 6 | -0.037 | 0.154 | [-0.118, +0.039] | 2/6 | **FAIL** |
| ensemble-5 vs HGB_stacked | 6 | -0.121 | 0.148 | [-0.190, -0.052] | 0/6 | **FAIL** |
| ensemble-3 vs flow_count | 6 | -0.090 | 0.354 | [-0.296, +0.067] | 2/6 | **FAIL** |
| ensemble-3 vs LR_last | 6 | +0.021 | 0.280 | [-0.142, +0.134] | 5/6 | **FAIL** |
| ensemble-3 vs HGB_last | 6 | -0.013 | 0.217 | [-0.124, +0.095] | 4/6 | **FAIL** |
| ensemble-3 vs HGB_stacked | 6 | -0.097 | 0.211 | [-0.212, -0.000] | 1/6 | **FAIL** |

### Operating point from OOF scores: ensemble-5, 1% day-balanced FPR budget

threshold = **0.64146** (epoch 9); realised per-day FPR range 0.0000-0.0345

| day | OOF FPR | OOF recall | alarm rate |
|---|---|---|---|
| 02-14 * | 0.0000 | 0.010 | 0.0034 |
| 02-15 * | 0.0160 | 0.050 | 0.0193 |
| 02-20 | 0.0002 | 0.997 | 0.0032 |
| 02-21 * | 0.0345 | 0.489 | 0.2339 |
| 02-22 * | 0.0003 | 0.000 | 0.0003 |
| 02-28 | 0.0058 | 0.029 | 0.0112 |
| 03-02 * | 0.0128 | 0.208 | 0.1395 |

### Operating point from OOF scores: single model, 1% budget

threshold = **0.69706** (epoch 1); realised per-day FPR range 0.0001-0.0330

| day | OOF FPR | OOF recall | alarm rate |
|---|---|---|---|
| 02-14 * | 0.0001 | 0.043 | 0.0151 |
| 02-15 * | 0.0155 | 0.113 | 0.0252 |
| 02-20 | 0.0001 | 0.946 | 0.0030 |
| 02-21 * | 0.0195 | 0.474 | 0.2187 |
| 02-22 * | 0.0009 | 0.006 | 0.0012 |
| 02-28 | 0.0330 | 0.088 | 0.0459 |
| 03-02 * | 0.0007 | 0.181 | 0.1177 |

### Operating point from OOF scores: ensemble-5, 5% budget

threshold = **0.39552** (epoch 9); realised per-day FPR range 0.0000-0.2902

| day | OOF FPR | OOF recall | alarm rate |
|---|---|---|---|
| 02-14 * | 0.0000 | 0.200 | 0.0698 |
| 02-15 * | 0.0254 | 0.062 | 0.0290 |
| 02-20 | 0.0003 | 0.998 | 0.0034 |
| 02-21 * | 0.2902 | 0.930 | 0.5710 |
| 02-22 * | 0.0023 | 0.006 | 0.0024 |
| 02-28 | 0.0124 | 0.050 | 0.0212 |
| 03-02 * | 0.0191 | 0.277 | 0.1865 |


GPU time of the 45 OOF runs: 1.81 h over 46 runs (logged in docs/lodo_v4/oof_timing.jsonl).

### Reading the LODO result

* **Selection by out-of-fold AUROC is itself noisy.** The day-mean curve of a single model over epochs 1-20 lies between 0.684 and 0.744 (epoch 1 is the argmax), of the 5-seed ensemble between
  0.706 and 0.757 (epoch 9). The ensemble's argmax optimism is visible: **0.757 at the selected epoch against 0.715 when each day is read at the epoch chosen from the other six days**
  (the number used in the gate). The seed-to-seed SD of one model on one day is 0.14 on 02-14, 0.07 on 02-15 and at most 0.02 on the other days.
* **No Transformer variant beats any baseline by the paired MDE; the gate returns FAIL for all 12 model-vs-baseline pairs on the 7 days and on the 6 pseudo-host days.** The MDE here is 0.13-0.35, not
  docs/16's 0.04 (that one assumes an SD of 0.0245): the observed SD of the per-day paired differences is about 0.10-0.23 because the days are heterogeneous (AUROC from 0.35 to 1.00), and the gate
  rule uses max(0.0245, observed SD). So FAIL means "not demonstrated"; it means "demonstrated worse" only where the bootstrap CI also excludes zero on the baseline's side, which
  is the case for **ensemble-5 vs HGB_stacked (-0.104, CI [-0.172, -0.039], 0 of 7 days won)** and, borderline, ensemble-3 vs HGB_stacked (-0.083, CI upper bound -0.000).
* **HGB_stacked is the best learned model in the LODO (0.818 mean) and ties the zero-training `flow_count` score (0.812):** HGB_stacked minus flow_count = +0.006
  (CI [-0.073, +0.074]). HGB_last (0.746) is not better than the volume score (-0.066, CI [-0.152, -0.012]). The single Transformer (0.744) equals HGB_last (-0.002) and LR_last (+0.027).
* The docs/16 success test for action 2 ("OOF mean of the selected recipe beats the HGB-LODO mean (0.72) and flow_count by more than the MDE") **fails**: 0.744 single /
  0.757 ensemble-5 at its own selected epoch (0.715 nested) against 0.746 (HGB_last) and 0.812 (flow_count). The HGB-LODO mean here (0.746 last window) is close to docs/16's 0.722,
  although the protocols differ (docs/16 trained on 9 days including the three test days; this LODO excludes them and uses a 70k sample of 02-20).
* Where the Transformer is better (descriptive; 7 days, none significant): the two unseen-family folds, 02-28 (single 0.711 vs flow_count 0.640, HGB_last 0.613, HGB_stacked 0.716) and
  03-02 (0.948 vs 0.740 / 0.731 / 0.892). Where it is worse: the slow-DoS day 02-15 (0.348, inverted, against flow_count 0.801) and 02-14 (0.670 vs 0.925-0.992 for the volume score and the trees).
  02-20 is 1.000 for every model that sees the graph/identity features of other 02-20 hosts: that fold is host-disjoint, not day-disjoint, and says nothing about transfer;
  the 6-pseudo-host-day means (0.701 single, 0.788 HGB_stacked, 0.782 flow_count) are the cleaner line.
* The operating-point tables show that the day-balanced 1% threshold does **not** transfer day to day inside the LODO: realised FPR per held-out day ranges 0.00%-3.45% (ensemble-5) and
  0.01%-3.30% (single), and recall on the non-02-20 days is 0%-50%. A threshold carried from other days is not a controlled false-alarm rate.

## 3. Results: the sealed test (opened once)

`final` trained the selected recipes on all seven days (87,058 rows: the six pseudo-host days plus the same 70,000-row sample of 02-20), 5 seeds, snapshots at epochs 1, 9 and 15, fitted the
baselines on the same rows, applied the thresholds frozen in `selection.json`, and scored `data/processed_real_v2_converged/test.npz` once (`docs/lodo_v4/test_sealed.json`;
the stage refuses to run again). Nothing below was used to change anything.

### Within-day AUROC on the sealed test days

| test day | seq | pos | episodes | **ensemble-5** | ensemble-3 | single (5 seeds: mean [min-max]) | flow_count | LR_last | HGB_last | HGB_stacked | label oracle |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 02-16 * | 483 | 297 | 2 | **0.989** | 0.988 | 0.982 [0.981-0.984] | 0.992 | 0.979 | 0.994 | 0.992 | 0.992 |
| 02-23 * | 3,318 | 255 | 8 | **0.492** | 0.485 | 0.508 [0.497-0.533] | 0.516 | 0.551 | 0.540 | 0.537 | 0.614 |
| 03-01 | 3,390 | 930 | 2 | **0.808** | 0.728 | 0.828 [0.780-0.857] | 0.621 | 0.615 | 0.708 | 0.766 | 0.999 |
| **mean of 3 days** | | | 12 | **0.763** | 0.734 | 0.773 | 0.709 | 0.715 | 0.748 | 0.765 | 0.868 |

### Baseline gate on the 3 sealed test days (informative only as far as 3 days allow)

| comparison (model minus baseline) | days | mean paired gain | MDE | day-bootstrap 95% CI | days won | verdict |
|---|---|---|---|---|---|---|
| transformer_ens5 vs flow_count | 3 | +0.053 | 0.361 | [-0.024, +0.187] | 1/3 | **FAIL** |
| transformer_ens5 vs LR_last | 3 | +0.048 | 0.404 | [-0.059, +0.193] | 2/3 | **FAIL** |
| transformer_ens5 vs HGB_last | 3 | +0.015 | 0.237 | [-0.049, +0.100] | 1/3 | **FAIL** |
| transformer_ens5 vs HGB_stacked | 3 | -0.002 | 0.135 | [-0.046, +0.042] | 1/3 | **FAIL** |
| transformer_ens3 vs flow_count | 3 | +0.024 | 0.227 | [-0.031, +0.107] | 1/3 | **FAIL** |
| transformer_ens3 vs LR_last | 3 | +0.019 | 0.279 | [-0.066, +0.113] | 2/3 | **FAIL** |
| transformer_ens3 vs HGB_last | 3 | -0.014 | 0.119 | [-0.056, +0.020] | 1/3 | **FAIL** |
| transformer_ens3 vs HGB_stacked | 3 | -0.032 | 0.077 | [-0.052, -0.004] | 0/3 | **FAIL** |
| transformer_single_seedmean vs flow_count | 3 | +0.063 | 0.386 | [-0.010, +0.207] | 1/3 | **FAIL** |
| transformer_single_seedmean vs LR_last | 3 | +0.058 | 0.422 | [-0.042, +0.213] | 2/3 | **FAIL** |
| transformer_single_seedmean vs HGB_last | 3 | +0.025 | 0.256 | [-0.032, +0.120] | 1/3 | **FAIL** |
| transformer_single_seedmean vs HGB_stacked | 3 | +0.008 | 0.148 | [-0.029, +0.062] | 1/3 | **FAIL** |

### Operating point: ensemble-5 at the OOF 1% threshold (threshold 0.64146, frozen before the test was opened)

| day | realised FPR | recall | alarm rate |
|---|---|---|---|
| 02-16 * | 0.0108 | 0.956 | 0.5921 |
| 02-23 * | 0.0000 | 0.000 | 0.0000 |
| 03-01 | 0.0049 | 0.245 | 0.0708 |

### Operating point: ensemble-5 at the OOF 5% threshold (threshold 0.39552, frozen before the test was opened)

| day | realised FPR | recall | alarm rate |
|---|---|---|---|
| 02-16 * | 0.0215 | 0.980 | 0.6108 |
| 02-23 * | 0.0000 | 0.004 | 0.0003 |
| 03-01 | 0.0049 | 0.290 | 0.0832 |

Pooled test AUROC (secondary): transformer_ens5 0.706, transformer_ens3 0.696, flow_count 0.524, LR_last 0.702, HGB_last 0.746, HGB_stacked 0.741, persistence_oracle 0.941.

Sealed test opened 2026-10-18 20:36:51; final training GPU time 8.6 min.

* The LODO-selected recipe is **not distinguishable from the served seed 1** on the same days (single-model mean of days 0.773 against seed 1's 0.755; with 3 days the paired MDE is 0.076 even at the
  0.0245 floor) and not from the trees (HGB_stacked 0.765, HGB_last 0.748; ensemble-5 0.763). Per day: on 02-16 every score is 0.98-0.99 (a volume score gets 0.992); **02-23 is at chance for every score
  (0.49-0.55; the label oracle 0.614)**; on 03-01 the Transformer is ahead (ensemble-5 0.808, single 0.828 [0.780-0.857 over 5 seeds]) of HGB_stacked (0.766), HGB_last (0.708) and flow_count (0.621) by 0.04-0.2.
  That is the one day-level difference in the Transformer's favour, and it is one day with 2 episodes.
* All 12 gate rows on the 3 test days are FAIL (MDE 0.08-0.42).
* Operating point: the frozen day-balanced 1% threshold gave realised FPR 1.08% / 0.00% / 0.49% on the three days (none above 1.1%), but recall 95.6% / 0.0% / 24.5%; the 5% threshold gave
  2.15% / 0.00% / 0.49%. In the LODO the same rule spanned 0%-3.5%, so three days within budget are three draws, not a validated alarm rate. The frozen tree thresholds gave
  HGB_stacked FPR 1.08% / 0.00% / 0.77%, recall 81.8% / 0.4% / 23.1%; HGB_last 0.00% / 0.20% / 0.61%, recall 55.6% / 1.2% / 8.0%. LR_last's OOF threshold saturated at 1.0, so it never alarms.

## 4. The `eval/benchmark.py` baseline gate

`eval/benchmark.py` now appends a **Baseline gate** section to both the single-dataset report and the cross-dataset report: `flow_count` (raw last window), `LR_last`, `HGB_last` and `HGB_stacked`
(sklearn `HistGradientBoostingClassifier`, 12-window stack) fitted on RAW features of the train split (per-day cap of 30,000 rows), the per-unit (day, or scenario) within-unit AUROC of the model and of each baseline, the paired gain,
the paired MDE, a day-bootstrap CI and PASS/FAIL per baseline, plus pooled AUROC/AUPRC as secondary rows (`eval/baseline_gate.py`, `eval.diagnostics.core.baseline_gate`; tests `tests/test_baseline_gate.py`, `tests/test_lodo_v4.py`).
With fewer than two units that contain both classes the verdict is FAIL ("fewer than 2 comparable units"), not N/A. `eval.benchmark.run()` was **not** executed on any existing config because `build_datasets` rewrites
`processed_dir/scaler.npz`; the section function was run on the real v2 splits through read-only `load_split` with the served seed-1 scores (`docs/lodo_v4/benchmark_gate_v2_test.md`):

#### Baseline gate (CIC-IDS-2018 v2 test (real data, read-only splits))

Baselines fitted on RAW features of the CIC-IDS-2018 v2 test (real data, read-only splits) train split (1,239,090 sequences; at most 30,000 rows per day), fixed hyper-parameters, no tuning. Gate units: 3 (days); 3 contain both classes. Pooled AUROC is secondary: it mixes units.

##### Per-unit AUROC and gate - World Model (Transformer) [seed1, served]

| score | 2018-02-16 | 2018-02-23 | 2018-03-01 | mean |
|---|---|---|---|---|
| World Model (Transformer) [seed1, served] | 0.989 | 0.500 | 0.778 | 0.755 |
| flow_count | 0.992 | 0.516 | 0.621 | 0.709 |
| LR_last | 0.990 | 0.564 | 0.597 | 0.717 |
| HGB_last | 0.962 | 0.593 | 0.706 | 0.754 |
| HGB_stacked | 0.988 | 0.574 | 0.745 | 0.769 |

| baseline | units | mean paired gain | MDE (sd used) | day-bootstrap 95% CI | verdict |
|---|---|---|---|---|---|
| flow_count | 3 | +0.046 | 0.299 (sd 0.096) | [-0.016, +0.157] | **FAIL** |
| LR_last | 3 | +0.038 | 0.394 (sd 0.127) | [-0.065, +0.181] | **FAIL** |
| HGB_last | 3 | +0.002 | 0.264 (sd 0.085) | [-0.093, +0.071] | **FAIL** |
| HGB_stacked | 3 | -0.014 | 0.170 (sd 0.055) | [-0.074, +0.033] | **FAIL** |

Gate rule: PASS iff mean paired per-unit AUROC gain over the baseline > paired MDE (80% power, 5% two-sided, SD = max(0.0245, observed SD of the per-unit differences)). All baselines beaten: **NO**.

| score (pooled, secondary) | AUROC | AUPRC |
|---|---|---|
| World Model (Transformer) [seed1, served] | 0.8003 | 0.6513 |
| flow_count | 0.5238 | 0.2661 |
| LR_last | 0.6631 | 0.4019 |
| HGB_last | 0.7586 | 0.5083 |
| HGB_stacked | 0.7639 | 0.6092 |

The seed-1 and baseline rows are the same numbers as in `docs/17`: the served model does not clear the gate against `flow_count` or any tree on the test days.

## 5. Recommendation

**If HGB is at least as good, say so plainly: it is.** On the leave-one-day-out OOF selection metric the stacked gradient-boosted tree (0.818) and the zero-training volume score (0.812) are ahead of the single Transformer
(0.744) and of the 5-seed ensemble (0.715 nested, 0.757 at its tuned epoch); on the sealed test the Transformer ensemble (0.763), the single model (0.773) and HGB_stacked (0.765) are tied on 3 days, and the one
day where the Transformer leads (03-01) is the only evidence in its favour. The Transformer never beat any baseline by the pre-registered paired MDE, on either protocol.

* **As a detector for the dashboard/alerts, the better-supported choice is `HGB_stacked` (or the volume score it equals within noise), not the Transformer.** It is 200 trees / 12,200 nodes / 390 KB, and a pure-numpy predictor
  reproduces sklearn's probabilities to 1e-16 (4.8 ms for one row, 49 ms for 5,000 rows on this CPU, no sklearn needed; measured once, not a benchmark). Frozen alert threshold from the OOF rule (1% day-balanced FPR): **0.6816** on the
  `HGB_stacked` probability (`docs/lodo_v4/hgb_export.json`). The Transformer's remaining case is the forecasting/explanation framework (rollout, stages, attention), which these gates do not test.
* **Bundle-compatible artefact (produced, not deployed):** `checkpoints_lodo_v4/final/hgb_stacked_flat.npz` (and `hgb_last_flat.npz`): plain numeric arrays loadable with `np.load(allow_pickle=False)`, exported by
  `models/tree_export.py` (round trip tested in `tests/test_tree_export.py`), so the "loading a model cannot execute code" property of `models/checkpoint_io.py` is kept. Inputs are RAW features (no scaler); the stacked
  columns are `last, mean, std, d1, d6, max` over the 12 windows of the 41 features (`eval.baseline_gate.stack_features`; names in the file's `meta_json`). Trained on the 7 non-test days with the 70,000-row 02-20 sample.
* **What serving it would need (not done; server default, `dist/` and production untouched).** (1) `common/bundle.py` hard-wires `checkpoint/world_model_best.pt` and `processed/scaler.npz` in `REQUIRED_FILES`, `build_bundle` and `verify_bundle`
  and records a feature schema and a graph-encoder fingerprint: it needs a `model_type` field (e.g. `"hgb_flat_v1"`) with `checkpoint/hgb_flat.npz` and no scaler. (2) `app/service.load_backend` builds a `ForecastEngine` around a `WorldModel`;
  a tree backend needs a small engine with `score(sequences) -> p(t+1)` that runs `stack_features` on the 12-window sequences the live pipeline already assembles and applies `predict_proba_flat`. (3) Everything that depends on the world model must be
  switched off or still served by the Transformer: the K-step rollout and what-if endpoints, the attention explanations, the stage heads (stage, CVE and MITRE narrative); a tree yields only a t+1 attack probability. (4) The alert
  threshold 0.6816 and the day-balanced 1% rule must be re-derived on the live network (the OOF FPR varied 0%-3.5% across days). (5) Add a feature-schema guard equal to `validate_feature_names` for the tree file.
  The practical shape is a two-model bundle (tree for the detector score, Transformer kept for forecasting and explanations), not a replacement.

## 6. What remains unfixed

* **The data, not the model, limits the answer.** 7 of the 10 source days are truncated (all LODO days except 02-20 and 02-28; test days 02-16 and 02-23 too). On 02-22/02-23 the positive windows hold a median of 2 attack flows
  among ~250 (every score is at chance on 02-23: 0.49-0.55, the label oracle 0.61), so those days cannot separate any two models.
* **Few independent units.** 7 LODO days (six are single network-wide series) and 3 test days; 8 of the 12 test episodes are the 02-23 flicker. Early warning is still not demonstrated (0 of 12, docs/13) and nothing here measures it.
* **Selection noise is of the same size as the effects.** Epoch curves vary by 0.03-0.06; the seed SD of one day is up to 0.14; the per-day paired SD is about 0.2. The ranking among the Transformer variants
  (single / ensemble-3 / ensemble-5) is not resolved by this design.
* **Strictly family-aware validation is not implemented.** Folds are day-grouped with a family-coverage flag; only two folds (02-28, 03-02) lack their family in training; 02-22 still sees 02-14 (same family), 02-15 still sees 02-20 and 02-21.
  The 02-20 folds are host-disjoint but same-day.
* **Training mix and features.** 02-20 is a 70,000-row sample (not the 99.2% of the served model's train set); feature hygiene (24 constant features, identity-like graph/`has_ip_data` columns, the flow_count dependence of seed 1: docs/16 F3, F8,
  action 4), causal windows (action 12), secondary label definitions (action 5) and the CIC-2017 re-extraction (action 6) are untouched.
* **Operating points do not transfer across days** (OOF FPR 0%-3.5% at a 1% budget); calibration remains per network.
* **Hyper-parameters of neither family were tuned.** The tree has fixed defaults; the Transformer is the converged recipe at 20 epochs.
* The sealed test is now used. It cannot be used again for selection; new independent evidence has to come from new days or networks (docs/16 actions 6, 7, 11).

## 7. Reproduce

```text
python -m scripts.build_lodo_v4                                   # per-day cache from train.npz/val.npz (test.npz is not opened)
python -m eval.lodo_v4_run oof --seeds 1 2 3 4 5 --epochs 20      # 45 runs + baselines -> checkpoints_lodo_v4/oof/
python -m eval.lodo_v4_run select                                 # docs/lodo_v4/selection.json (the frozen rules of section 0)
python -m eval.lodo_v4_run final                                  # opens the sealed test ONCE -> docs/lodo_v4/test_sealed.json
python -m eval.lodo_v4_run export                                 # flat tree arrays + docs/lodo_v4/hgb_export.json
python -m eval.lodo_v4_render                                     # docs/lodo_v4/tables.md (every table above)
python -m eval.report_v4                                          # docs/17-results-per-day.md + docs/results_per_day_v4.json
python -m pytest tests -q
```
