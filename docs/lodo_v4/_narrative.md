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

{LODO}

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

{SEALED}

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

{BENCH}

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
