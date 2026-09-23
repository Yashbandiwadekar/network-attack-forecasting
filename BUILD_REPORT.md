# BUILD REPORT (INTERIM, updated 2026-09-23, end of day)

Interim status, not the final report -- work continues in a later session. `docs/AUDIT.md`'s
Part A status column has been updated to match everything below. This commit is being pushed to a
branch for review, not merged; none of the project's original checkpoints, processed data, or
`docs/04-*` reports (other than newly-added `*_v2`/`*_REGEN`/`*_unsw` files) have been touched or
overwritten.

## Findings status

| ID | Status | Files changed | Note |
|---|---|---|---|
| S13 | FIXED | `scripts/check_robustness.py`, `scripts/check_adversarial_robustness.py` | Added the missing `graph_embed_*` merge. Both scripts ran on `configs/real_data.yaml`. |
| E1 | IN PROGRESS | `pipeline/build_dataset.py`, `configs/real_data_v2.yaml` | Day-disjoint split built into `data/processed_real_v2/`. Model NOT yet retrained or re-evaluated on it. |
| E8 | IN PROGRESS | `pipeline/build_dataset.py` | Split drops sequences whose window span crosses a day boundary. Reported 0 dropped in the v2 build. Not independently verified. |
| S8 | IN PROGRESS | `eval/lofo.py` | Runner written. Only a 1-epoch smoke run on one fold (command_and_control) has been done, so no LOFO result exists yet. |
| Everything else (E2-E7, E9-E11, S4-S7, S9-S12, D1, D2) | NOT STARTED | | E7 stays open by your decision. D1 waits on the dataset download. |

## Measured today

- `pytest tests/`: 157 passed at start, 160 passed now (3 new tests for the day split and LOFO folds).
- Robustness re-measured on the 41-feature checkpoint (`checkpoints_real`): large benign transfer peaks at 0.037 (PASS). PGD evasion (epsilon 1.5 std, 25 steps) drops t+1 infiltration probability from 0.9975 to 0.0000. **The evasion weakness is real on the current model and is unfixed.**
- v2 split (`configs/real_data_v2.yaml`): train 1,239,090 / val 9,110 / test 8,731 sequences. Test days 02-16, 02-23, 03-01, 04-02. Command-and-control (03-02) is in train only, because it is the only C2 day; it is held out only in LOFO.

## Not to quote

- The 1-epoch LOFO smoke run (AUROC 0.53 held-out C2) is a pipeline check, not a result. I deleted its output file.

## Known issues found

1. `eval/metrics.py::threshold_at_fpr` can return `inf` when the val split has no positives above the budget (seen in the smoke run), so the operating-point metrics are all zero. Fix belongs to the E5 work.
2. v2 train is 98% one day (02-20, ~1.2M sequences, DDoS on real IPs). Val (9.1k) and test (8.7k) are small, so confidence intervals (E10) matter more.
3. `chronological_split` and the old `data/processed_real/` are untouched.

## Artefacts

- New, safe to delete: `data/processed_real_v2/`, `configs/real_data_v2.yaml`, `eval/lofo.py`, `build_v2.log`, `checkpoints_real_v2_lofo/` and `data/processed_real_v2_lofo/` (smoke-run outputs).
- Untouched: `checkpoints_real/`, `data/processed_real/`, all `docs/04-*` reports. Backups in `../_backup_phase0/`.

## D1: UNSW-NB15 added (2026-09-23)

Raw CSVs (`UNSW-NB15_1..4.csv`, 587 MB, on `V:\Datasets\UNSW NB15\CSV Files`, downloaded by the user)
confirmed to carry real `srcip`/`dstip` and Unix `Stime`/`Ltime` timestamps — unlike CICIoT2023
(verified separately: no IPs, no timestamps, ruled out) and unlike 9/10 CIC-IDS-2018 days.

New files: `pipeline/adapters/unsw_nb15.py` (column mapping, mirrors `pipeline/adapters/ctu13.py`),
`pipeline/mitre_mapping.py::unsw_label_to_stage`/`UNSW_LABEL_TO_STAGE` (9 UNSW attack categories ->
stage; only `Reconnaissance` -> reconnaissance and `Worms` -> lateral_movement are mapped to a
kill-chain stage with any confidence; `Backdoor(s)`/`Exploits`/`Shellcode` -> initial_access;
`Generic`/`DoS`/`Fuzzers`/`Analysis` deliberately left as `impact`, excluded from the 5-way head,
same treatment as CIC's own DoS/DDoS — see the file's comment for why), `pipeline/build_unsw_dataset.py`,
`configs/unsw_nb15.yaml`, `tests/test_unsw_adapter.py` (4 new tests, 164 total passing).

Built `data/processed_unsw/`: 108,372 sequences (75,845 / 16,238 / 16,289 train/val/test, chronological
per-host split — NOT day-disjoint, since UNSW-NB15's attacks are interleaved across a 4-week capture
rather than day-partitioned by family; this dataset's value is as a *held-out dataset*, not an
internally leak-free one). Real counts: 2,845 reconnaissance windows, 31 lateral_movement (Worms),
8,248 initial_access, 6,979 impact.

**Ran the zero-shot cross-dataset eval** (`eval.benchmark.run_cross_dataset`, train=CIC-IDS-2018
`checkpoints_real` [the pre-E1-fix v1 checkpoint — v2 not yet trained], test=UNSW-NB15) ->
`docs/04-evaluation-unsw_cross_from_real_data.md`. **Result, reported honestly, not spun:**

- World model, zero-shot CIC->UNSW: F1 0.255 @0.5 threshold, F1 0.371 @5% FPR budget. Stage macro-F1 0.187.
- Native UNSW baselines (trained on UNSW's own train split) are far stronger: LR-stacked F1 0.985,
  Markov 0.995, persistence 0.995.
- **The CIC-trained model does not generalise well to UNSW-NB15 zero-shot.** This is real, negative
  evidence — it directly undercuts any "generalises to unseen attacks" claim, which is consistent
  with E1's finding rather than a fix for it. I am not presenting this as a win. It should be
  reported alongside E1 in the final audit response, not instead of fixing E1.
- Persistence/Markov being ~0.995 on UNSW-NB15 too suggests the same short-attack-session
  autocorrelation problem E6 describes exists in this dataset as well.

**Not done:** no native UNSW-NB15 model has been trained (`checkpoints_unsw` doesn't exist). The
cross-dataset run against `configs/real_data_v2.yaml` (the day-disjoint checkpoint) hasn't happened
yet either, because that checkpoint doesn't exist yet (see below) — worth re-running once it does,
since the v1 checkpoint used here is the one E1 says memorised its own test sessions.

## v2 transformer trained (2026-09-23)

`checkpoints_real_v2/world_model_best.pt`, 15 epochs, best val loss at epoch 15 (0.908). Val loss
never converged smoothly (oscillated 0.9-1.25 the whole run) -- the day-disjoint val days really
are a different distribution from train, as intended. Re-measured on the v2 (day-disjoint) test
set, 8,731 sequences -> `docs/04-evaluation-real-v2.md`:

- Next-step F1 @ 0.5 threshold: World Model 0.431 vs label-persistence ORACLE 0.878 (gap widens
  sharply vs the old leaky split's 0.917 vs 0.988).
- Lead time: 628 real transitions (vs 32 on the old split), **93.5% missed**, only 3.7% detected
  early. This is the honest number the old "0 missed, 46.9% early" result (measured on 32
  near-duplicate re-onsets) was overstating.
- This confirms E1's core finding: the old headline numbers came from train/test session overlap,
  not real generalisation.

## Correction to yesterday's report

I previously flagged `threshold_at_fpr` returning `inf` as a bug. On inspection it's correct
behaviour (sklearn's `roc_curve` legitimately returns `inf` as "predict nothing" when no threshold
meets a very strict FPR budget with degenerate/oracle scores) -- only the JSON serialization of
`inf` in the LOFO smoke output looked broken. Not a real bug; retracting that finding.

## Honest-metrics fixes (E3, E4, E5, E6) -- 2026-09-23

All four implemented in `eval/metrics.py`, `eval/benchmark.py`, `models/baseline_lr.py`,
`models/markov_baseline.py`. 9 new tests (`tests/test_honest_metrics.py`,
`tests/test_persistence_on_predicted_label.py`), 173 total passing. Verified end-to-end by
re-running `eval.benchmark` on the v2 checkpoint (see `docs/04-evaluation-real-v2.md`).

- **E3 (lead time ignores false alarms):** `lead_time_metrics` now also scores every sequence
  that stays benign for the whole horizon, reporting `false_alarm_rate` and `alarm_precision`.
  Measured on v2: **alarm precision 1.5%** (2,735 false alarms against 41 true early alarms) --
  matches the audit's own hand-measured "~1%" almost exactly, now produced automatically.
- **E4 (stage macro-F1 mislabelled "5-way"):** `stage_metrics` reports `n_classes_present` and
  per-class `support`; the report header is generated from these instead of hard-coded. Added a
  `f1_macro_attack_only` column (macro-F1 over attack classes, excluding benign) alongside the
  existing all-class macro-F1.
- **E5 ("5% FPR" understates the model):** added 1% and 0.1% FPR budget tables plus a
  threshold-free AUROC/AUPRC table, alongside the original 5% table (kept, not replaced, with an
  inline note not to quote it alone).
- **E6 (persistence/Markov are oracles):** both are now labelled
  `[ORACLE -- reads true current label, not deployable]` everywhere they appear in a report.
  Added `models/baseline_lr.py::PersistenceOnPredictedLabel` -- fits its own last-window
  classifier to predict the current label from features, then persists that prediction forward.
  Measured on v2: oracle F1 0.878 vs deployable-persistence F1 0.153 @ default threshold -- the
  real gap E6 asked to expose.
- Applied to both `run()` (single-dataset) and `run_cross_dataset()` in `eval/benchmark.py`.

## GPU utilization (user request, 2026-09-23)

Added `pin_memory=True` + non-blocking transfer in `models/train.py`, and bumped `batch_size`
64->512 in `configs/real_data_v2.yaml` and `configs/unsw_nb15.yaml` only (NOT `configs/real_data.yaml`
or other pre-existing configs, to keep `checkpoints_real` reproducible). Confirmed working (2,422
steps/epoch instead of 19,361 on the LOFO folds), but GPU utilization is still only ~13% --
the model itself (d_model=64, 3 layers) is just small enough that even large batches don't need
much compute per step. Said this plainly rather than overclaiming the fix.

## Waiting on you

- Nothing blocking right now. LOFO folds are running in the background.

## S8: leave-one-attack-family-out results (2026-09-23)

All 4 folds complete (10 epochs each): `docs/lofo_results_v2.json`, checkpoints under
`checkpoints_real_v2_lofo/<family>/`. Found and fixed a real bug along the way: `eval/lofo.py`'s
`evaluate_fold` pushed the entire test split through the model in one forward pass; the `impact`
fold's test set (the DDoS days) is 1.23M sequences and OOM'd a 16GB GPU mid-run (7+ GiB single
allocation). Root cause was the missing batching, not a fluke -- fixed with a batched
`_predict_infiltration` helper (batch_size=8192), added 4 regression tests
(`tests/test_lofo.py`), re-ran only the failed fold's evaluation against its already-trained
checkpoint (training itself had completed fine before the crash). 177 tests passing.
**Same bug pattern exists in `eval/benchmark.py::_world_model_predictions`** (also an unbatched
`model(ds.X)` call) -- harmless today since every dataset it's called on (CIC-IDS-2018,
UNSW-NB15) is small enough (\<20k sequences) to fit in one batch, but it would OOM the same way on
a larger test split. Not fixed (out of scope for this pass, no observed failure), flagged here
per the audit's "same bug pattern elsewhere" rule.

**Results — AUROC on the held-out family's own days (never seen during that fold's training):**

| Held-out family | Held-out days | Test sequences | Positives | AUROC | AUPRC |
|---|---|---|---|---|---|
| initial_access | 02-14, 02-22, 02-23, 04-02 | 11,369 | 1,549 | 0.612 | 0.499 |
| lateral_movement | 02-28, 03-01, 04-02 | 8,319 | 1,728 | **0.432** | 0.187 |
| command_and_control | 03-02, 04-02 | 4,666 | 2,028 | 0.531 | 0.404 |
| impact (DDoS) | 02-15, 02-16, 02-20, 02-21, 04-02 | 1,234,772 | 4,655 | 0.872 | 0.035 |

**This is a real, negative finding and should be reported as one.** AUROC 0.5 is chance-level;
0.432 is *worse than chance*. Only two families show any real signal:
- `impact` (DDoS) generalises well (AUROC 0.872) -- but DDoS is the one family the project already
  has abundant real-IP, per-host data for (E7), so this is the least surprising result, not
  evidence the model generalises to genuinely novel attack shapes.
- `initial_access` shows weak-but-real signal (0.612).
- `lateral_movement` and `command_and_control` -- the two families with the fewest real
  training days available once held out -- show no usable signal at all.

**Conclusion for S8/PS's "generalise to unseen attack patterns" claim:** not supported by this
evidence. The model generalises to a held-out DDoS day (E7's flood-heavy setting) but not to the
lower-data attack families. This should go in the final report plainly, not softened.

## CIC->UNSW-NB15 cross-dataset, re-run on v2 checkpoint (2026-09-23)

`docs/04-evaluation-unsw_cross_from_real_data_v2.md`. Same direction as the LOFO result, and
worse than the v1 checkpoint's cross-dataset number: **AUROC 0.443 -- below chance.** Alarm
precision on the lead-time metric is 0.1% (11,390 false alarms against essentially no true early
warnings). Native UNSW-NB15 baselines score AUROC 0.99+ on their own data, so this isn't
"UNSW-NB15 is unlearnable" -- it's specifically that the CIC-trained model's zero-shot transfer is
this weak. Consistent, independent confirmation (via a completely different dataset and method)
of what the LOFO folds already showed: this model's claim to generalise beyond the CIC-IDS-2018
attack sessions it trained on is not supported by the evidence gathered so far.

## E9: CTU-13 cross-dataset report regenerated (2026-09-23)

Written to `docs/04-evaluation-ctu13_cross_from_real_data_REGEN.md` -- **not** overwriting the
original `docs/04-evaluation-ctu13_cross_from_real_data.md` (a protected report per the project
rules); left both on disk pending your confirmation to swap.

The LR rows did change as the audit expected from the scaler fix (e.g. LR-last-window F1 0.014 ->
0.012 @ 0.5 threshold -- small but real). **Unexpected finding**: the World Model row also
changed (F1 0.001 -> 0.006 @ 0.5 threshold), which the audit's own E9 text says should NOT happen
("the world-model row is unaffected: it uses the CIC scaler"). Same checkpoint
(`checkpoints_real/world_model_best.pt`, trained 2026-09-17), same train config, `model.eval()` is
called correctly (no dropout-randomness explanation). The CTU-13 `test.npz` on disk carries 41
features and was last rebuilt 2026-09-19 -- two days after the checkpoint's training date and
after the GNN Phase-3 graph-embedding columns landed (`ed065b6`, 2026-09-17). My working
hypothesis, **not confirmed**: the original report's world-model row was computed against an
older build of the CTU-13 processed data (pre- or differently-aligned graph-embedding columns),
and got stale for a reason beyond the one E9 named. I have not chased this further -- it doesn't
change either report's conclusion (both show the world model failing to generalise to CTU-13 at
the default threshold), but the report should say this rather than present the regenerated numbers
as a clean drop-in replacement.

## S4 (PCAP/PCAPNG-only input) and S5 (real-model uploads) -- FIXED, 2026-09-23

**S4 finding was narrower than it looked.** `pipeline/packet_features.py::load_pcap` already
parsed genuine `.pcapng` files correctly -- scapy's `PcapReader` class dispatches on the file's
magic bytes, not its extension (verified with a real `PcapNgWriter`-produced file, magic
`\x0a\x0d\x0d\x0a`, not a renamed `.pcap`). The actual rejection was the Streamlit uploader's
`type="pcap"` restriction. Fixed: `type=["pcap", "pcapng"]`; confirmed at the DOM level after the
fix (`accept="application/streamlit,.pcap,.pcapng"`).

**The PCAP-only path itself was genuinely missing** -- a flow CSV was mandatory; PCAP only ever
supplemented one. Added `pipeline/packet_features.py::build_flow_records`: aggregates raw packets
(now also capturing TCP SYN/ACK/FIN/RST/PSH/URG flags, which `load_pcap` didn't extract before)
into per-flow records in the same normalized schema `clean_and_normalize` produces from a CSV --
merges both directions of a conversation into one flow (CICFlowMeter's own definition), no
inactivity timeout (documented simplification for a bounded demo capture, not fabricated data).
`app/streamlit_app.py::_process_uploads` now accepts `flow_csv_path=None` and derives flow records
from the PCAP alone in that case.

**S5**: uploads were only ever wired up under the synthetic-data config -- selecting "Real
CIC-IDS-2018 (trained model)" always replayed the bundled dataset with no upload option at all.
Unified both branches behind one "use bundled sample vs. upload" checkbox (label adapts to which
model is selected), so an upload is now scored by whichever model the sidebar has selected. Added
an explicit `📊 Scored by: **<model>**` caption above every result, bundled or uploaded.

**Security (rule 3), while touching the upload path:** added explicit file-size limits
(`MAX_CSV_UPLOAD_MB` / `MAX_PCAP_UPLOAD_MB` = 300 MB each, checked before any parsing) on top of
the server-wide 1024 MB ceiling already in `.streamlit/config.toml`; upload processing errors are
now caught and shown as a plain message (no stack traces to the user); filenames on disk stay
fixed (`upload_flows.csv` / `upload.pcap` or `.pcapng`), never taken from the uploaded filename, so
there's no path-traversal surface.

**Tests**: `tests/test_packet_features.py` (7 tests -- classic pcap, genuine pcapng, flag capture,
flow merging, ICMP-only rejection) and `tests/test_streamlit_uploads.py` (2 tests, calling
`app.streamlit_app._process_uploads` directly with a real generated PCAP -- confirms non-zero
packet-level features and correct host/window derivation with no CSV at all). 186 total passing.

**Verified live** (`streamlit-demo` preview): both branches (synthetic and real-data configs) show
the upload widgets correctly when "bundled sample" is unchecked, both uploader `type=` lists
render as expected including PCAPNG, the "Scored by" caption appears correctly for the bundled
path in both branches, and the bundled real-data replay (pre-existing, untouched code) still works
end to end (9,194 hosts, alerts rendering). Did not inject an actual file through the browser's
file input (no such capability in the available browser tools) -- relying on the direct-call
integration test for that half of the proof instead.

## S6/S7 (Recon/Exfiltration/DoS-DDoS stage handling) -- FIXED, 2026-09-23

**Root cause, not previously stated this precisely:** the trained stage classifier has zero real
Reconnaissance examples (S6) and every DoS/DDoS ("impact") window is masked OUT of its training
loss entirely (`models/train.py`) -- so its own softmax has literally never been taught either
class. Measured: it fills the impact gap with `command_and_control` 570/684 times (S7). This
isn't a bug to patch in the classifier; the classifier has nothing to learn from for these
classes on real data.

**Fix:** `models/forecast.py::_heuristic_stage_override`, wired into `ForecastEngine.rollout` and
`rollout_batch` -- the two functions behind every stage annotation the app and the lead-time
metric show. Re-applies the SAME kind of feature-derived signal already used to build
Reconnaissance *training* labels (`apply_reconnaissance_heuristic`) to the model's own
*prediction* instead: extreme flow-volume + low destination diversity -> `impact`; high
`port_scan_score` -> `reconnaissance`. Thresholds are z-scores against the checkpoint's own
`scaler.npz` mean/std -- no new calibration artifact, no invented numbers.

**Discovered while scoping this:** `models/response.py` (`RESPONSE_PLAYBOOK`), `models/cve_lookup.py`
(the CVE snapshot has curated entries for `impact` and `reconnaissance` already), and
`models/narrative.py` (`_STAGE_PHRASING`) were ALL already fully wired to handle `impact` and
`reconnaissance` as first-class stage values -- the only thing missing was the classifier's output
space ever producing them. This significantly de-risked the fix: no downstream consumer needed
changes.

**Disclosure ("never invent labels, say so wherever shown"):** every override is reported back via
a new `stage_is_heuristic` field and shown in the UI as "heuristic override on
[flow-volume/port-scan] signature, not the trained classifier" (`_stage_disclosure_note`,
`app/streamlit_app.py`). `impact` is also rendered as its own badge outside the 5-way kill-chain
stepper (it isn't one of `config["mitre_stages"]`), instead of just leaving no pill lit. Whenever
`exfiltration` is shown at all (only ever on the synthetic sample), the same caption mechanism
adds "synthetic, demo-only label -- not present in real CIC-IDS-2018 data."

**Tests**: `tests/test_stage_heuristic.py` (8 tests -- the heuristic function directly, and its
wiring into `ForecastEngine`, including that it degrades gracefully to a no-op for the
pre-existing minimal test config that has no `features` section at all). 194 total passing, no
regressions in `test_forecast_rollout.py`/`test_narrative_and_response.py`.

**Verified live**: ran the synthetic-sample demo end to end -- the "EXFILTRATION" pill lights up
correctly with the disclosure caption directly beneath it in both the alert card and the host
drill-down view; a genuinely benign host (10.0.0.5) shows no caption, confirming the heuristic
stays silent on ordinary traffic. The synthetic sample's 3 hosts didn't happen to exercise the
impact/recon heuristic paths live; those are covered by the direct unit tests instead.

**Honest limitation stated in `docs/03-mitre-mapping.md`**: this is a heuristic layered on top of
an honestly-limited classifier, not a fix to the classifier's own weights -- it catches the two
specific failure modes the audit measured (a flood, a scan), not general five-way understanding.

## Next

1. E8 (split embargo) is already implemented as part of `day_disjoint_split` (drops sequences
   whose span crosses into a different day) -- worth confirming this explicitly in the final report.
2. E10 (multi-seed + CIs), E11 (report/README hygiene).
3. D2 (CAPEC linkage) -- not yet started.

---

# WORK ORDER RESPONSE (started 2026-09-23, branch `builder/audit-fixes-2026-09-23`)

| W-id | Finding | Status | Files changed |
|---|---|---|---|
| W1 | G1 | FIXED | `README.md`, `docs/05-related-work-and-competitive-landscape.md`, `docs/04-evaluation-ctu13_cross_from_real_data.md` (now the regenerated report), `docs/archive/04-evaluation-ctu13_cross_from_real_data_RETRACTED-2026-09-23.md` |
| W2 | G5 | FIXED | `pipeline/packet_features.py`, `tests/test_packet_features.py` |
| W3-W12 | | NOT STARTED | |

## W1 -- retracted CTU-13 number (FIXED)

Owner approved swapping the regenerated report in and archiving the original (2026-09-23). The
original is kept at `docs/archive/...RETRACTED-2026-09-23.md` with a dated retraction note on top;
the regenerated report now sits at the original path with a header explaining the swap. README and
`docs/05` now state the model does **not** transfer (F1 0.009, AUROC 0.517, attack-class stage F1
0.000 -- all read from the regenerated report, not carried from memory).

Acceptance (`grep -rn "0\.534" --include=*.md .`, excluding the auditor's own AUDIT.md/WORK_ORDER.md):
```
./docs/04-evaluation-real.md:30:| Baseline (LR, stacked window) | 0.534 | 0.364 | 1.000 | 0.014 |
./docs/archive/04-evaluation-ctu13_cross_from_real_data_RETRACTED-2026-09-23.md:1:> **RETRACTED 2026-09-23.** The World Model figures below (including F1 0.534 at the 5% FPR budget)
./docs/archive/04-evaluation-ctu13_cross_from_real_data_RETRACTED-2026-09-23.md:36:| World Model (Train: CIC-IDS-2018 / Test: CTU-13) | 0.534 | 0.453 | 0.651 | 0.028 |
./README.md:111:version of this README quoted F1 0.534; that number came from a 33-feature checkpoint and dataset
```
Every remaining hit is either a retraction note or unrelated: `docs/04-evaluation-real.md:30` is the
CIC-IDS-2018 LR-stacked-window baseline's F1 -- a coincidental match, not the CTU-13 figure.

## W2 -- PCAP inter-arrival-time unit bug (FIXED)

`pipeline/packet_features.py::build_flow_records` now scales `iat_mean/std/max` by 1e6 (CIC's
microseconds; it was seconds, so PCAP uploads fed the model IAT 10^6x too small). Checked the other
fields against the CSV path as asked: `duration_s` was already correct, and **byte counts also
disagreed** -- `payload_size` was the whole IP payload (includes TCP/UDP header) while CIC's
`TotLen Fwd/Bwd Pkts` is L4 payload only. Added `l4_payload_size` to `load_pcap` and use it in
`build_flow_records` (`payload_size` left untouched for the packet-level features).

Acceptance: `tests/test_packet_features.py::test_pcap_and_csv_paths_produce_matching_window_features`
builds the same 2-flow, 10-packet traffic as a real PCAP and as a CIC-format CSV (expected values
computed independently in the test), runs both through `build_flow_windows`, and asserts 13 window
features agree (flow_count, total_packets, total_bytes, mean_duration, syn/ack/fin/psh ratio,
mean/var/max_iat, bidir_ratio, tcp_ratio) plus mean_iat > 1e5 (microsecond scale). Passes; full
suite passes. `data/raw/pcap/synthetic_sample.pcap` cannot exercise this (all 944 flows are
single-packet), so the test generates its own capture.

## W3 -- packet features into a flow-only model (G11) -- FIXED (with a premise correction)

`app/streamlit_app.py::_is_flow_only_model` reads the checkpoint's own `processed_dir/metadata.json`
(`flow_only` / `packet_features_available`); `_process_uploads` then skips the packet merge, so
`merge_packet_features(..., None, ...)` zero-fills all packet features and sets `has_packet_features=0`.
**Premise correction:** the work order expected the synthetic-data model to get populated packet features.
It does not qualify: `data/processed/cicids2018/splits/metadata.json` (the synthetic-data model's dataset)
is ALSO `flow_only: true`, because `pipeline/build_dataset.py` always zero-fills packet features. Both
shipped checkpoints are flow-only, so both get zeros. The "populated" branch applies only to a model whose
metadata lacks the flag; it is tested with a hypothetical packet-trained config.
Evidence (`pytest tests/test_streamlit_uploads.py -s`, PCAP upload of a real generated SYN scan):
```
configs/real_data.yaml max packet features: {mean_ttl 0.0, var_ttl 0.0, mean_window_size 0.0, frag_ratio 0.0, mean_payload_size 0.0, std_payload_size 0.0, port_scan_score 0.0, retransmit_ratio 0.0, has_packet_features 0.0}
configs/default.yaml max packet features:   (identical, all 0.0)
packet-trained (hypothetical): {mean_ttl 64.0, ..., port_scan_score 1.0, has_packet_features 1.0}
3 passed
```
Side effect: the port-scan reconnaissance heuristic (uses `port_scan_score`) is now also inert for PCAP
uploads to these models, consistent with how they were trained.
