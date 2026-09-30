# BUILD REPORT (INTERIM, updated 2026-09-23, end of day)

Interim status, not the final report -- work continues in a later session. `docs/AUDIT.md`'s
Part A status column has been updated to match everything below. This commit is being pushed to a
branch for review, not merged; none of the project's original checkpoints, processed data, or
`docs/04-*` reports (other than newly-added `*_v2`/`*_REGEN`/`*_unsw` files) have been touched or
overwritten.

## Findings status (rebuilt for W10 from the sections below; keyed to audit ID and work-order item)

| Audit ID | W-item | Status | Where documented |
|---|---|---|---|
| S13 | - | FIXED | Robustness scripts on 41-feature schema (see W8/W11 runs) |
| E1 | W7 | PARTIALLY FIXED | Day-disjoint split built and model retrained (`checkpoints_real_v2_converged`); F1 0.370 / AUROC 0.706 vs v1 0.917; val curve not stable, no multi-seed CIs |
| E8 | - | PARTIALLY FIXED | Day-boundary embargo in `day_disjoint_split`; 0 dropped, which is vacuous with one pseudo-host per day |
| S8 | - | FIXED (negative result) | LOFO results section: AUROC 0.432-0.872, no unseen-family generalisation except DDoS |
| E2 | W6 | PARTIALLY FIXED | 628 windows / 181 episodes / 3 pseudo-hosts / 96% one day (re-measured) |
| E3, E4, E5, E6 | W9 (E5/lead-time) | FIXED | Honest-metrics section; W9 adds achieved FPR to lead-time section |
| E7 | - | OPEN by owner decision | |
| E9 | W1 | FIXED | CTU-13 report regenerated and swapped in; retraction in README |
| E10, E11 | - | NOT DONE | No seeds/CIs; README still partly stale |
| S4, S5 | W2, W3 | FIXED | PCAP-only path, real-model uploads, IAT unit fix, flow-only packet zero-fill |
| S6, S7 | W8 | FIXED | Heuristic stage override, now gated on infiltration probability |
| G4 (UNSW adapter) | W5 | FIXED | AUROC 0.4239 re-measured, negative |
| G12 (deserialisation) | W4 | FIXED | `weights_only=True`; two allow_pickle loads remain, disclosed |
| G10 | W12 | FIXED | Batched benchmark inference |
| Adversarial evasion | W11 | PARTIALLY FIXED | Threat model + OR-gate done (recovers evasion); scale-invariance run truncated at 25/30 and did not stop the evasion (0.605 to 0.0000) |
| D1 | W5 | PARTIALLY FIXED | UNSW-NB15 added; no LANL/auth telemetry |
| S9 | - | FIXED | `app/streamlit_app.py` caches a downsampled `shap_background.npy` instead of loading the full training file (added in `f1e432c`) |
| D2 | - | FIXED | `models/cve_lookup.py` maps MITRE stages to curated CAPEC IDs, rendered in the UI (added in `f1e432c`) |
| S10, S11 | - | NOT STARTED | |
| W13 | H1 | FIXED | `app/api.py` hardened: off by default, bearer auth, webhook allowlist + SSRF address check |
| W14 | H2 | FIXED | `requirements.txt` now declares fastapi/pydantic/uvicorn/requests/networkx |
| W15 | H3 | FIXED | `scripts/stream_consumer.py` computes real graph/graph-embedding features per batch, uses `feature_columns(config)` |
| W16 | H4 | FIXED | 0-byte `docs/demo.mp4`, `docs/presentation.pdf` removed; README checklist corrected |
| W17 | H5 | FIXED | `docs/AUDIT.md` S6 row corrected -- reconnaissance unreachable on any shipped checkpoint |
| W18 | H6 | VERIFIED, no action needed | Branch already tracks its own remote, not `origin/master` |
| W19 | schema-drift class | FIXED | `models/checkpoint_io.py::validate_feature_names`, wired into `load_world_model` and `stream_consumer.py`, checked at load time by name and order |

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
- Lead time: 628 transition windows across 181 episodes on 3 day-level pseudo-hosts, 96% from
  2018-02-23 (vs 32 windows / ~2 episodes / 2 hosts on the old split; re-measured independently
  under W6 below, not "many hosts/days" as an earlier draft of this section said), **93.5% missed**,
  only 3.7% detected early. This is the honest number the old "0 missed, 46.9% early" result
  (measured on 32 near-duplicate re-onsets) was overstating.
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

**SUPERSEDED by W5 below (G4): this section's AUROC 0.443 used a broken adapter (constant-zero TCP
flags, un-converted IAT units) and must not be quoted. The re-measured, adapter-fixed number is
AUROC 0.4239 -- see the W5 row in the work-order table below.** Original text, kept for history:

`docs/04-evaluation-unsw_cross_from_real_data_v2.md` (since overwritten by the W5 rebuild). Same
direction as the LOFO result, and worse than the v1 checkpoint's cross-dataset number: **AUROC
0.443 -- below chance.** Alarm
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
2. E10 (multi-seed + CIs), E11 (report/README hygiene), S10, S11.

---

# WORK ORDER RESPONSE (started 2026-09-23, branch `builder/audit-fixes-2026-09-23`)

**W20/H7 note (2026-09-29): this section used to carry its own summary table, which was never
updated past W1/W2 and contradicted the body below it (audit finding H7). It's removed rather than
re-synced a second time -- the "Findings status" table at the top of this file is now the one and
only summary table; every row below documents its own status inline in its own section heading.**

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

## W4 -- arbitrary-code deserialization (G12) -- FIXED

New `models/checkpoint_io.py::load_checkpoint` loads with `torch.load(..., weights_only=True)`
(with an explicit numpy-safe-globals allowlist, only needed for the joint-GNN checkpoint's numpy
bool mask) and transparently reads either a JSON-string `config_json` (new saves) or the old
pickled `config` dict (existing checkpoints), so nothing on disk needed migrating.
`models/forecast.py`, `models/lstm_model.py`, `models/train_joint.py` now call it instead of
`torch.load(weights_only=False)`. `models/train.py` and `models/train_joint.py` now save via
`with_config_json(...)`, so future checkpoints carry a JSON config. `models/baseline_lr.py::BaselineModel.load`
now uses a `_RestrictedUnpickler` allowing only `sklearn.*`/`numpy.*`/`scipy.*`/this module (and
blocking dangerous builtins), instead of a bare `pickle.load`.

Acceptance evidence:
- `grep -rn "weights_only=False\|pickle.load(" models eval app --include=*.py` -> no matches.
- New tests `tests/test_checkpoint_io.py`: new-style roundtrip, a malicious `__reduce__` checkpoint
  is refused, `_RestrictedUnpickler` blocks `os.system`, and every existing `.pt` under
  `checkpoints*/` (8 files, including `checkpoints/joint_gnn_world_model_*.pt`) still loads. 211
  tests total passing (`.venv/Scripts/python -m pytest tests -q` -> `211 passed`).
- Same-score check on `checkpoints_real/world_model_best.pt` against the real-data test split
  (194,632 sequences): outputs from `weights_only=False` (old path) and `weights_only=True` (new
  path) are bit-identical (`torch.equal`), and infiltration F1@0.5 matches exactly: **0.917142**
  both ways.
- Same check repeated for the other two checkpoint types the audit's acceptance line covers:
  `checkpoints_real/lstm_baseline_best.pt` (4,000 test sequences, bit-identical outputs, F1@0.5
  0.871 both ways) and `checkpoints_real_v2/world_model_best.pt` (8,731 test sequences,
  bit-identical outputs, F1@0.5 0.4305 both ways -- matches the W12 re-measurement above).

**Review tightening (post-advisor):**
- `glob("checkpoints*/*.pt")` in `tests/test_checkpoint_io.py` was non-recursive and silently
  missed the 8 checkpoints under `checkpoints_real_v2_lofo/<family>/`. Changed to
  `glob("checkpoints*/**/*.pt", recursive=True)`; all 20 on-disk checkpoints (incl. the joint-GNN
  ones) now load and are covered by the parametrized test. `checkpoints_ctu13/` has no `.pt` files
  on disk, so it contributes 0 cases, not a gap.
- `_RestrictedUnpickler` had never round-tripped a real `BaselineModel`; added
  `test_baseline_model_fit_save_load_roundtrip` (fits on synthetic data, saves, reloads, predicts) --
  this caught a real allowlist gap (`numpy.ndarray`'s pickle reconstructor lives at the bare
  `numpy` module, not under an `numpy.*` submodule) which is now fixed.
- Replaced the builtins **blocklist** with an **allowlist** (`set`, `frozenset`, `slice`, `complex`,
  `list`, `dict`, `tuple`, `bytearray`) -- a blocklist can miss a dangerous builtin a reviewer
  would flag; an allowlist can only be too strict, never too permissive.
- **Not closed by this item, flagged for the record:** `np.load(..., allow_pickle=True)` in
  `models/dataset.py:57` (loading `.npz` splits) and the `pickle.load` inside
  `pipeline/graph_builder.py` for `window_graphs.pkl` are the same class of issue (arbitrary
  deserialization) but are outside G12's literal scope (`models/`, `eval/`, `app/` were the named
  directories, and `.npz`/graph-pickle loading of the project's OWN generated artefacts is lower
  risk than loading an externally-supplied checkpoint) -- not fixed in this pass.

## W8 -- gate stage override on infiltration probability (G7) -- FIXED

`models/forecast.py::_heuristic_stage_override` now takes `infiltration_prob` and returns
immediately (no override, `stage_is_heuristic=False`) unless it has crossed `windowing.alert_threshold`
(default 0.3 -- the same value `scripts/check_robustness.py` already uses as its own pass/fail
line). Both `rollout` (passes the just-computed `inf_prob`) and `rollout_batch` (passes each row's
freshly computed probability) now thread this through, so a stage label can no longer disagree with
a PASS-ing (benign) probability next to it.

Acceptance (`python -m scripts.check_robustness --config configs/real_data.yaml`):
```
OOD-benign capture (large legitimate transfer, 10.0.0.201 -> 203.0.113.200):
  infiltration probability per step: [0.0369, 0.0342, 0.0316, 0.0278, 0.0251, 0.022]
  peak: 0.0369 at step 0 (predicted stage: benign)
  PASS - peak stays below 0.3 despite unusual volume
```
Before the fix this same capture was labelled `stage: impact` at step 0 despite PASSing (per the
audit's finding); it is now `benign`. `pytest tests` still 211 passed.

**Strengthened further:** the 0.3 gate is below the app's lowest "flagged" severity level
(`SEVERITY_LEVELS` in `app/streamlit_app.py` starts at 0.15 "warning"), so the guarantee is strictly
stronger than the acceptance check asked for: the override can never fire on a window the UI itself
shows as unflagged (below 0.15), not just below the robustness script's own 0.3 pass line. Added two
direct unit tests (`tests/test_stage_heuristic.py::test_override_gated_off_below_alert_threshold`,
`::test_override_fires_above_alert_threshold`) confirming the same textbook flood signature is NOT
overridden at infiltration_prob=0.1 and IS overridden at 0.9. 213 tests passing.

## W12 -- batch benchmark's inference call (G10) -- FIXED

`eval/lofo.py::_predict_infiltration` extended with a `return_stage` flag (still batched at 8192,
unchanged default behaviour for existing callers) instead of writing a second batching helper.
`eval/benchmark.py::_world_model_predictions` now calls it instead of a single unbatched
`model(ds.X)` forward pass over the whole split — the same OOM pattern that hit `eval/lofo.py` on
the 1.23M-sequence `impact` fold (S8 section above), just not yet triggered here because every
dataset `_world_model_predictions` is called on today is small.

Acceptance: ran `eval.benchmark` against a throwaway copy of `configs/default.yaml` whose
`eval_report` path was redirected to `docs/04-evaluation_W12_check.md` (deleted afterwards, never
touching the real `docs/04-evaluation.md`) — once on the pre-change code (`git stash`) and once
after. **The two generated reports are byte-identical** (`diff` -> no output). `pytest tests -q` ->
`211 passed` both before and after.

**Correction/strengthening:** the first check above only exercised the synthetic split (72/68/72
sequences), which is smaller than the 8192 default batch size -- both old and new code took a
single batch, so it didn't actually prove batching correctness. Re-verified properly on the v2
(day-disjoint) test split, **8,731 sequences, forced `batch_size=16` -> 546 batches**, comparing the
old single-forward-pass code path directly against the new `_predict_infiltration(..., batch_size=16,
return_stage=True)` path on `checkpoints_real_v2/world_model_best.pt`:
```
N = 8731 -> num batches at bs=16: 546
probs allclose: True
stage identical: True
old (unbatched)      {'f1': 0.43050430504305043, 'precision': 0.54858934169279, 'recall': 0.354251012145749, 'false_positive_rate': 0.059594426817492066}
new (batched bs=16)  {'f1': 0.43050430504305043, 'precision': 0.54858934169279, 'recall': 0.354251012145749, 'false_positive_rate': 0.059594426817492066}
```
Also confirmed the benchmark run's `build_datasets` call did not perturb the protected synthetic
scaler: `git status --short data` shows no change to `data/processed/cicids2018/splits/scaler.npz`.

## W6 -- correct two overstated claims in the audit's own status table (G2, G6) -- FIXED

No code change, per the acceptance criteria. Both numbers re-measured independently from
`data/processed_real_v2/*.npz` (not copied from the auditor's own G2/G6 write-up), matching it
exactly:

1. **G2** (`docs/AUDIT.md` Part A, E2 row): reworded from "628 real transitions across many
   hosts/days" to "628 transition windows across 181 episodes on 3 day-level pseudo-hosts, 96% from
   2018-02-23", with the comparison to the original 32 stated as windows/episodes/hosts, not just a
   count. Same reword applied to `BUILD_REPORT.md`'s "Measured today" section. Re-measurement
   (`current_infiltration==0` sequences whose K-step trajectory contains an attack step, per
   `eval/metrics.py::lead_time_metrics`'s own definition of a transition):
   ```
   n_transitions: 628
   distinct hosts: 3 {NETWORK-2018-02-23, NETWORK-2018-02-16, NETWORK-2018-03-01}
   day concentration: 2018-02-23: 604 (96.2%), 2018-02-16: 12 (1.9%), 2018-03-01: 12 (1.9%)
   onset stage counts: initial_access 604, lateral_movement 12, impact(masked -1) 12
   episodes (consecutive-index runs collapsed): 181
   ```
   (Only Part A of `docs/AUDIT.md` was touched, per the work order; Part G's own G2 text was left alone.)

2. **G6** (`docs/04-evaluation-real-v2.md`): added a disclosure header stating the fabricated-traffic
   fraction. Re-measured directly from the split files (day = `window_end_time` truncated to date):
   ```
   val:  total 9110, april(fabricated) 2425  -> 26.6%   (2018-02-15: 3412, 2018-02-22: 3273, 2018-04-01: 2425)
   test: total 8731, april(fabricated) 1540  -> 17.6%   (2018-03-01: 3390, 2018-02-23: 3318, 2018-04-02: 1540, 2018-02-16: 483)
   ```
   Matches the audit's 26.6%/17.6% exactly. Note: this report will be regenerated in W7 (retrain) --
   the disclosure needs to be re-added there (or moved into the report generator) if W7 rewrites the
   whole file; flagged in the W7 section below.

Acceptance: both documents now state the corrected figures; `pytest tests -q` -> 222 passed
(no code touched, so unchanged from before this item).

## W5 -- UNSW-NB15 adapter fix (G4) -- FIXED

`pipeline/adapters/unsw_nb15.py::_normalize_columns` changed:
1. `iat_mean` now converts `(Sintpkt+Dintpkt)/2` from **milliseconds to microseconds** (`*1000`) to
   match CIC's `Flow IAT Mean` units -- previously never converted at all (the core G4 bug).
2. The six TCP flag ratios are no longer constant zero. Derived honestly, TCP flows only, one
   flag-equivalent per flow (not invented per-packet counts): `syn_cnt`/`ack_cnt` from the
   `synack`/`ackdat` handshake-completion timers being > 0 (a completed handshake structurally
   implies exactly one SYN and one final ACK); `fin_cnt`/`rst_cnt` from `state` == `FIN`/`RST`.
   `psh_cnt`/`urg_cnt` stay at zero -- UNSW-NB15 has no push/urgent signal anywhere in its schema,
   and inventing one would violate the "never invent labels/data" rule.
3. Rebuilt the UNSW-NB15 dataset into a **new** location, `data/processed_unsw_v2/` (via new
   `configs/unsw_nb15_v2.yaml`), never touching `data/processed_unsw/` or any protected artefact:
   108,372 sequences, same split sizes as before (75,845/16,238/16,289) since only feature values
   changed, not windowing.
4. Re-ran `eval.benchmark --train-config configs/real_data_v2.yaml --test-config
   configs/unsw_nb15_v2.yaml --output docs/04-evaluation-unsw_cross_from_real_data_v2.md` (this path
   already carries a `_v2` suffix, so overwriting the earlier broken-adapter version there is
   within the protection rule, not an exception to it). The new report lists every zero-filled or
   derived feature with its caveat, per the work-order's item 4.

**Feature-mean comparison (BUILD_REPORT acceptance table, train-split means, before vs. after):**

| Feature | UNSW before (broken) | UNSW after (fixed) | CIC (`real_data_v2` train, reference) |
|---|---:|---:|---:|
| `syn_ratio` | 0.0000 | 0.0134 | 0.0368 |
| `ack_ratio` | 0.0000 | 0.0134 | 0.2166 |
| `fin_ratio` | 0.0000 | 0.0137 | 0.0054 |
| `rst_ratio` | 0.0000 | 0.0000 | 0.0123 |
| `psh_ratio` | 0.0000 | 0.0000 | 0.0387 |
| `urg_ratio` | 0.0000 | 0.0000 | 0.0471 |
| `mean_iat` | 34.00 | 34,004.85 | 4,180,031.25 |
| `var_iat` | 0.0000 | 0.0000 | 29,328,377,118,720.00 |
| `max_iat` | 0.0000 | 0.0000 | 12,543,920.00 |

`rst_ratio`/`psh_ratio`/`urg_ratio` are honestly still zero (no derivable UNSW signal for them);
`syn_ratio`/`ack_ratio`/`fin_ratio` are no longer constant zero, though they measure something
structurally different from CIC's per-packet counts (documented in the report). `mean_iat` closed
~1000x of the gap (the ms->us fix); a further ~123x residual gap vs. CIC's own mean is a genuine
distributional difference (UNSW-NB15 flows are shorter/burstier on average), not a further bug.

**Re-measured AUROC: 0.4239** (was 0.443 under the broken adapter -- essentially unchanged, both
below-chance). **This is a real, negative result, reported honestly**: fixing the adapter did not
make the CIC-trained model transfer to UNSW-NB15; it only removed the confound of testing it on
obviously-wrong feature values. Native UNSW-NB15 baselines still score AUROC 0.99+ on their own
data (LR-stacked 0.9993, Markov/Persistence ORACLE 0.9969), so this remains independent
confirmation of E1/S8/LOFO's finding, not new evidence against it. Full table in
`docs/04-evaluation-unsw_cross_from_real_data_v2.md`.

Per the work order's binding constraint, **the old AUROC 0.443 must not be quoted as current
anywhere** -- `docs/AUDIT.md` Part A's D1 row and this file's earlier "CIC->UNSW-NB15 cross-dataset"
section are both now marked superseded, pointing to this section's 0.4239. (`docs/AUDIT.md` Part G's
own text was left untouched, per the work order's instruction to only edit Part A / W6 there.)

New tests: `tests/test_unsw_adapter.py` adds 5 cases (flags derived from handshake timers and
`state`, no-handshake -> no flags, RST state, flags never set for non-TCP rows, ms->us conversion) --
14 total in that file, 227 passing overall.

## W11 parts 1-2 -- adversarial threat model + reconstruction-error second gate -- FIXED (part 3 pending W7)

**Part 1 (threat model, written down, not just fixed-by-claim):** `README.md`'s "Known limitations"
section now states precisely what the PGD evasion requires: the attack drives down `flow_count`,
`total_packets`, `total_bytes` (the top-3 perturbed features, re-measured, not assumed) -- i.e. the
attacker must genuinely send less, lower-volume-looking traffic. For a flood (DDoS, brute-force at
scale -- the traffic class this project's real-IP data actually has, per E7), that defeats the
attack's own purpose. It is a real threat only for a low-and-slow intrusion that was never
volume-heavy. This reframing is stated as a precise limitation, not presented as a fix.

**Part 2 (second gate):** added `models/forecast.py::batched_reconstruction_errors` (vectorized
one-step reconstruction error over a whole split, for threshold calibration) and
`models/forecast.py::or_gate_alarm` (alarm if infiltration probability OR reconstruction error
crosses its own threshold). Wired into `scripts/check_adversarial_robustness.py`: the
reconstruction-error threshold is calibrated to the 99th percentile of the **val** split's
currently-benign one-step errors (never test), and the added false-positive cost is then
*measured* (not assumed) on the **test** split's own currently-benign windows.

Acceptance -- re-ran `python -m scripts.check_adversarial_robustness --config configs/real_data.yaml`:
```
PGD evasion attack: 25 steps, epsilon=1.5 std, step_size=0.15
  t+1 infiltration probability: 0.9975 -> 0.0000 (min reached: 0.0000)
  WARNING - evasion succeeded ...

  Second gate (W11 part 2): reconstruction-error threshold = 8.2628 (99th percentile of val-split
  currently-benign one-step errors).
    Reconstruction error before attack: 5.5295 (quiet)
    Reconstruction error after attack:  9.7673 (ALARMS)
    Added false-positive rate this threshold costs on the TEST split's own currently-benign
    windows: 1.06% (measured, not assumed).
    RECOVERED - the OR-gate still alarms on this evasion case.
```
**Real, positive result reported honestly**: on this specific evasion case, the OR-gate recovers
the alarm at a measured 1.06% added FPR (close to the 1% the 99th-percentile calibration targets,
so it generalises from val to test reasonably well here). This is evidence for the threat-model
argument above, not a claim the vulnerability is closed -- it is not wired into the app's own
alerting logic, and was only tested against this one synthetic attack capture, not a broader suite.

New tests: `tests/test_forecast_rollout.py` adds `test_or_gate_alarm_fires_on_either_signal` and
`test_batched_reconstruction_errors_matches_one_step_version` (cross-checked numerically against
the existing single-sequence `one_step_reconstruction_error`). 229 tests passing.

**Part 3 (scale-invariance augmentation) deliberately deferred to fold into W7's retrain, as a
separately-named run** -- see the W7 section for why it is kept out of the clean v1-vs-v2 retrain.

## W9 -- report achieved FPR in the lead-time section (G8) -- FIXED

`eval/benchmark.py::_format_lead_time_section` now takes `achieved_test_fpr` (the World Model's
own row from the already-computed 5%-FPR-budget `binary_metrics` table -- no new computation) and
adds a row plus a plain-language note when it diverges sharply (>2x the budget) from the budget it
was tuned for. Wired into both `run()` and `run_cross_dataset()`.

Acceptance -- regenerated `docs/04-evaluation-real-v2.md` (re-running `eval.benchmark` against the
existing, still-undertrained `checkpoints_real_v2` checkpoint -- this file is regenerated again,
converged, under W7 below):
```
| Achieved FPR on this test split, at the val-tuned 5%-budget threshold | 35.9% |
...
Audit G8/W9: the threshold above is tuned on the val split for a 5% FPR budget, then applied here
to the test split unchanged, exactly as a deployment would carry it forward. Here it came out
35.9% -- 7.2x the 5% budget it was tuned for. The operating threshold does not transfer across
days; this is a result worth stating plainly, not a footnote -- a defender who tunes on one day's
traffic and deploys the next day should expect the false-positive rate to move substantially, not
stay near the budget they picked.
```
35.9% matches the audit's own cited figure exactly (re-measured independently, not copied).
`pytest tests -q` -> 229 passed.

## W7 -- clean v2-vs-v1 comparison (G3, G6) -- FIXED (honest result: v2 does not converge)

Findings: the existing `checkpoints_real_v2` was actually trained at batch 64 (log shows 19,361 steps/epoch); the 512 in `configs/real_data_v2.yaml` was edited afterwards and never used. Real differences were epochs (15 vs 30) and split.
Retrain: `configs/real_data_v2_converged.yaml` (batch 64, 30 epochs, everything else identical), new dirs `data/processed_real_v2_converged`, `checkpoints_real_v2_converged`; existing v2 artefacts untouched. Fabricated April days **dropped** from val/test (chosen over spreading). Run WITHOUT W11 part 3 so the comparison stays attributable.
Evidence (re-measured): v1 F1 0.9171 / AUROC 0.9995 (194,632 test seq); v2 converged F1 0.3697 / AUROC 0.7058 (7,191 test seq). Val loss stayed noisy (best 0.8011 at epoch 11; epoch 25 spiked to 2.04) while train loss fell; not converged in the sense of a stable val curve. Full table/curve: `docs/04-evaluation-real-v2.md` (regenerated, includes W9 achieved-FPR row: 2.8% on this test split, alarm precision 13.2%, 91.2% missed of 628 transitions). The earlier "35.9% FPR" (W9) was on the old undertrained/fabricated-day version; the threshold instability is much smaller here, so that claim should not be generalised.
Caveat: test sets differ (v1 leaky split vs v2 3 days); no multi-seed CIs.

## W11 part 3 -- scale-invariance augmentation (separately-named run) -- PARTIALLY FIXED (truncated run, evasion still succeeds)

Run: `configs/real_data_v2_scaleinv.yaml` (identical to `real_data_v2_converged.yaml` plus `augmentation.scale_invariance: true`, factor range 0.3-3.0 on flow_count/total_packets/total_bytes, train split only). **The run was TRUNCATED at epoch 25 of 30** (usage limit; process died, no "Best val loss" line). I did not retrain; the results below use the `world_model_best.pt` saved through epoch 25, whose best val epoch is **epoch 2 (val 0.8136)**, so it is an early, barely-trained checkpoint. Val loss per epoch: 0.894, 0.814, 0.855, 0.891, 1.056, 0.976, 1.058, 0.915, 1.291, 1.156, 1.189, 1.164, 0.900, 1.013, 1.269, 0.832, 1.205, 0.869, 0.992, 1.102, 0.841, 0.921, 1.105, 0.893, 0.866 (train 0.336 to 0.282). Val loss is as unstable as in the clean run.

(1) `python -m scripts.check_adversarial_robustness --config configs/real_data_v2_scaleinv.yaml` (own checkpoint and scaler; `checkpoints_real` untouched):
```
infiltration probability before attack (K-step): [0.605, 0.9376, 0.977, 0.9837, 0.9879, 0.9916]
t+1 infiltration probability: 0.6050 -> 0.0000 (min reached: 0.0000)
Top perturbed: flow_count -1.5, unique_dst_ports -1.5, unique_dst_ips -1.5, has_ip_data +1.5, total_bytes -1.5
WARNING - evasion succeeded
Reconstruction error 5.4775 -> 9.5661 vs threshold 6.2790 (ALARMS); added test FPR 1.42%; RECOVERED by OR-gate
```
**Honest negative: augmentation did not stop the evasion** (0.605 to 0.0000; the attack now leans on destination-diversity features as well as volume). The clean baseline before attack is also weaker (t+1 0.605 vs 0.9975 on `checkpoints_real`, which is a different model, so not a like-for-like comparison). The OR-gate still recovers it.

(2) Same v2 test split (7,191 seq, days 02-16/02-23/03-01), t+1 infiltration @0.5, this checkpoint vs converged v2 (F1 0.370 / AUROC 0.706): F1 **0.203**, precision 0.934, recall 0.114, FPR 0.0021, AUROC **0.800**, AUPRC 0.583. Same test set, but different checkpoint epochs (epoch 2 here vs epoch 11), single seed, so F1 fell while AUROC rose; not a clean effect estimate.

Conclusion: W11 part 3 is not shown to help; only the second gate (part 2) helps. Not re-run to completion.

## Follow-up to W4 -- remaining pickle loads closed (owner approved 2026-09-24)

- `models/dataset.py::load_split`: `np.load(..., allow_pickle=False)`. Checked first that all 45
  processed `.npz` files across `data/` load without pickle (none contain object arrays).
- `pipeline/graph_builder.py::load_window_graphs`: bare `pickle.load` replaced by a restricted
  unpickler (only numpy, `WindowGraph`, pandas Timestamp types and a few builtins; anything else
  raises `Blocked global`). All 7 real `window_graphs.pkl` files still load (processed_real,
  v2, v2_converged, unsw, unsw_v2, ctu13, cicids2018).
- Tests: `tests/test_safe_loading.py` (4) -- Timestamp-key round trip, a malicious `os.system` pickle
  is blocked, an object-array `.npz` is refused, plain arrays load. Full suite: 239 passed.
- Scores unchanged: new loader returns arrays identical to the old `allow_pickle=True` load, and
  `checkpoints_real` still scores F1 0.917142 @0.5 on `data/processed_real` test (same as W4).
- A first grep missed some: `pipeline/build_ctu13_dataset.py` and four analysis scripts
  (`scripts/check_chronology.py`, `inspect_attack_distribution.py`, `inspect_attack_timing.py`,
  `inspect_true_timeline.py`) also used `allow_pickle=True`. All flipped to `False` (safe: every
  `.npz` under `data/` was verified pickle-free), and each file compiles. Final check,
  `grep -rn "allow_pickle=True\|pickle\.load(" --include=*.py .` (excluding `.venv` and the two
  restricted unpicklers): **no matches**. Writers use `pickle.dump`, which is not a code-execution risk.
- Not re-run: the CTU-13 builder and the four scripts themselves (compile-checked only).

---

# PACKET-AWARE PILOT ON UNSW-NB15 (started 2026-09-24; owner-approved pilot before the CIC/CICIoT downloads)

## Step 1 -- fast streaming PCAP parser (DONE)

`pipeline/fast_packet_windows.py` + `scripts/extract_packet_windows.py`. Reads raw frames with Scapy's
`RawPcapReader` (no dissection), hand-parses IPv4/TCP/UDP with `struct`, aggregates in bounded chunks and
runs one file per worker. No new dependency. Handles classic PCAP and PCAPNG (UNSW ships both, all named
`.pcap`: 21 classic, 42 pcapng) and Ethernet + Linux-cooked (link type 113, what UNSW uses).

**Parity with the existing Scapy path, on real UNSW packets** (first 150,000 packets of one classic and one
pcapng file, all 8 packet features per (src_ip, window)):
```
[classic pcap] 1.pcap  | scapy 3,343 pkt/s | fast 259,637 pkt/s (78x)  | matched windows 575/575  | max|diff| = 0.0 for all 8 features
[pcapng]      13.pcap  | scapy 3,277 pkt/s | fast 161,437 pkt/s (49x)  | matched windows 110/110  | max|diff| = 0.0 for all 8 features
```
Also `tests/test_fast_packet_windows.py` (5 tests: Ethernet + SLL parity with `load_pcap`, pcapng, chunk
carry-over invariance, unsupported link type rejected). Full suite: 244 passed.

**Full run** (`python -m scripts.extract_packet_windows --workers 12`), all of `V:\Datasets\UNSW NB15\pcap files`:
```
{"files": 63, "frames": 127230729, "seconds": 93.14, "gb": 72.46, "aggregate_frames_per_s": 1365959, "gb_per_hour": 2800}
```
-> 156,637 packet windows, 40 distinct src IPs (matches the 40 hosts in the UNSW flow CSVs), no NaN cells,
windows on 2015-01-22 (104,466), 2015-01-23 (3,164), 2015-02-18 (49,007).

**Consequence for the CIC-IDS-2018 / CICIoT2023 plan:** parsing is no longer the bottleneck. At this measured
rate (local disk, 12 workers) 370 GB is roughly 8 minutes and 547 GB roughly 12 minutes of parsing. This
assumes the captures sit on the same fast drive and have similar packet sizes; the download time and
disk space (917 GB > the 749 GB free on V:) are the real constraints now.

**Limits (in the module docstring):** IPv4 only; Ethernet / Linux-SLL only; first and last window of each
file dropped (boundary windows are not additive for the unique-port / retransmit features).

**Finding -- `retransmit_ratio` is not a retransmission count.** It is inherited from
`compute_packet_window_features`: any repeated (src, dst, sport, dport, seq) inside a window counts. On a real
UNSW slice 68.5% of TCP packets are flagged and about half of those are payload-free ACK-style packets, so the
feature averages 0.63 over the dataset. The fast path reproduces it exactly on purpose (parity). Recommended
follow-up (not done): count duplicates only among packets that carry L4 payload.

## Steps 2-4 -- packet-aware dataset, matched training, comparison (DONE 2026-09-24)

**Dataset** (`pipeline/build_unsw_pkt_dataset.py`, `configs/unsw_nb15_pkt.yaml`, output `data/processed_unsw_pkt/`):
UNSW flow CSVs restricted to the time the PCAPs cover (1,524,983 of 2,486,033 flows, 61.3%), REAL packet features
merged onto the flow windows (68,199 of 68,222 windows = 100.0% have them), then sequences:
train 44,059 (1,896 positives), val 3,694 (601), test 18,853 (4,995). Held-out-day split: train/val from 2015-01-22,
test = 2015-02-18. **Split detail worth knowing:** all 01-22 attacks fall in one ~3 h stretch and the rest of that day
(and all of 01-23) is benign, so a time-tail or the 01-23 day gives a val set with **zero** positives. Val is therefore a
block inside the attack period (from the 75th-percentile positive), each side kept clear of train (a sequence is in val
only if its whole span is inside the block, in train only if its whole span is outside; 684 straddlers dropped).
`tests/test_unsw_pkt_split.py`. The reconnaissance heuristic, now fed real `port_scan_score`, added 3 windows
(1,200 -> 1,203) on top of UNSW's own labels.

**Training**: the same Transformer and hyper-parameters for both variants (batch 64, 30 epochs, lr 3e-4), 3 seeds each
(new opt-in `--seed`, seeded before model build; checkpoints under `seed<N>/`). Control = identical sequences with all 9
packet-level columns zeroed (`data/processed_unsw_pkt_flowonly/`, `configs/unsw_nb15_pkt_flowonly.yaml`).

**Result, held-out day 02-18 (`python -m eval.pilot_packet_compare`, output `docs/unsw_pkt_pilot_results.json`):**
```
packet-aware       AUROC 0.99816 +/- 0.00024   AUPRC 0.99139 +/- 0.00079
flow-only control  AUROC 0.99809 +/- 0.00002   AUPRC 0.99027 +/- 0.00027
paired AUROC diff (packet - flow): per seed [+0.00034, -0.00011, -0.00001], mean +0.00007, bootstrap 95% CI [-0.00011, +0.00034]
threshold from val, test 1% FPR budget: packet-aware precision 0.975 recall 0.987 achieved FPR 0.0091 F1 0.981
                                        flow-only     precision 0.983 recall 0.941 achieved FPR 0.0057 F1 0.962
```
**Reading it honestly:** there is **no measurable AUROC benefit** from packet features here (the CI spans zero). At the
val-chosen 1% budget the packet-aware model has higher recall (0.987 vs 0.941) and F1 (0.981 vs 0.962), but that is 3 seeds,
threshold-dependent, and F1 at a fixed 0.5 threshold is mixed per seed ([0.986, 0.956, 0.981] vs [0.981, 0.972, 0.977]) --
suggestive, **not established**. The reason this pilot cannot show a real benefit is a **ceiling effect**: both models score
AUROC ~0.998 because the held-out day uses the same four attacker hosts and the same attack generator as the training day, so
it is close to in-distribution. That is a very different (much easier) test than CIC's held-out days (v2 F1 0.370, AUROC 0.706)
and than any cross-dataset test, so **do not read this as "packets don't help" or as generalisation evidence.** Note the
best val loss differs a lot (0.55 packet-aware vs 0.38 control): the val block is small and attack-only-ish, so val loss is a
poor guide here. `retransmit_ratio` is the inherited "repeated seq" definition (see Step 1).

**What the pilot did establish:** (1) real packet features can be extracted at scale and correctly (parity-checked); (2) the
PCAP -> labelled window pipeline works end to end on a real dataset; (3) a packet-aware model can be trained and evaluated with
matched controls and multiple seeds. Whether packets improve *generalisation* needs a harder test (CIC-IDS-2018 PCAPs).
Not done: a flow-features-from-PCAP fast path (flow records still come from the CSVs here; `build_flow_records` is still the
slow Scapy path, needed for CIC because its CSVs lack IPs on 9 of 10 days).

---

# CIC-IDS-2018 ONE-DAY PCAP TEST -- Wednesday 14-02-2018 (2026-09-24, owner-approved download)

**Download:** `pcap.zip`, 39,913,353,098 bytes from the public CIC bucket
(`cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Original Network Traffic and Log data/Wednesday-14-02-2018/`), size
matched the server's Content-Length exactly (one interruption, auto-resumed). Saved to
`V:\Datasets\CIC-IDS-2018\Wednesday-14-02-2018\`. **Correction:** the official total for all 10 days of PCAP is ~477 GB
(I had said 370 GB); a day is a ZIP, so unpacking needs extra space.

**What is in it:** 449 capture files (+1 folder entry), 46 GB unpacked, all classic PCAP, Ethernet. **Each file is ONE
machine's own capture** (e.g. `capPC1-172.31.64.37`, `UCAP172.31.69.25` = the Ubuntu server), not a network-wide capture, so
a packet between two captured machines appears in both files. `extract_packet_windows --keep-at-sender` keeps each packet
only in its sender's capture (senders with no capture of their own, e.g. the external attacker, are kept wherever seen);
`tests/test_fast_packet_windows.py::test_sender_rule_...`.

**Run:** 449 captures, 48.6 GB, 87,783,076 frames in 76 s (1.15M frames/s, 2,300 GB/h) -> 6,799,964 (src, 10 s window)
rows, 75,261 distinct sources (74,803 are outside internet hosts), no NaN cells, span 2018-02-14 12:28 -> 2018-02-15 00:47 UTC.

**Bug found and fixed:** the first run wrote only 18 output files for 449 captures, several corrupt: output names used
`Path.stem`, which cuts at the last dot, and CIC captures have no extension but dots in the name
(`capPC1-172.31.64.37` -> `capPC1-172.31.64`), so machines collided and overwrote each other in parallel. Now
`output_name()` uses the full file name; regression test added; bad output deleted and regenerated (449 -> 449 files).
UNSW's `N.pcap` names never triggered it.

**Labels verified against the data (not assumed):** in the victim's capture `UCAP172.31.69.25`
- FTP-Patator: **18.221.219.4 -> :21, 193,360 packets, 14:33:26-16:10:31 UTC**. The CIC label CSV has exactly **193,360**
  `FTP-BruteForce` rows -- an exact match.
- SSH-Patator: **13.58.98.64 -> :22, 2,208,736 packets, 18:01:50-19:32:30 UTC** (187,589 `SSH-Bruteforce` flows in the CSV;
  many packets per flow, so no 1:1 match expected).
- CIC's CSV clock is UTC-4: PCAP time = CSV time + 4 h (FTP 10:33:26-12:10:31 in the CSV). The CSV's SSH rows read
  02:01-03:32 because its 12-hour timestamps are being parsed without the PM -- the same span, 14:01-15:32 local.
This is the labelling rule for this day: packets from those two sources to 172.31.69.25 in those windows are attack.

**Still open before a packet-aware CIC dataset can be built:**
1. Flow-level records from PCAP: the CSV for this day has no IP columns, and `build_flow_records` is still the slow Scapy
   path (~3,200 packets/s), so flow features need a fast path (the packet-feature path is fast, the flow one is not).
2. Duplicate (src, window) rows: 3.4M of the 6.8M rows repeat across files because an outside source seen by several victims
   gets one partial row per victim capture. They cannot simply be stacked (unique-port and repeated-seq features are not
   additive); either merge from sufficient statistics or restrict to internal hosts plus the two attackers.
3. Windowing/label assignment and a held-out split for a single day (no second day yet).

---

## CIC-IDS-2018 ONE-DAY PACKET-AWARE TRAINING (Wed 14-02-2018)

**Fast flow-record path.** `pipeline/fast_packet_windows.py::assemble_flows` + `scripts/extract_flow_records.py` build CICFlowMeter-style flow records straight from the PCAPs (bidirectional 5-tuple, 120 s timeout, no FIN split, keep-at-initiator for host-based captures). 84.4 M packets -> 5,775,275 flows in 99 s (8 workers). `tests/test_fast_flows.py` (5 tests): independent expected values, agreement with the slow `build_flow_records` within classic-pcap microsecond tolerance, timeout cut, keep-at-initiator.

**Dataset** (`pipeline/build_cic_pkt_dataset.py`, `configs/cic_pkt*.yaml`). Labels: BENIGN 5,487,748 / FTP-BruteForce 193,330 / SSH-Bruteforce 94,197 flows (CIC's CSV has 187,589 SSH rows because CICFlowMeter splits at FIN; ours does not -- approximation). 810,283 sequences; 99.9% of windows have packet features. Split by time: train = FTP-Patator period (352,493 seq, 418 positives), val carved inside it (24,243 seq, 131 pos), test = later, unseen SSH-Patator (371,915 seq, 529 pos). Flow-only control = identical data with the 9 packet columns zeroed. Batch 256 (UNSW pilot used 64), 30 epochs, 3 seeds; six runs, no errors.

**Results** (`docs/cic_pkt_results.json`, from `python -m eval.pilot_packet_compare --dataset cic`), test = unseen SSH:

| | AUROC | AUPRC |
|---|---|---|
| packet-aware | 1.000 | 1.000 |
| flow-only control | 0.999997 | 0.992 +/- 0.013 |

Paired AUROC diff 2.6e-6, bootstrap 95% CI [0, 7.9e-6] (3 seeds, rough). **Ceiling effect: this day cannot show whether packet features help.** Brute force is separable from flow features alone (same as the UNSW pilot).

**Threshold failure under attack-type shift (finding).** Thresholds chosen on val (5% / 1% FPR) give recall 0 on test for every run. Cause (seed 1): on val (FTP) attacks score exactly 1.0 and benign ~0, so the chosen threshold is 0.9999988; on the unseen SSH attack the model scores 0.01-0.45, ranked above all benign (AUROC 1.0) but far below that threshold. A val block containing only the training attack type gives an extreme, non-transferable threshold. The evaluation code is correct.

**Extra operating point (label-free).** Threshold = 99th / 99.9th percentile of BENIGN val scores (no attack labels needed). Test recall 1.00 in all six runs; FPR 0.9-1.7% / 0.07-0.21%; precision at q99.9: packet-aware 0.40-0.51, flow-only 0.49-0.66 (flow-only slightly better). Caveat: benign val scores are ~0, so the threshold is ~0 and works only because SSH attack scores are >=0.01; single day, same victim.

**Other caveats.** One day, two attacks, positives ~0.1% of sequences; outside sources seen by several victims have averaged packet rows; `retransmit_ratio` still counts pure ACKs (recommended follow-up: count only packets with L4 payload). Harder days (DoS / web) or more days are needed to test the packet-feature claim.

---

## W13-W20 (2026-09-29 work order) — status

### W18 — branch upstream (VERIFIED, no action needed)

`git status -sb` at current HEAD:
```
## integration/all-branches-2026-09-29...origin/integration/all-branches-2026-09-29
```
Tracks its own remote branch, not `origin/master`. This was set by `git push -u origin
integration/all-branches-2026-09-29` when the branch was first pushed (2026-09-29) -- H6's push
hazard predates that push and no longer applies. A bare `git push` now updates only this branch.

### W13 -- harden app/api.py (FIXED, option b)

Owner decision: harden rather than remove. `app/api.py` rewritten (audit H1):
- Off by default: refuses to boot (`HTTP 503`) unless `NAF_API_ENABLED=1`.
- Every endpoint requires `Authorization: Bearer <token>`, compared with `hmac.compare_digest`
  against `NAF_API_TOKEN` (env only, never a request field or module global default).
- Webhook URLs must be `https`, host must appear in `NAF_WEBHOOK_ALLOWLIST` (env), and are
  re-resolved and checked against private/loopback/link-local/multicast/reserved ranges both at
  registration and at every dispatch (closes the SSRF path to `169.254.169.254` and similar).

`scripts/stream_consumer.py` (the only other caller) now sends `Authorization: Bearer` from
`--api-token` / `NAF_API_TOKEN`.

**Acceptance (`tests/test_api_hardening.py`, 8 tests):**
```
tests/test_api_hardening.py ........                                    [100%]
8 passed, 1 warning in 0.49s
```
Covers: disabled by default; unauthenticated request to `/api/v1/alerts`,
`/api/v1/alerts/ingest`, `/api/v1/webhooks` all rejected (401); wrong token rejected; correct
token accepted; webhook to `169.254.169.254` refused (400) and nothing registered; webhook to a
non-allowlisted host refused; webhook to an allowlisted `https` host accepted; `http://` scheme
rejected.

### W14 -- dependencies match imports (FIXED)

Added `fastapi>=0.110`, `pydantic>=2.6`, `uvicorn>=0.29`, `requests>=2.31`, `networkx>=3.2` to
`requirements.txt` (the true new hard imports from `app/api.py`, `scripts/stream_consumer.py`,
`scripts/visualize_topology.py`; `pyvis` stays undeclared since that script already degrades
gracefully without it via its own try/except).

**Acceptance:**
```
OK app.api
OK scripts.stream_consumer
OK scripts.visualize_topology
OK models.cve_lookup
```
(all four modules import cleanly after `pip install -r requirements.txt` in the project venv,
which previously lacked fastapi/pydantic/uvicorn/networkx entirely.)

### W15 -- streaming consumer feature schema (FIXED)

`scripts/stream_consumer.py` rewritten: `_build_batch_windows` now runs the same flow -> graph ->
graph-embedding -> packet-feature assembly `pipeline/build_dataset.py` uses, computing REAL graph
and graph-embedding features per batch (a batch already has the cross-host context a graph needs)
instead of zero-padding them. Only packet-level columns stay zero-filled, matching the documented,
in-distribution flow-only convention (W3). Column order/width now come from
`common.config.feature_columns(config)`, asserted against the checkpoint's own `scaler.mean` width
at startup (raises `ValueError` on mismatch rather than silently padding -- see W19). Also fixed a
pre-existing bug this exposed: `simulate_stream` read the raw CICFlowMeter CSV directly instead of
through `load_flow_csv` + `clean_and_normalize`, so column names (`Timestamp` vs `timestamp`) never
matched what `build_flow_windows` expects.

**Acceptance:** ran against the bundled sample --
```
python -m scripts.stream_consumer --config configs/default.yaml --data data/raw/flows/synthetic_sample.csv --api-url http://localhost:1
[FORECAST] 10.0.0.9 - peak infiltration prob: 0.9836 - stage: lateral_movement
[ALERT] 10.0.0.9 - Prob: 0.98 - Stage: lateral_movement
...
[FORECAST] 10.0.0.9 - peak infiltration prob: 0.5557 - stage: exfiltration
[ALERT] 10.0.0.9 - Prob: 0.56 - Stage: exfiltration
```
`tests/test_stream_consumer.py::test_assembled_matrix_width_matches_checkpoint_in_features` --
asserts every `feature_columns(config)` name is present in the assembled window and that
`graph_embed_0` is not all-zero (the specific H3 symptom): **1 passed**.

### W16 -- 0-byte placeholders removed (FIXED)

```
$ ls -l docs/demo.mp4 docs/presentation.pdf
ls: cannot access 'docs/demo.mp4': No such file or directory
ls: cannot access 'docs/presentation.pdf': No such file or directory
```
Both deleted (`git rm`). README's deliverables checklist now shows this item as `[ ]` (open),
with a note that a prior commit had checked it off against 0-byte placeholders.

### W17 -- reconnaissance-unreachable claim corrected (FIXED, option 2)

Chose to correct the claim rather than rebuild a processed dataset with PCAP, given the rest of
this work order's size. `docs/AUDIT.md`'s S6 row corrected: withdraws "now genuinely usable on
PCAP-only uploads (S4)" and states plainly that both shipped processed builds
(`data/processed_real`, `data/processed/cicids2018/splits`) report `flow_only: true`, so W3's own
zero-fill guard makes `port_scan_score` zero before the S6 override can ever read it -- reconnaissance
is unreachable on every shipped checkpoint today, including the PCAP-only upload path. Checked
`app/streamlit_app.py` and `README.md` for the same overclaim elsewhere: none found (the README's
"3 of 5 MITRE stages" note already does not claim reconnaissance is reachable).

### W19 -- close the schema-drift class (FIXED)

Four times now (S13, G11, H3, the `a60c549` merge bug) a module assembling its own feature matrix
drifted from the trained 41-column schema, three of which shipped. Added the checked-at-load-time
guard the finding asked for:

- `models/checkpoint_io.py::validate_feature_names(checkpoint, feature_names)` -- compares by
  NAME and ORDER, not count, since every prior instance of this bug produced the RIGHT WIDTH with
  the WRONG columns (a shape check alone would have passed all four).
- `models/train.py` and `models/train_joint.py` now save `feature_names` (`feature_columns(config)`,
  masked appropriately for the joint model) into every checkpoint going forward. Older checkpoints
  have no such key and are passed through unchecked (same backward-compatible pattern as G12's
  `weights_only` fix) -- nothing on disk is invalidated.
- `models/forecast.py::load_world_model` self-checks a checkpoint's stored `feature_names` against
  `feature_columns()` of its own stored config at load time.
- `scripts/stream_consumer.py` (the module H3 was raised against) now calls
  `validate_feature_names` explicitly against the loaded checkpoint before starting the stream.

**Acceptance -- deliberately-wrong feature list raises a clear error at load time:**
```
Feature schema mismatch (audit W19): this checkpoint was trained on 3 columns
['flow_count', 'total_bytes', 'graph_embed_0'], but the caller assembled 3 columns
['flow_count', 'total_bytes', 'wrong_column']. Refusing to score -- a matching width with
mismatched columns produces silently wrong predictions, not a crash. Build the feature matrix
with common.config.feature_columns(config), which is the only supported way to assemble a model
input.
```
`tests/test_feature_schema_guard.py` (5 tests: matching passes, older-checkpoint-without-the-field
passes through, wrong column raises, wrong order at matching width/names raises, and a grep-based
check that no `.py` file outside `common/config.py` hand-picks `flow_level` alone as a model input)
+ `tests/test_stream_consumer.py` -- **6 passed**. Full suite: **290 passed**.

### W20 -- summary tables + one v2 config (FIXED)

**Duplicate summary table removed.** `BUILD_REPORT.md` had two summary tables: the top
"Findings status" one (kept, now the only one) and a second under "WORK ORDER RESPONSE" that
stopped being updated after W2 and still said `W3-W12 | NOT STARTED` while every section beneath it
documented them as done (H7). Replaced with a pointer to the top table. Also corrected the top
table's `S9-S12, D2 | NOT STARTED` row: S9 (cached SHAP background) and D2 (CAPEC linkage) were
both added by `f1e432c` and are FIXED; only S10/S11 remain NOT STARTED. New rows added for
W13-W19.

**v2 config/checkpoint mapping.** Investigated `configs/real_data_v2.yaml` vs
`configs/real_data_v2_converged.yaml` vs the checkpoints on disk:

| Checkpoint | Config that reproduces it | Notes |
|---|---|---|
| `checkpoints_real_v2/` | none | Trained at batch 64, 15 epochs (confirmed via `train_v2.log`, 15 `epoch` lines) with a split that includes the fabricated April benign days. `configs/real_data_v2.yaml`'s batch_size/epochs were later edited to 64/30 (matching the converged run) without updating its split, so it now reproduces neither checkpoint. Superseded by the converged run (`docs/04-evaluation-real-v2.md`); left untouched on disk (protected artefact). |
| `checkpoints_real_v2_converged/` | `configs/real_data_v2_converged.yaml` | Canonical v2 result (W7): batch 64, 30 epochs, April days dropped from val/test. This is the config to use for a v2 result going forward. |
| `checkpoints_real_v2_scaleinv/` | `configs/real_data_v2_scaleinv.yaml` | W11 part 3, truncated at epoch 25/30 (documented as an honest negative, not a completed experiment). |
| `checkpoints_real_v2_lofo/<family>/` | `configs/real_data_v2.yaml` (via `eval/lofo.py::BASE_CONFIG`, paths overridden per fold) | **Not orphaned** -- `real_data_v2.yaml` is a live dependency of the LOFO eval script, not a standalone result config. Left in place with a header explaining both roles; deleting it would break `eval/lofo.py`. |

`configs/real_data_v2.yaml` is kept (LOFO needs it) but given a header explaining it no longer
represents a standalone, reproducible v2 checkpoint result and pointing to
`real_data_v2_converged.yaml` for that purpose.


## W21 — Frozen-state rollout ablation (2026-09-30) — DONE, negative result

Work order: `WORK_ORDER-2026-09-30.md`. Script: `scripts/ablate_frozen_state.py`.
Report: `docs/04-evaluation-frozen-state-ablation.md`. Raw: `docs/frozen_state_ablation.json`.

Acceptance asked for the conclusion "in whichever direction the numbers land". It landed negative.

```
  step   seconds           genuine AUROC            frozen AUROC     delta
     1       10s      0.7937 +/- 0.0349       0.7937 +/- 0.0349    +0.0000
     2       20s      0.7823 +/- 0.0443       0.7917 +/- 0.0360    -0.0094
     3       30s      0.7725 +/- 0.0510       0.7894 +/- 0.0352    -0.0170
     4       40s      0.7663 +/- 0.0545       0.7876 +/- 0.0358    -0.0213
     5       50s      0.7602 +/- 0.0581       0.7868 +/- 0.0346    -0.0267
     6       60s      0.7549 +/- 0.0608       0.7853 +/- 0.0335    -0.0303
```

- k=1 is identical by construction (sanity check passed) and reproduces the published headline
  AUROC to the digit: 0.7937 here vs 0.794 in `docs/04-evaluation-real-v2-seeds.md`.
- Advancing the world model's state makes infiltration ranking **worse**, monotonically with
  horizon. AUPRC and F1@0.5 at k=6 agree (0.5714 vs 0.6214, 0.4121 vs 0.4735).
- All 15 paired comparisons (3 seeds x k=2..6) are negative, but |t| ~ 1.56 at df=2 against the
  4.303 needed. Reported as "no evidence the rollout adds value, consistent evidence of a small
  penalty" -- not as proof of harm.
- Side finding, arguably the more important one: **the published headline is a t+1 (10-second)
  measurement.** `eval/lofo.py::_predict_infiltration` runs a single forward pass and scores
  `infiltration[:, 0]`; the K-step rollout had never been evaluated. Any claim that F1 0.481 /
  AUROC 0.794 describe a 60-second forecast is overstating them.

Seeds 1/2/3 at k=6: genuine 0.7743 / 0.6728 / 0.8178 vs frozen 0.7930 / 0.7409 / 0.8218.


## W22 / W23 (2026-09-30) — DONE

### W23 — measured latency, on real traffic

`scripts/benchmark_latency.py`, report `docs/04-latency-benchmark.md`, raw
`docs/latency_benchmark.json`. Input is a real CIC-IDS-2018 slice (Friday 02-03-2018, 120,000
flows: 99,707 Bot / 20,293 Benign), never generated noise. Windows 10, CUDA.

```
stage                                         P50        P95        mean+/-sd    n
ingestion (parse + windowing + features)  2004.4ms   2112.3ms   2037.5+/-64.9    3
score_all_hosts (batched rollout)            7.1ms      7.3ms      7.1+/-0.1    20
single-host K=6 rollout                      6.6ms      6.9ms      6.6+/-0.1    20
explainability (gradient x input)            3.4ms      3.9ms      3.4+/-0.2    20

interactive drill-down (rollout + explain) P50: 9.9 ms
batch scaling (replicated real sequence):
     1 host   6.2ms   |   100   7.0ms   |   1000  13.0ms   |   5000  60.1ms (0.012 ms/host)
```

Scoring 5,000 hosts in 60 ms means a full K=6 forecast for every host on a mid-sized network
finishes inside one 10-second window. Not compared against ShadowCat's 1,630 ms: theirs is CPU,
bundles a 37-fold ensemble and graph traversal, and uses a different denominator. Stated in the
report rather than converted into a speedup claim.

Limitations recorded: CUDA only (no CPU figure), one capture/day/machine, no concurrency or
cold-start measurement, and the batch-scaling rows replicate one real sequence rather than
scoring N distinct hosts.

### W22 — limitations moved next to the results

New `## What this system does not do` section in `README.md`, placed with the results instead of
60 lines below them: recall 0.325 (misses ~2 in 3 attack windows), lead time -0.5s mean / +0.0s
median over 628 transitions, the headline being a t+1 (10-second) number, the frozen-state
result, no demonstrated generalisation, single dataset. Each line carries its measured figure and
its source file.

Two stale bullets in the existing `Known limitations` were corrected while doing it, both of
which understated the project:

- "Split reuses attack sessions ... cut per host in time order" described the **v1** split. The
  headline has used the day-disjoint split since W7; the bullet now says so and explains that the
  old split is what produced the withdrawn 0.917.
- "32 benign-to-attack transitions from 2 pseudo-hosts" predates the day-disjoint re-measure,
  which covers **628** transitions across 3 pseudo-hosts (96% from one day), with false alarms
  now counted per E3.


## W24 / W25 (2026-09-30) — DONE

### W24 — the "no competitor publishes a negative result" claim, retracted for the second time

`docs/05-related-work-and-competitive-landscape.md`. The 09-29 pass had already narrowed this
once (from "no repo reports a negative result" to "none about its own *model*"); the narrowed
version is also false. Both counter-examples read at source:

- **ShadowCat** ran a 37-fold Leave-One-Entity-Out evaluation of its GraphSAGE fusion, found
  F1 0.0000 in 3 of 18 DDOS-LOIC-UDP folds (macro 0.9157 vs 0.9971 for plain stacked LSTM),
  attributed it to over-smoothing in dense bipartite subgraphs, and issued a NO-GO retiring the
  architecture. It also retired its own latency benchmark for timing an untrained model on
  `np.random.randn`.
- **CyberPulse** states in its README summary that it is not a demonstrated early-warning system,
  that its GRU loses to logistic regression, and that its "t+1 to t+4" horizons are dataset rows
  rather than time.

Recorded with the caveat that ShadowCat's folds appear to withhold one *episode* while training
on other episodes of the same attack type — not leave-one-family-out — so 0.9971 and this
project's 0.53–0.82 LOFO figures measure different difficulties and must not be compared. That
reading is from fold naming and per-category reporting, not from their split code.

The paragraph now also cites this project's own new negative result (W21), so the section states
a symmetric position rather than an unmatched claim.

Acceptance: `grep -nE "[Nn]o (surveyed |other )?(repo|team|competitor)...(publishes|describes|
reports|has)"` returns only the sentence performing the retraction.

### W25 — the "Feature #4" citation

The `raushankumarsah07` row claimed "this project independently built the same capability, see
Feature #4". When the last-minute build order raised this as item 0 the capability did not exist
at all; it does now (`2c4474b`, `93f6bcc`). Two defects remained:

- there is no "Feature #4" anywhere in the repository — a dangling reference in the one document
  whose whole value is its accuracy;
- "independently" was unsupportable: the capability was built *after* this competitor was
  surveyed and explicitly in response to it (build-order item 4).

Replaced with the real endpoint and the true chronology: "built ... on 2026-09-30,
`POST /api/v1/forecast/what-if` in `app/server.py`, *after* and in response to this survey — not
independently". Verified the cited endpoint exists (`app/server.py:476`).

Acceptance: `grep -c "Feature #4" docs/05-related-work-and-competitive-landscape.md` returns 0.

**W21–W25 of `WORK_ORDER-2026-09-30.md` are now all closed.**
