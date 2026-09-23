# WORK ORDER — 2026-09-23

**From:** Auditor agent · **To:** Builder agent
**Source of findings:** `docs/AUDIT.md` Part G (branch review of `builder/audit-fixes-2026-09-23`,
commit `db49ea0`). Every item below traces to a finding ID there; read the finding before starting
the item.
**Branch:** work on `builder/audit-fixes-2026-09-23`. Do not merge to `master` without asking.

Items are in execution order. W1 is the only item that currently shows a reader something untrue,
so it goes first regardless of size. Do not reorder without saying why.

## Ground rules for this order

- **Acceptance criteria are binding.** An item is only FIXED when its acceptance check has been
  run and its output pasted into `BUILD_REPORT.md`. "Code changed, looks right" is not FIXED.
- **Re-measure, never carry forward.** Any number you report must come from a run you did after
  your change. If you could not run it, write "not measured".
- **Do not touch** without asking first: `checkpoints_real/`, `data/processed_real/`,
  `data/processed_real/scaler.npz`, and any `docs/04-*.md` that does not carry a `_v2`, `_REGEN`
  or `_unsw` suffix. `eval/benchmark.py` overwrites reports; `pipeline/build_dataset.py` rewrites
  `scaler.npz`.
- **Schema rule.** The feature vector is 41 columns. If you change it, grep every caller of
  `build_flow_windows` first — that is the recurring failure mode in this repo (S13, G11).
- If you think an item is wrong, mark it DISPUTED with a technical reason and a proposed
  alternative. Do not silently fix it a different way.

---

## W1 — Correct the retracted CTU-13 number wherever it appears
**Finding:** G1 (Critical) · **Effort:** minutes · **Depends on:** nothing

`README.md` lines ~108-110 state: *"Zero-shot on CTU-13 … F1 0.534 at a calibrated operating point,
versus 0.045 for CTU-13-native LR."* Recomputed against the shipped checkpoint and the current
CTU-13 build, the real figures are **F1 0.009, AUROC 0.517 (chance)**. The 0.534 came from a
33-feature checkpoint and a 33-feature CTU-13 build that no longer exist on disk.

**Do:**
1. Replace the README paragraph with the corrected numbers and state plainly that the model does
   not transfer to CTU-13.
2. Add a dated retraction note at the top of `docs/04-evaluation-ctu13_cross_from_real_data.md`
   pointing to the REGEN file, or swap the REGEN file in and archive the original — ask which the
   owner prefers before deleting anything.
3. Grep the repo for `0.534` and fix every other occurrence.

**Acceptance:** `grep -rn "0\.534" --include=*.md .` returns only retraction notes that explain the
number is withdrawn.

---

## W2 — Fix the PCAP inter-arrival-time unit bug
**Finding:** G5 (High) · **Effort:** ~1 hour · **Depends on:** nothing

`pipeline/packet_features.py::build_flow_records` computes `iat_mean`/`iat_std`/`iat_max` with
`.dt.total_seconds()` — seconds. The CSV path carries CIC's values through in **microseconds**.
Every PCAP-only upload therefore feeds the model three features 10^6 times too small.

**Do:** multiply the three IAT fields by `1e6` in `build_flow_records`. Check whether any other
field in that function disagrees with the CSV path's units while you are there (`duration_s` is
already correct).

**Acceptance:** a new test builds the same traffic twice — once as a flow CSV, once as a PCAP —
and asserts the resulting `mean_iat`/`var_iat`/`max_iat` agree within a small tolerance. Note in
`BUILD_REPORT.md` that `data/raw/pcap/synthetic_sample.pcap` cannot exercise this (all 944 of its
flows are single-packet), so the test must generate its own multi-packet capture.

---

## W3 — Stop feeding packet features to a flow-only model
**Finding:** G11 (High) · **Effort:** ~1 hour · **Depends on:** nothing

`app/streamlit_app.py::_process_uploads` merges packet-level features whenever a PCAP is supplied,
with no check on which checkpoint is selected. Since S5 unified the upload path, a PCAP can now be
scored by the real CIC-IDS-2018 model, which was trained flow-only — 8 packet features plus
`has_packet_features=1`, none of which it has ever seen.

**Do:** detect flow-only training from the processed dataset's own `metadata.json`
(`"flow_only": true` / `"packet_features_available": false`) and either zero-fill packet features
for that checkpoint or refuse the combination with a clear message. Do not hardcode a config name.

**Acceptance:** with the real model selected and a PCAP uploaded, the windows handed to
`ForecastEngine` have all 8 packet features zero and `has_packet_features == 0`; with the synthetic
model selected, they are populated. Show both in `BUILD_REPORT.md`.

---

## W4 — Remove arbitrary-code deserialization
**Finding:** G12 (Medium) · **Effort:** ~1 hour · **Depends on:** nothing

`torch.load(..., weights_only=False)` in `models/forecast.py:123`, `models/lstm_model.py:57`,
`models/train_joint.py:199`, and `pickle.load` in `models/baseline_lr.py:88`. Loading a checkpoint
executes whatever is in the file. Low practical risk today (all artefacts are locally produced),
but this is a security project and a reviewer will grep for exactly this.

**Do:** switch to `weights_only=True` and store the config next to the tensors as JSON rather than
pickling it into the checkpoint. Keep a backward-compatible read path for existing checkpoints, or
provide a one-shot re-save script — do not invalidate `checkpoints_real/`.

**Acceptance:** all existing checkpoints still load and score identically (same F1 on the same
split, before and after), and no `weights_only=False` or bare `pickle.load` remains in
`models/`, `eval/` or `app/`.

---

## W5 — Fix the UNSW-NB15 adapter before anyone cites its result
**Finding:** G4 (High) · **Effort:** ~half a day · **Depends on:** nothing

`pipeline/adapters/unsw_nb15.py` hands the CIC-trained model 9 wrong features: all six TCP flag
ratios are constant zero, `var_iat`/`max_iat` are zero, and `mean_iat` is ~3,000x low because
`Sintpkt`/`Dintpkt` are in **milliseconds** and are never converted to the **microseconds** the CIC
features use. The six flag ratios are exactly what the problem statement singles out.

**Do:**
1. Convert `Sintpkt`/`Dintpkt` to microseconds.
2. Derive what flag information UNSW's `state` field genuinely supports (e.g. `CON`, `FIN`, `RST`)
   — **do not invent counts**. If a flag cannot be derived honestly, leave it zero and record it.
3. Re-run the cross-dataset evaluation and regenerate
   `docs/04-evaluation-unsw_cross_from_real_data_v2.md`.
4. In that report, list every feature that is zero-filled or derived, so the transfer number is
   read with its caveat attached.

**Acceptance:** a table in `BUILD_REPORT.md` of UNSW vs CIC feature means before and after the fix,
plus the re-measured AUROC. Until this lands, **AUROC 0.443 must not be quoted anywhere.**

---

## W6 — Correct two overstated claims in the audit's own status table
**Finding:** G2, G6 (High / Medium) · **Effort:** minutes · **Depends on:** nothing

1. Part A's E2 row says the v2 split "produces 628 real transitions across many hosts/days". It is
   628 transition windows across **181 episodes on 3 day-level pseudo-hosts, 96% from 2018-02-23**.
   Reword it, and reword the same claim in `BUILD_REPORT.md`.
2. `docs/04-evaluation-real-v2.md` presents itself as a real-CIC-IDS-2018 evaluation, but
   **26.6% of its val split and 17.6% of its test split are fabricated** traffic from
   `scripts/augment_benign_high_volume.py` (the "2018-04-01"/"2018-04-02" days; CIC-IDS-2018 has no
   April data). Add that disclosure to the report header.

**Acceptance:** both documents state the corrected figures. No code change.

---

## W7 — Make the v2-vs-v1 comparison clean
**Finding:** G3, G6 (High / Medium) · **Effort:** GPU retrain · **Depends on:** W6

`configs/real_data_v2.yaml` changed three things at once versus v1: the split, `batch_size` 64→512,
and `epochs` 30→15, at an unchanged learning rate — and the best validation loss landed on the
final epoch, so the model is not converged. "F1 0.917 → 0.431 confirms E1" therefore cannot
separate leakage from undertraining.

**Do:**
1. Retrain v2 at v1's `batch_size` and `epochs`, everything else identical, and re-measure. If
   training to convergence needs more epochs, say so and report the curve.
2. In the same rebuild, spread the synthetic benign days across train/val/test instead of letting
   them all fall into val/test — or drop them from v2 entirely. State which you chose.

**Acceptance:** `docs/04-evaluation-real-v2.md` regenerated from the converged run, with a table
comparing v1 and v2 under matched hyperparameters, so the remaining gap is attributable to the
split alone.

---

## W8 — Gate the stage override on the infiltration probability
**Finding:** G7 (Medium) · **Effort:** ~1 hour · **Depends on:** nothing

`models/forecast.py::_heuristic_stage_override` promotes any high-volume, low-destination-diversity
window to `impact` regardless of the model's own score. Reproduced with the project's own
robustness script: a capture it explicitly calls a *legitimate* large transfer scores 0.0369
(benign, PASS) and is simultaneously labelled **stage: impact**.

**Do:** apply the override only when the infiltration probability crosses the alert threshold, so a
stage annotation can never contradict the score beside it. Keep the existing `stage_is_heuristic`
disclosure.

**Acceptance:** `python -m scripts.check_robustness --config configs/real_data.yaml` shows the OOD
benign transfer as PASS **and** not labelled `impact`. Paste the output.

---

## W9 — Report achieved FPR in the lead-time section
**Finding:** G8 (Medium) · **Effort:** ~1 hour · **Depends on:** nothing

The threshold tuned for a 5% FPR budget on the v2 val split gives **35.9%** FPR on the v2 test
split — off by roughly 7x once the day changes. E5's fix reports achieved FPR in the budget tables;
the lead-time section still does not.

**Do:** report the achieved test FPR next to every budgeted lead-time number, and add a short note
that the operating threshold does not transfer across days. Treat that instability as a result
worth stating, not a footnote.

**Acceptance:** the regenerated v2 report shows achieved FPR beside alarm precision.

---

## W10 — Regenerate `BUILD_REPORT.md`'s summary table
**Finding:** G9 (Low) · **Effort:** minutes · **Depends on:** W1-W9

Its top table still says E1/E8/S8 are "IN PROGRESS", the v2 model is "NOT yet retrained", and
"E2-E7, E9-E11, S4-S7, S9-S12, D1, D2" are "NOT STARTED", while later sections of the same file
document most of those as done. Rebuild the table from the sections beneath it, and key each row to
both its finding ID and its work-order item.

**Acceptance:** no row contradicts the body of the file.

---

## W11 — Adversarial evasion: state the threat model, then raise the cost
**Finding:** README "Known limitations"; measured 0.9975 → 0.0000 on the current 41-feature
checkpoint · **Effort:** first part ~1 hour, rest with W7's retrain · **Depends on:** W7 for part 3

The PGD attack works by suppressing `flow_count`/`total_packets` — the model learned "volume =
attack". This is unfixed and should not be hidden.

**Do, in order:**
1. **Write the threat model down.** The evasion requires the attacker to genuinely send less
   traffic. For a flood that defeats the attack's own purpose; it is a real threat only for
   low-and-slow intrusion. Stating this precisely is stronger than claiming a fix.
2. **Add a second gate** using the existing `models/forecast.py::one_step_reconstruction_error`:
   traffic that fakes low volume while an attack proceeds should not match learned dynamics. Alarm
   on high infiltration probability **or** high reconstruction error, and measure whether this
   recovers any of the evaded cases.
3. **Scale-invariance augmentation** (fold into W7's retrain): randomly rescale volume features
   during training so the model must use shape — `syn_ratio`, `bidir_ratio`, destination entropy —
   rather than magnitude. This targets the same shortcut behind G6.

**Acceptance:** re-run `scripts/check_adversarial_robustness.py` and report the post-change
evasion probability. If the attack still succeeds, say so — an honest negative is acceptable here;
an unmeasured claim is not.

---

## W12 — Batch the benchmark's inference call
**Finding:** G10 (Low) · **Effort:** minutes · **Depends on:** nothing

`eval/benchmark.py::_world_model_predictions` pushes an entire split through the model in one
forward pass — the same pattern that OOM'd `eval/lofo.py` on the 1.23M-sequence impact fold. It is
harmless on today's splits and would fail the same way on a larger one.

**Do:** reuse the batched helper already written for `eval/lofo.py`.

**Acceptance:** existing benchmark output is unchanged on a current split (same metrics), and the
call is batched.

---

## Reporting back

Update `BUILD_REPORT.md` with a row per work-order item: **W-id, finding ID, status (FIXED /
PARTIALLY FIXED / DISPUTED / BLOCKED), files changed, acceptance evidence (the actual command
output), and any number you re-measured.** The auditor will re-check this branch against this
work order and that evidence, not against the narrative.
