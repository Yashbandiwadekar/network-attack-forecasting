# WORK ORDER — 2026-09-29

**From:** Auditor agent · **To:** Builder agent
**Supersedes:** `WORK_ORDER.md` (2026-09-23). That order's items are closed out in the verdict
table below; this file carries only what is still open, starting at **W13**.
**Source of findings:** `docs/AUDIT.md` Part H (audit of `integration/all-branches-2026-09-29`,
HEAD `a60c549`). Read the finding before starting its item.
**Branch:** work on `integration/all-branches-2026-09-29`.

## Verdict on the 2026-09-23 work order

Checked at integration HEAD. The "how" column states exactly what was run; where a row says *not
re-checked*, treat it as unverified rather than accepted.

| Item | Finding | Verdict | How it was checked |
|---|---|---|---|
| W1 | G1 | **VERIFIED** | Every `0.534` in the tree is a retraction, an archived file, or an unrelated metric. |
| W2 | G5 | **VERIFIED — and it earned its keep** | The parity test caught a real double-conversion introduced by the merge; confirmed by running it at pre-fix `af062e4`, where it fails with a value exactly 1e6 too large. |
| W3 | G11 | **VERIFIED** | PCAP-only upload on the real config: 0 of 258 windows carry packet features. But see **W17** — it disables S6. |
| W4 | G12 | **VERIFIED** | No `weights_only=False`, bare `pickle.load` or `allow_pickle=True` left in `models/`, `eval/`, `app/`, `pipeline/`. |
| W5 | G4 | **Partially verified** | Units confirmed: UNSW `Sintpkt=1000 ms` → `iat_mean = 1,000,000 us`. The rest of W5's acceptance (re-measured UNSW AUROC, and a listing of which features remain zero-filled) was **not re-checked** this pass. |
| W6 | G2, G6 | **VERIFIED** | The "181 episodes / 3 pseudo-hosts" wording appears 4x in each of `BUILD_REPORT.md` and `docs/AUDIT.md`. |
| W7 | G3, G6 | **VERIFIED to the digit** | Recomputed: 7,191 seq, F1 0.3697, P 0.8785, R 0.2341, FPR 0.0084, AUROC 0.7058 — matches the report exactly; zero synthetic rows remain. Convergence honestly reported as *not* converged. |
| W8 | G7 | **VERIFIED by its own acceptance command** | `python -m scripts.check_robustness --config configs/real_data.yaml` at HEAD: the OOD benign transfer peaks at 0.0369, PASSes, and is now labelled `predicted stage: benign` (it said `impact` when G7 was raised). Note the shipped implementation came from the teammate's `f1e432c`, not the builder's `f14a95f` — see Part H, H7. |
| W9 | G8 | **VERIFIED** | `docs/04-evaluation-real-v2.md` carries false-alarm-rate and alarm-precision rows with the E3 explanation beside them. |
| W10 | G9 | **CONTRADICTED — still open** | `BUILD_REPORT.md` now has *two* summary tables. The rebuilt one is near the top; a second at ~line 332 still reads `\| W3-W12 \| \| NOT STARTED \|` while the body documents them as done. The top table's `S9-S12, D2 \| NOT STARTED` row is also wrong now that `f1e432c` fixed S9. Re-opened as **W20**. |
| W11 | adversarial | **Partially fixed, honestly reported** | `BUILD_REPORT.md` grades it PARTIALLY FIXED itself: threat model and OR-gate done, scale-invariance run **truncated at 25/30 epochs** and the evasion still succeeds (0.605 → 0.0000). Accepted as an honest negative; the truncated run should not be cited as a completed experiment. |
| W12 | G10 | **VERIFIED** | `eval/benchmark.py::_world_model_predictions` now delegates to `eval.lofo._predict_infiltration`, the batched helper. |

Open from earlier rounds: **E7** (per-host attack data is DDoS only, open by owner's decision),
**E10** (no seeds or confidence intervals — though `5d95cda` claims a 3-seed UNSW comparison that
this audit has not verified), **E11**, **S10**, **S11**, **D1** partial. **S9 is now fixed** by
`f1e432c` (cached SHAP background), and **D2 appears closed** by the CAPEC snapshot in
`models/cve_lookup.py` — neither has been re-audited in depth.

## Ground rules

- **Acceptance criteria are binding.** An item is FIXED only when its check has been run and the
  actual output pasted into `BUILD_REPORT.md`.
- **Re-measure, never carry forward.** If you did not run it after your change, write "not measured".
- **Do not touch** without asking: `checkpoints_real*/`, `data/processed_real*/`, and any
  `docs/04-*.md` without a `_v2` / `_REGEN` / `_unsw` suffix. `eval/benchmark.py` overwrites reports;
  `pipeline/build_dataset.py` rewrites `scaler.npz`.
- **Do not push before W18 is done** — see that item; this branch's upstream is `origin/master`.
- Mark an item DISPUTED with a technical reason rather than silently doing something else.

---

## W13 — Remove or secure `app/api.py`
**Finding:** H1 (High) · **Effort:** minutes to remove, ~half a day to harden · **Depends on:** nothing

An unauthenticated FastAPI service that (a) lets any caller register an arbitrary webhook URL and
then forwards every alert to it, (b) will POST to internal addresses including cloud metadata
endpoints, (c) accepts unauthenticated alert injection and serves up to 1,000 alerts with real host
IPs to anyone, and (d) makes outbound HTTP calls, contradicting the PS's "fully offline" requirement
and the README's "no network calls" claim. It is imported by nothing, so today it is pure risk with
no functionality.

**This is a product decision, so ask the owner first — do not delete a teammate's feature on the
auditor's say-so.** Two acceptable outcomes:

- **(a) Remove it.** Delete `app/api.py`, and state in the README that the demo makes no network
  calls at all.
- **(b) Keep and harden it.** Off by default behind an explicit flag; authentication on every
  endpoint; webhook URLs validated against a configured allowlist with private and link-local
  ranges rejected; tokens read from the environment rather than a module global; documented as an
  optional online component that is disabled in the offline demo.

**Acceptance:** for (a), the file is gone and
`grep -rn "requests\.\(post\|get\)" app/ models/ pipeline/ scripts/` returns nothing — note
`scripts/stream_consumer.py` also posts to this API, so it is in scope either way. For (b), a test
showing an unauthenticated request to each endpoint is rejected and a webhook URL pointing at
`169.254.169.254` is refused. Paste the output.

---

## W14 — Make the shipped dependency list match the shipped imports
**Finding:** H2 (High) · **Effort:** minutes · **Depends on:** W13 (deleting api.py removes some)

Measured: `fastapi` and `pydantic` are not importable in the project venv at all; `requests` and
`uvicorn` import only because `streamlit` happens to depend on them. None of the four is declared
in `requirements.txt`. So `app/api.py` cannot start, and `scripts/stream_consumer.py` relies on a
transitive dependency nothing guarantees.

**Acceptance:** in a fresh virtual environment built only from `requirements.txt`, every module that
ships in the repo imports successfully. Paste the import check. If a file is deleted instead, say so.

---

## W15 — Fix the streaming consumer's feature schema
**Finding:** H3 (High) · **Effort:** ~1 hour · **Depends on:** nothing

`scripts/stream_consumer.py` builds its matrix from `config["features"]["flow_level"]` — 19 columns
— then **pads the remaining 22 with zeros** and feeds that to a 41-feature checkpoint. It does not
crash; it emits confident forecasts whose graph, graph-embedding and packet features are all zero,
which is off-distribution by construction (the 8 `graph_embed_*` values are never zero in training).
Silent degradation, not a visible failure.

**Do:** use `common.config.feature_columns(config)`, the same helper every other consumer uses.

**Acceptance:** run the consumer against the bundled sample and paste a real forecast line. Add a
test asserting the assembled matrix width equals the loaded checkpoint's `in_features`.

---

## W16 — Remove the 0-byte deliverable placeholders
**Finding:** H4 (High) · **Effort:** minutes · **Depends on:** nothing

`docs/demo.mp4` and `docs/presentation.pdf` are 0 bytes. They make a known gap look closed.

**Acceptance:** either real files with non-zero size, or the placeholders deleted and the README's
deliverables checklist showing both as outstanding. `ls -l docs/demo.mp4 docs/presentation.pdf`
pasted either way.

---

## W17 — Resolve the W3/S6 conflict: reconnaissance is currently unreachable
**Finding:** H5 (Medium) · **Effort:** ~1 hour to correct the claim; a rebuild if you want the capability · **Depends on:** nothing

Both shipped processed builds report `flow_only: true`, so W3's guard zero-fills `port_scan_score`
before the S6 reconnaissance override can read it. Reconnaissance therefore cannot be predicted on
any shipped configuration — including the PCAP-only upload path that `BUILD_REPORT.md` says makes it
"genuinely usable".

**Pick one and say which:**
1. Rebuild the synthetic processed dataset *with* its PCAP so `flow_only` is false there, letting the
   demo actually exercise recon (and making the S6 claim true for that path); or
2. Correct the S6 claim in `BUILD_REPORT.md` and `docs/AUDIT.md`, and state in the UI that
   reconnaissance is unreachable on flow-only checkpoints.

**Acceptance:** for (1), a PCAP-only upload on the synthetic config produces at least one window with
non-zero `port_scan_score` and a reconnaissance override firing, with output pasted. For (2), the
corrected wording.

---

## W18 — Fix this branch's upstream before anyone pushes
**Finding:** H6 (Medium) · **Effort:** one command · **Depends on:** nothing

`integration/all-branches-2026-09-29` tracks `origin/master` and is 25 ahead. `push.default` is
unset, so Git's `simple` mode refuses a bare `git push` — the real hazard is the remedy Git prints
with that refusal (`git push origin HEAD:master`), or a GUI "push to upstream" button. Either lands
25 commits on `master`, including H1's webhook service and H4's empty placeholders.

**Acceptance:** `git status -sb` shows the branch tracking a remote branch of its own name, or the
team agrees in writing to push only with an explicit refspec. Paste the output.

---

## W19 — Close the schema-drift class, not the fourth instance of it
**Finding:** H3, and the pattern behind S13, G11 and the `a60c549` merge bug · **Effort:** ~half a day · **Depends on:** W15

Four separate times now, code that assembles its own feature matrix or converts its own units has
drifted from the 41-column schema, and three of those four shipped. Individual fixes are not
reducing the rate.

**Do:** make one helper the only supported way to assemble a model input, have it assert its width
against the checkpoint it is about to feed, and add a test that fails if any module builds a matrix
another way (a grep-based test is acceptable and honest). Consider storing `n_features` and the
feature-name list inside the checkpoint so a mismatch is impossible to ignore at load time.

**Acceptance:** a deliberately-wrong feature list raises a clear error at load time rather than
producing predictions. Paste the failure message.

---

## W20 — Rebuild `BUILD_REPORT.md`'s summary tables and pick one v2 config
**Finding:** H7 (Medium) · **Effort:** ~1 hour · **Depends on:** W13–W19 landing first

Two loose ends the merge created:

1. `BUILD_REPORT.md` holds two summary tables. The second (~line 332) still says
   `| W3-W12 | | NOT STARTED |` while the body documents them as done, and the top table's
   `S9-S12, D2 | NOT STARTED` row is wrong now that `f1e432c` fixed S9 (cached SHAP background) and
   the CAPEC snapshot appears to close D2. This is the finding W10 was supposed to close.
2. `configs/real_data_v2.yaml` was changed to `batch_size 64 / epochs 30` by `f1e432c`, the same fix
   the builder made by creating `configs/real_data_v2_converged.yaml`. `checkpoints_real_v2` was
   trained at 512/15, so no config in the tree reproduces it, and the `_converged` config carries a
   now-false comment about what `real_data_v2.yaml` "carries today".

**Do:** regenerate the summary from the body, with one table only; verify the S9/D2 rows against the
code; then keep exactly one v2 config, retire or rename the other, and make sure every checkpoint
still on disk names a config that reproduces it.

**Acceptance:** no row in `BUILD_REPORT.md` contradicts its body, and for each of
`checkpoints_real_v2*`, the config named in the report reproduces the hyperparameters it was trained
with. Paste the config/checkpoint mapping.

---

## Reporting back

Update `BUILD_REPORT.md` with a row per item: **W-id, finding ID, status, files changed, acceptance
evidence (actual command output), any re-measured number.** The next audit checks that evidence, not
the narrative.
