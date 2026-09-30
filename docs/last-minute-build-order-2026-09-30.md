# Last-minute build order — competitive-parity features (2026-09-30)

Source: `docs/05-related-work-and-competitive-landscape.md`, 09-30 re-survey. Five items, in the
order to build them: cheapest and lowest-risk first, so a time cut anywhere in this list still
leaves everything before it shipped and working.

**Correction this order depends on:** `docs/05-related-work-and-competitive-landscape.md` line
~253 currently claims *"this project independently built the same capability [counterfactual
what-if rollout], see Feature #4"*. Checked directly (`grep -rn "counterfactual" models/ app/
frontend/src`): **nothing matches.** No such capability exists anywhere in the codebase. This is
a wrong claim in the doc, not a stale one — fix it (item 0) before item 4 makes it look
retroactively true.

---

## Item 0 — Fix the wrong claim in the competitive doc
**Effort:** 5 minutes · **Risk:** none · **Depends on:** nothing

`docs/05-related-work-and-competitive-landscape.md`: replace the "this project independently
built the same capability, see Feature #4" clause in the `raushankumarsah07` row with an honest
note that counterfactual rollout does not exist yet (or, once item 4 ships, that it now does —
reorder this fix to run *after* item 4 if item 4 lands).

**Acceptance:** `grep -n "Feature #4" docs/05-related-work-and-competitive-landscape.md` returns
nothing.

---

## Item 1 — "Digital twin" framing
**Effort:** 15 minutes · **Risk:** none, copy only · **Depends on:** nothing

Add one sentence to `README.md`'s opening description and `docs/01-architecture.md`'s summary:
something like *"a digital twin of network behavior that forecasts state K steps ahead"* —
alongside the existing "world model" language, not replacing it. Same model, more judge-legible
term; `AegisTwin`, `axorarbxy/network-digital-twin` and others in the field use this vocabulary.

**Files:** `README.md`, `docs/01-architecture.md`, whatever slide/pitch text exists.
**Acceptance:** the phrase appears once in each; no code touched.

---

## Item 2 — Frame the existing ledger as blockchain-adjacent
**Effort:** 15 minutes · **Risk:** none, copy only · **Depends on:** nothing

`models/audit_ledger.py` already implements a SHA-256 hash chain
(`AuditLedger.append`/`verify_integrity`) — the core tamper-evidence primitive of a blockchain,
without a distributed ledger. Several competitors (`raushankumarsah07`, `ShipraSharma08`,
`Radhika-coder46`) use actual blockchain framing to hit the PS's "Blockchain & Cybersecurity"
theme; state explicitly in the README/pitch that this project has the tamper-evidence property
via a hash chain, and name the tradeoff (single-writer, not distributed) rather than let judges
assume the theme was skipped.

**Files:** `README.md` (wherever `audit_ledger` is already described), pitch text.
**Acceptance:** the README's audit-ledger bullet explicitly says "blockchain-style hash chain" (or
equivalent) and states it is not a distributed ledger. No code touched.

---

## Item 3 — Label the rollout curve "t+1 ... t+K" explicitly
**Effort:** ~30 minutes · **Risk:** low, frontend-only · **Depends on:** nothing

The backend already returns everything needed:
`app/server.py::predict_forecast` returns `step_seconds` (real seconds per step) and
`infiltration_probs`/`predicted_stages` arrays of length K. Check
`frontend/src/components/ForecastProbabilityCurve` and `ForecastTimeline` — if the x-axis
currently shows raw seconds or an unlabeled index, add explicit `t+1, t+2, ..., t+K` tick labels
(or `t+{i} (+{step_seconds[i]}s)`) so the multi-horizon nature reads immediately, matching how
`shonaxx/cyberpulse` markets "t+1 to t+4" as a headline feature. You already compute more steps
(K=6) than their claimed 4.

**Files:** `frontend/src/components/ForecastProbabilityCurve/*`,
`frontend/src/components/ForecastTimeline/*`.
**Acceptance:** a screenshot of the forecast panel showing labeled `t+1..t+6` ticks (or however
many the loaded checkpoint's horizon is — do not hardcode 6, read it from the `predict` response's
`horizon_k`).

---

## Item 4 — Counterfactual "what-if" rollout
**Effort:** ~3-4 hours · **Risk:** medium (new backend endpoint + new UI panel) · **Depends on:**
nothing, but do items 1-3 first since they're strictly cheaper and this is the first item that can
go wrong under time pressure

The only genuine feature gap on this list. Three competitors (`raushankumarsah07`, `TARUN-AM`,
and whichever the doc's wrong claim was originally about) claim this; it does not exist here yet.
Cheap to build because `ForecastEngine.rollout(raw_sequence)` (`models/forecast.py`) already takes
a raw, unscaled `(L, F)` feature window and returns a full `ForecastResult` — a what-if is just
running it twice on two different last-windows and diffing the results.

**Backend (`app/server.py`):**
1. New endpoint `POST /api/v1/forecast/what-if`, body:
   ```json
   { "host_ip": "...", "perturbations": [{"feature": "flow_count", "scale": 0.0}] }
   ```
   (`scale: 0.0` zeroes it out, matching W15's own "scale-invariance" vocabulary already used
   elsewhere in this repo — reuse that concept rather than inventing new terminology.)
2. Reuse `_sequence_for(host_ip, config)` (already in `app/server.py`) to get the real sequence,
   then build a second copy with each named feature's value in the **last window only** multiplied
   by `scale` (matching `common.config.feature_columns(config)` for the column index — do not
   hand-index columns, see `models/checkpoint_io.py::validate_feature_names` and audit W19 on why).
3. Call `engine.rollout(...)` on both the real and perturbed sequences.
4. Return both `infiltration_probs` arrays plus their difference, e.g.:
   ```json
   {
     "baseline_infiltration_probs": [...],
     "counterfactual_infiltration_probs": [...],
     "probability_delta": [...],
     "perturbations_applied": [...]
   }
   ```

**Frontend:** a small new panel (or an extra control inside `ForecastProbabilityCurve`) letting the
user pick a feature from a short, curated list (not all 41 — `flow_count`, `total_packets`,
`port_scan_score`, `syn_cnt` are the ones with an obvious plain-language story, e.g. "what if this
host stopped scanning?") and a scale slider (0x-2x), then overlays the counterfactual curve on the
baseline one.

**Honesty note to carry into the pitch, not hide:** this is the model's own learned dynamics
responding to a perturbed input, not a causal simulation — the same caveat that applies to
`raushankumarsah07`'s and `TARUN-AM`'s versions of the same feature. State it as "what does the
model predict *would* happen," not "what will happen."

**Acceptance:** `tests/test_what_if_endpoint.py` — call the endpoint with a known host and
`{"feature": "flow_count", "scale": 0.0}`, assert `probability_delta` is non-trivial (not all
zeros) and that `validate_feature_names`-style column indexing is used (grep-based check, same
pattern as `tests/test_feature_schema_guard.py`, so this doesn't become a fifth instance of the
schema-drift bug class from audit W19).

---

## Item 5 — Simulated device-isolation action
**Effort:** ~1-2 hours · **Risk:** low if kept clearly simulated · **Depends on:** nothing, but do
after item 4 since it is lower-value and this order is meant to survive a time cut

`axorarbxy/sentinel-network-defense` claims automated device isolation. Do **not** build real
network automation this late (scope and safety risk, and `models/response.py`'s own docstring is
explicit that "nothing here is executed automatically" — a deliberate design choice worth keeping
for a security demo). Instead, add a UI-only simulated action that tells the same story safely:

1. **Backend:** new endpoint `POST /api/v1/response/simulate-isolation`, body `{"host_ip": "..."}`.
   It does not touch any network config — it calls `AuditLedger.append(host, peak_prob, peak_stage,
   "SIMULATED: host isolated (demo action, no real network change)")` (reusing the existing ledger
   from `models/audit_ledger.py`, same as every other recommended-action entry already logs) and
   returns `{"status": "simulated", "host_ip": ..., "note": "This is a UI simulation. No real
   network or firewall change was made."}`.
2. **Frontend:** a button on the alert card next to the existing recommended-action text —
   "Simulate isolation" — that calls the endpoint and flips that host's card to a visibly
   different "Isolated (simulated)" state, with the disclosure text from the response shown, not
   hidden in a tooltip.

**Why the wording matters:** the word "simulated" must appear in the API response, the ledger
entry, and the UI, all three — not just the UI. A judge reading the ledger export or the API
response alone should not be able to conclude a real isolation happened.

**Acceptance:** `tests/test_simulated_isolation.py` — call the endpoint, assert the ledger gained
one entry whose `recommended_action` contains the literal string `SIMULATED`, and that no function
touching real network state (e.g. no `subprocess`, no firewall/iptables call) exists anywhere in
the new code path (grep-based check).

---

## Suggested execution order and cut points

| Order | Item | Cumulative effort | Safe to stop here? |
|---|---|---|---|
| 1 | Item 1 (digital twin framing) | 15 min | Yes |
| 2 | Item 2 (ledger framing) | 30 min | Yes |
| 3 | Item 3 (t+1..t+K labels) | ~1 hour | Yes |
| 4 | Item 4 (counterfactual rollout) | ~4-5 hours | Yes — this is the one real feature; stop after this if time runs out |
| 5 | Item 5 (simulated isolation) | ~5-7 hours | N/A, last item |
| — | Item 0 (fix the doc claim) | +5 min, run last | Run once, after item 4's outcome is known |

Each item is independently committable and does not block the next — if time runs out after
item 3, ship items 1-3 and stop; do not start item 4 or 5 partially.
