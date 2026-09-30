# Frozen-state ablation — does the K-step rollout earn its keep? (W21)

**Run 2026-09-30.** `scripts/ablate_frozen_state.py`, config `configs/real_data_v2_converged.yaml`,
the same day-disjoint test split and the same three seed checkpoints behind
`docs/04-evaluation-real-v2-seeds.md`. Raw output: `docs/frozen_state_ablation.json`.

## Why this was run

Every headline number this project publishes — F1 0.481, AUROC 0.794, the LOFO folds — comes from
`eval/lofo.py::_predict_infiltration`, which runs **one forward pass** and scores it against
`infiltration[:, 0]`. **That is a t+1 measurement.** The K-step autoregressive rollout that the
dashboard renders, and that the phrase "60-second forecast" refers to, had never been evaluated at
all. Nothing in this repository answered the question "does rolling the world model's state
forward do anything?"

The experiment is borrowed from a competitor, `ShipraSharma08/AI-Network-Attack-Forecasting`,
which publishes exactly this ablation (see `docs/05-related-work-and-competitive-landscape.md`).

## Method

Two rollouts, scored against the same per-horizon labels on the same 7,191 test sequences:

- **genuine** — the real rollout: feed the predicted next state back in and advance the window,
  the state-advance line copied verbatim from `ForecastEngine.rollout_batch`.
- **frozen** — the control: never advance the state. Because the model is deterministic, this is
  the t+1 prediction reused for all six steps. It answers: *would simply keeping the first-step
  estimate for the whole minute do just as well?*

The two are identical at k=1 by construction. That is the sanity check, not a result — and it
holds to the digit. k=1 also reproduces the published headline exactly (0.7937 mean vs the 0.794
in `docs/04-evaluation-real-v2-seeds.md`), which anchors everything below to the existing numbers.

## Result — the rollout does not earn its keep

Mean ± SD over three seeds, AUROC:

| Step | Forecast | Genuine (real rollout) | Frozen (t+1 reused) | Δ |
|---|---|---|---|---|
| k=1 | t+10s | 0.7937 ± 0.0349 | 0.7937 ± 0.0349 | +0.0000 |
| k=2 | t+20s | 0.7823 ± 0.0443 | 0.7917 ± 0.0360 | −0.0094 |
| k=3 | t+30s | 0.7725 ± 0.0510 | 0.7894 ± 0.0352 | −0.0170 |
| k=4 | t+40s | 0.7663 ± 0.0545 | 0.7876 ± 0.0358 | −0.0213 |
| k=5 | t+50s | 0.7602 ± 0.0581 | 0.7868 ± 0.0346 | −0.0267 |
| **k=6** | **t+60s** | **0.7549 ± 0.0608** | **0.7853 ± 0.0335** | **−0.0303** |

The other two metrics agree at k=6: AUPRC 0.5714 (genuine) vs 0.6214 (frozen); F1@0.5 0.4121 vs
0.4735.

**Advancing the state makes the forecast worse, monotonically with horizon.** Frozen is
essentially flat (0.7937 → 0.7853 over the full minute) while genuine decays. The rollout is not
adding information about the future; it is compounding its own prediction error.

### Is it statistically established? No — but the direction is unanimous

Paired per-seed differences (genuine − frozen):

| Step | seed1 | seed2 | seed3 | mean | t (df=2) | p<0.05? |
|---|---|---|---|---|---|---|
| k=2 | −0.0076 | −0.0203 | −0.0003 | −0.0094 | −1.60 | no |
| k=4 | −0.0105 | −0.0484 | −0.0050 | −0.0213 | −1.56 | no |
| k=6 | −0.0188 | −0.0681 | −0.0040 | −0.0303 | −1.56 | no |

Every one of the 15 paired comparisons (3 seeds × k=2..6) is negative, and all three metrics
agree — but with three seeds the test needs |t| > 4.303 and reaches ≈1.56. The defensible
statement is therefore **"no evidence the rollout adds predictive value, and consistent evidence
of a small penalty"**, not "the rollout is proven harmful". Seed 2 drives most of the magnitude
(−0.068 at k=6 against −0.019 and −0.004); its k=1 AUROC is also the weakest of the three
(0.7481), so the worst-initialised model degrades fastest under rollout.

## What this means for the project's claims

1. **"60-second forecast" must be stated carefully.** The system does produce a six-step, 60-second
   trajectory, and that is what the dashboard shows. What is *not* supported is that the
   autoregressive rollout makes the later steps better than simply holding the t+1 estimate. On
   this evidence it makes them slightly worse.
2. **The published headline is a t+1 number.** F1 0.481 / AUROC 0.794 measure one step ahead —
   10 seconds — not 60. This was true before this ablation; the ablation is what made it visible.
   Any slide implying those figures describe a 60-second forecast is overstating them.
3. **It does not invalidate the architecture.** The world model's learned state transition is still
   what produces per-step stage predictions, `transition_magnitude` and the what-if
   counterfactual path, none of which a frozen estimate can produce. What it invalidates is the
   narrower claim that rollout improves *infiltration ranking* at longer horizons.
4. **This is a negative result about this project's own model**, of the kind the competitive survey
   had claimed no team publishes. Two competitors already do (`ShadowCat`'s GraphSAGE NO-GO,
   `CyberPulse`'s README). This is ours.

## Limitations

- Three seeds, one dataset, one split. Underpowered, as the t-values say.
- The frozen control is deterministic-model-specific: it is the t+1 prediction repeated. A
  stochastic model would need MC sampling for a fair frozen baseline.
- Only infiltration probability is scored. Per-step *stage* accuracy under rollout is not measured
  here and could behave differently.
- `future_stages` carries −1 (no stage label) on 297 of 7,191 windows. Those rows are scored
  anyway, because `infiltration` is defined for them and because that is what the published path
  does; excluding them moves k=1 from 0.794 to 0.744 and does not change the genuine-vs-frozen
  direction. The per-seed figures for the excluded-row variant are in the JSON under
  `genuine_stage_labelled_only`.

## Reproduce

```bash
python -m scripts.ablate_frozen_state --config configs/real_data_v2_converged.yaml --seeds 1 2 3
```
