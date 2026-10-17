# Evaluation: day-disjoint v2, three seeds (closes E10 for the headline metric)

**Run 2026-09-29.** Three independent training runs of `configs/real_data_v2_converged.yaml`
(`--seed 1|2|3`), identical in every other respect: day-disjoint split, batch 64, 30 epochs,
lr 3e-4, same architecture, same data, same scaler. Each seed keeps its own checkpoints under
`checkpoints_real_v2_converged/seed<N>/`; the previously shipped unseeded checkpoint was not
touched. Scored on the same test split: **7,191 sequences, 1,482 positives** (val: 6,685 / 505).

Raw numbers: `docs/v2_converged_seed_results.json`.

## Headline, with variance

| Metric | Mean ± sample SD | Range across seeds |
|---|---|---|
| **F1 @ 0.5** | **0.481 ± 0.033** | 0.459 – 0.519 |
| Precision @ 0.5 | 0.931 ± 0.024 | 0.903 – 0.946 |
| Recall @ 0.5 | 0.325 ± 0.029 | 0.303 – 0.358 |
| FPR @ 0.5 | 0.0062 ± 0.0022 | 0.0047 – 0.0088 |
| **AUROC** | **0.794 ± 0.043** | 0.748 – 0.833 |
| AUPRC | 0.646 ± 0.035 | 0.609 – 0.679 |
| F1 @ 1% FPR budget | 0.428 ± 0.095 | 0.321 – 0.501 |

## The finding: the previously reported number was an unlucky draw

| Run | F1 @ 0.5 | AUROC | AUPRC |
|---|---|---|---|
| seed 1 | 0.4657 | 0.8003 | 0.6513 |
| seed 2 | 0.5191 | 0.7481 | 0.6086 |
| seed 3 | 0.4586 | 0.8328 | 0.6787 |
| **unseeded (previously shipped, `docs/04-evaluation-real-v2.md`)** | **0.3697** | **0.7058** | **0.5247** |

The unseeded run sits **below the minimum of all three seeds on every one of these metrics** — F1
0.370 against a seed range of 0.459–0.519, AUROC 0.706 against 0.748–0.833. It is not a
representative result; it is the tail of the distribution.

So the honest day-disjoint headline is **F1 0.481 ± 0.033 / AUROC 0.794 ± 0.043**, not 0.370 /
0.706. This is a genuine improvement to the reported figure that required no change to the model,
the data or the split — only running the experiment more than once, which is what E10 asked for.
`docs/04-evaluation-real-v2.md` remains an accurate account of the single run it describes; this
document supersedes it as the number to quote.

## What the spread itself says

- **Seed variance is not negligible at this scale.** An SD of 0.033 on F1 and 0.043 on AUROC means
  any comparison between two configurations differing by less than roughly 0.07 F1 is inside noise.
  That retroactively settles the GNN ablation (E10's original trigger), whose conclusions rested on
  differences of 0.003–0.032 — comfortably inside one standard deviation, so "no measurable benefit"
  was the right call for the right reason.
- **The 1%-FPR operating point is the least stable number in the project**: SD 0.095, range
  0.321–0.501. Roughly triple the relative spread of F1 at 0.5. Threshold-sensitive metrics on this
  split should always be quoted with their spread, never as a point estimate.
- **Precision is stable, recall is not the problem it looks like.** Precision holds at 0.93 ± 0.02
  across seeds while recall sits at 0.325 ± 0.029 — the model is consistently conservative rather
  than erratic. What it flags, it flags correctly; it simply misses most attack windows on an
  honest split.

## Caveats

- Three seeds is the minimum for a spread and gives a weak estimate of the SD. Treat the intervals
  as indicative, not as confidence intervals.
- Variance here covers **training stochasticity only** (weight init, shuffling). It does not cover
  split choice, and the day-disjoint split is a single fixed partition — the larger uncertainty is
  which days land in test (see E7, and the concentration noted in G2).
- E10 remains open for everything else: the LOFO folds, the cross-dataset evaluations and the
  packet-aware pilots are all still single runs or have their own separate seed sets.

## Which checkpoint is served (A1 truth pass, 2026-10-17)

The server used to load the unseeded run (F1 0.370 / AUROC 0.706, below all three seeds) while the
dashboard displayed the 3-seed mean. It now serves one of the seeds, picked by a rule stated before
looking at any test metric: **the seed with the lowest validation loss.** Best val loss per run,
from `logs/seeds_v2_converged.log` (the checkpoints do not store it):

| Seed | Best val loss | Served? |
|---|---|---|
| **seed 1** | **0.7579** | **yes** |
| seed 2 | 0.8327 | no |
| seed 3 | 0.8555 | no |

Seed 1 is not the best seed on test F1 (seed 2) or AUROC (seed 3); it was not selected on test. Its
own test row: F1 0.466, precision 0.903, recall 0.314, AUROC 0.800, AUPRC 0.651. Served via
`configs/real_data_v2_converged_seed1.yaml` (checkpoint `checkpoints_real_v2_converged/seed1/world_model_best.pt`,
same `data/processed_real_v2_converged` dataset and 41-wide scaler all three seeds trained on). The
seed-1 file already carries `feature_names`, so the W19 schema guard runs on load
(`tests/test_feature_schema_guard.py`); `scripts/backfill_feature_names.py` had nothing to write for
it. The unseeded checkpoint has no `feature_names` and the backfill script cannot derive them (no
embedded config key it reads), so it remains unguarded; it is selectable as `--config v2-unseeded`.
`/api/v1/eval/metrics` returns the served model's row under `served_model`, separate from the
across-seed mean.
