# Leave-one-attack-family-out, three seeds (E10 for the LOFO folds)

**Run 2026-09-29.** Each of the four LOFO folds retrained three times (`--seed 1|2|3`, 10 epochs,
otherwise identical to the original run), scored on the same held-out days. Per-seed results:
`docs/lofo_results_v2_seed{1,2,3}.json`; aggregate: `docs/lofo_seed_summary.json`.

## Results

| Held-out family | Test seq | Positives | AUROC mean ± SD | Range | Single unseeded run |
|---|---|---|---|---|---|
| initial_access | 11,369 | 1,549 | **0.685 ± 0.087** | 0.626 – 0.785 | 0.612 |
| lateral_movement | 8,319 | 1,728 | **0.528 ± 0.129** | 0.415 – 0.669 | 0.432 |
| command_and_control | 4,666 | 2,028 | **0.646 ± 0.131** | 0.525 – 0.785 | 0.531 |
| impact (DDoS) | 1,234,772 | 4,655 | **0.819 ± 0.128** | 0.671 – 0.894 | 0.872 |

## What changes

**1. "Worse than chance" was a single-seed artefact, and should be withdrawn.** The published
lateral-movement figure of AUROC 0.432 was the project's most damaging number — it implied the model
was actively anti-predictive on that family. Across three seeds the mean is **0.528**, with the
single run sitting near the bottom of a 0.415–0.669 range. The honest statement is *chance-level*,
not *worse than chance*. Any slide or report carrying 0.432 as evidence of anti-prediction is wrong.

**2. Three of four single-seed runs were unlucky draws.** initial_access 0.612 → 0.685,
lateral_movement 0.432 → 0.528, command_and_control 0.531 → 0.646. Only `impact` moved down
(0.872 → 0.819). This is the same pattern the day-disjoint headline showed
(`docs/04-evaluation-real-v2-seeds.md`): the project's published figures were systematically drawn
from the low tail because nothing was repeated.

**3. Seed variance on LOFO is large — 0.087 to 0.131 SD**, two to three times the day-disjoint
headline's 0.043. Folds train on smaller, more heterogeneous data, so they are far less stable. No
LOFO conclusion from a single run was ever safe, in either direction.

## Is any fold distinguishable from chance?

A rough t-test against AUROC 0.5 with three seeds (df = 2, so |t| > 4.303 for p < 0.05):

| Family | mean | t | Verdict |
|---|---|---|---|
| initial_access | 0.685 | +3.66 | not distinguishable |
| lateral_movement | 0.528 | +0.38 | not distinguishable |
| command_and_control | 0.646 | +1.92 | not distinguishable |
| impact (DDoS) | 0.819 | +4.32 | distinguishable, but only just |

**Read this as weak evidence, not proof of absence.** Three seeds gives df = 2, which is a very
low-powered test — it cannot detect a real effect of this size. The correct conclusion is *"no
statistically supported evidence of transfer to held-out families"*, not *"proven no transfer"*.
Equally, `impact` clears the bar by 0.02 of a t-statistic and should not be presented as a solid
positive.

## What this means for the project's claims

- The generalisation story is **unchanged in direction**: only DDoS, the one family with abundant
  real per-host data (E7), shows any transfer, and even that is marginal once seeded.
- The story is **less damning in magnitude**: nothing is anti-predictive; three families sit at
  chance with wide intervals.
- The right framing is that the experiment is **underpowered by the data**, not that the model is
  broken. Three of four families have no real per-host structure to learn from — which is exactly
  what CIC-IDS-2017 (now on disk, per-host IPs on all 8 days) is there to fix.

## Caveats

- Three seeds is the minimum for a spread; treat SDs as indicative, and the t-tests as directional.
- Variance covers training stochasticity only — not the choice of held-out days, which is fixed per
  fold and is the larger uncertainty (see E7, G2).
- Fold training sets remain wildly uneven: `impact` trains on ~16k sequences against ~1.24M for the
  others, so cross-family AUROC comparisons are still not like-for-like.
