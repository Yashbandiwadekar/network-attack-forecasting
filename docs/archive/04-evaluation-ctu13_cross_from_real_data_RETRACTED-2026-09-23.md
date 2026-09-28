> **RETRACTED 2026-09-23.** The World Model figures below (including F1 0.534 at the 5% FPR budget)
> came from a 33-feature checkpoint and 33-feature CTU-13 build that no longer exist on disk, and the
> native-LR rows used a scaler fitted on the test split (audit E9). Recomputed against the shipped
> checkpoint and the current CTU-13 build: F1 0.009, AUROC 0.517 (chance) -- the model does **not**
> transfer to CTU-13. See `docs/04-evaluation-ctu13_cross_from_real_data.md` (regenerated) and
> `docs/AUDIT.md` G1. Kept here only as a record of the withdrawn claim.

# Cross-Dataset Evaluation: Train on CIC-IDS-2018 / Test on CTU-13

Test set: 186520 sequences from **CTU-13** (never seen during training).

The world model was trained on **CIC-IDS-2018** and evaluated here on **CTU-13** using
the *CIC-IDS-2018 scaler* — the model sees feature values on the same scale it was trained with.
This is the strongest available evidence against signature memorisation: the model must generalise
to a different dataset, capture tool, botnet family, and traffic distribution entirely.

Native-dataset baselines (LR + Persistence) are trained on **CTU-13**'s own training split
with a **CTU-13 scaler** — they represent the best a dataset-specific shallow model can do,
and serve as the comparison anchor.

## Infiltration probability — default threshold (0.5)

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Train: CIC-IDS-2018 / Test: CTU-13) | 0.001 | 0.057 | 0.001 | 0.000 |
| Baseline (LR, last window, native CTU-13) | 0.014 | 0.362 | 0.007 | 0.000 |
| Baseline (LR, stacked window, native CTU-13) | 0.002 | 0.207 | 0.001 | 0.000 |
| Persistence (no learning, CTU-13) | 0.980 | 0.980 | 0.980 | 0.001 |

## Infiltration probability — fixed 5% FPR budget

Threshold selected on the **CTU-13 val split** only (never test).

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Train: CIC-IDS-2018 / Test: CTU-13) | 0.534 | 0.453 | 0.651 | 0.028 |
| Baseline (LR, last window, native CTU-13) | 0.045 | 0.505 | 0.023 | 0.001 |
| Baseline (LR, stacked window, native CTU-13) | 0.000 | 0.000 | 0.000 | 0.000 |
| Persistence (no learning, CTU-13) | 0.980 | 0.980 | 0.980 | 0.001 |

## MITRE stage classification (5-way, `impact`-mapped windows excluded)

| Model | F1 (macro) | Precision (macro) | Recall (macro) |
|---|---|---|---|
| World Model (Train: CIC-IDS-2018 / Test: CTU-13) | 0.328 | 0.323 | 0.333 |
| Baseline (LR, last window, native CTU-13) | 0.520 | 0.831 | 0.514 |
| Baseline (LR, stacked window, native CTU-13) | 0.529 | 0.976 | 0.519 |
| Persistence (no learning, CTU-13) | 1.000 | 1.000 | 1.000 |

## Interpretation

- **Cross-dataset World Model vs native baselines**: a cross-dataset world model that outperforms
  a native-trained LR classifier demonstrates genuine generalisation — the Transformer has learned
  attack *dynamics*, not dataset-specific feature correlations.
- **Graph features**: CTU-13 has real IP data throughout, so `graph_out_degree`,
  `graph_fan_out_ratio`, `graph_fan_in_ratio`, `graph_component_size`, and `graph_dst_entropy`
  all carry real signal here.  The 12-window temporal structure over these graph features
  is what the world model exploits.
- **Feature alignment**: both configs share identical `features:` sections (flow + graph + packet
  levels), so the checkpoint loads without any shape mismatch.
