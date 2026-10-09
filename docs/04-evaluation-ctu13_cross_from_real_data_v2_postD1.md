> **Post-D-1-fix CTU-13 evaluation, generated 2026-10-10.** Checkpoint `checkpoints_real_v2/` (v2, day-disjoint),
> scaler `data/processed_real_v2/scaler.npz`, test data = rebuilt `data/processed/ctu13/final_splits` with
> corrected labels (test positives 5,944; 0 onset windows; old build backed up in `final_splits_pre_D1_fix/`).
> Command: `python -m eval.benchmark --train-config configs/real_data_v2.yaml --test-config configs/ctu13.yaml`.
> The older `docs/04-evaluation-ctu13*.md` reports reflect **pre-fix labels**.
>
> | World Model AUROC | v1 ckpt (`real_data.yaml`) | v2 ckpt (`real_data_v2.yaml`) |
> |---|---|---|
> | pre-fix labels | 0.5172 (published) | 0.7646 (re-scored on backup) |
> | post-fix labels | 0.5175 | **0.7804** |
>
> Caveat: the corrected test set has no benign-to-attack transitions, so this is current-state detection of
> ongoing botnet C2 traffic, not forecasting; AUPRC is 0.070 and every F1 at the 0.5 threshold is ~0. This does
> not make CTU-13 a usable forecasting benchmark.

# Cross-Dataset Evaluation: Train on real_data_v2 / Test on CTU-13

Test set: 186520 sequences from **CTU-13** (never seen during training).

The world model was trained on **real_data_v2** and evaluated here on **CTU-13** using
the *real_data_v2 scaler* — the model sees feature values on the same scale it was trained with.
This is the strongest available evidence against signature memorisation: the model must generalise
to a different dataset, capture tool, botnet family, and traffic distribution entirely.

Native-dataset baselines (LR + Persistence) are trained on **CTU-13**'s own training split
with a **CTU-13 scaler** — they represent the best a dataset-specific shallow model can do,
and serve as the comparison anchor.

## Infiltration probability — default threshold (0.5)

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Train: real_data_v2 / Test: CTU-13) | 0.000 | 0.000 | 0.000 | 0.001 |
| Baseline (LR, last window, native CTU-13) | 0.036 | 0.505 | 0.019 | 0.001 |
| Baseline (LR, stacked window, native CTU-13) | 0.090 | 0.943 | 0.047 | 0.000 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native CTU-13 | 1.000 | 1.000 | 1.000 | 0.000 |
| Persistence [ORACLE -- reads true current label, not deployable], native CTU-13 | 1.000 | 1.000 | 1.000 | 0.000 |
| Persistence (on predicted label -- deployable, native CTU-13) | 0.036 | 0.505 | 0.019 | 0.001 |

## Infiltration probability — fixed 5% FPR budget

Threshold selected on the **CTU-13 val split** only (never test).

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Train: real_data_v2 / Test: CTU-13) | 0.000 | 0.000 | 0.000 | 0.000 |
| Baseline (LR, last window, native CTU-13) | 0.000 | 0.000 | 0.000 | 0.000 |
| Baseline (LR, stacked window, native CTU-13) | 0.000 | 0.000 | 0.000 | 0.000 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native CTU-13 | 1.000 | 1.000 | 1.000 | 0.000 |
| Persistence [ORACLE -- reads true current label, not deployable], native CTU-13 | 1.000 | 1.000 | 1.000 | 0.000 |
| Persistence (on predicted label -- deployable, native CTU-13) | 0.000 | 0.000 | 0.000 | 0.000 |

## Infiltration probability — fixed 1% FPR budget

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Train: real_data_v2 / Test: CTU-13) | 0.000 | 0.000 | 0.000 | 0.000 |
| Baseline (LR, last window, native CTU-13) | 0.000 | 0.000 | 0.000 | 0.000 |
| Baseline (LR, stacked window, native CTU-13) | 0.000 | 0.000 | 0.000 | 0.000 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native CTU-13 | 1.000 | 1.000 | 1.000 | 0.000 |
| Persistence [ORACLE -- reads true current label, not deployable], native CTU-13 | 1.000 | 1.000 | 1.000 | 0.000 |
| Persistence (on predicted label -- deployable, native CTU-13) | 0.000 | 0.000 | 0.000 | 0.000 |

## Infiltration probability — fixed 0.1% FPR budget

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Train: real_data_v2 / Test: CTU-13) | 0.000 | 0.000 | 0.000 | 0.000 |
| Baseline (LR, last window, native CTU-13) | 0.000 | 0.000 | 0.000 | 0.000 |
| Baseline (LR, stacked window, native CTU-13) | 0.000 | 0.000 | 0.000 | 0.000 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native CTU-13 | 1.000 | 1.000 | 1.000 | 0.000 |
| Persistence [ORACLE -- reads true current label, not deployable], native CTU-13 | 1.000 | 1.000 | 1.000 | 0.000 |
| Persistence (on predicted label -- deployable, native CTU-13) | 0.000 | 0.000 | 0.000 | 0.000 |

## Infiltration probability — threshold-free ranking (AUROC / AUPRC)

| Model | AUROC | AUPRC |
|---|---|---|
| World Model (Train: real_data_v2 / Test: CTU-13) | 0.7804 | 0.0700 |
| Baseline (LR, last window, native CTU-13) | 0.6029 | 0.1122 |
| Baseline (LR, stacked window, native CTU-13) | 0.7811 | 0.2432 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native CTU-13 | 1.0000 | 1.0000 |
| Persistence [ORACLE -- reads true current label, not deployable], native CTU-13 | 1.0000 | 1.0000 |
| Persistence (on predicted label -- deployable, native CTU-13) | 0.6029 | 0.1122 |

## MITRE stage classification (2 classes present, `impact`-mapped windows excluded)

Support by class: benign: 180576, command_and_control: 5944.

| Model | F1 (macro, all classes) | F1 (macro, attack classes only) | Precision (macro) | Recall (macro) |
|---|---|---|---|---|
| World Model (Train: real_data_v2 / Test: CTU-13) | 0.246 | 0.000 | 0.242 | 0.250 |
| Baseline (LR, last window, native CTU-13) | 0.510 | 0.036 | 0.737 | 0.509 |
| Baseline (LR, stacked window, native CTU-13) | 0.537 | 0.090 | 0.956 | 0.524 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native CTU-13 | 1.000 | 1.000 | 1.000 | 1.000 |
| Persistence [ORACLE -- reads true current label, not deployable], native CTU-13 | 1.000 | 1.000 | 1.000 | 1.000 |
| Persistence (on predicted label -- deployable, native CTU-13) | 0.510 | 0.036 | 0.737 | 0.509 |

## K-step forecast lead time

No benign-to-attack transitions occurred within the forecast horizon in this test set, so lead time is undefined here (not zero — there was nothing to detect early).
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
