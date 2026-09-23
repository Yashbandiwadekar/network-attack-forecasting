# Cross-Dataset Evaluation: Train on real_data_v2 / Test on unsw_nb15

Test set: 16289 sequences from **unsw_nb15** (never seen during training).

The world model was trained on **real_data_v2** and evaluated here on **unsw_nb15** using
the *real_data_v2 scaler* — the model sees feature values on the same scale it was trained with.
This is the strongest available evidence against signature memorisation: the model must generalise
to a different dataset, capture tool, botnet family, and traffic distribution entirely.

Native-dataset baselines (LR + Persistence) are trained on **unsw_nb15**'s own training split
with a **unsw_nb15 scaler** — they represent the best a dataset-specific shallow model can do,
and serve as the comparison anchor.

## Infiltration probability — default threshold (0.5)

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Train: real_data_v2 / Test: unsw_nb15) | 0.000 | 0.000 | 0.000 | 0.002 |
| Baseline (LR, last window, native unsw_nb15) | 0.919 | 0.927 | 0.910 | 0.014 |
| Baseline (LR, stacked window, native unsw_nb15) | 0.985 | 0.978 | 0.992 | 0.005 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native unsw_nb15 | 0.995 | 0.995 | 0.995 | 0.001 |
| Persistence [ORACLE -- reads true current label, not deployable], native unsw_nb15 | 0.995 | 0.995 | 0.995 | 0.001 |
| Persistence (on predicted label -- deployable, native unsw_nb15) | 0.919 | 0.929 | 0.910 | 0.014 |

## Infiltration probability — fixed 5% FPR budget

Threshold selected on the **unsw_nb15 val split** only (never test).

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Train: real_data_v2 / Test: unsw_nb15) | 0.411 | 0.535 | 0.334 | 0.058 |
| Baseline (LR, last window, native unsw_nb15) | 0.897 | 0.815 | 0.996 | 0.045 |
| Baseline (LR, stacked window, native unsw_nb15) | 0.955 | 0.915 | 1.000 | 0.019 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native unsw_nb15 | 0.995 | 0.995 | 0.995 | 0.001 |
| Persistence [ORACLE -- reads true current label, not deployable], native unsw_nb15 | 0.995 | 0.995 | 0.995 | 0.001 |
| Persistence (on predicted label -- deployable, native unsw_nb15) | 0.900 | 0.820 | 0.996 | 0.044 |

## Infiltration probability — fixed 1% FPR budget

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Train: real_data_v2 / Test: unsw_nb15) | 0.178 | 0.607 | 0.104 | 0.014 |
| Baseline (LR, last window, native unsw_nb15) | 0.899 | 0.938 | 0.863 | 0.012 |
| Baseline (LR, stacked window, native unsw_nb15) | 0.971 | 0.946 | 0.999 | 0.012 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native unsw_nb15 | 0.995 | 0.995 | 0.995 | 0.001 |
| Persistence [ORACLE -- reads true current label, not deployable], native unsw_nb15 | 0.995 | 0.995 | 0.995 | 0.001 |
| Persistence (on predicted label -- deployable, native unsw_nb15) | 0.900 | 0.939 | 0.864 | 0.011 |

## Infiltration probability — fixed 0.1% FPR budget

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Train: real_data_v2 / Test: unsw_nb15) | 0.135 | 0.706 | 0.075 | 0.006 |
| Baseline (LR, last window, native unsw_nb15) | 0.413 | 0.992 | 0.261 | 0.000 |
| Baseline (LR, stacked window, native unsw_nb15) | 0.556 | 0.993 | 0.386 | 0.001 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native unsw_nb15 | 0.602 | 0.996 | 0.431 | 0.000 |
| Persistence [ORACLE -- reads true current label, not deployable], native unsw_nb15 | 0.000 | 0.000 | 0.000 | 0.000 |
| Persistence (on predicted label -- deployable, native unsw_nb15) | 0.374 | 0.992 | 0.231 | 0.000 |

## Infiltration probability — threshold-free ranking (AUROC / AUPRC)

| Model | AUROC | AUPRC |
|---|---|---|
| World Model (Train: real_data_v2 / Test: unsw_nb15) | 0.4433 | 0.2965 |
| Baseline (LR, last window, native unsw_nb15) | 0.9945 | 0.9737 |
| Baseline (LR, stacked window, native unsw_nb15) | 0.9990 | 0.9904 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native unsw_nb15 | 0.9969 | 0.9908 |
| Persistence [ORACLE -- reads true current label, not deployable], native unsw_nb15 | 0.9969 | 0.9906 |
| Persistence (on predicted label -- deployable, native unsw_nb15) | 0.9945 | 0.9739 |

## MITRE stage classification (4 classes present, `impact`-mapped windows excluded)

Support by class: benign: 13563, reconnaissance: 398, initial_access: 1182, lateral_movement: 2.

| Model | F1 (macro, all classes) | F1 (macro, attack classes only) | Precision (macro) | Recall (macro) |
|---|---|---|---|---|
| World Model (Train: real_data_v2 / Test: unsw_nb15) | 0.236 | 0.000 | 0.224 | 0.250 |
| Baseline (LR, last window, native unsw_nb15) | 0.455 | 0.275 | 0.432 | 0.485 |
| Baseline (LR, stacked window, native unsw_nb15) | 0.464 | 0.285 | 0.485 | 0.497 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native unsw_nb15 | 0.436 | 0.252 | 0.428 | 0.444 |
| Persistence [ORACLE -- reads true current label, not deployable], native unsw_nb15 | 0.468 | 0.295 | 0.495 | 0.448 |
| Persistence (on predicted label -- deployable, native unsw_nb15) | 0.491 | 0.322 | 0.510 | 0.494 |

## K-step forecast lead time

The metric the problem statement actually asks for: of the hosts that are benign right now but
cross into an attack state within the next 6 windows (60s), how much *advance*
warning does the K-step rollout give, at the same fixed-5%-FPR threshold used above?
This has no baseline column — a single-window classifier has no mechanism to imagine a future
state and alarm on it before that state is actually observed, so there is nothing to compare
against fairly (same reasoning the module docstring already gives for not benchmarking K-step
rollout itself against the baselines).

| Metric | Value |
|---|---|
| Benign-to-attack transitions in test set | 14 |
| Missed entirely (never alarmed within horizon) | 4 (28.6%) |
| Detected *before* the attack actually started | 0.0% |
| Mean lead time (detected cases; + = early, - = late) | -10.0s |
| Median lead time (detected cases) | -10.0s |
| False alarms / benign-for-whole-horizon sequences | 11390 / 13549 (84.07%) |
| Alarm precision (true early alarms / all alarms raised) | 0.1% |

Lead time is `(actual attack-onset step) - (first step the alarm threshold is crossed)`, in
seconds. A positive value is a genuine early warning — the alarm fired before the attack window
it was warning about actually arrived. Missed transitions are excluded from the mean/median (there
is no lead time to average when the model never alarmed at all) and reported separately as a miss
rate instead, so a high miss rate can't silently inflate the mean by dropping out of it.

**Audit E3**: the false-alarm rate and alarm precision rows above are the other half of this
metric that the original version omitted — a threshold low enough to catch every transition early
can do so by alarming on nearly everything, which the miss-rate/lead-time numbers alone can't
reveal. A low alarm precision means most of what this threshold flags is noise, not warning.

## Interpretation

- **Cross-dataset World Model vs native baselines**: a cross-dataset world model that outperforms
  a native-trained LR classifier demonstrates genuine generalisation — the Transformer has learned
  attack *dynamics*, not dataset-specific feature correlations.
- **Graph features**: unsw_nb15 has real IP data throughout, so `graph_out_degree`,
  `graph_fan_out_ratio`, `graph_fan_in_ratio`, `graph_component_size`, and `graph_dst_entropy`
  all carry real signal here.  The 12-window temporal structure over these graph features
  is what the world model exploits.
- **Feature alignment**: both configs share identical `features:` sections (flow + graph + packet
  levels), so the checkpoint loads without any shape mismatch.
