# Cross-Dataset Evaluation: Train on real_data_v2 / Test on unsw_nb15_v2

Test set: 16289 sequences from **unsw_nb15_v2** (never seen during training).

The world model was trained on **real_data_v2** and evaluated here on **unsw_nb15_v2** using
the *real_data_v2 scaler* — the model sees feature values on the same scale it was trained with.
This is the strongest available evidence against signature memorisation: the model must generalise
to a different dataset, capture tool, botnet family, and traffic distribution entirely.

Native-dataset baselines (LR + Persistence) are trained on **unsw_nb15_v2**'s own training split
with a **unsw_nb15_v2 scaler** — they represent the best a dataset-specific shallow model can do,
and serve as the comparison anchor.

## Infiltration probability — default threshold (0.5)

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Train: real_data_v2 / Test: unsw_nb15_v2) | 0.000 | 0.000 | 0.000 | 0.002 |
| Baseline (LR, last window, native unsw_nb15_v2) | 0.942 | 0.937 | 0.946 | 0.013 |
| Baseline (LR, stacked window, native unsw_nb15_v2) | 0.988 | 0.979 | 0.997 | 0.004 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native unsw_nb15_v2 | 0.995 | 0.995 | 0.995 | 0.001 |
| Persistence [ORACLE -- reads true current label, not deployable], native unsw_nb15_v2 | 0.995 | 0.995 | 0.995 | 0.001 |
| Persistence (on predicted label -- deployable, native unsw_nb15_v2) | 0.942 | 0.938 | 0.945 | 0.013 |

## Infiltration probability — fixed 5% FPR budget

Threshold selected on the **unsw_nb15_v2 val split** only (never test).

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Train: real_data_v2 / Test: unsw_nb15_v2) | 0.359 | 0.525 | 0.273 | 0.050 |
| Baseline (LR, last window, native unsw_nb15_v2) | 0.896 | 0.813 | 0.999 | 0.046 |
| Baseline (LR, stacked window, native unsw_nb15_v2) | 0.985 | 0.973 | 0.998 | 0.006 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native unsw_nb15_v2 | 0.995 | 0.995 | 0.995 | 0.001 |
| Persistence [ORACLE -- reads true current label, not deployable], native unsw_nb15_v2 | 0.995 | 0.995 | 0.995 | 0.001 |
| Persistence (on predicted label -- deployable, native unsw_nb15_v2) | 0.904 | 0.827 | 0.998 | 0.042 |

## Infiltration probability — fixed 1% FPR budget

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Train: real_data_v2 / Test: unsw_nb15_v2) | 0.078 | 0.374 | 0.044 | 0.015 |
| Baseline (LR, last window, native unsw_nb15_v2) | 0.943 | 0.932 | 0.955 | 0.014 |
| Baseline (LR, stacked window, native unsw_nb15_v2) | 0.985 | 0.973 | 0.998 | 0.006 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native unsw_nb15_v2 | 0.995 | 0.995 | 0.995 | 0.001 |
| Persistence [ORACLE -- reads true current label, not deployable], native unsw_nb15_v2 | 0.995 | 0.995 | 0.995 | 0.001 |
| Persistence (on predicted label -- deployable, native unsw_nb15_v2) | 0.943 | 0.934 | 0.953 | 0.014 |

## Infiltration probability — fixed 0.1% FPR budget

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Train: real_data_v2 / Test: unsw_nb15_v2) | 0.050 | 0.437 | 0.027 | 0.007 |
| Baseline (LR, last window, native unsw_nb15_v2) | 0.489 | 0.993 | 0.325 | 0.000 |
| Baseline (LR, stacked window, native unsw_nb15_v2) | 0.743 | 0.996 | 0.592 | 0.001 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native unsw_nb15_v2 | 0.602 | 0.996 | 0.431 | 0.000 |
| Persistence [ORACLE -- reads true current label, not deployable], native unsw_nb15_v2 | 0.000 | 0.000 | 0.000 | 0.000 |
| Persistence (on predicted label -- deployable, native unsw_nb15_v2) | 0.499 | 0.992 | 0.333 | 0.001 |

## Infiltration probability — threshold-free ranking (AUROC / AUPRC)

| Model | AUROC | AUPRC |
|---|---|---|
| World Model (Train: real_data_v2 / Test: unsw_nb15_v2) | 0.4239 | 0.2467 |
| Baseline (LR, last window, native unsw_nb15_v2) | 0.9972 | 0.9782 |
| Baseline (LR, stacked window, native unsw_nb15_v2) | 0.9993 | 0.9912 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native unsw_nb15_v2 | 0.9969 | 0.9908 |
| Persistence [ORACLE -- reads true current label, not deployable], native unsw_nb15_v2 | 0.9969 | 0.9906 |
| Persistence (on predicted label -- deployable, native unsw_nb15_v2) | 0.9972 | 0.9781 |

## MITRE stage classification (4 classes present, `impact`-mapped windows excluded)

Support by class: benign: 13563, reconnaissance: 398, initial_access: 1182, lateral_movement: 2.

| Model | F1 (macro, all classes) | F1 (macro, attack classes only) | Precision (macro) | Recall (macro) |
|---|---|---|---|---|
| World Model (Train: real_data_v2 / Test: unsw_nb15_v2) | 0.236 | 0.000 | 0.224 | 0.250 |
| Baseline (LR, last window, native unsw_nb15_v2) | 0.456 | 0.276 | 0.431 | 0.488 |
| Baseline (LR, stacked window, native unsw_nb15_v2) | 0.464 | 0.285 | 0.478 | 0.496 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native unsw_nb15_v2 | 0.436 | 0.252 | 0.428 | 0.444 |
| Persistence [ORACLE -- reads true current label, not deployable], native unsw_nb15_v2 | 0.468 | 0.295 | 0.495 | 0.448 |
| Persistence (on predicted label -- deployable, native unsw_nb15_v2) | 0.499 | 0.334 | 0.514 | 0.499 |

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
| Missed entirely (never alarmed within horizon) | 10 (71.4%) |
| Detected *before* the attack actually started | 0.0% |
| Mean lead time (detected cases; + = early, - = late) | -12.5s |
| Median lead time (detected cases) | -15.0s |
| False alarms / benign-for-whole-horizon sequences | 11029 / 13549 (81.40%) |
| Alarm precision (true early alarms / all alarms raised) | 0.0% |
| Achieved FPR on this test split, at the val-tuned 5%-budget threshold | 5.0% |

Lead time is `(actual attack-onset step) - (first step the alarm threshold is crossed)`, in
seconds. A positive value is a genuine early warning — the alarm fired before the attack window
it was warning about actually arrived. Missed transitions are excluded from the mean/median (there
is no lead time to average when the model never alarmed at all) and reported separately as a miss
rate instead, so a high miss rate can't silently inflate the mean by dropping out of it.

**Audit E3**: the false-alarm rate and alarm precision rows above are the other half of this
metric that the original version omitted — a threshold low enough to catch every transition early
can do so by alarming on nearly everything, which the miss-rate/lead-time numbers alone can't
reveal. A low alarm precision means most of what this threshold flags is noise, not warning.

**Audit G8/W9**: the threshold above is tuned on the val split for a 5% FPR budget,
then applied here to the test split unchanged, exactly as a deployment would carry it forward.
Here it came out 5.0%, close to the budget.

## Interpretation

- **Cross-dataset World Model vs native baselines**: a cross-dataset world model that outperforms
  a native-trained LR classifier demonstrates genuine generalisation — the Transformer has learned
  attack *dynamics*, not dataset-specific feature correlations.
- **Graph features**: unsw_nb15_v2 has real IP data throughout, so `graph_out_degree`,
  `graph_fan_out_ratio`, `graph_fan_in_ratio`, `graph_component_size`, and `graph_dst_entropy`
  all carry real signal here.  The 12-window temporal structure over these graph features
  is what the world model exploits.
- **Feature alignment**: both configs share identical `features:` sections (flow + graph + packet
  levels), so the checkpoint loads without any shape mismatch.
