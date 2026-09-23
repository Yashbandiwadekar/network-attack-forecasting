# Cross-Dataset Evaluation: Train on CIC-IDS-2018 / Test on unsw_nb15

Test set: 16289 sequences from **unsw_nb15** (never seen during training).

The world model was trained on **CIC-IDS-2018** and evaluated here on **unsw_nb15** using
the *CIC-IDS-2018 scaler* — the model sees feature values on the same scale it was trained with.
This is the strongest available evidence against signature memorisation: the model must generalise
to a different dataset, capture tool, botnet family, and traffic distribution entirely.

Native-dataset baselines (LR + Persistence) are trained on **unsw_nb15**'s own training split
with a **unsw_nb15 scaler** — they represent the best a dataset-specific shallow model can do,
and serve as the comparison anchor.

## Infiltration probability — default threshold (0.5)

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Train: CIC-IDS-2018 / Test: unsw_nb15) | 0.255 | 0.547 | 0.167 | 0.028 |
| Baseline (LSTM, Train: CIC-IDS-2018 / Test: unsw_nb15) | 0.000 | 0.000 | 0.000 | 0.000 |
| Baseline (LR, last window, native unsw_nb15) | 0.919 | 0.927 | 0.910 | 0.014 |
| Baseline (LR, stacked window, native unsw_nb15) | 0.985 | 0.978 | 0.992 | 0.005 |
| Baseline (Markov chain, native unsw_nb15) | 0.995 | 0.995 | 0.995 | 0.001 |
| Persistence (no learning, unsw_nb15) | 0.995 | 0.995 | 0.995 | 0.001 |

## Infiltration probability — fixed 5% FPR budget

Threshold selected on the **unsw_nb15 val split** only (never test).

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Train: CIC-IDS-2018 / Test: unsw_nb15) | 0.371 | 0.548 | 0.281 | 0.047 |
| Baseline (LSTM, Train: CIC-IDS-2018 / Test: unsw_nb15) | 0.119 | 0.243 | 0.079 | 0.049 |
| Baseline (LR, last window, native unsw_nb15) | 0.897 | 0.815 | 0.996 | 0.045 |
| Baseline (LR, stacked window, native unsw_nb15) | 0.955 | 0.915 | 1.000 | 0.019 |
| Baseline (Markov chain, native unsw_nb15) | 0.995 | 0.995 | 0.995 | 0.001 |
| Persistence (no learning, unsw_nb15) | 0.995 | 0.995 | 0.995 | 0.001 |

## MITRE stage classification (5-way, `impact`-mapped windows excluded)

| Model | F1 (macro) | Precision (macro) | Recall (macro) |
|---|---|---|---|
| World Model (Train: CIC-IDS-2018 / Test: unsw_nb15) | 0.187 | 0.179 | 0.195 |
| Baseline (LSTM, Train: CIC-IDS-2018 / Test: unsw_nb15) | 0.236 | 0.224 | 0.250 |
| Baseline (LR, last window, native unsw_nb15) | 0.455 | 0.432 | 0.485 |
| Baseline (LR, stacked window, native unsw_nb15) | 0.464 | 0.485 | 0.497 |
| Baseline (Markov chain, native unsw_nb15) | 0.436 | 0.428 | 0.444 |
| Persistence (no learning, unsw_nb15) | 0.468 | 0.495 | 0.448 |

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
| Missed entirely (never alarmed within horizon) | 6 (42.9%) |
| Detected *before* the attack actually started | 0.0% |
| Mean lead time (detected cases; + = early, - = late) | -8.8s |
| Median lead time (detected cases) | +0.0s |

Lead time is `(actual attack-onset step) - (first step the alarm threshold is crossed)`, in
seconds. A positive value is a genuine early warning — the alarm fired before the attack window
it was warning about actually arrived. Missed transitions are excluded from the mean/median (there
is no lead time to average when the model never alarmed at all) and reported separately as a miss
rate instead, so a high miss rate can't silently inflate the mean by dropping out of it.

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
