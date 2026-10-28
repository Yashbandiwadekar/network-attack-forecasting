> **PRE-FIX LABELS (defect D-1, noted 2026-10-10).** This report was computed on CTU-13 splits whose labels
> mapped benign `From-Background`, `To-Normal` and `Normal` flows to a positive (`impact`) label. Its test
> positives (6,438) and onset windows (551) include those artifacts. Superseded by
> `docs/04-evaluation-ctu13_cross_from_real_data_v2_postD1.md`. Kept unchanged below for the record.

> **Regenerated 2026-09-23** (replaces a withdrawn earlier version, archived at
> `docs/archive/04-evaluation-ctu13_cross_from_real_data_RETRACTED-2026-09-23.md`). Trained on
> `checkpoints_real/` (v1), tested on the current 41-feature CTU-13 build. **The model does not
> transfer to CTU-13** (AUROC 0.517, chance level).

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
| World Model (Train: CIC-IDS-2018 / Test: CTU-13) | 0.006 | 0.014 | 0.004 | 0.010 |
| Baseline (LSTM, Train: CIC-IDS-2018 / Test: CTU-13) | 0.000 | 0.000 | 0.000 | 0.000 |
| Baseline (LR, last window, native CTU-13) | 0.012 | 0.336 | 0.006 | 0.000 |
| Baseline (LR, stacked window, native CTU-13) | 0.006 | 0.447 | 0.003 | 0.000 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native CTU-13 | 0.980 | 0.980 | 0.980 | 0.001 |
| Persistence [ORACLE -- reads true current label, not deployable], native CTU-13 | 0.980 | 0.980 | 0.980 | 0.001 |
| Persistence (on predicted label -- deployable, native CTU-13) | 0.012 | 0.302 | 0.006 | 0.000 |

## Infiltration probability — fixed 5% FPR budget

Threshold selected on the **CTU-13 val split** only (never test).

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Train: CIC-IDS-2018 / Test: CTU-13) | 0.009 | 0.008 | 0.009 | 0.038 |
| Baseline (LSTM, Train: CIC-IDS-2018 / Test: CTU-13) | 0.003 | 0.002 | 0.003 | 0.046 |
| Baseline (LR, last window, native CTU-13) | 0.189 | 0.319 | 0.134 | 0.010 |
| Baseline (LR, stacked window, native CTU-13) | 0.268 | 0.413 | 0.198 | 0.010 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native CTU-13 | 0.980 | 0.980 | 0.980 | 0.001 |
| Persistence [ORACLE -- reads true current label, not deployable], native CTU-13 | 0.980 | 0.980 | 0.980 | 0.001 |
| Persistence (on predicted label -- deployable, native CTU-13) | 0.179 | 0.345 | 0.121 | 0.008 |

## Infiltration probability — fixed 1% FPR budget

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Train: CIC-IDS-2018 / Test: CTU-13) | 0.000 | 0.002 | 0.000 | 0.003 |
| Baseline (LSTM, Train: CIC-IDS-2018 / Test: CTU-13) | 0.000 | 0.000 | 0.000 | 0.009 |
| Baseline (LR, last window, native CTU-13) | 0.000 | 0.000 | 0.000 | 0.000 |
| Baseline (LR, stacked window, native CTU-13) | 0.000 | 0.000 | 0.000 | 0.000 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native CTU-13 | 0.980 | 0.980 | 0.980 | 0.001 |
| Persistence [ORACLE -- reads true current label, not deployable], native CTU-13 | 0.980 | 0.980 | 0.980 | 0.001 |
| Persistence (on predicted label -- deployable, native CTU-13) | 0.000 | 0.000 | 0.000 | 0.000 |

## Infiltration probability — fixed 0.1% FPR budget

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Train: CIC-IDS-2018 / Test: CTU-13) | 0.000 | 0.000 | 0.000 | 0.000 |
| Baseline (LSTM, Train: CIC-IDS-2018 / Test: CTU-13) | 0.000 | 0.000 | 0.000 | 0.000 |
| Baseline (LR, last window, native CTU-13) | 0.000 | 0.000 | 0.000 | 0.000 |
| Baseline (LR, stacked window, native CTU-13) | 0.000 | 0.000 | 0.000 | 0.000 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native CTU-13 | 0.980 | 0.980 | 0.980 | 0.001 |
| Persistence [ORACLE -- reads true current label, not deployable], native CTU-13 | 0.980 | 0.980 | 0.980 | 0.001 |
| Persistence (on predicted label -- deployable, native CTU-13) | 0.000 | 0.000 | 0.000 | 0.000 |

## Infiltration probability — threshold-free ranking (AUROC / AUPRC)

| Model | AUROC | AUPRC |
|---|---|---|
| World Model (Train: CIC-IDS-2018 / Test: CTU-13) | 0.5172 | 0.0322 |
| Baseline (LSTM, Train: CIC-IDS-2018 / Test: CTU-13) | 0.8032 | 0.0897 |
| Baseline (LR, last window, native CTU-13) | 0.6195 | 0.1096 |
| Baseline (LR, stacked window, native CTU-13) | 0.6589 | 0.1757 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native CTU-13 | 0.9902 | 0.9800 |
| Persistence [ORACLE -- reads true current label, not deployable], native CTU-13 | 0.9899 | 0.9619 |
| Persistence (on predicted label -- deployable, native CTU-13) | 0.6187 | 0.1057 |

## MITRE stage classification (2 classes present, `impact`-mapped windows excluded)

Support by class: benign: 180082, command_and_control: 5944.

| Model | F1 (macro, all classes) | F1 (macro, attack classes only) | Precision (macro) | Recall (macro) |
|---|---|---|---|---|
| World Model (Train: CIC-IDS-2018 / Test: CTU-13) | 0.328 | 0.000 | 0.323 | 0.333 |
| Baseline (LSTM, Train: CIC-IDS-2018 / Test: CTU-13) | 0.492 | 0.000 | 0.484 | 0.500 |
| Baseline (LR, last window, native CTU-13) | 0.509 | 0.035 | 0.727 | 0.509 |
| Baseline (LR, stacked window, native CTU-13) | 0.536 | 0.089 | 0.957 | 0.523 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable], native CTU-13 | 1.000 | 1.000 | 1.000 | 1.000 |
| Persistence [ORACLE -- reads true current label, not deployable], native CTU-13 | 1.000 | 1.000 | 1.000 | 1.000 |
| Persistence (on predicted label -- deployable, native CTU-13) | 0.509 | 0.035 | 0.732 | 0.509 |

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
| Benign-to-attack transitions in test set | 551 |
| Missed entirely (never alarmed within horizon) | 436 (79.1%) |
| Detected *before* the attack actually started | 11.8% |
| Mean lead time (detected cases; + = early, - = late) | +10.1s |
| Median lead time (detected cases) | +10.0s |
| False alarms / benign-for-whole-horizon sequences | 19606 / 179531 (10.92%) |
| Alarm precision (true early alarms / all alarms raised) | 0.6% |

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
- **Graph features**: CTU-13 has real IP data throughout, so `graph_out_degree`,
  `graph_fan_out_ratio`, `graph_fan_in_ratio`, `graph_component_size`, and `graph_dst_entropy`
  all carry real signal here.  The 12-window temporal structure over these graph features
  is what the world model exploits.
- **Feature alignment**: both configs share identical `features:` sections (flow + graph + packet
  levels), so the checkpoint loads without any shape mismatch.
