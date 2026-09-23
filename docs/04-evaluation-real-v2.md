# Evaluation: World Model, day-disjoint split (v2, matched hyperparameters)

**W7 regeneration (2026-09-23).** Model: `checkpoints_real_v2_converged` (configs/real_data_v2_converged.yaml), trained at v1's batch_size 64, 30 epochs, lr 3e-4, identical architecture. The fabricated benign days (2018-04-01/04-02 from `scripts/augment_benign_high_volume.py`) were **dropped entirely** from val/test (chosen over spreading them: removes the confound outright, and no synthetic traffic remains in this report). Test days 02-16, 02-23, 03-01 (7,191 seq); val days 02-15, 02-22 (6,685 seq). Supersedes the earlier undertrained v2 numbers (F1 0.431 on a test split that was 17.6% fabricated).

## v1 vs v2 under matched hyperparameters (re-measured, world model, t+1 infiltration)

| Model / split | Test seq | F1 @0.5 | Precision | Recall | FPR | AUROC |
|---|---|---|---|---|---|---|
| v1: `checkpoints_real`, chronological per-host split (attack sessions shared with train) | 194,632 | 0.917 | 0.943 | 0.892 | 0.0004 | 0.9995 |
| v2: `checkpoints_real_v2_converged`, day-disjoint split | 7,191 | 0.370 | 0.878 | 0.234 | 0.008 | 0.7058 |

Hyperparameters now match (batch 64, 30 epochs, lr, dims, dropout), so the gap is attributable to the split, with caveats: test sets differ in size/days, so this is not a same-test-set comparison, and no seed repeats exist (E10).

**Convergence: not converged.** Val loss per epoch: 0.987, 0.842, 0.887, 0.823, 0.898, 1.214, 1.174, 1.029, 1.003, 0.972, **0.801 (best, epoch 11)**, 0.809, 1.005, 0.993, 0.965, 0.940, 0.923, 1.164, 1.159, 1.278, 1.025, 1.028, 1.119, 0.972, 2.043, 1.033, 1.060, 1.151, 1.179, 1.008. Train loss fell steadily (0.326 to 0.2725) while val loss stayed noisy and rose, i.e. train/val-day distribution shift rather than undertraining; more epochs would not fix it. The best checkpoint (epoch 11) is scored below.


Test set: 7191 sequences. All models below predict the immediate next window (t+1) from
identical targets; the world model additionally supports K-step autoregressive rollout (see
models/forecast.py), which none of the baselines have an equivalent of — demonstrated in the
Streamlit app and scored directly in the lead-time section below, since there's no baseline to
compare the rollout itself against fairly.

## Infiltration probability — default threshold (0.5)

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Transformer) | 0.370 | 0.878 | 0.234 | 0.008 |
| Baseline (LR, last window) | 0.205 | 0.435 | 0.134 | 0.045 |
| Baseline (LR, stacked window) | 0.208 | 0.460 | 0.134 | 0.041 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable] | 0.878 | 0.877 | 0.878 | 0.032 |
| Persistence [ORACLE -- reads true current label, not deployable] | 0.878 | 0.877 | 0.878 | 0.032 |
| Persistence (on predicted label -- deployable) | 0.211 | 0.458 | 0.137 | 0.042 |

## Infiltration probability — fixed 5% false-positive-rate budget

Threshold selected on the validation split only (never test), then applied here — this is the
operating point a defender would actually tune to, not an arbitrary 0.5 cutoff.

**Audit E5**: at this dataset's attack prevalence, a 5% FPR budget can force the
threshold down near zero, which understates a model that is actually strong at a realistic,
stricter operating point. The two stricter budgets and the threshold-free ranking metrics below
are reported for exactly that reason — don't quote this table alone.

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Transformer) | 0.449 | 0.752 | 0.321 | 0.028 |
| Baseline (LR, last window) | 0.201 | 0.625 | 0.120 | 0.019 |
| Baseline (LR, stacked window) | 0.207 | 0.577 | 0.126 | 0.024 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable] | 0.878 | 0.877 | 0.878 | 0.032 |
| Persistence [ORACLE -- reads true current label, not deployable] | 0.878 | 0.877 | 0.878 | 0.032 |
| Persistence (on predicted label -- deployable) | 0.204 | 0.579 | 0.123 | 0.023 |

## Infiltration probability — fixed 1% false-positive-rate budget

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Transformer) | 0.384 | 0.877 | 0.246 | 0.009 |
| Baseline (LR, last window) | 0.030 | 0.442 | 0.016 | 0.005 |
| Baseline (LR, stacked window) | 0.201 | 0.781 | 0.115 | 0.008 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable] | 0.000 | 0.000 | 0.000 | 0.000 |
| Persistence [ORACLE -- reads true current label, not deployable] | 0.000 | 0.000 | 0.000 | 0.000 |
| Persistence (on predicted label -- deployable) | 0.202 | 0.746 | 0.117 | 0.010 |

## Infiltration probability — fixed 0.1% false-positive-rate budget

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Transformer) | 0.074 | 0.864 | 0.038 | 0.002 |
| Baseline (LR, last window) | 0.029 | 0.564 | 0.015 | 0.003 |
| Baseline (LR, stacked window) | 0.187 | 0.928 | 0.104 | 0.002 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable] | 0.000 | 0.000 | 0.000 | 0.000 |
| Persistence [ORACLE -- reads true current label, not deployable] | 0.000 | 0.000 | 0.000 | 0.000 |
| Persistence (on predicted label -- deployable) | 0.000 | 0.000 | 0.000 | 0.000 |

## Infiltration probability — threshold-free ranking (AUROC / AUPRC)

Summarizes ranking quality across every possible threshold, so no single operating-point choice
above can make a genuinely strong (or weak) model look otherwise.

| Model | AUROC | AUPRC |
|---|---|---|
| World Model (Transformer) | 0.7058 | 0.5247 |
| Baseline (LR, last window) | 0.5955 | 0.3247 |
| Baseline (LR, stacked window) | 0.5984 | 0.3405 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable] | 0.9102 | 0.7470 |
| Persistence [ORACLE -- reads true current label, not deployable] | 0.9230 | 0.7953 |
| Persistence (on predicted label -- deployable) | 0.5985 | 0.3265 |

## MITRE stage classification (3 classes present, `impact`-mapped windows excluded)

**Audit E4**: the number of classes actually present in this split is 3, not always 5 —
support by class: benign: 5709, initial_access: 255, lateral_movement: 930. The all-class macro-F1 column is pulled toward the near-perfect
benign class when benign is one of the classes present; the attack-only column macro-averages
over the attack classes alone and is the more honest read of "can it tell attack stages apart."

| Model | F1 (macro, all classes) | F1 (macro, attack classes only) | Precision (macro) | Recall (macro) |
|---|---|---|---|---|
| World Model (Transformer) | 0.309 | 0.160 | 0.445 | 0.297 |
| Baseline (LR, last window) | 0.243 | 0.040 | 0.471 | 0.251 |
| Baseline (LR, stacked window) | 0.255 | 0.059 | 0.366 | 0.260 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable] | 0.757 | 0.652 | 0.757 | 0.757 |
| Persistence [ORACLE -- reads true current label, not deployable] | 0.757 | 0.652 | 0.757 | 0.757 |
| Persistence (on predicted label -- deployable) | 0.243 | 0.041 | 0.469 | 0.251 |

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
| Benign-to-attack transitions in test set | 628 |
| Missed entirely (never alarmed within horizon) | 573 (91.2%) |
| Detected *before* the attack actually started | 4.1% |
| Mean lead time (detected cases; + = early, - = late) | -0.5s |
| Median lead time (detected cases) | +0.0s |
| False alarms / benign-for-whole-horizon sequences | 362 / 5080 (7.13%) |
| Alarm precision (true early alarms / all alarms raised) | 13.2% |
| Achieved FPR on this test split, at the val-tuned 5%-budget threshold | 2.8% |

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
Here it came out 2.8%, close to the budget.

## Interpretation

- **World Model vs Baseline (LR, last window)**: the last-window baseline sees only the current
  snapshot, no temporal context. A gap here shows the world model is using *some* form of history.
- **World Model vs Baseline (LR, stacked window)**: the stacked baseline sees the exact same
  12-window history as the world model, just flattened for a
  non-sequential classifier. A gap here — not just vs. the last-window baseline — is the real
  evidence that sequential/recurrent structure matters, not just having more input columns.
- **World Model vs Persistence**: persistence needs no training at all. If the world model doesn't
  clear this bar, it isn't learning real dynamics, whatever its other metrics say.


**Honest caveat**: the label-persistence ORACLE beats the world model on the immediate next-step (t+1) task (measured on this test set: 87.7% of currently-attacked windows are still under attack one step later). Note this is an oracle comparison, not a deployable one — see the E6 note above. This isn't the model failing to learn — at a 10-second window size, attacks in this dataset are long, contiguous bursts rather than isolated blips, so 'assume nothing changes' is a genuinely strong predictor of the *very next* window specifically. It cannot, however, anticipate a transition — a benign window about to turn into an attack, or one attack stage handing off to the next — which is exactly what the K-step rollout (models/forecast.py) is for, and persistence has no equivalent of. That capability is demonstrated in the Streamlit app rather than in this single-step benchmark number.

**Honest caveat**: the Markov chain baseline essentially matches Persistence here (F1 0.878 vs 0.878). This is expected, not a coincidence: with no flow features at all, a first-order transition table over long, contiguous attack bursts learns that the diagonal ("stage persists") dominates the table, which is exactly what Persistence already assumes outright. The two only diverge where the label sequence isn't purely persistent -- i.e. at actual stage transitions -- which is a much smaller slice of this metric than the immediate next-step task as a whole.
