# Evaluation: World Model vs Baselines

Test set: 194632 sequences. All models below predict the immediate next window (t+1) from
identical targets; the world model additionally supports K-step autoregressive rollout (see
models/forecast.py), which none of the baselines have an equivalent of — demonstrated in the
Streamlit app and scored directly in the lead-time section below, since there's no baseline to
compare the rollout itself against fairly.

## Infiltration probability — default threshold (0.5)

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Transformer) | 0.917 | 0.943 | 0.892 | 0.000 |
| Baseline (LSTM) | 0.908 | 0.947 | 0.872 | 0.000 |
| Baseline (LR, last window) | 0.787 | 0.943 | 0.676 | 0.000 |
| Baseline (LR, stacked window) | 0.866 | 0.926 | 0.814 | 0.001 |
| Baseline (Markov chain) | 0.988 | 0.987 | 0.989 | 0.000 |
| Persistence (no learning) | 0.988 | 0.987 | 0.989 | 0.000 |

## Infiltration probability — fixed 5% false-positive-rate budget

Threshold selected on the validation split only (never test), then applied here — this is the
operating point a defender would actually tune to, not an arbitrary 0.5 cutoff.

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Transformer) | 0.535 | 0.365 | 0.999 | 0.014 |
| Baseline (LSTM) | 0.535 | 0.366 | 0.996 | 0.014 |
| Baseline (LR, last window) | 0.314 | 0.186 | 1.000 | 0.035 |
| Baseline (LR, stacked window) | 0.534 | 0.364 | 1.000 | 0.014 |
| Baseline (Markov chain) | 0.988 | 0.987 | 0.989 | 0.000 |
| Persistence (no learning) | 0.988 | 0.987 | 0.989 | 0.000 |

## MITRE stage classification (5-way, `impact`-mapped windows excluded)

| Model | F1 (macro) | Precision (macro) | Recall (macro) |
|---|---|---|---|
| World Model (Transformer) | 0.820 | 0.849 | 0.796 |
| Baseline (LSTM) | 0.715 | 0.819 | 0.682 |
| Baseline (LR, last window) | 0.450 | 0.600 | 0.418 |
| Baseline (LR, stacked window) | 0.506 | 0.748 | 0.481 |
| Baseline (Markov chain) | 0.998 | 0.997 | 0.999 |
| Persistence (no learning) | 0.998 | 0.997 | 0.999 |

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
| Benign-to-attack transitions in test set | 32 |
| Missed entirely (never alarmed within horizon) | 0 (0.0%) |
| Detected *before* the attack actually started | 46.9% |
| Mean lead time (detected cases; + = early, - = late) | +6.9s |
| Median lead time (detected cases) | +0.0s |

Lead time is `(actual attack-onset step) - (first step the alarm threshold is crossed)`, in
seconds. A positive value is a genuine early warning — the alarm fired before the attack window
it was warning about actually arrived. Missed transitions are excluded from the mean/median (there
is no lead time to average when the model never alarmed at all) and reported separately as a miss
rate instead, so a high miss rate can't silently inflate the mean by dropping out of it.

## Interpretation

- **World Model vs Baseline (LR, last window)**: the last-window baseline sees only the current
  snapshot, no temporal context. A gap here shows the world model is using *some* form of history.
- **World Model vs Baseline (LR, stacked window)**: the stacked baseline sees the exact same
  12-window history as the world model, just flattened for a
  non-sequential classifier. A gap here — not just vs. the last-window baseline — is the real
  evidence that sequential/recurrent structure matters, not just having more input columns.
- **World Model vs Persistence**: persistence needs no training at all. If the world model doesn't
  clear this bar, it isn't learning real dynamics, whatever its other metrics say.


**Honest caveat**: persistence beats the world model on the immediate next-step (t+1) task (measured on this test set: 98.7% of currently-attacked windows are still under attack one step later). This isn't the model failing to learn — at a 10-second window size, attacks in this dataset are long, contiguous bursts rather than isolated blips, so 'assume nothing changes' is a genuinely strong predictor of the *very next* window specifically. It cannot, however, anticipate a transition — a benign window about to turn into an attack, or one attack stage handing off to the next — which is exactly what the K-step rollout (models/forecast.py) is for, and persistence has no equivalent of. That capability is demonstrated in the Streamlit app rather than in this single-step benchmark number.

**Honest caveat**: the Markov chain baseline essentially matches Persistence here (F1 0.988 vs 0.988). This is expected, not a coincidence: with no flow features at all, a first-order transition table over long, contiguous attack bursts learns that the diagonal ("stage persists") dominates the table, which is exactly what Persistence already assumes outright. The two only diverge where the label sequence isn't purely persistent -- i.e. at actual stage transitions -- which is a much smaller slice of this metric than the immediate next-step task as a whole.
