# Evaluation: World Model vs Baselines

Test set: 193993 sequences. All four models predict the immediate next window (t+1) from
identical targets; the world model additionally supports K-step autoregressive rollout (see
models/forecast.py), which none of the baselines have an equivalent of — demonstrated in the
Streamlit app rather than benchmarked here, since there's nothing to compare it against fairly.

## Infiltration probability — default threshold (0.5)

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Transformer) | 0.908 | 0.931 | 0.886 | 0.001 |
| Baseline (LR, last window) | 0.783 | 0.944 | 0.669 | 0.000 |
| Baseline (LR, stacked window) | 0.878 | 0.937 | 0.826 | 0.000 |
| Persistence (no learning) | 0.988 | 0.987 | 0.989 | 0.000 |

## Infiltration probability — fixed 5% false-positive-rate budget

Threshold selected on the validation split only (never test), then applied here — this is the
operating point a defender would actually tune to, not an arbitrary 0.5 cutoff.

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Transformer) | 0.535 | 0.366 | 0.999 | 0.014 |
| Baseline (LR, last window) | 0.215 | 0.120 | 1.000 | 0.058 |
| Baseline (LR, stacked window) | 0.529 | 0.359 | 1.000 | 0.014 |
| Persistence (no learning) | 0.988 | 0.987 | 0.989 | 0.000 |

## MITRE stage classification (5-way, `impact`-mapped windows excluded)

| Model | F1 (macro) | Precision (macro) | Recall (macro) |
|---|---|---|---|
| World Model (Transformer) | 0.761 | 0.819 | 0.727 |
| Baseline (LR, last window) | 0.476 | 0.698 | 0.431 |
| Baseline (LR, stacked window) | 0.512 | 0.748 | 0.495 |
| Persistence (no learning) | 0.998 | 0.997 | 0.999 |

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
