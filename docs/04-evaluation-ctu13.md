> **PRE-FIX LABELS (defect D-1, noted 2026-10-10).** This report was computed on CTU-13 splits whose labels
> mapped benign `From-Background`, `To-Normal` and `Normal` flows to a positive (`impact`) label. Its test
> positives (6,438) and onset windows (551) include those artifacts. Superseded by
> `docs/04-evaluation-ctu13_cross_from_real_data_v2_postD1.md`. Kept unchanged below for the record.

# Evaluation: World Model vs Baselines

Test set: 223754 sequences. All four models predict the immediate next window (t+1) from
identical targets; the world model additionally supports K-step autoregressive rollout (see
models/forecast.py), which none of the baselines have an equivalent of — demonstrated in the
Streamlit app rather than benchmarked here, since there's nothing to compare it against fairly.

## Infiltration probability — default threshold (0.5)

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Transformer) | 0.797 | 0.809 | 0.786 | 0.008 |
| Baseline (LR, last window) | 0.010 | 0.048 | 0.005 | 0.005 |
| Baseline (LR, stacked window) | 0.017 | 0.039 | 0.011 | 0.012 |
| Persistence (no learning) | 0.990 | 0.990 | 0.989 | 0.000 |

## Infiltration probability — fixed 5% false-positive-rate budget

Threshold selected on the validation split only (never test), then applied here — this is the
operating point a defender would actually tune to, not an arbitrary 0.5 cutoff.

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Transformer) | 0.496 | 0.339 | 0.924 | 0.077 |
| Baseline (LR, last window) | 0.167 | 0.125 | 0.251 | 0.075 |
| Baseline (LR, stacked window) | 0.226 | 0.168 | 0.341 | 0.072 |
| Persistence (no learning) | 0.990 | 0.990 | 0.989 | 0.000 |

## MITRE stage classification (5-way, `impact`-mapped windows excluded)

| Model | F1 (macro) | Precision (macro) | Recall (macro) |
|---|---|---|---|
| World Model (Transformer) | 0.907 | 0.896 | 0.919 |
| Baseline (LR, last window) | 0.497 | 0.509 | 0.501 |
| Baseline (LR, stacked window) | 0.568 | 0.629 | 0.549 |
| Persistence (no learning) | 1.000 | 1.000 | 1.000 |

## Interpretation

- **World Model vs Baseline (LR, last window)**: the last-window baseline sees only the current
  snapshot, no temporal context. A gap here shows the world model is using *some* form of history.
- **World Model vs Baseline (LR, stacked window)**: the stacked baseline sees the exact same
  12-window history as the world model, just flattened for a
  non-sequential classifier. A gap here — not just vs. the last-window baseline — is the real
  evidence that sequential/recurrent structure matters, not just having more input columns.
- **World Model vs Persistence**: persistence needs no training at all. If the world model doesn't
  clear this bar, it isn't learning real dynamics, whatever its other metrics say.

