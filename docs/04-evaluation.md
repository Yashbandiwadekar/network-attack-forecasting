# Evaluation: World Model vs Baselines

Test set: 70 sequences. All four models predict the immediate next window (t+1) from
identical targets; the world model additionally supports K-step autoregressive rollout (see
models/forecast.py), which none of the baselines have an equivalent of — demonstrated in the
Streamlit app rather than benchmarked here, since there's nothing to compare it against fairly.

## Infiltration probability — default threshold (0.5)

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Transformer) | 1.000 | 1.000 | 1.000 | 0.000 |
| Baseline (LR, last window) | 0.961 | 1.000 | 0.925 | 0.000 |
| Baseline (LR, stacked window) | 1.000 | 1.000 | 1.000 | 0.000 |
| Persistence (no learning) | 0.987 | 1.000 | 0.975 | 0.000 |

## Infiltration probability — fixed 5% false-positive-rate budget

Threshold selected on the validation split only (never test), then applied here — this is the
operating point a defender would actually tune to, not an arbitrary 0.5 cutoff.

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Transformer) | 0.988 | 0.976 | 1.000 | 0.033 |
| Baseline (LR, last window) | 0.904 | 1.000 | 0.825 | 0.000 |
| Baseline (LR, stacked window) | 1.000 | 1.000 | 1.000 | 0.000 |
| Persistence (no learning) | 0.987 | 1.000 | 0.975 | 0.000 |

## MITRE stage classification (5-way, `impact`-mapped windows excluded)

| Model | F1 (macro) | Precision (macro) | Recall (macro) |
|---|---|---|---|
| World Model (Transformer) | 0.895 | 0.951 | 0.873 |
| Baseline (LR, last window) | 0.857 | 0.928 | 0.822 |
| Baseline (LR, stacked window) | 0.914 | 0.974 | 0.887 |
| Persistence (no learning) | 0.878 | 0.942 | 0.848 |

## Interpretation

- **World Model vs Baseline (LR, last window)**: the last-window baseline sees only the current
  snapshot, no temporal context. A gap here shows the world model is using *some* form of history.
- **World Model vs Baseline (LR, stacked window)**: the stacked baseline sees the exact same
  12-window history as the world model, just flattened for a
  non-sequential classifier. A gap here — not just vs. the last-window baseline — is the real
  evidence that sequential/recurrent structure matters, not just having more input columns.
- **World Model vs Persistence**: persistence needs no training at all. If the world model doesn't
  clear this bar, it isn't learning real dynamics, whatever its other metrics say.

**Honest caveat**: the stacked-window baseline matches or beats the world model here. On the current (small, synthetic) sample the attack-phase transitions are clean enough that a flat classifier with the same information does just as well — this benchmark hasn't yet demonstrated that sequential/recurrent structure earns its keep. That's exactly the kind of gap real CIC-IDS-2018 data, with much noisier and more overlapping traffic, is expected to actually show; see docs/02-dataset-and-features.md.
