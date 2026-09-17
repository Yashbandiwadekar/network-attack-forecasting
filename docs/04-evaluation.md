# Evaluation: World Model vs Baselines

Test set: 72 sequences. All models below predict the immediate next window (t+1) from
identical targets; the world model additionally supports K-step autoregressive rollout (see
models/forecast.py), which none of the baselines have an equivalent of — demonstrated in the
Streamlit app and scored directly in the lead-time section below, since there's no baseline to
compare the rollout itself against fairly.

## Infiltration probability — default threshold (0.5)

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Transformer) | 1.000 | 1.000 | 1.000 | 0.000 |
| Baseline (LSTM) | 1.000 | 1.000 | 1.000 | 0.000 |
| Baseline (LR, last window) | 1.000 | 1.000 | 1.000 | 0.000 |
| Baseline (LR, stacked window) | 1.000 | 1.000 | 1.000 | 0.000 |
| Baseline (Markov chain) | 1.000 | 1.000 | 1.000 | 0.000 |
| Persistence (no learning) | 1.000 | 1.000 | 1.000 | 0.000 |

## Infiltration probability — fixed 5% false-positive-rate budget

Threshold selected on the validation split only (never test), then applied here — this is the
operating point a defender would actually tune to, not an arbitrary 0.5 cutoff.

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Transformer) | 1.000 | 1.000 | 1.000 | 0.000 |
| Baseline (LSTM) | 1.000 | 1.000 | 1.000 | 0.000 |
| Baseline (LR, last window) | 0.909 | 1.000 | 0.833 | 0.000 |
| Baseline (LR, stacked window) | 1.000 | 1.000 | 1.000 | 0.000 |
| Baseline (Markov chain) | 1.000 | 1.000 | 1.000 | 0.000 |
| Persistence (no learning) | 1.000 | 1.000 | 1.000 | 0.000 |

## MITRE stage classification (5-way, `impact`-mapped windows excluded)

| Model | F1 (macro) | Precision (macro) | Recall (macro) |
|---|---|---|---|
| World Model (Transformer) | 0.891 | 0.965 | 0.858 |
| Baseline (LSTM) | 0.681 | 0.667 | 0.700 |
| Baseline (LR, last window) | 0.891 | 0.965 | 0.858 |
| Baseline (LR, stacked window) | 0.891 | 0.965 | 0.858 |
| Baseline (Markov chain) | 0.891 | 0.965 | 0.858 |
| Persistence (no learning) | 0.891 | 0.965 | 0.858 |

## K-step forecast lead time

No benign-to-attack transitions occurred within the forecast horizon in this test set, so lead time is undefined here (not zero — there was nothing to detect early).
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


**Honest caveat**: the Markov chain baseline essentially matches Persistence here (F1 1.000 vs 1.000). This is expected, not a coincidence: with no flow features at all, a first-order transition table over long, contiguous attack bursts learns that the diagonal ("stage persists") dominates the table, which is exactly what Persistence already assumes outright. The two only diverge where the label sequence isn't purely persistent -- i.e. at actual stage transitions -- which is a much smaller slice of this metric than the immediate next-step task as a whole.
