# Evaluation: World Model vs Logistic Regression Baseline

Test set: 69 sequences. Both models predict the immediate next window (t+1); the world
model additionally supports K-step autoregressive rollout (see models/forecast.py), which the
baseline has no equivalent of and is demonstrated in the Streamlit app instead of benchmarked here.

## Infiltration probability (binary: attack in next window?)

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Transformer) | 1.000 | 1.000 | 1.000 | 0.000 |
| Baseline (Logistic Regression) | 1.000 | 1.000 | 1.000 | 0.000 |

## MITRE stage classification (5-way, `impact`-mapped windows excluded)

| Model | F1 (macro) | Precision (macro) | Recall (macro) |
|---|---|---|---|
| World Model (Transformer) | 0.801 | 0.793 | 0.811 |
| Baseline (Logistic Regression) | 0.777 | 0.766 | 0.790 |

## Interpretation

The baseline sees only the current window's feature vector, with no temporal context. The world
model sees the last 12 windows and is trained on the same
next-step targets. A gap in favour of the world model here is evidence that the extra temporal
context (attack progression patterns like the SYN-ratio ramp, port-scan-then-bruteforce sequencing)
is actually being used, not just memorized from the single most recent window.
