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
| Baseline (LR, last window) | 1.000 | 1.000 | 1.000 | 0.000 |
| Baseline (LR, stacked window) | 1.000 | 1.000 | 1.000 | 0.000 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable] | 1.000 | 1.000 | 1.000 | 0.000 |
| Persistence [ORACLE -- reads true current label, not deployable] | 1.000 | 1.000 | 1.000 | 0.000 |
| Persistence (on predicted label -- deployable) | 0.984 | 0.968 | 1.000 | 0.024 |

## Infiltration probability — fixed 5% false-positive-rate budget

Threshold selected on the validation split only (never test), then applied here — this is the
operating point a defender would actually tune to, not an arbitrary 0.5 cutoff.

**Audit E5**: at this dataset's attack prevalence, a 5% FPR budget can force the
threshold down near zero, which understates a model that is actually strong at a realistic,
stricter operating point. The two stricter budgets and the threshold-free ranking metrics below
are reported for exactly that reason — don't quote this table alone.

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Transformer) | 1.000 | 1.000 | 1.000 | 0.000 |
| Baseline (LR, last window) | 0.909 | 1.000 | 0.833 | 0.000 |
| Baseline (LR, stacked window) | 1.000 | 1.000 | 1.000 | 0.000 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable] | 1.000 | 1.000 | 1.000 | 0.000 |
| Persistence [ORACLE -- reads true current label, not deployable] | 1.000 | 1.000 | 1.000 | 0.000 |
| Persistence (on predicted label -- deployable) | 0.909 | 1.000 | 0.833 | 0.000 |

## Infiltration probability — fixed 1% false-positive-rate budget

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Transformer) | 1.000 | 1.000 | 1.000 | 0.000 |
| Baseline (LR, last window) | 0.065 | 1.000 | 0.033 | 0.000 |
| Baseline (LR, stacked window) | 1.000 | 1.000 | 1.000 | 0.000 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable] | 0.983 | 1.000 | 0.967 | 0.000 |
| Persistence [ORACLE -- reads true current label, not deployable] | 0.000 | 0.000 | 0.000 | 0.000 |
| Persistence (on predicted label -- deployable) | 0.065 | 1.000 | 0.033 | 0.000 |

## Infiltration probability — fixed 0.1% false-positive-rate budget

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
| World Model (Transformer) | 1.000 | 1.000 | 1.000 | 0.000 |
| Baseline (LR, last window) | 0.065 | 1.000 | 0.033 | 0.000 |
| Baseline (LR, stacked window) | 1.000 | 1.000 | 1.000 | 0.000 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable] | 0.983 | 1.000 | 0.967 | 0.000 |
| Persistence [ORACLE -- reads true current label, not deployable] | 0.000 | 0.000 | 0.000 | 0.000 |
| Persistence (on predicted label -- deployable) | 0.065 | 1.000 | 0.033 | 0.000 |

## Infiltration probability — threshold-free ranking (AUROC / AUPRC)

Summarizes ranking quality across every possible threshold, so no single operating-point choice
above can make a genuinely strong (or weak) model look otherwise.

| Model | AUROC | AUPRC |
|---|---|---|
| World Model (Transformer) | 1.0000 | 1.0000 |
| Baseline (LR, last window) | 1.0000 | 1.0000 |
| Baseline (LR, stacked window) | 1.0000 | 1.0000 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable] | 1.0000 | 1.0000 |
| Persistence [ORACLE -- reads true current label, not deployable] | 1.0000 | 1.0000 |
| Persistence (on predicted label -- deployable) | 1.0000 | 1.0000 |

## MITRE stage classification (4 classes present, `impact`-mapped windows excluded)

**Audit E4**: the number of classes actually present in this split is 4, not always 5 —
support by class: benign: 42, lateral_movement: 13, command_and_control: 15, exfiltration: 2. The all-class macro-F1 column is pulled toward the near-perfect
benign class when benign is one of the classes present; the attack-only column macro-averages
over the attack classes alone and is the more honest read of "can it tell attack stages apart."

| Model | F1 (macro, all classes) | F1 (macro, attack classes only) | Precision (macro) | Recall (macro) |
|---|---|---|---|---|
| World Model (Transformer) | 0.891 | 0.854 | 0.965 | 0.858 |
| Baseline (LR, last window) | 0.891 | 0.854 | 0.965 | 0.858 |
| Baseline (LR, stacked window) | 0.891 | 0.854 | 0.965 | 0.858 |
| Baseline (Markov chain) [ORACLE -- reads true current label, not deployable] | 0.891 | 0.854 | 0.965 | 0.858 |
| Persistence [ORACLE -- reads true current label, not deployable] | 0.891 | 0.854 | 0.965 | 0.858 |
| Persistence (on predicted label -- deployable) | 0.879 | 0.843 | 0.950 | 0.852 |

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
