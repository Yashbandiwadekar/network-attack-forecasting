# eval.benchmark baseline-gate section on the real v2 test (generated; no scaler written)

## Baseline gate (CIC-IDS-2018 v2 test (real data, read-only splits))

Baselines fitted on RAW features of the CIC-IDS-2018 v2 test (real data, read-only splits) train split (1,239,090 sequences; at most 30,000 rows per day), fixed hyper-parameters, no tuning. Gate units: 3 (days); 3 contain both classes. Pooled AUROC is secondary: it mixes units.

### Per-unit AUROC and gate - World Model (Transformer) [seed1, served]

| score | 2018-02-16 | 2018-02-23 | 2018-03-01 | mean |
|---|---|---|---|---|
| World Model (Transformer) [seed1, served] | 0.989 | 0.500 | 0.778 | 0.755 |
| flow_count | 0.992 | 0.516 | 0.621 | 0.709 |
| LR_last | 0.990 | 0.564 | 0.597 | 0.717 |
| HGB_last | 0.962 | 0.593 | 0.706 | 0.754 |
| HGB_stacked | 0.988 | 0.574 | 0.745 | 0.769 |

| baseline | units | mean paired gain | MDE (sd used) | day-bootstrap 95% CI | verdict |
|---|---|---|---|---|---|
| flow_count | 3 | +0.046 | 0.299 (sd 0.096) | [-0.016, +0.157] | **FAIL** |
| LR_last | 3 | +0.038 | 0.394 (sd 0.127) | [-0.065, +0.181] | **FAIL** |
| HGB_last | 3 | +0.002 | 0.264 (sd 0.085) | [-0.093, +0.071] | **FAIL** |
| HGB_stacked | 3 | -0.014 | 0.170 (sd 0.055) | [-0.074, +0.033] | **FAIL** |

Gate rule: PASS iff mean paired per-unit AUROC gain over the baseline > paired MDE (80% power, 5% two-sided, SD = max(0.0245, observed SD of the per-unit differences)). All baselines beaten: **NO**.

| score (pooled, secondary) | AUROC | AUPRC |
|---|---|---|
| World Model (Transformer) [seed1, served] | 0.8003 | 0.6513 |
| flow_count | 0.5238 | 0.2661 |
| LR_last | 0.6631 | 0.4019 |
| HGB_last | 0.7586 | 0.5083 |
| HGB_stacked | 0.7639 | 0.6092 |
