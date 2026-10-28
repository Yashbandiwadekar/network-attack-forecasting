## LODO

Selected epochs (1-based, by OOF day-mean within-day AUROC, ties to the earlier epoch): single **1**, ensemble of 5 seeds **9**, ensemble of 3 seeds **15**. Validation loss was not used.


| held-out day | family (in train?) | seq | pos | episodes | **single (5-seed mean), nested epoch** | single, global epoch | **ensemble-5, nested** | ensemble-3, nested | flow_count | LR_last | HGB_last | HGB_stacked | label oracle |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 02-14 * | initial_access (yes) | 3,238 | 1,130 | 2 | **0.670** | 0.670 | **0.736** | 0.768 | 0.944 | 0.568 | 0.925 | 0.992 | 0.999 |
| 02-15 * | impact (yes) | 3,412 | 341 | 5 | **0.348** | 0.348 | **0.345** | 0.263 | 0.801 | 0.625 | 0.484 | 0.600 | 0.992 |
| 02-20 | impact (yes) | 1,228,717 | 3,745 | 0 | **1.000** | 1.000 | **1.000** | 1.000 | 0.992 | 0.999 | 1.000 | 1.000 | 1.000 |
| 02-21 * | impact (yes) | 620 | 272 | 2 | **0.924** | 0.924 | **0.899** | 0.932 | 0.963 | 0.877 | 0.927 | 0.941 | 0.961 |
| 02-22 * | initial_access (yes) | 3,273 | 164 | 9 | **0.608** | 0.608 | **0.534** | 0.574 | 0.604 | 0.506 | 0.546 | 0.588 | 0.678 |
| 02-28 | lateral_movement (**NO**) | 3,389 | 798 | 2 | **0.711** | 0.711 | **0.662** | 0.686 | 0.640 | 0.559 | 0.613 | 0.716 | 0.999 |
| 03-02 * | command_and_control (**NO**) | 3,126 | 2,028 | 2 | **0.948** | 0.948 | **0.826** | 0.925 | 0.740 | 0.888 | 0.731 | 0.892 | 0.999 |
| **mean, all 7 days** | | | | | 0.744 (sd 0.23) | 0.744 (sd 0.23) | 0.715 (sd 0.22) | 0.736 (sd 0.26) | 0.812 (sd 0.16) | 0.717 (sd 0.20) | 0.746 (sd 0.21) | 0.818 (sd 0.18) | 0.947 (sd 0.12) |
| mean, 6 pseudo-host days (without 02-20) | | | | | 0.701 (sd 0.22) | 0.701 (sd 0.22) | 0.667 (sd 0.20) | 0.692 (sd 0.25) | 0.782 (sd 0.15) | 0.671 (sd 0.17) | 0.704 (sd 0.19) | 0.788 (sd 0.18) | 0.938 (sd 0.13) |
| mean, 5 family-covered days | | | | | 0.710 (sd 0.26) | 0.710 (sd 0.26) | 0.703 (sd 0.27) | 0.708 (sd 0.30) | 0.861 (sd 0.16) | 0.715 (sd 0.21) | 0.776 (sd 0.24) | 0.824 (sd 0.21) | 0.926 (sd 0.14) |


`*` = partial source day (CSV truncated at 1,048,575 rows). 02-20 = the three host-group folds pooled (host-disjoint, not day-disjoint). 'nested' = each day read at the epoch chosen from the other six days.


### AUPRC (secondary)

| held-out day | single AUPRC (nested) | ensemble-5 AUPRC (nested) | flow_count | LR_last | HGB_last | HGB_stacked | positive rate |
|---|---|---|---|---|---|---|---|
| 02-14 * | 0.637 | 0.716 | 0.827 | 0.375 | 0.891 | 0.982 | 0.349 |
| 02-15 * | 0.184 | 0.182 | 0.324 | 0.301 | 0.152 | 0.117 | 0.100 |
| 02-20 | 0.985 | 0.999 | 0.281 | 0.791 | 0.999 | 1.000 | 0.003 |
| 02-21 * | 0.900 | 0.871 | 0.960 | 0.838 | 0.932 | 0.927 | 0.439 |
| 02-22 * | 0.082 | 0.064 | 0.074 | 0.058 | 0.060 | 0.086 | 0.050 |
| 02-28 | 0.409 | 0.384 | 0.351 | 0.259 | 0.371 | 0.446 | 0.235 |
| 03-02 * | 0.969 | 0.900 | 0.796 | 0.918 | 0.838 | 0.931 | 0.649 |

### OOF day-mean within-day AUROC by epoch (the selection curve)

| epoch | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| single (5-seed mean) | 0.744 | 0.716 | 0.703 | 0.712 | 0.714 | 0.700 | 0.703 | 0.708 | 0.714 | 0.696 | 0.715 | 0.701 | 0.684 | 0.690 | 0.698 | 0.715 | 0.699 | 0.702 | 0.701 | 0.687 |
| ensemble-5 | 0.757 | 0.721 | 0.706 | 0.721 | 0.728 | 0.726 | 0.716 | 0.752 | 0.757 | 0.732 | 0.734 | 0.731 | 0.721 | 0.713 | 0.756 | 0.738 | 0.751 | 0.752 | 0.731 | 0.716 |
| ensemble-3 | 0.761 | 0.718 | 0.706 | 0.712 | 0.725 | 0.725 | 0.718 | 0.715 | 0.730 | 0.725 | 0.745 | 0.711 | 0.719 | 0.705 | 0.764 | 0.737 | 0.753 | 0.753 | 0.733 | 0.709 |


Nested epoch per held-out day (single): 02-14 * -> 1, 02-15 * -> 1, 02-20 -> 1, 02-21 * -> 1, 02-22 * -> 1, 02-28 -> 1, 03-02 * -> 1.

Nested epoch per held-out day (ensemble-5): 02-14 * -> 1, 02-15 * -> 1, 02-20 -> 9, 02-21 * -> 15, 02-22 * -> 9, 02-28 -> 15, 03-02 * -> 8.


### Baseline gate, all 7 LODO days (primary)

| comparison (model minus baseline) | days | mean paired gain | MDE | day-bootstrap 95% CI | days won | verdict |
|---|---|---|---|---|---|---|
| single Transformer vs flow_count | 7 | -0.068 | 0.282 | [-0.231, +0.072] | 4/7 | **FAIL** |
| single Transformer vs LR_last | 7 | +0.027 | 0.180 | [-0.082, +0.103] | 6/7 | **FAIL** |
| single Transformer vs HGB_last | 7 | -0.002 | 0.196 | [-0.114, +0.101] | 4/7 | **FAIL** |
| single Transformer vs HGB_stacked | 7 | -0.074 | 0.188 | [-0.181, +0.016] | 2/7 | **FAIL** |
| ensemble-5 vs flow_count | 7 | -0.097 | 0.232 | [-0.232, +0.012] | 3/7 | **FAIL** |
| ensemble-5 vs LR_last | 7 | -0.003 | 0.181 | [-0.108, +0.085] | 5/7 | **FAIL** |
| ensemble-5 vs HGB_last | 7 | -0.032 | 0.127 | [-0.104, +0.033] | 3/7 | **FAIL** |
| ensemble-5 vs HGB_stacked | 7 | -0.104 | 0.133 | [-0.172, -0.039] | 0/7 | **FAIL** |
| ensemble-3 vs flow_count | 7 | -0.076 | 0.292 | [-0.252, +0.059] | 3/7 | **FAIL** |
| ensemble-3 vs LR_last | 7 | +0.018 | 0.227 | [-0.119, +0.119] | 6/7 | **FAIL** |
| ensemble-3 vs HGB_last | 7 | -0.011 | 0.176 | [-0.107, +0.081] | 5/7 | **FAIL** |
| ensemble-3 vs HGB_stacked | 7 | -0.083 | 0.177 | [-0.185, -0.000] | 1/7 | **FAIL** |
| HGB_last vs flow_count (is the tree better than the one-liner?) | 7 | -0.066 | 0.143 | [-0.152, -0.012] | 1/7 | **FAIL** |
| HGB_stacked vs flow_count (is the tree better than the one-liner?) | 7 | +0.006 | 0.139 | [-0.073, +0.074] | 4/7 | **FAIL** |

### Baseline gate, 6 pseudo-host days only (02-20 removed)

| comparison (model minus baseline) | days | mean paired gain | MDE | day-bootstrap 95% CI | days won | verdict |
|---|---|---|---|---|---|---|
| single Transformer vs flow_count | 6 | -0.081 | 0.344 | [-0.267, +0.086] | 3/6 | **FAIL** |
| single Transformer vs LR_last | 6 | +0.031 | 0.221 | [-0.097, +0.113] | 5/6 | **FAIL** |
| single Transformer vs HGB_last | 6 | -0.003 | 0.242 | [-0.131, +0.115] | 3/6 | **FAIL** |
| single Transformer vs HGB_stacked | 6 | -0.087 | 0.226 | [-0.206, +0.019] | 2/6 | **FAIL** |
| ensemble-5 vs flow_count | 6 | -0.115 | 0.277 | [-0.269, +0.013] | 2/6 | **FAIL** |
| ensemble-5 vs LR_last | 6 | -0.003 | 0.222 | [-0.128, +0.099] | 4/6 | **FAIL** |
| ensemble-5 vs HGB_last | 6 | -0.037 | 0.154 | [-0.118, +0.039] | 2/6 | **FAIL** |
| ensemble-5 vs HGB_stacked | 6 | -0.121 | 0.148 | [-0.190, -0.052] | 0/6 | **FAIL** |
| ensemble-3 vs flow_count | 6 | -0.090 | 0.354 | [-0.296, +0.067] | 2/6 | **FAIL** |
| ensemble-3 vs LR_last | 6 | +0.021 | 0.280 | [-0.142, +0.134] | 5/6 | **FAIL** |
| ensemble-3 vs HGB_last | 6 | -0.013 | 0.217 | [-0.124, +0.095] | 4/6 | **FAIL** |
| ensemble-3 vs HGB_stacked | 6 | -0.097 | 0.211 | [-0.212, -0.000] | 1/6 | **FAIL** |

### Operating point from OOF scores: ensemble-5, 1% day-balanced FPR budget

threshold = **0.64146** (epoch 9); realised per-day FPR range 0.0000-0.0345

| day | OOF FPR | OOF recall | alarm rate |
|---|---|---|---|
| 02-14 * | 0.0000 | 0.010 | 0.0034 |
| 02-15 * | 0.0160 | 0.050 | 0.0193 |
| 02-20 | 0.0002 | 0.997 | 0.0032 |
| 02-21 * | 0.0345 | 0.489 | 0.2339 |
| 02-22 * | 0.0003 | 0.000 | 0.0003 |
| 02-28 | 0.0058 | 0.029 | 0.0112 |
| 03-02 * | 0.0128 | 0.208 | 0.1395 |

### Operating point from OOF scores: single model, 1% budget

threshold = **0.69706** (epoch 1); realised per-day FPR range 0.0001-0.0330

| day | OOF FPR | OOF recall | alarm rate |
|---|---|---|---|
| 02-14 * | 0.0001 | 0.043 | 0.0151 |
| 02-15 * | 0.0155 | 0.113 | 0.0252 |
| 02-20 | 0.0001 | 0.946 | 0.0030 |
| 02-21 * | 0.0195 | 0.474 | 0.2187 |
| 02-22 * | 0.0009 | 0.006 | 0.0012 |
| 02-28 | 0.0330 | 0.088 | 0.0459 |
| 03-02 * | 0.0007 | 0.181 | 0.1177 |

### Operating point from OOF scores: ensemble-5, 5% budget

threshold = **0.39552** (epoch 9); realised per-day FPR range 0.0000-0.2902

| day | OOF FPR | OOF recall | alarm rate |
|---|---|---|---|
| 02-14 * | 0.0000 | 0.200 | 0.0698 |
| 02-15 * | 0.0254 | 0.062 | 0.0290 |
| 02-20 | 0.0003 | 0.998 | 0.0034 |
| 02-21 * | 0.2902 | 0.930 | 0.5710 |
| 02-22 * | 0.0023 | 0.006 | 0.0024 |
| 02-28 | 0.0124 | 0.050 | 0.0212 |
| 03-02 * | 0.0191 | 0.277 | 0.1865 |


GPU time of the 45 OOF runs: 1.81 h over 46 runs (logged in docs/lodo_v4/oof_timing.jsonl).

## SEALED

### Within-day AUROC on the sealed test days

| test day | seq | pos | episodes | **ensemble-5** | ensemble-3 | single (5 seeds: mean [min-max]) | flow_count | LR_last | HGB_last | HGB_stacked | label oracle |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 02-16 * | 483 | 297 | 2 | **0.989** | 0.988 | 0.982 [0.981-0.984] | 0.992 | 0.979 | 0.994 | 0.992 | 0.992 |
| 02-23 * | 3,318 | 255 | 8 | **0.492** | 0.485 | 0.508 [0.497-0.533] | 0.516 | 0.551 | 0.540 | 0.537 | 0.614 |
| 03-01 | 3,390 | 930 | 2 | **0.808** | 0.728 | 0.828 [0.780-0.857] | 0.621 | 0.615 | 0.708 | 0.766 | 0.999 |
| **mean of 3 days** | | | 12 | **0.763** | 0.734 | 0.773 | 0.709 | 0.715 | 0.748 | 0.765 | 0.868 |

### Baseline gate on the 3 sealed test days (informative only as far as 3 days allow)

| comparison (model minus baseline) | days | mean paired gain | MDE | day-bootstrap 95% CI | days won | verdict |
|---|---|---|---|---|---|---|
| transformer_ens5 vs flow_count | 3 | +0.053 | 0.361 | [-0.024, +0.187] | 1/3 | **FAIL** |
| transformer_ens5 vs LR_last | 3 | +0.048 | 0.404 | [-0.059, +0.193] | 2/3 | **FAIL** |
| transformer_ens5 vs HGB_last | 3 | +0.015 | 0.237 | [-0.049, +0.100] | 1/3 | **FAIL** |
| transformer_ens5 vs HGB_stacked | 3 | -0.002 | 0.135 | [-0.046, +0.042] | 1/3 | **FAIL** |
| transformer_ens3 vs flow_count | 3 | +0.024 | 0.227 | [-0.031, +0.107] | 1/3 | **FAIL** |
| transformer_ens3 vs LR_last | 3 | +0.019 | 0.279 | [-0.066, +0.113] | 2/3 | **FAIL** |
| transformer_ens3 vs HGB_last | 3 | -0.014 | 0.119 | [-0.056, +0.020] | 1/3 | **FAIL** |
| transformer_ens3 vs HGB_stacked | 3 | -0.032 | 0.077 | [-0.052, -0.004] | 0/3 | **FAIL** |
| transformer_single_seedmean vs flow_count | 3 | +0.063 | 0.386 | [-0.010, +0.207] | 1/3 | **FAIL** |
| transformer_single_seedmean vs LR_last | 3 | +0.058 | 0.422 | [-0.042, +0.213] | 2/3 | **FAIL** |
| transformer_single_seedmean vs HGB_last | 3 | +0.025 | 0.256 | [-0.032, +0.120] | 1/3 | **FAIL** |
| transformer_single_seedmean vs HGB_stacked | 3 | +0.008 | 0.148 | [-0.029, +0.062] | 1/3 | **FAIL** |

### Operating point: ensemble-5 at the OOF 1% threshold (threshold 0.64146, frozen before the test was opened)

| day | realised FPR | recall | alarm rate |
|---|---|---|---|
| 02-16 * | 0.0108 | 0.956 | 0.5921 |
| 02-23 * | 0.0000 | 0.000 | 0.0000 |
| 03-01 | 0.0049 | 0.245 | 0.0708 |

### Operating point: ensemble-5 at the OOF 5% threshold (threshold 0.39552, frozen before the test was opened)

| day | realised FPR | recall | alarm rate |
|---|---|---|---|
| 02-16 * | 0.0215 | 0.980 | 0.6108 |
| 02-23 * | 0.0000 | 0.004 | 0.0003 |
| 03-01 | 0.0049 | 0.290 | 0.0832 |

Pooled test AUROC (secondary): transformer_ens5 0.706, transformer_ens3 0.696, flow_count 0.524, LR_last 0.702, HGB_last 0.746, HGB_stacked 0.741, persistence_oracle 0.941.

Sealed test opened 2026-10-18 20:36:51; final training GPU time 8.6 min.