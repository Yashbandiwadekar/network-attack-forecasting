## Generated tables (eval/baselines_v5_render.py from docs/lodo_v5/*.json)

### Feature variants

| variant | columns | base features / blocks | recipe |
|---|---|---|---|
| S0_stacked41 | 246 | 41 raw/window features x 6 stack blocks  | current HGB_stacked: all 41 raw features x 6 stack blocks (anchor, reproduces docs/18) |
| S1_no_zero9 | 192 | 32 raw/window features x 6 stack blocks  | S0 without the 9 always-zero packet features |
| S2_no_ident | 102 | 17 raw/window features x 6 stack blocks  | S1 without has_ip_data, unique_dst_ips, 5 graph features, 8 graph_embed features (17 behavioural features) |
| S3_log | 102 | 17 raw/window features x 6 stack blocks  | S2 with log1p on count/volume/duration/IAT features before stacking |
| S4_ratio | 138 | 17 raw/window features x 6 stack blocks +6 ratios | S3 + per-window ratio/rate features (bytes/packet, packets/flow, bytes/flow, ports/flow, syn-ack, rst+fin) |
| S5_temporal | 162 | 17 raw/window features x 6 stack blocks +6 ratios +temporal block | S4 + causal in-sequence features (z / jump / slope / burst vs the earlier 11 windows, spike count, seconds since quiet, gaps) |
| S6_context | 172 | 17 raw/window features x 6 stack blocks +6 ratios +temporal block +context block | S5 + z / difference of the last window against the unit's rolling baseline of the previous 120 sequences (causal) |
| S7_relative | 154 | 17 raw/window features x 6 stack blocks +6 ratios +temporal block +context block (level blocks of volume dropped) | S6 without the absolute LEVEL blocks (last/mean/max) of the volume features: only relative / shape information about volume |

### Anchor

S0 + default HGB reproduces docs/18 `HGB_stacked`: ok=True, max abs score difference 3.0e-08, mean AUROC 0.8185 vs 0.8185.

### Per-day OOF within-day AUROC of every registered arm


| arm | 02-14 | 02-15 | 02-20 | 02-21 | 02-22 | 02-28 | 03-02 | mean 7 [95% day-boot CI] | mean 6 pseudo | SD (7) | min | max |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A_S0_stacked41 | 0.992 | 0.600 | 1.000 | 0.941 | 0.588 | 0.716 | 0.892 | **0.818** [0.695, 0.935] | 0.788 | 0.180 | 0.588 | 1.000 |
| A_S1_no_zero9 | 0.994 | 0.567 | 1.000 | 0.945 | 0.578 | 0.709 | 0.888 | **0.812** [0.681, 0.935] | 0.780 | 0.190 | 0.567 | 1.000 |
| A_S2_no_ident | 0.941 | 0.502 | 1.000 | 0.934 | 0.600 | 0.742 | 0.916 | **0.805** [0.670, 0.928] | 0.773 | 0.193 | 0.502 | 1.000 |
| A_S3_log | 0.923 | 0.586 | 1.000 | 0.926 | 0.618 | 0.720 | 0.898 | **0.810** [0.697, 0.917] | 0.778 | 0.166 | 0.586 | 1.000 |
| A_S4_ratio | 0.820 | 0.564 | 1.000 | 0.947 | 0.566 | 0.687 | 0.909 | **0.785** [0.663, 0.902] | 0.749 | 0.181 | 0.564 | 1.000 |
| A_S5_temporal | 0.957 | 0.564 | 1.000 | 0.953 | 0.574 | 0.698 | 0.901 | **0.807** [0.679, 0.929] | 0.775 | 0.189 | 0.564 | 1.000 |
| A_S6_context | 0.949 | 0.510 | 1.000 | 0.941 | 0.593 | 0.687 | 0.895 | **0.796** [0.663, 0.923] | 0.763 | 0.196 | 0.510 | 1.000 |
| A_S7_relative | 0.627 | 0.332 | 1.000 | 0.937 | 0.566 | 0.599 | 0.802 | **0.695** [0.537, 0.848] | 0.644 | 0.233 | 0.332 | 1.000 |
| B_S1_no_zero9_HGBtuned | 0.720 | 0.642 | 1.000 | 0.947 | 0.613 | 0.684 | 0.888 | **0.785** [0.682, 0.892] | 0.749 | 0.157 | 0.613 | 1.000 |
| B_S3_log_HGBtuned | 0.823 | 0.705 | 1.000 | 0.936 | 0.592 | 0.716 | 0.862 | **0.805** [0.708, 0.900] | 0.772 | 0.143 | 0.592 | 1.000 |
| C_S1_no_zero9_ET | 0.974 | 0.474 | 1.000 | 0.624 | 0.582 | 0.708 | 0.911 | **0.753** [0.616, 0.893] | 0.712 | 0.208 | 0.474 | 1.000 |
| C_S1_no_zero9_LR | 0.533 | 0.340 | 1.000 | 0.640 | 0.563 | 0.675 | 0.926 | **0.668** [0.515, 0.825] | 0.613 | 0.229 | 0.340 | 1.000 |
| C_S1_no_zero9_RF | 0.989 | 0.564 | 1.000 | 0.882 | 0.635 | 0.715 | 0.932 | **0.817** [0.697, 0.931] | 0.786 | 0.177 | 0.564 | 1.000 |
| *references (docs/18)* | | | | | | | | | | | | |
| flow_count | 0.944 | 0.801 | 0.992 | 0.963 | 0.604 | 0.640 | 0.740 | **0.812** [0.702, 0.918] | 0.782 | 0.159 | 0.604 | 0.992 |
| LR_last | 0.568 | 0.625 | 0.999 | 0.877 | 0.506 | 0.559 | 0.888 | **0.717** [0.591, 0.853] | 0.671 | 0.198 | 0.506 | 0.999 |
| HGB_last | 0.925 | 0.484 | 1.000 | 0.927 | 0.546 | 0.613 | 0.731 | **0.746** [0.609, 0.886] | 0.704 | 0.207 | 0.484 | 1.000 |
| HGB_stacked | 0.992 | 0.600 | 1.000 | 0.941 | 0.588 | 0.716 | 0.892 | **0.818** [0.695, 0.935] | 0.788 | 0.180 | 0.588 | 1.000 |
| Transformer_single_nested | 0.670 | 0.348 | 1.000 | 0.924 | 0.608 | 0.711 | 0.948 | **0.744** [0.577, 0.889] | 0.701 | 0.232 | 0.348 | 1.000 |
| Transformer_ens5_nested | 0.736 | 0.345 | 1.000 | 0.899 | 0.534 | 0.662 | 0.826 | **0.715** [0.560, 0.859] | 0.667 | 0.224 | 0.345 | 1.000 |
| **nested arm selection (the claim)** | 0.823 | 0.564 | 1.000 | 0.882 | 0.588 | 0.716 | 0.892 | **0.781** [0.671, 0.888] | 0.744 | | | |
| nested selection, anchor excluded | 0.823 | 0.564 | 1.000 | 0.882 | 0.578 | 0.715 | 0.888 | 0.778 | 0.742 | | | |
| arm chosen per day (nested) | B S3 log HGBtuned | C S1 no zero9 RF | A S0 stacked41 | C S1 no zero9 RF | A S0 stacked41 | A S0 stacked41 | A S0 stacked41 | | | | | |

Best non-anchor arm (un-nested): **C_S1_no_zero9_RF**; best arm overall (un-nested): A_S0_stacked41. Chosen configuration per fold: see the tuning table.

### Gate, 7 days

| candidate | reference | days | mean paired gain | MDE | day-bootstrap 95% CI | days won | verdict |
|---|---|---|---|---|---|---|---|
| nested_selection | HGB_stacked | 7 | -0.038 | 0.079 | [-0.086, -0.005] | 0/7 | **FAIL** |
| nested_selection | flow_count | 7 | -0.031 | 0.164 | [-0.121, +0.054] | 3/7 | **FAIL** |
| nested_selection | HGB_last | 7 | +0.034 | 0.115 | [-0.028, +0.095] | 5/7 | **FAIL** |
| nested_selection | LR_last | 7 | +0.063 | 0.139 | [-0.005, +0.144] | 6/7 | **FAIL** |
| nested_selection | Transformer_single_nested | 7 | +0.037 | 0.133 | [-0.028, +0.113] | 4/7 | **FAIL** |
| nested_selection | Transformer_ens5_nested | 7 | +0.066 | 0.097 | [+0.020, +0.121] | 6/7 | **FAIL** |
| nested_selection_non_anchor | HGB_stacked | 7 | -0.040 | 0.077 | [-0.088, -0.007] | 0/7 | **FAIL** |
| nested_selection_non_anchor | flow_count | 7 | -0.034 | 0.162 | [-0.121, +0.052] | 3/7 | **FAIL** |
| nested_selection_non_anchor | HGB_last | 7 | +0.032 | 0.113 | [-0.030, +0.092] | 5/7 | **FAIL** |
| nested_selection_non_anchor | LR_last | 7 | +0.061 | 0.139 | [-0.007, +0.142] | 6/7 | **FAIL** |
| nested_selection_non_anchor | Transformer_single_nested | 7 | +0.034 | 0.135 | [-0.030, +0.111] | 4/7 | **FAIL** |
| nested_selection_non_anchor | Transformer_ens5_nested | 7 | +0.064 | 0.098 | [+0.019, +0.120] | 5/7 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | HGB_stacked | 7 | -0.002 | 0.048 | [-0.027, +0.024] | 2/7 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | flow_count | 7 | +0.005 | 0.170 | [-0.092, +0.089] | 5/7 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | HGB_last | 7 | +0.070 | 0.100 | [+0.017, +0.124] | 6/7 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | LR_last | 7 | +0.099 | 0.204 | [+0.005, +0.222] | 6/7 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | Transformer_single_nested | 7 | +0.073 | 0.175 | [-0.010, +0.175] | 5/7 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | Transformer_ens5_nested | 7 | +0.102 | 0.130 | [+0.036, +0.174] | 5/7 | **FAIL** |

### Gate, 6 pseudo-host days

| candidate | reference | days | mean paired gain | MDE | day-bootstrap 95% CI | days won | verdict |
|---|---|---|---|---|---|---|---|
| nested_selection | HGB_stacked | 6 | -0.044 | 0.094 | [-0.096, -0.006] | 0/6 | **FAIL** |
| nested_selection | flow_count | 6 | -0.038 | 0.200 | [-0.140, +0.063] | 2/6 | **FAIL** |
| nested_selection | HGB_last | 6 | +0.040 | 0.139 | [-0.034, +0.108] | 4/6 | **FAIL** |
| nested_selection | LR_last | 6 | +0.074 | 0.165 | [-0.004, +0.164] | 5/6 | **FAIL** |
| nested_selection | Transformer_single_nested | 6 | +0.043 | 0.162 | [-0.033, +0.130] | 3/6 | **FAIL** |
| nested_selection | Transformer_ens5_nested | 6 | +0.077 | 0.111 | [+0.026, +0.142] | 5/6 | **FAIL** |
| nested_selection_non_anchor | HGB_stacked | 6 | -0.047 | 0.091 | [-0.098, -0.009] | 0/6 | **FAIL** |
| nested_selection_non_anchor | flow_count | 6 | -0.040 | 0.198 | [-0.141, +0.061] | 2/6 | **FAIL** |
| nested_selection_non_anchor | HGB_last | 6 | +0.037 | 0.138 | [-0.036, +0.105] | 4/6 | **FAIL** |
| nested_selection_non_anchor | LR_last | 6 | +0.071 | 0.166 | [-0.007, +0.161] | 5/6 | **FAIL** |
| nested_selection_non_anchor | Transformer_single_nested | 6 | +0.040 | 0.164 | [-0.038, +0.129] | 3/6 | **FAIL** |
| nested_selection_non_anchor | Transformer_ens5_nested | 6 | +0.075 | 0.112 | [+0.023, +0.139] | 5/6 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | HGB_stacked | 6 | -0.002 | 0.059 | [-0.033, +0.028] | 2/6 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | flow_count | 6 | +0.004 | 0.210 | [-0.112, +0.103] | 4/6 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | HGB_last | 6 | +0.082 | 0.113 | [+0.020, +0.141] | 5/6 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | LR_last | 6 | +0.116 | 0.241 | [+0.007, +0.248] | 5/6 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | Transformer_single_nested | 6 | +0.085 | 0.209 | [-0.013, +0.198] | 4/6 | **FAIL** |
| best_non_anchor=C_S1_no_zero9_RF | Transformer_ens5_nested | 6 | +0.119 | 0.144 | [+0.047, +0.194] | 5/6 | **FAIL** |

### Gate of every registered arm against the incumbent and against flow_count (7 days / 6 days)

| candidate | reference | days | mean paired gain | MDE | day-bootstrap 95% CI | days won | verdict |
|---|---|---|---|---|---|---|---|
| A_S1_no_zero9 | HGB_stacked | 7 | -0.007 | 0.031 | [-0.016, +0.000] | 2/7 | **FAIL** |
| A_S1_no_zero9 | flow_count | 7 | -0.001 | 0.151 | [-0.088, +0.071] | 4/7 | **FAIL** |
| A_S2_no_ident | HGB_stacked | 7 | -0.013 | 0.057 | [-0.047, +0.014] | 3/7 | **FAIL** |
| A_S2_no_ident | flow_count | 7 | -0.007 | 0.188 | [-0.117, +0.083] | 3/7 | **FAIL** |
| A_S3_log | HGB_stacked | 7 | -0.008 | 0.039 | [-0.032, +0.011] | 3/7 | **FAIL** |
| A_S3_log | flow_count | 7 | -0.002 | 0.146 | [-0.086, +0.071] | 4/7 | **FAIL** |
| A_S4_ratio | HGB_stacked | 7 | -0.034 | 0.081 | [-0.083, -0.001] | 2/7 | **FAIL** |
| A_S4_ratio | flow_count | 7 | -0.027 | 0.163 | [-0.117, +0.058] | 3/7 | **FAIL** |
| A_S5_temporal | HGB_stacked | 7 | -0.012 | 0.031 | [-0.025, +0.001] | 3/7 | **FAIL** |
| A_S5_temporal | flow_count | 7 | -0.005 | 0.152 | [-0.095, +0.069] | 4/7 | **FAIL** |
| A_S6_context | HGB_stacked | 7 | -0.022 | 0.045 | [-0.048, -0.002] | 2/7 | **FAIL** |
| A_S6_context | flow_count | 7 | -0.016 | 0.172 | [-0.120, +0.065] | 4/7 | **FAIL** |
| A_S7_relative | HGB_stacked | 7 | -0.124 | 0.179 | [-0.227, -0.035] | 0/7 | **FAIL** |
| A_S7_relative | flow_count | 7 | -0.117 | 0.249 | [-0.261, +0.000] | 2/7 | **FAIL** |
| B_S1_no_zero9_HGBtuned | HGB_stacked | 7 | -0.034 | 0.136 | [-0.118, +0.018] | 3/7 | **FAIL** |
| B_S1_no_zero9_HGBtuned | flow_count | 7 | -0.027 | 0.159 | [-0.116, +0.055] | 4/7 | **FAIL** |
| B_S3_log_HGBtuned | HGB_stacked | 7 | -0.014 | 0.102 | [-0.076, +0.037] | 2/7 | **FAIL** |
| B_S3_log_HGBtuned | flow_count | 7 | -0.007 | 0.110 | [-0.066, +0.052] | 3/7 | **FAIL** |
| C_S1_no_zero9_ET | HGB_stacked | 7 | -0.065 | 0.153 | [-0.156, -0.000] | 1/7 | **FAIL** |
| C_S1_no_zero9_ET | flow_count | 7 | -0.059 | 0.250 | [-0.192, +0.065] | 4/7 | **FAIL** |
| C_S1_no_zero9_LR | HGB_stacked | 7 | -0.150 | 0.239 | [-0.284, -0.032] | 1/7 | **FAIL** |
| C_S1_no_zero9_LR | flow_count | 7 | -0.144 | 0.318 | [-0.313, +0.023] | 3/7 | **FAIL** |
| C_S1_no_zero9_RF | HGB_stacked | 7 | -0.002 | 0.048 | [-0.027, +0.024] | 2/7 | **FAIL** |
| C_S1_no_zero9_RF | flow_count | 7 | +0.005 | 0.170 | [-0.092, +0.089] | 5/7 | **FAIL** |

| candidate | reference | days | mean paired gain | MDE | day-bootstrap 95% CI | days won | verdict |
|---|---|---|---|---|---|---|---|
| A_S1_no_zero9 | HGB_stacked | 6 | -0.008 | 0.035 | [-0.019, +0.000] | 2/6 | **FAIL** |
| A_S1_no_zero9 | flow_count | 6 | -0.002 | 0.186 | [-0.103, +0.086] | 3/6 | **FAIL** |
| A_S2_no_ident | HGB_stacked | 6 | -0.016 | 0.070 | [-0.054, +0.017] | 3/6 | **FAIL** |
| A_S2_no_ident | flow_count | 6 | -0.009 | 0.231 | [-0.138, +0.097] | 2/6 | **FAIL** |
| A_S3_log | HGB_stacked | 6 | -0.010 | 0.048 | [-0.035, +0.013] | 3/6 | **FAIL** |
| A_S3_log | flow_count | 6 | -0.004 | 0.180 | [-0.102, +0.083] | 3/6 | **FAIL** |
| A_S4_ratio | HGB_stacked | 6 | -0.039 | 0.097 | [-0.094, -0.000] | 2/6 | **FAIL** |
| A_S4_ratio | flow_count | 6 | -0.033 | 0.199 | [-0.134, +0.067] | 2/6 | **FAIL** |
| A_S5_temporal | HGB_stacked | 6 | -0.014 | 0.035 | [-0.029, +0.002] | 2/6 | **FAIL** |
| A_S5_temporal | flow_count | 6 | -0.007 | 0.187 | [-0.112, +0.080] | 3/6 | **FAIL** |
| A_S6_context | HGB_stacked | 6 | -0.026 | 0.053 | [-0.056, -0.002] | 2/6 | **FAIL** |
| A_S6_context | flow_count | 6 | -0.019 | 0.211 | [-0.141, +0.076] | 3/6 | **FAIL** |
| A_S7_relative | HGB_stacked | 6 | -0.144 | 0.203 | [-0.256, -0.046] | 0/6 | **FAIL** |
| A_S7_relative | flow_count | 6 | -0.138 | 0.294 | [-0.300, -0.002] | 1/6 | **FAIL** |
| B_S1_no_zero9_HGBtuned | HGB_stacked | 6 | -0.039 | 0.166 | [-0.136, +0.022] | 3/6 | **FAIL** |
| B_S1_no_zero9_HGBtuned | flow_count | 6 | -0.033 | 0.195 | [-0.134, +0.063] | 3/6 | **FAIL** |
| B_S3_log_HGBtuned | HGB_stacked | 6 | -0.016 | 0.126 | [-0.086, +0.047] | 2/6 | **FAIL** |
| B_S3_log_HGBtuned | flow_count | 6 | -0.010 | 0.135 | [-0.079, +0.059] | 2/6 | **FAIL** |
| C_S1_no_zero9_ET | HGB_stacked | 6 | -0.076 | 0.183 | [-0.182, -0.000] | 1/6 | **FAIL** |
| C_S1_no_zero9_ET | flow_count | 6 | -0.070 | 0.304 | [-0.223, +0.074] | 3/6 | **FAIL** |
| C_S1_no_zero9_LR | HGB_stacked | 6 | -0.175 | 0.276 | [-0.321, -0.044] | 1/6 | **FAIL** |
| C_S1_no_zero9_LR | flow_count | 6 | -0.169 | 0.378 | [-0.360, +0.024] | 2/6 | **FAIL** |
| C_S1_no_zero9_RF | HGB_stacked | 6 | -0.002 | 0.059 | [-0.033, +0.028] | 2/6 | **FAIL** |
| C_S1_no_zero9_RF | flow_count | 6 | +0.004 | 0.210 | [-0.112, +0.103] | 4/6 | **FAIL** |

### Tuned configurations per fold

| arm | fold | chosen configuration |
|---|---|---|
| B_S1_no_zero9_HGBtuned | 2018-02-14 | {"learning_rate": 0.15, "max_leaf_nodes": 31, "min_samples_leaf": 300, "l2_regularization": 0.0, "class_weight": "balanced"} |
| B_S1_no_zero9_HGBtuned | 2018-02-15 | {"learning_rate": 0.05, "max_leaf_nodes": 8, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": null} |
| B_S1_no_zero9_HGBtuned | 2018-02-20#g0 | {"learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": "balanced"} |
| B_S1_no_zero9_HGBtuned | 2018-02-20#g1 | {"learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": "balanced"} |
| B_S1_no_zero9_HGBtuned | 2018-02-20#g2 | {"learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": "balanced"} |
| B_S1_no_zero9_HGBtuned | 2018-02-21 | {"learning_rate": 0.15, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": null} |
| B_S1_no_zero9_HGBtuned | 2018-02-22 | {"learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": null} |
| B_S1_no_zero9_HGBtuned | 2018-02-28 | {"learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": null} |
| B_S1_no_zero9_HGBtuned | 2018-03-02 | {"learning_rate": 0.05, "max_leaf_nodes": 8, "min_samples_leaf": 300, "l2_regularization": 10.0, "class_weight": null} |
| B_S3_log_HGBtuned | 2018-02-14 | {"learning_rate": 0.15, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": null} |
| B_S3_log_HGBtuned | 2018-02-15 | {"learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": null} |
| B_S3_log_HGBtuned | 2018-02-20#g0 | {"learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": null} |
| B_S3_log_HGBtuned | 2018-02-20#g1 | {"learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": null} |
| B_S3_log_HGBtuned | 2018-02-20#g2 | {"learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": null} |
| B_S3_log_HGBtuned | 2018-02-21 | {"learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": "balanced"} |
| B_S3_log_HGBtuned | 2018-02-22 | {"learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": "balanced"} |
| B_S3_log_HGBtuned | 2018-02-28 | {"learning_rate": 0.15, "max_leaf_nodes": 31, "min_samples_leaf": 20, "l2_regularization": 10.0, "class_weight": null} |
| B_S3_log_HGBtuned | 2018-03-02 | {"learning_rate": 0.05, "max_leaf_nodes": 8, "min_samples_leaf": 300, "l2_regularization": 10.0, "class_weight": null} |
| C_S1_no_zero9_ET | 2018-02-14 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_ET | 2018-02-15 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_ET | 2018-02-20#g0 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_ET | 2018-02-20#g1 | {"min_samples_leaf": 5, "class_weight": "balanced_subsample"} |
| C_S1_no_zero9_ET | 2018-02-20#g2 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_ET | 2018-02-21 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_ET | 2018-02-22 | {"min_samples_leaf": 50, "class_weight": null} |
| C_S1_no_zero9_ET | 2018-02-28 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_ET | 2018-03-02 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_LR | 2018-02-14 | {"C": 0.01, "class_weight": "balanced"} |
| C_S1_no_zero9_LR | 2018-02-15 | {"C": 0.01, "class_weight": "balanced"} |
| C_S1_no_zero9_LR | 2018-02-20#g0 | {"C": 0.01, "class_weight": "balanced"} |
| C_S1_no_zero9_LR | 2018-02-20#g1 | {"C": 0.01, "class_weight": "balanced"} |
| C_S1_no_zero9_LR | 2018-02-20#g2 | {"C": 0.01, "class_weight": "balanced"} |
| C_S1_no_zero9_LR | 2018-02-21 | {"C": 0.01, "class_weight": null} |
| C_S1_no_zero9_LR | 2018-02-22 | {"C": 0.01, "class_weight": "balanced"} |
| C_S1_no_zero9_LR | 2018-02-28 | {"C": 0.01, "class_weight": null} |
| C_S1_no_zero9_LR | 2018-03-02 | {"C": 0.01, "class_weight": "balanced"} |
| C_S1_no_zero9_RF | 2018-02-14 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_RF | 2018-02-15 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_RF | 2018-02-20#g0 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_RF | 2018-02-20#g1 | {"min_samples_leaf": 5, "class_weight": "balanced_subsample"} |
| C_S1_no_zero9_RF | 2018-02-20#g2 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_RF | 2018-02-21 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_RF | 2018-02-22 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_RF | 2018-02-28 | {"min_samples_leaf": 5, "class_weight": null} |
| C_S1_no_zero9_RF | 2018-03-02 | {"min_samples_leaf": 5, "class_weight": null} |

### Exploratory (not registered, excluded from every verdict): mean probability of the incumbent and the best non-anchor arm

7-day mean 0.827; per day 02-14 0.991, 02-15 0.563, 02-20 1.000, 02-21 0.934, 02-22 0.649, 02-28 0.719, 03-02 0.935; vs HGB_stacked gain +0.009, MDE 0.042, verdict FAIL.

### Threshold transfer

#### Realised FPR / recall per day, leave-one-day-out threshold, target 1% (threshold from inner OOF scores of the other days)

| arm | 02-14 | 02-15 | 02-20 | 02-21 | 02-22 | 02-28 | 03-02 | FPR min-max | mean abs log(FPR/target) | days within x3 of target |
|---|---|---|---|---|---|---|---|---|---|---|
| flow_count | 0.62% / 4.16% | 1.24% / 9.68% | 0.00% / 0.00% | 0.29% / 48.90% | 3.73% / 4.27% | 0.42% / 4.14% | 1.64% / 3.11% | 0.00%-3.73% | 2.10 | 4/7 |
| A_S0_stacked41 | 0.00% / 22.30% | 1.89% / 0.00% | 0.00% / 99.57% | 0.57% / 45.96% | 6.18% / 16.46% | 1.62% / 3.88% | 0.64% / 13.61% | 0.00%-6.18% | 2.54 | 4/7 |
| C_S1_no_zero9_RF | 0.00% / 0.09% | 0.20% / 0.00% | 0.11% / 99.09% | 3.45% / 45.59% | 0.00% / 0.00% | 1.89% / 4.01% | 0.82% / 14.00% | 0.00%-3.45% | 1.97 | 2/7 |
| B_S3_log_HGBtuned | 0.00% / 3.27% | 1.92% / 1.76% | 0.00% / 90.23% | 0.57% / 45.59% | 3.83% / 9.15% | 1.00% / 4.51% | 1.09% / 18.39% | 0.00%-3.83% | 2.36 | 4/7 |
| A_S5_temporal | 0.00% / 16.46% | 1.14% / 0.00% | 0.00% / 99.89% | 0.57% / 45.96% | 0.42% / 1.22% | 2.16% / 7.39% | 1.09% / 19.92% | 0.00%-2.16% | 2.32 | 5/7 |
| A_S6_context | 0.00% / 29.82% | 1.47% / 0.59% | 0.00% / 99.87% | 0.57% / 45.59% | 1.16% / 4.88% | 2.47% / 6.27% | 1.09% / 19.53% | 0.00%-2.47% | 1.90 | 5/7 |
| A_S7_relative | 0.66% / 9.91% | 0.13% / 0.00% | 0.00% / 99.89% | 0.00% / 11.40% | 0.16% / 0.61% | 0.69% / 1.13% | 0.64% / 4.04% | 0.00%-0.69% | 1.92 | 3/7 |
| B_S3_log_HGBtuned+platt | 0.00% / 3.27% | 1.92% / 1.76% | 0.00% / 90.23% | 0.57% / 45.59% | 3.83% / 9.15% | 1.00% / 4.51% | 1.09% / 18.39% | 0.00%-3.83% | 2.36 | 4/7 |
| B_S3_log_HGBtuned+isotonic | 0.00% / 0.62% | 1.92% / 1.76% | 0.00% / 89.77% | 0.57% / 45.59% | 3.96% / 9.15% | 0.46% / 1.38% | 1.09% / 17.95% | 0.00%-3.96% | 2.47 | 4/7 |

#### Realised FPR / recall per day, leave-one-day-out threshold, target 5% (threshold from inner OOF scores of the other days)

| arm | 02-14 | 02-15 | 02-20 | 02-21 | 02-22 | 02-28 | 03-02 | FPR min-max | mean abs log(FPR/target) | days within x3 of target |
|---|---|---|---|---|---|---|---|---|---|---|
| flow_count | 4.93% / 45.58% | 11.04% / 44.28% | 0.00% / 0.00% | 0.29% / 48.90% | 14.51% / 22.56% | 2.59% / 7.02% | 5.92% / 21.50% | 0.00%-14.51% | 1.89 | 5/7 |
| A_S0_stacked41 | 0.57% / 52.74% | 3.81% / 1.47% | 0.00% / 99.95% | 20.40% / 94.12% | 24.83% / 32.93% | 2.86% / 14.29% | 1.64% / 20.76% | 0.00%-24.83% | 2.69 | 2/7 |
| C_S1_no_zero9_RF | 0.43% / 49.65% | 0.98% / 0.29% | 0.26% / 99.79% | 3.45% / 48.90% | 4.05% / 7.32% | 3.63% / 20.30% | 1.09% / 17.65% | 0.26%-4.05% | 1.36 | 3/7 |
| B_S3_log_HGBtuned | 0.00% / 40.18% | 5.60% / 11.73% | 0.05% / 99.89% | 12.64% / 78.31% | 15.05% / 25.61% | 3.09% / 14.29% | 1.28% / 23.32% | 0.00%-15.05% | 1.98 | 3/7 |
| A_S5_temporal | 0.09% / 47.96% | 2.25% / 1.76% | 0.00% / 99.92% | 19.25% / 94.49% | 8.94% / 17.07% | 14.09% / 33.33% | 1.82% / 41.52% | 0.00%-19.25% | 2.43 | 4/7 |
| A_S6_context | 0.38% / 49.03% | 3.13% / 2.64% | 0.01% / 99.97% | 8.33% / 76.47% | 11.16% / 23.17% | 12.85% / 30.08% | 2.37% / 39.60% | 0.01%-12.85% | 1.79 | 5/7 |
| A_S7_relative | 2.80% / 45.40% | 1.63% / 0.00% | 0.10% / 100.00% | 0.00% / 18.75% | 8.01% / 12.80% | 8.68% / 10.15% | 1.18% / 17.85% | 0.00%-8.68% | 1.67 | 3/7 |
| B_S3_log_HGBtuned+platt | 0.00% / 40.18% | 5.60% / 11.73% | 0.05% / 99.89% | 12.64% / 78.31% | 15.05% / 25.61% | 3.09% / 14.29% | 1.28% / 23.32% | 0.00%-15.05% | 1.98 | 3/7 |
| B_S3_log_HGBtuned+isotonic | 0.00% / 0.62% | 1.92% / 1.76% | 0.02% / 90.33% | 0.57% / 45.59% | 9.62% / 17.68% | 2.12% / 11.40% | 1.09% / 17.95% | 0.00%-9.62% | 2.42 | 3/7 |

#### Label-free adaptive rule (adaptive_q99): realised FPR / recall per pseudo-host day

| arm | 02-14 | 02-15 | 02-21 | 02-22 | 02-28 | 03-02 | FPR min-max | mean abs log ratio | within x3 |
|---|---|---|---|---|---|---|---|---|---|
| flow_count | 1.09% / 2.21% | 1.17% / 2.35% | 0.00% / 0.37% | 1.22% / 3.05% | 1.12% / 2.13% | 1.28% / 1.53% | 0.00%-1.28% | 0.46 | 5/6 |
| A_S0_stacked41 | 1.47% / 6.02% | 1.60% / 3.81% | 0.00% / 6.99% | 1.87% / 4.88% | 1.58% / 2.26% | 1.64% / 4.44% | 0.00%-1.87% | 0.73 | 5/6 |
| C_S1_no_zero9_RF | 1.09% / 4.34% | 1.69% / 3.23% | 0.00% / 8.82% | 2.03% / 3.66% | 1.78% / 3.38% | 2.00% / 4.88% | 0.00%-2.03% | 0.75 | 5/6 |
| B_S3_log_HGBtuned | 1.57% / 3.19% | 1.76% / 6.16% | 0.57% / 17.28% | 2.09% / 4.88% | 1.47% / 3.38% | 1.18% / 5.37% | 0.57%-2.09% | 0.48 | 6/6 |
| A_S5_temporal | 1.47% / 4.16% | 1.73% / 5.57% | 0.00% / 2.21% | 2.32% / 6.71% | 1.24% / 2.88% | 2.28% / 5.67% | 0.00%-2.32% | 0.79 | 5/6 |
| A_S6_context | 1.52% / 3.45% | 1.40% / 7.33% | 0.00% / 8.09% | 2.57% / 5.49% | 1.24% / 2.76% | 1.82% / 5.03% | 0.00%-2.57% | 0.74 | 5/6 |
| A_S7_relative | 2.32% / 2.21% | 2.12% / 3.23% | 0.57% / 1.10% | 1.80% / 4.88% | 1.81% / 1.88% | 2.64% / 4.44% | 0.57%-2.64% | 0.72 | 6/6 |

#### Label-free adaptive rule (adaptive_q95): realised FPR / recall per pseudo-host day

| arm | 02-14 | 02-15 | 02-21 | 02-22 | 02-28 | 03-02 | FPR min-max | mean abs log ratio | within x3 |
|---|---|---|---|---|---|---|---|---|---|
| flow_count | 4.89% / 10.09% | 4.95% / 10.85% | 0.00% / 5.51% | 5.66% / 4.88% | 4.94% / 6.52% | 5.37% / 7.00% | 0.00%-5.66% | 0.63 | 5/6 |
| A_S0_stacked41 | 4.84% / 16.64% | 4.95% / 11.73% | 0.57% / 12.50% | 6.34% / 14.02% | 5.44% / 10.65% | 4.64% / 13.46% | 0.57%-6.34% | 0.43 | 5/6 |
| C_S1_no_zero9_RF | 4.51% / 12.83% | 5.50% / 9.97% | 0.57% / 12.87% | 7.56% / 10.37% | 4.75% / 11.78% | 4.19% / 12.38% | 0.57%-7.56% | 0.50 | 5/6 |
| B_S3_log_HGBtuned | 6.12% / 11.33% | 5.89% / 14.37% | 0.86% / 20.22% | 6.40% / 12.80% | 4.98% / 9.02% | 4.28% / 10.95% | 0.86%-6.40% | 0.42 | 5/6 |
| A_S5_temporal | 5.65% / 13.01% | 5.05% / 14.37% | 0.00% / 5.15% | 6.92% / 15.24% | 4.82% / 7.89% | 5.10% / 13.02% | 0.00%-6.92% | 0.68 | 5/6 |
| A_S6_context | 5.27% / 12.48% | 5.21% / 13.78% | 1.72% / 16.18% | 7.17% / 14.63% | 5.36% / 7.64% | 5.37% / 12.28% | 1.72%-7.17% | 0.28 | 6/6 |
| A_S7_relative | 6.36% / 7.79% | 6.38% / 4.99% | 1.44% / 5.51% | 6.53% / 10.37% | 6.33% / 5.64% | 5.92% / 9.66% | 1.44%-6.53% | 0.40 | 5/6 |

#### Calibration of B_S3_log_HGBtuned (outer held-out; Brier / ECE-10 per day; calibrators fitted on inner OOF scores of the other days only)

| score | 02-14 | 02-15 | 02-20 | 02-21 | 02-22 | 02-28 | 03-02 | mean Brier | mean AUROC |
|---|---|---|---|---|---|---|---|---|---|
| raw | 0.231 / 0.266 | 0.102 / 0.090 | 0.000 / 0.001 | 0.099 / 0.050 | 0.152 / 0.200 | 0.215 / 0.210 | 0.443 / 0.482 | 0.1774 | 0.8047 |
| platt | 0.187 / 0.183 | 0.115 / 0.087 | 0.001 / 0.015 | 0.102 / 0.071 | 0.197 / 0.341 | 0.162 / 0.032 | 0.323 / 0.370 | 0.1551 | 0.8047 |
| isotonic | 0.205 / 0.182 | 0.124 / 0.101 | 0.001 / 0.014 | 0.108 / 0.087 | 0.197 / 0.338 | 0.169 / 0.027 | 0.350 / 0.371 | 0.1647 | 0.7711 |

### Secondary labels

| day | k, s (train-derived) | definition | positives kept | dropped as ambiguous | median attack flows in primary-positive windows |
|---|---|---|---|---|---|
| 02-14 | 2, 0.010 | primary | 1130 | 0 | 340.0 |
| 02-14 | 2, 0.010 | S_fix(k>=5,s>=5%) | 1130 | 0 | 340.0 |
| 02-14 | 2, 0.010 | S_train(k>=2,s>=0.010) | 1130 | 0 | 340.0 |
| 02-14 | 2, 0.010 | S_run6 | 1129 | 1 | 340.0 |
| 02-15 | 2, 0.010 | primary | 341 | 0 | 37.0 |
| 02-15 | 2, 0.010 | S_fix(k>=5,s>=5%) | 302 | 39 | 37.0 |
| 02-15 | 2, 0.010 | S_train(k>=2,s>=0.010) | 339 | 2 | 37.0 |
| 02-15 | 2, 0.010 | S_run6 | 340 | 1 | 37.0 |
| 02-21 | 2, 0.010 | primary | 272 | 0 | 21.0 |
| 02-21 | 2, 0.010 | S_fix(k>=5,s>=5%) | 255 | 17 | 21.0 |
| 02-21 | 2, 0.010 | S_train(k>=2,s>=0.010) | 266 | 6 | 21.0 |
| 02-21 | 2, 0.010 | S_run6 | 237 | 35 | 21.0 |
| 02-22 | 18, 0.100 | primary | 164 | 0 | 2.0 |
| 02-22 | 18, 0.100 | S_fix(k>=5,s>=5%) | 0 | 164 | 2.0 |
| 02-22 | 18, 0.100 | S_train(k>=18,s>=0.100) | 0 | 164 | 2.0 |
| 02-22 | 18, 0.100 | S_run6 | 0 | 164 | 2.0 |
| 02-28 | 2, 0.010 | primary | 798 | 0 | 52.0 |
| 02-28 | 2, 0.010 | S_fix(k>=5,s>=5%) | 782 | 16 | 52.0 |
| 02-28 | 2, 0.010 | S_train(k>=2,s>=0.010) | 796 | 2 | 52.0 |
| 02-28 | 2, 0.010 | S_run6 | 798 | 0 | 52.0 |
| 03-02 | 2, 0.010 | primary | 2028 | 0 | 90.0 |
| 03-02 | 2, 0.010 | S_fix(k>=5,s>=5%) | 2006 | 22 | 90.0 |
| 03-02 | 2, 0.010 | S_train(k>=2,s>=0.010) | 2027 | 1 | 90.0 |
| 03-02 | 2, 0.010 | S_run6 | 2027 | 1 | 90.0 |

AUROC on each label definition (scores from the primary-trained arms; ambiguous windows dropped from scoring):

| day | score | primary | S_fix(k>=5,s>=5%) | S_train(k>=2,s>=0.010) | S_run6 |
|---|---|---|---|---|---|
| 02-14 | flow_count | 0.944 | 0.944 | 0.944 | 0.945 |
| 02-14 | HGB_stacked(current) | 0.992 | 0.992 | 0.992 | 0.992 |
| 02-14 | best=C_S1_no_zero9_RF | 0.989 | 0.989 | 0.989 | 0.990 |
| 02-15 | flow_count | 0.801 | 0.800 | 0.804 | 0.803 |
| 02-15 | HGB_stacked(current) | 0.600 | 0.607 | 0.603 | 0.602 |
| 02-15 | best=C_S1_no_zero9_RF | 0.564 | 0.580 | 0.564 | 0.565 |
| 02-21 | flow_count | 0.963 | 0.965 | 0.964 | 0.977 |
| 02-21 | HGB_stacked(current) | 0.941 | 0.943 | 0.943 | 0.948 |
| 02-21 | best=C_S1_no_zero9_RF | 0.882 | 0.889 | 0.887 | 0.901 |
| 02-22 | flow_count | 0.604 | n/a | n/a | n/a |
| 02-22 | HGB_stacked(current) | 0.588 | n/a | n/a | n/a |
| 02-22 | best=C_S1_no_zero9_RF | 0.635 | n/a | n/a | n/a |
| 02-28 | flow_count | 0.640 | 0.638 | 0.640 | 0.640 |
| 02-28 | HGB_stacked(current) | 0.716 | 0.713 | 0.716 | 0.716 |
| 02-28 | best=C_S1_no_zero9_RF | 0.715 | 0.713 | 0.715 | 0.715 |
| 03-02 | flow_count | 0.740 | 0.740 | 0.740 | 0.740 |
| 03-02 | HGB_stacked(current) | 0.892 | 0.897 | 0.892 | 0.892 |
| 03-02 | best=C_S1_no_zero9_RF | 0.932 | 0.937 | 0.932 | 0.932 |

Trained on S_train (ambiguous dropped from training), evaluated on S_train, against the primary-trained arm on the same rows:

| day | arm | primary-trained | S_train-trained |
|---|---|---|---|
| 02-14 | HGB_stacked(current) | 0.992 | 0.885 |
| 02-14 | best=C_S1_no_zero9_RF | 0.989 | 0.986 |
| 02-15 | HGB_stacked(current) | 0.603 | 0.565 |
| 02-15 | best=C_S1_no_zero9_RF | 0.564 | 0.508 |
| 02-21 | HGB_stacked(current) | 0.943 | 0.934 |
| 02-21 | best=C_S1_no_zero9_RF | 0.887 | 0.693 |
| 02-22 | HGB_stacked(current) | n/a | n/a |
| 02-22 | best=C_S1_no_zero9_RF | n/a | n/a |
| 02-28 | HGB_stacked(current) | 0.716 | 0.702 |
| 02-28 | best=C_S1_no_zero9_RF | 0.715 | 0.713 |
| 03-02 | HGB_stacked(current) | 0.892 | 0.833 |
| 03-02 | best=C_S1_no_zero9_RF | 0.932 | 0.937 |

Alignment check (raw-CSV rebuilt label vs primary): 02-14 100.00% match, 100.0% of primary positives recovered, 02-15 100.00% match, 100.0% of primary positives recovered, 02-21 99.68% match, 99.3% of primary positives recovered, 02-22 100.00% match, 100.0% of primary positives recovered, 02-28 100.00% match, 100.0% of primary positives recovered, 03-02 100.00% match, 100.0% of primary positives recovered

### Robustness

| arm | ablation | 02-14 | 02-15 | 02-20 | 02-21 | 02-22 | 02-28 | 03-02 | max drop (volumetric days 02-14, 02-15, 02-21) |
|---|---|---|---|---|---|---|---|---|---|
| HGB_stacked(current) | none | 0.992 | 0.600 | 1.000 | 0.941 | 0.588 | 0.716 | 0.892 | |
| HGB_stacked(current) | flow_count | 0.945 (+0.047) | 0.631 (-0.031) | 1.000 (-0.000) | 0.944 (-0.003) | 0.575 (+0.014) | 0.681 (+0.035) | 0.871 (+0.021) | +0.047 |
| HGB_stacked(current) | volume4 | 0.950 (+0.042) | 0.724 (-0.124) | 1.000 (+0.000) | 0.895 (+0.046) | 0.571 (+0.017) | 0.626 (+0.091) | 0.830 (+0.062) | +0.046 |
| best=C_S1_no_zero9_RF | none | 0.989 | 0.564 | 1.000 | 0.882 | 0.635 | 0.715 | 0.932 | |
| best=C_S1_no_zero9_RF | flow_count | 0.986 (+0.003) | 0.590 (-0.026) | 1.000 (+0.000) | 0.877 (+0.005) | 0.589 (+0.046) | 0.679 (+0.036) | 0.924 (+0.009) | +0.005 |
| best=C_S1_no_zero9_RF | volume4 | 0.929 (+0.060) | 0.456 (+0.108) | 1.000 (+0.000) | 0.520 (+0.361) | 0.449 (+0.186) | 0.652 (+0.063) | 0.865 (+0.067) | +0.361 |

Share of held-out feature values outside the fold-training range / beyond 6 training SD (per day):

| features | 02-14 | 02-15 | 02-20 | 02-21 | 02-22 | 02-28 | 03-02 |
|---|---|---|---|---|---|---|---|
| HGB_stacked(current) (outside range) | 0.00% | 0.00% | 0.00% | 1.22% | 0.00% | 0.00% | 0.05% |
| HGB_stacked(current) (> 6 SD) | 0.01% | 0.02% | 0.22% | 2.47% | 0.07% | 0.15% | 0.06% |
| best=C_S1_no_zero9_RF (outside range) | 0.00% | 0.00% | 0.00% | 1.57% | 0.00% | 0.00% | 0.06% |
| best=C_S1_no_zero9_RF (> 6 SD) | 0.02% | 0.02% | 0.28% | 3.17% | 0.10% | 0.19% | 0.07% |
| raw 41 last-window features, Transformer-scaler analogue (> 6 SD) | 0.01% | 0.01% | 0.29% | 2.49% | 0.04% | 0.04% | 0.02% |

Clean re-score check (max abs difference to the stored OOF score): HGB_stacked(current) 3.0e-08, best=C_S1_no_zero9_RF 3.0e-08

### Export and secondary cross-dataset (zero-shot, not used for selection)

Best non-anchor arm **C_S1_no_zero9_RF** (variant S1_no_zero9, family RF), configuration chosen by the full 7-day inner LODO: `{"min_samples_leaf": 5, "class_weight": null}`; 1% day-balanced FPR threshold from the inner OOF scores 0.4800; export `checkpoints_baselines_v5\final\C_S1_no_zero9_RF.npz`; numpy-vs-sklearn max abs difference on 5,000 rows 2.2e-16.

| dataset (sequences / positive) | score | pooled sequence AUROC | unit-balanced (scenario,ip) | unit-balanced (ip) | host-mean AUROC (hosts / positive hosts) |
|---|---|---|---|---|---|
| CTU-13 (355302 / 21066) | flow_count | 0.488 | 0.724 | 0.871 | 0.907 (311 / 10) |
| CTU-13 (355302 / 21066) | HGB_stacked(current) | 0.278 | 0.615 | 0.529 | 0.792 (311 / 10) |
| CTU-13 (355302 / 21066) | candidate=C_S1_no_zero9_RF | 0.241 | 0.453 | 0.210 | 0.205 (311 / 10) |
| CTU-13 (355302 / 21066) | S3_log default HGB (post-hoc) | 0.398 | 0.647 | 0.739 | 0.850 (311 / 10) |
| UNSW-NB15 (96299 / 9997) | flow_count | 0.292 | 0.229 | 0.229 | 0.500 (19 / 4) |
| UNSW-NB15 (96299 / 9997) | HGB_stacked(current) | 0.081 | 0.082 | 0.082 | 0.067 (19 / 4) |
| UNSW-NB15 (96299 / 9997) | candidate=C_S1_no_zero9_RF | 0.142 | 0.113 | 0.113 | 0.000 (19 / 4) |
| UNSW-NB15 (96299 / 9997) | S3_log default HGB (post-hoc) | 0.013 | 0.037 | 0.037 | 0.100 (19 / 4) |
| CIC-2017 60s (41713 / 901) | flow_count | 0.710 | 0.898 | 0.898 | 0.995 (473 / 10) |
| CIC-2017 60s (41713 / 901) | HGB_stacked(current) | 0.784 | 0.854 | 0.854 | 0.984 (473 / 10) |
| CIC-2017 60s (41713 / 901) | candidate=C_S1_no_zero9_RF | 0.714 | 0.842 | 0.842 | 0.989 (473 / 10) |
| CIC-2017 60s (41713 / 901) | S3_log default HGB (post-hoc) | 0.844 | 0.939 | 0.939 | 0.995 (473 / 10) |
