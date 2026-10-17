# 16 - Diagnosis and improvement plan

**Written 2026-10-17** on branch `test/session-2026-10-10` (base `87f88af`, nothing committed). Inference and small CPU diagnostic fits
only. No checkpoint, `data/processed*`, config or pipeline code was modified; scalers were loaded with `FeatureScaler.load` and never
re-fit into an existing directory (`models.dataset.build_datasets` overwrites `scaler.npz`, so it was not called). Code:
`eval/diagnostics/` (`core.py` reusable and tested by `tests/test_diagnostics_core.py`; `exp1_*` ... `exp14_*` are the experiment scripts
and `harness.py` their loader). Raw outputs: `docs/diagnostics16/` (CSV/JSON) and `docs/diagnostics16/logs/` (full console output of every
experiment). Section 0 was written before any number was computed and is kept verbatim; the exploratory additions made after the first results are
listed separately in section 0b, and the scorecard in section 2 (F10) reports how each hypothesis fared.

**Anchor.** The harness reproduces the existing numbers before anything else is read from it: seed 1 = 0.8003 on the v2 test (7,191
sequences) and 0.155 on CTU-13 contiguous (docs/15), and the six joint_v3 pooled AUROCs of docs/15 section 3.1.

## 0. Pre-registered hypotheses and arms (written before computing)

Rules for every experiment here: inference or small CPU/GPU diagnostic fits only; scalers are loaded with
`FeatureScaler.load` and never re-fit into an existing directory (`models.dataset.build_datasets` overwrites
`processed_dir/scaler.npz`, so it is NOT called); no existing checkpoint, `data/processed*`, config or pipeline is modified;
nothing is selected on the CIC-2018 test split (it is used for diagnosis, reported per day, never to choose a model, threshold or seed);
the harness is first anchored by reproducing seed 1 = 0.8003 AUROC on the v2 test and 0.155 on CTU-13 contiguous (docs/15).

| ID | Hypothesis | What would refute it |
|---|---|---|
| H1 | The pooled AUROC on val/test is dominated by a between-day offset (3 test days = 3 pseudo-hosts with positive rates 0.615 / 0.077 / 0.274; val 0.10 / 0.05), so pooled val AUROC (0.34-0.64) and pooled test AUROC (0.75-0.82) can differ for reasons unrelated to within-day ranking. | Within-day AUROCs are as low/high as the pooled ones and day-mean-score AUROC is near 0.5. |
| H2 | The CTU-13/UNSW inversion is a feature-sign flip: volume/rate and graph/has_ip features that mean "attack" on CIC-2018 have the opposite or no sign on CTU-13/UNSW (botnet and background hosts there are low volume), and the model's scores correlate with flow volume. | Univariate feature signs agree across datasets and counterfactually neutralising volume / has_ip / graph features does not move CTU/UNSW AUROC. |
| H3 | Val loss bottoms at epoch 1-3 because the checkpoint criterion is `mse + ce + bce` over 41 standardized features and the MSE (dynamics) term on out-of-scale pseudo-host aggregates dominates the rise, not the detection term. | The BCE term rises as fast as the MSE term. |
| H4 | A zero-training score (last-window flow_count) already ranks well on CIC-2018 (volume shortcut) and inverts on CTU-13; a tabular GBT or LR on last-window features matches or beats the Transformer on held-out data. | The Transformer beats LR/HGB on the same splits by more than the between-seed spread. |
| H5 | Label noise at the published 7% error scale caps attainable AUROC only modestly (a few AUROC points) at these base rates; noise is not what limits the numbers. | A simulated flip at that rate lowers a perfect-ranker AUROC by more than ~0.1. |
| H6 | The number of independent units is tiny (test 3 days / 12 episodes; val 2 days), so the minimum detectable AUROC difference is of the order 0.1 and the early-warning rate cannot be bounded below ~25%. | A bootstrap over days/episodes gives intervals narrower than +/-0.05. |

Arms for H4 (fixed before any run; default hyperparameters, no tuning): `score = last-window flow_count`, `score = last-window
total_bytes`; sklearn `LogisticRegression` (max_iter 1000, on standardized last window), sklearn `HistGradientBoostingClassifier`
(max_iter 200, early_stopping False, other defaults) on last-window features; persistence (label oracle, not deployable) as an upper
reference. Training sets: (a) CIC-2018 v2-converged train (day-disjoint, the seed 1 train set, subsampled stratified for speed where
stated) and (b) the contiguous B train (`cic18c_v3`). Evaluated on v2 test (pooled and per day), val, CTU-13 contig, UNSW contig,
CIC-2017 60 s (no Monday). Leave-one-day-out HGB over the CIC-2018 days gives the per-day spread.

### 0b. Exploratory additions made after the first results (not pre-registered)

Added: LR on log1p-transformed count features
and a variant of every trained baseline without the identity-like features (`noident`); an HGB on stacked history features (last
window, mean, std, 1-step and 6-step deltas, max over the 12 windows) so the baseline is not denied the history the Transformer sees;
mean-ablation counterfactuals; unit-balanced and host-mean AUROC and the subnet-restricted CTU negatives; the 7-model score average; the `wc -l` row count of all CIC-2018 files.

## 1. Summary

1. **The headline 0.80 is a one-day result.** Pooled test AUROC (seed 1: 0.800) = 0.989 on the 02-16 DoS day (483 sequences), **0.500 on
   02-23** and 0.778 on 03-01. Every one of the 7 trained models is at 0.50-0.53 on 02-23 (8 of the 12 test onset episodes), 0.95-0.99 on 02-16,
   0.78-0.85 on 03-01. Scoring each sequence by its *day's mean score* (a score that is constant within each day) already gives **0.715**.
2. **The cause is the data/label definition, not the network.** 9 of the 10 CIC-2018 days are one network-wide pseudo-host, and a 10 s window
   is positive if it contains *any* attack-labelled flow. On 02-22 and 02-23 a positive window holds a median of **2 attack flows out of ~250**
   (60% / 71% of positive windows have 2 or fewer, 100% are under 5% of the window's flows). Aggregated features cannot see that, and even the
   label oracle "persistence" only reaches 0.61 (02-23) / 0.68 (02-22) there versus 0.99-1.00 on the volumetric days.
3. **A plain gradient-boosted tree matches the Transformer within noise, and a zero-training score beats both on validation.** HGB on the last
   window: 0.76-0.78 pooled test (Transformers 0.77-0.82); flow_count alone: **0.735 on val (best of all models, all of which are 0.34-0.69)**,
   0.99 on 02-16. The Transformer wins on 03-01 (0.78-0.85 vs 0.67-0.76); the trees win on 02-23 (0.57-0.60 vs 0.50-0.52); none of these is distinguishable
   from noise with 3 days.
4. **Seed 1 is a volume shortcut; the CTU/UNSW "inversion" depends on how hosts are weighted, plus a sign flip of volume on UNSW.** Setting `flow_count`
   to its train mean takes seed 1 on 02-16 from 0.989 to **0.078**. On UNSW attack windows have *less* volume (univariate AUROC of total_packets 0.05,
   total_bytes 0.10), so any volume-using model inverts there. On CTU-13 the same seed-1 scores give **0.155 sequence-weighted, 0.61 with every
   (scenario, IP) series weighted equally, 0.84 as a host-mean AUROC [0.79-0.89], and 0.50-0.65 when the negatives are restricted to the bots' own subnet**; the six
   retrained models give 0.11-0.30 / 0.47-0.56 / 0.48-0.60 / 0.37-0.50. With about 10 bot IPs (CTU) and 4 attackers (UNSW) the supportable statement is "sign and size depend
   on weighting; no consistent above-chance transfer", not "inverted".
5. **Validation cannot do model selection here, and the val-loss rise is the detection heads, not the dynamics head.** Between best-val and
   final checkpoints MSE *falls* (0.224 to 0.205 for seed 1) while CE rises x1.2-1.6 and BCE x1.5-2.1. Across the 7 selected checkpoints val loss vs test AUROC has
   Spearman 0.18 (p = 0.70), and over all 14 best+final checkpoints pooled val AUROC vs pooled test AUROC has Spearman 0.05; val AUROC of one day (02-15) ranges **0.23-0.69 across the 7 models**, while
   the test per-day SD across models is 0.01-0.03. The early checkpoint is nevertheless the better one on test in 7 of 7 models (diagnostic only).

## 2. Findings

Confidence: **high** = reproduced two ways or a direct count; **medium** = one experiment with an obvious alternative; **low** = suggestive.

### F1. Pooled AUROC is a between-day artefact plus one easy day (confidence: high)

Experiment `exp1_perday` (all 7 models, best and final checkpoints; `docs/diagnostics16/exp1_perday.json`). AUROC pooled, within each day,
and with every score replaced by its day's mean ("day-constant"; carries no within-day information).

| model (best ckpt) | pooled test | day-constant | 02-16 (n=483, 61.5% pos) | 02-23 (n=3,318, 7.7%) | 03-01 (n=3,390, 27.4%) |
|---|---|---|---|---|---|
| seed1 (served) | 0.800 | 0.715 | 0.989 | 0.500 | 0.778 |
| B s1 | 0.786 | 0.715 | 0.972 | 0.515 | 0.797 |
| B s2 | 0.774 | 0.715 | 0.962 | 0.525 | 0.840 |
| B s3 | 0.820 | 0.715 | 0.953 | 0.502 | 0.827 |
| B+ s1 | 0.765 | 0.715 | 0.956 | 0.504 | 0.829 |
| B+ s2 | 0.810 | 0.715 | 0.983 | 0.512 | 0.811 |
| B+ s3 | 0.807 | 0.715 | 0.956 | 0.515 | 0.850 |
| ensemble (mean of 7 scores, `exp14`) | 0.801 | 0.715 | 0.974 | 0.516 | 0.822 |
| baseline: HGB on last window (train A / B) | 0.759 / 0.782 | - | 0.962 / 0.988 | 0.593 / 0.571 | 0.706 / 0.702 |
| baseline: HGB on stacked history (train A / B) | 0.764 / 0.778 | - | 0.988 / 0.994 | 0.574 / 0.585 | 0.745 / 0.761 |
| zero-training: flow_count | 0.524 | - | 0.992 | 0.516 | 0.621 |
| **oracle: persistence of the current label (not deployable)** | 0.941 | - | 0.992 | **0.614** | 0.999 |

Reading: (i) 0.715 of the 0.80 comes from a score that is constant within each day (the day's mean score): the days differ in base rate (0.615 / 0.077 / 0.274) and the models
give the high-rate day higher scores - that between-day ordering is itself learned, so this is the part of the pooled number that is not within-day ranking; the mean of the three within-day AUROCs is 0.755 for seed 1. (ii) The models agree with each other to
+/-0.01-0.03 on every test day, so the test set is stable; what varies is which *day* is easy. (iii) 02-23 is at chance for every model; even the label oracle reaches only 0.614. The day-constant value is identical for all models because it depends only on the ordering of the three days by mean score (02-16 > 03-01 > 02-23, the same as their base rates). **The validation days behave differently**: 02-15 per-model AUROC is 0.69 / 0.26 / 0.32 / 0.41 / 0.36 / 0.23 / 0.41
(seed1, B s1-3, B+ s1-3), 02-22 is 0.48-0.66; this is why val AUROC 0.34-0.64 does not predict test 0.75-0.82 (F5).

### F2. 8 of 12 test episodes (and 9 of 14 on val) are 1-2-flow flicker that no aggregate feature can see (confidence: high)

Experiment `exp9_label_dilution`: for each raw CIC-2018 file, attack flows per positive 10 s window (same windowing as the pipeline).

| day (role) | attack flows / all flows | positive windows | attack flows per positive window (median) | positive windows with <= 2 attack flows | attack share of window flows, median | persistence-oracle AUROC |
|---|---|---|---|---|---|---|
| 02-15 (val, GoldenEye/Slowloris) | 5.0% | 341 | 37 | 1% | 11.6% | 0.992 |
| 02-16 (test, Hulk/SlowHTTPTest) | 57.4% | 297 | 640 | 0% | 100% | 0.992 |
| **02-22 (val, brute-force web/XSS/SQLi)** | 0.035% | 164 | **2** | **60%** | 0.7% | 0.678 |
| **02-23 (test, same family)** | 0.054% | 258 | **2** | **71%** | 0.8% | 0.614 |
| 02-28 (train, infiltration) | 11.2% | 798 | 52 | 0% | 38.9% | 0.999 |
| 03-01 (test, infiltration) | 28.1% | 930 | 50 | 0% | 75.0% | 0.999 |

The whole 02-23 day contains 566 attack flows among 1,048,575. Because the unit being predicted is "is any flow in the next 10 s an attack flow" on a
network-wide aggregate of ~250 flows, a positive window on the web-attack days differs from a benign one by one or two flows. Consequences:
the 8 "episodes" on 02-23 (and 9 on 02-22) are built from windows with a median of 2 attack flows (99% have 5 or fewer), early warning of them is not a learnable target from these features, and the
oracle's 0.61-0.68 shows the label is only weakly persistent in time there. Whether those flows are real attacks or label noise cannot be settled
from labels alone (F7).

Side finding (high confidence for the counts, medium for the cause): `wc -l` on all 10 raw CIC-2018 flow files shows **7 of 10 have exactly 1,048,576 lines (header + 1,048,575 rows)**:
02-14, 02-15, 02-16, 02-21, 02-22, 02-23 and 03-02; only 02-20 (7,948,749 lines), 02-28 (613k rows) and 03-01 (331k rows) are below that. 1,048,576 is a spreadsheet's row limit, so these
seven days are probably truncated prefixes of the real day; the 02-16 file ends after 500 windows (about 83 minutes), which is why the 02-16 test day has only 483 sequences, and 02-21 has only 620.
The cause was not verified against the dataset owner or the PCAPs. It means that 6 of the 9 pseudo-host days used in train/val/test are slices of unknown extent.

### F3. Seed 1 learned "volume = attack"; the six retrained models learned something else but get the same ranking (confidence: high for seed 1, medium for B)

Experiment `exp11_perday_ablation` (mean-ablation: a feature set to the model's own train mean in all 12 steps; diagnostic, not a recommendation).

| model | none | flow_count | unique_dst_ports | flow_count + unique_dst_ports | duration + IAT group |
|---|---|---|---|---|---|
| seed1 pooled / 02-16 / 02-23 / 03-01 | 0.800 / 0.989 / 0.500 / 0.778 | 0.607 / **0.078** / 0.467 / 0.699 | 0.589 / 0.989 / 0.494 / 0.678 | 0.372 / 0.078 / 0.453 / 0.455 | 0.570 / 0.988 / 0.493 / 0.714 |
| B s3 pooled / 02-16 / 02-23 / 03-01 | 0.820 / 0.953 / 0.502 / 0.827 | 0.822 / 0.964 / 0.472 / 0.822 | 0.762 / 0.965 / 0.510 / 0.822 | 0.823 / 0.952 / 0.483 / 0.810 | 0.610 / 0.938 / 0.474 / 0.729 |

* Seed 1's 02-16 detection is a function of `flow_count` alone (0.989 to 0.078). On 02-16 the benign background is a median of 1 flow per window versus 640 in
  attack windows, so any monotone function of flow_count solves that day (raw flow_count: 0.992).
* The seed-1 scaler is fit on a train set that is **99.2% one day** (02-20: 1,228,717 of 1,239,090 sequences, 0.30% positive, per-host windows with a median of 2
  flows). On the pseudo-host test days `flow_count` has mean z = +3.7 (val +3.4; 02-16 **+24**) and 7.6% of test / 11.3% of val / **34.4% of 02-16** values
  exceed the +/-6 clip (`psh_ratio`: 59% on 02-16). The B scaler (70k of 02-20 plus 10k pseudo-host sequences) clips under 0.5% except 4% on 02-16, and the B
  models score the same (pooled 0.79 +/- 0.02), so scaler saturation is a serving risk, not what limits accuracy.
* The B family does not use flow_count (ablation changes nothing: B s3 0.820 to 0.822) and instead depends on the duration/IAT features (pooled 0.82 to 0.61,
  mostly through 03-01 0.827 to 0.729 and through the between-day offset). `has_ip_data` is set to 0 in 100% of val/test windows; replacing it by the train mean
  lowers pooled test AUROC by 0.07-0.09 (seed 1 0.800 to 0.729; B s3 0.820 to 0.733; B+ s1 0.765 to 0.699), i.e. the model uses "pseudo-host day" as an attack prior
  (in B's train, has_ip_data = 0 sequences are 42% positive versus 5% for has_ip_data = 1; docs/15).

### F4. The CTU-13 / UNSW "inversion" (confidence: medium-high; mechanism decomposed)

Experiments `exp2_univariate`, `exp2b_scores`, `exp3_ablate`, `exp4_shift`, `exp5_ctu_unsw_weighting`, `exp12_weighting`.

**(a) Scores sit in a regime nobody calibrated.** Median seed-1 score is 0.001 (CTU) and 0.000 (UNSW); only 0.8% / 1.3% of sequences reach 0.40. The AUROC there ranks values
between 1e-4 and 1e-2; no training signal ever shaped that range.

**(b) Feature signs differ by dataset** (univariate AUROC of the last window against the t+1 label; 0.5 = no information; full table `univariate.csv`):

| feature | CIC 02-20 train (99% of seed-1 train) | CIC pseudo-host train days (10,373 seq) | CIC test 02-16 / 02-23 / 03-01 | CTU-13 | UNSW | CIC-2017 60 s |
|---|---|---|---|---|---|---|
| flow_count | 0.99 | 0.80 | 0.99 / 0.52 / 0.62 | 0.49 | **0.29** | 0.71 |
| total_packets | 0.98 | 0.76 | 0.99 / 0.52 / 0.60 | 0.48 | **0.05** | 0.75 |
| total_bytes | 0.97 | 0.69 | **0.34** / 0.51 / 0.59 | 0.43 | **0.10** | 0.75 |
| mean_duration | 0.78 | 0.30 | 0.05 / 0.44 / 0.39 | 0.79 | 0.66 | 0.70 |
| tcp_ratio | 0.59 | 0.67 | 0.74 / 0.49 / 0.47 | **0.87** | 0.58 | 0.48 |
| unique_dst_ips | 0.33 | 0.50 (constant) | 0.50 (constant) | 0.71 | **0.03** | 0.55 |
| graph_fan_out_ratio | **0.00** | 0.50 (constant) | 0.50 (constant) | 0.66 | 0.47 | 0.30 |

The sign of the volume features is the same on 02-20 and CTU/UNSW only for CTU (no signal); on UNSW attack windows carry *less* traffic than benign ones (the attacker
hosts 175.45.176.x are low-rate generators; the benign 59.166.0.x hosts are high-volume), so anything that learned "more volume = attack" ranks UNSW backwards.
`mean_duration` flips sign between 02-20 (0.78) and the pseudo-host train days (0.30), the same flip that makes the B models invert on val 02-15 (slow DoS: GoldenEye/Slowloris).
`graph_fan_out_ratio`/`graph_fan_in_ratio` separate the 02-20 attackers perfectly (AUROC 0.00 / 0.01) and are *constant zero* on every pseudo-host day, so they are
identifiers of one day's DDoS source IPs, not behaviour.

**(c) Counterfactuals** (mean-ablation, `ablate_*.csv`, `exp5_ctu_unsw_weighting.log`; seed 1):

| ablated | CTU-13 | UNSW | CIC-2017 | CIC test |
|---|---|---|---|---|
| none | 0.155 | 0.454 | 0.690 | 0.800 |
| volume (flow_count, packets, bytes) | 0.147 | 0.420 | 0.622 | 0.598 |
| has_ip_data | 0.157 | 0.450 | 0.690 | 0.729 |
| graph + has_ip + unique_dst_ips + graph_embed | 0.292 | 0.316 | 0.568 | 0.595 |
| tcp_ratio + udp_ratio | 0.366 | 0.510 | 0.677 | 0.757 |
| identity group + proto | 0.587 | 0.244 | - | - |
| every feature group (sanity: must be 0.5) | 0.495 | 0.525 | - | - |

For CTU volume is not the mechanism (0.155 to 0.147); the driver is protocol mix and the identity/graph group (0.155 to 0.587 together). CTU has tcp_ratio z = -2.1 and
udp_ratio z = +2.2 against the seed-1 train, `mean_duration` z = +4.6 (11.7% of values clipped), 18 of its 41 features are exactly zero (6 flag ratios, 3 IAT, 9 packet) and
UNSW has 13 (psh, urg, var_iat, max_iat, 9 packet). The B models' good UNSW numbers (0.92-0.97) vanish when the TCP-flag ratios are ablated (B s3 0.968 to 0.462, B+ s1 0.920 to 0.501;
`fin_ratio` alone: 0.968 to 0.714): they rest on UNSW's FIN/SYN/ACK ratios (univariate 0.77-0.78), which differ between its generators, not on attack dynamics.

**(d) The CTU/UNSW numbers change sign with the weighting, and with about 10 and 4 positive hosts none of them is a robust statement.**
Unit = (scenario, IP) for CTU, IP for UNSW (`weighting.csv`, `ctu_negatives.csv`, `logs/exp5_*`, `logs/exp15_*`). "Host-mean" is the AUROC of the mean score per host.

| model | CTU seq-weighted | CTU unit-balanced | CTU host-mean (by IP) [host bootstrap] | CTU, negatives restricted to the bots' subnet 147.32.84.x: seq / unit-balanced / unit-mean | CTU without the 3 largest positive series | UNSW seq / unit-balanced |
|---|---|---|---|---|---|---|
| seed1 | 0.155 | 0.611 | **0.842** [0.788-0.888] | 0.126 / 0.497 / 0.645 | 0.290 | 0.454 / 0.338 |
| B s1 / s2 / s3 | 0.240 / 0.144 / 0.162 | 0.473 / 0.560 / 0.554 | B s3 0.477 [0.392-0.562] | seq 0.31 / 0.18 / 0.21; unit-balanced 0.41 / 0.41 / 0.48; unit-mean 0.46 / 0.44 / 0.50 | 0.189 / 0.250 / 0.190 | seq 0.967 / 0.561 / 0.968; unit-balanced 0.694 / 0.406 / 0.685 |
| B+ s1 / s2 / s3 | 0.117 / 0.299 / 0.113 | 0.527 / 0.513 / 0.559 | B+ s1 0.513 [0.452-0.582] | seq 0.12 / 0.44 / 0.12; unit-balanced 0.37 / 0.44 / 0.45; unit-mean 0.39 / 0.49 / 0.46 | 0.184 / 0.222 / 0.169 | seq 0.920 / 0.636 / 0.940; unit-balanced 0.665 / 0.451 / 0.680 |

* CTU has 29 positive (scenario, IP) series (10 distinct bot IPs) against 592 negative series, 195 of them inside the bots' own subnet; the 3 largest positive series, all the same bot (147.32.84.165 in scenarios 13, 3, 1), hold 58% of the 21,066
  positive sequences. Removing those three does **not** repair the ranking (0.17-0.29), so a few long bot series are not the whole story; what changes the number is how the *negatives* are weighted: 301 external hosts with 1-12 sequences each count
  as much as the busy ones under unit weighting.
* The seed-1 host-mean advantage (0.842 on CTU, and 0.976 [0.959-0.992] on CIC-2017 with 10 positive hosts of 473) is plausibly a confound of host type - the positives are busy internal hosts and most negatives are sporadic external ones - because restricting
  the negatives to the bots' own subnet takes seed 1 to 0.645 (unit-mean) and 0.497 (unit-balanced) and the other six models to 0.37-0.50. This confound is the likely reading, not a demonstrated one (the ">= smallest positive series" filter in `exp15` is vacuous: the smallest
  positive series has 1 sequence).
* UNSW has **4 attacker hosts** against 15 benign-only hosts (19 in total): the sequence-level 0.97 and the unit-balanced 0.69 are both statements about 60 attacker/benign host pairs (Hanley-McNeil MDE vs chance at 4/15: 0.47), and the same recipe ranges from 0.56 to 0.97 across seeds.
  Trivial models trained on CIC-2018 swing across the same range (CTU 0.33-0.83, UNSW 0.14-0.58 depending on feature subset and train set - `baselines.csv`).
* **Supported statement: the sign and size of cross-dataset AUROC depend on how hosts are weighted; with 10 and 4 positive hosts there is no evidence of consistent above-chance transfer and none of consistent inversion.** The one robust mechanism
  is the volume sign flip on UNSW (item b), not "inversion" in general.

### F5. Why validation loss bottoms at epoch 1-3 and why val does not track test (confidence: high for the decomposition, medium for the cause)

Experiment `exp1_perday` (val loss recomputed per term for the best and final checkpoint of all 7 models).

| model | val MSE best / final | val CE best / final | val BCE best / final | test AUROC best / final |
|---|---|---|---|---|
| seed1 | 0.224 / 0.205 | 0.258 / 0.349 | 0.286 / 0.436 | 0.800 / 0.754 |
| B s1 | 0.081 / 0.072 | 0.241 / 0.383 | 0.381 / 0.707 | 0.786 / 0.732 |
| B s2 | 0.097 / 0.072 | 0.223 / 0.297 | 0.331 / 0.649 | 0.774 / 0.711 |
| B s3 | 0.088 / 0.072 | 0.235 / 0.360 | 0.325 / 0.536 | 0.820 / 0.735 |
| B+ s1 | 0.088 / 0.070 | 0.240 / 0.346 | 0.308 / 0.598 | 0.765 / 0.720 |
| B+ s2 | 0.088 / 0.072 | 0.238 / 0.286 | 0.371 / 0.728 | 0.810 / 0.639 |
| B+ s3 | 0.091 / 0.069 | 0.241 / 0.361 | 0.323 / 0.668 | 0.807 / 0.652 |

* The dynamics (MSE) term keeps improving; **the rise is entirely in CE (x1.2-1.6) and BCE (x1.5-2.1)**: the heads become over-confident on the 4 pseudo-host training days
  (10,373 sequences of 1.24M for seed 1, 9,947 of 80,243 for B) and on the single real-IP day. H3 (MSE drives the rise) is refuted.
* Overconfidence hurts ranking too: **test AUROC is lower at the final checkpoint in 7 of 7 models** (by 0.05-0.17), so early stopping is directionally right. This is a
  diagnostic on the test set and must not be used to choose an epoch.
* Val cannot rank checkpoints across seeds: over the 7 selected checkpoints val total loss vs test pooled AUROC has Spearman 0.18 (p = 0.70); pooled val AUROC vs pooled test
  AUROC 0.05 and mean within-day val vs test AUROC -0.25 (both over the 14 best+final checkpoints).
* Val composition: 2 days = 2 independent series, 14 onset episodes (5 on 02-15, 9 on 02-22). 02-15 is a *slow* DoS (GoldenEye/Slowloris; `mean_duration` AUROC 0.73 where it was
  0.30 in train) so models trained on flood-type DoS invert on it (0.23-0.41 for six models), seed 1 does not (0.69, volume); 02-22 is the sparse web-attack day (oracle 0.68). Neither
  is representative of the test mix (one flood day, one sparse day, one infiltration day), and positive rate differs (7.6% vs 20.6%).
* Calibration is day-specific and stays off after the fact: seed 1 mean score vs observed rate on val 0.119/0.10 and 0.034/0.05, but on test 0.594/0.615, 0.029/0.077, **0.094/0.274**.
  A threshold fitted on val (0.397 for 5% false alarms) will not carry to a day with a different attack mix.

### F6. Trivial and tabular baselines (confidence: high for parity; medium for "better")

Experiments `exp6_baselines`, `exp7_lodo_hgb`, `exp10_calib_stack` (hyperparameters fixed in section 0; no tuning). Numbers are AUROC; pooled test / per test day.

| score | trained on | val pooled (02-15 / 02-22) | test pooled | 02-16 | 02-23 | 03-01 | CTU | UNSW | CIC-17 |
|---|---|---|---|---|---|---|---|---|---|
| Transformer, 7 models | seed1 train or B/B+ | 0.34-0.64 (0.23-0.69 / 0.48-0.66) | 0.765-0.820 | 0.95-0.99 | 0.50-0.53 | 0.78-0.85 | 0.11-0.30 | 0.45-0.97 | 0.36-0.69 |
| HGB, last window | seed1 train (sub) | 0.489 (0.47 / 0.48) | 0.759 | 0.962 | 0.593 | 0.706 | 0.345 | 0.578 | 0.772 |
| HGB, last window | B train | 0.522 | 0.782 | 0.988 | 0.571 | 0.702 | 0.396 | 0.469 | 0.552 |
| HGB, stacked history | seed1 train (sub) / B | 0.474 / 0.483 | 0.764 / 0.778 | 0.988 / 0.994 | 0.574 / 0.585 | 0.745 / 0.761 | 0.348 / 0.688 | 0.019 / 0.072 | 0.793 / 0.708 |
| LR, last window | seed1 train (sub) / B | 0.611 / 0.614 | 0.666 / 0.645 | 0.990 / 0.989 | 0.565 / 0.554 | 0.601 / 0.605 | 0.456 / 0.332 | 0.448 / 0.542 | 0.670 / 0.692 |
| zero-training: flow_count | none | **0.735** (0.80 / 0.60) | 0.524 | 0.992 | 0.516 | 0.621 | 0.488 | 0.292 | 0.710 |
| zero-training: total_packets | none | 0.682 | 0.431 | 0.988 | 0.518 | 0.601 | 0.476 | 0.048 | 0.750 |
| oracle persistence (label) | n/a | 0.893 (0.99 / 0.68) | 0.941 | 0.992 | 0.614 | 0.999 | 1.000 | 0.990 | 0.914 |

Reading: the Transformer is not better than a default gradient-boosted tree on pooled test (0.77-0.82 vs 0.76-0.78; the paired seed-to-seed SD is 0.024), wins 03-01 by
0.05-0.15, loses 02-23 by 0.05-0.08; none of these differences is separable with 3 days (section 2, F9). On validation *every* trained model, including the Transformer, is
worse than the one-line `flow_count` score. The oracle table also bounds what is reachable: 02-22/02-23 cannot exceed about 0.6-0.7 for a model that knows the current label.

**Leave-one-day-out HGB over all 10 CIC-2018 days** (train on the other 9; 02-20 evaluated on a 200k-sequence sample): 

| held-out day | 02-14 | 02-15 | 02-16 | 02-20 | 02-21 | 02-22 | 02-23 | 02-28 | 03-01 | 03-02 |
|---|---|---|---|---|---|---|---|---|---|---|
| HGB (all features) | 0.764 | 0.489 | 0.977 | 0.997 | 0.909 | 0.515 | 0.511 | 0.592 | 0.678 | 0.786 |
| flow_count alone | 0.944 | 0.801 | 0.992 | 0.989 | 0.963 | 0.604 | 0.516 | 0.640 | 0.621 | 0.740 |
| persistence oracle | 0.999 | 0.992 | 0.992 | n/a | 0.948 | 0.678 | 0.614 | 0.999 | 0.999 | 0.998 |

Mean 0.722, SD across days **0.195**: a held-out-day AUROC can be anything from 0.49 to 0.997. `flow_count` alone beats the all-features HGB on 7 of the 9 pseudo-host days (02-23 by only 0.005) and the `noident` HGB on 6 of 9. This SD is the
real size of the noise that a day-disjoint split with 2-3 test days has to live with.

### F7. Label quality (confidence: medium; simulation, not measurement)

* **No corrected-label files exist on disk.** `V:\Datasets` holds only the original CIC-2018 `TrafficForML_CICFlowMeter` CSVs (plus the same 02-23 file as `labels.csv`), the original CIC-2017
  `*.pcap_ISCX.csv`, UNSW-NB15 CSVs (with `NUSW-NB15_GT.csv`) and CTU-13; nothing named corrected, improved, relabelled, Engelen or Lanvin. The relabelling code (`GintsEngelen/CNS2022_Code`,
  docs/05, no licence) works from PCAPs plus their CICFlowMeter fork: feasible for CIC-2017 once the owner's PCAPs are complete; not feasible for CIC-2018 (37 GB/day, not downloaded).
* **Published rate** (as cited in docs/AUDIT.md, not re-verified here): about 6.7-7.5% label error on CIC-2018/2017 (Cantone et al.; Liu, Engelen et al. 2022 report the same order).
* **Simulation of the ceiling** (`exp13`, `units_mde_noise.json`): a *perfect* ranker, scored against labels flipped at random on the real val/test windows:

| assumed window-label noise | test (20.6% pos) | val (7.6% pos) |
|---|---|---|
| none | 1.000 | 1.000 |
| 7% flipped in both directions | 0.879 | 0.757 |
| 10% of positives lost, 1% of negatives gain a false positive | 0.967 | 0.937 |
| 2% / 5% of benign windows labelled attack | 0.965 / 0.920 | 0.902 / 0.811 |

  So at the published scale noise *could* cap measured AUROC at 0.76-0.88 (H5 refuted as pre-stated: more than 0.1), but only if it acts on windows symmetrically, which is not established.
  Two cautions: (1) the window label is an OR over ~250 flows, so a tiny flow-level false-attack rate is amplified: per-flow rate 5e-4 flips 11.8% of 250-flow benign windows, 1e-3 flips 22%
  (and 02-23's entire attack mass is 0.054% of flows, so a handful of stray labels is first-order); (2) the label noise is not what separates the days: the persistence oracle reads the same
  labels and scores 0.95-1.00 on 7 of the 9 pseudo-host days (0.61-0.68 on the other two). For 02-22/02-23 whether the isolated 1-2 flow windows are attacks or noise is unresolvable without PCAPs.

### F8. Feature set and windowing (confidence: high for counts, medium for consequences)

* **Constant features.** 9 packet-level features (`mean_ttl` ... `has_packet_features`) are exactly zero in every dataset used (CIC-2018, CTU, UNSW, CIC-2017). On the pseudo-host days that make
  up all val and test data **24 of 41 features are exactly constant** (the 9 above, `has_ip_data`, `unique_dst_ips`, 5 graph, 8 graph_embed). The effective input of every val/test sequence is 17 features
  per step, of which `tcp_ratio`/`udp_ratio` are collinear (r = -0.96 on pseudo days, -0.95 on 02-20). On 02-20, `unique_dst_ips` and `graph_out_degree` are identical (r = 1.00) and
  `mean_iat` ~ `graph_embed_2` (r = 0.92). `graph_embed_*` come from a frozen random-initialised encoder (config comment), so they add nothing learnable beyond an identity code.
* **Identity-like features that encourage shortcuts.** `has_ip_data` (day type), the 5 graph features and `graph_embed_*` exist only for 02-20 (and the external CTU/UNSW/CIC-2017 sets). In seed 1's train they are non-constant for
  99.2% of the sequences (02-20) and exactly zero for all 4,228 positives of the other four days, so "graph features present" means "02-20 mass" (99.7% benign) and their absence means "pseudo-host day" (41% positive).
* **10 s window and 120 s flow timeout.** Windows are keyed by flow *start*, and CICFlowMeter writes a flow when it ends or at the 120 s timeout. The share of windows whose mean flow duration is >= 10 s (flows that end after
  the window does) is 98% on 02-23, 77% on 03-01, 87% on val, 55% on the pseudo-host train days, 22% on 02-20. So the t window used to predict t+1 contains flows that, in a live deployment,
  would still be running; docs/11 already discloses live 30 s vs training 120 s as a skew. The offline "10 s ahead" number therefore uses a feature view that a causal deployment gets only 30-130 s later;
  it is optimistic by an unknown amount (not measured here).
* **Pseudo-host aggregation.** On 9 of 10 days one "host" is the whole network, so the task becomes "will any attack flow appear anywhere in the network in the next 10 s" - see F2.

### F9. Independent units and what the data can support (confidence: high for counts; medium for MDE)

Counts from `exp8_units_redundancy` (episodes = runs of positive windows merged when fewer than 6 benign windows separate them, docs/13 convention) and docs/13, docs/15.

| dataset | independent series | attack episodes | notes |
|---|---|---|---|
| CIC-2018, 10 days | 9 pseudo-host day-series + 1 real-IP day (6,810 hosts, 10 attacking) | 73 (02-20: 39; pseudo days: 2, 5, 2, 2, 2, 9, 2, 8, 2) | families: initial_access 3 days (2 sparse web), impact 4, infiltration 2, C2/bot 1 |
| CIC-2018 test | 3 series | 12 | docs/13 |
| CIC-2018 val | 2 series | 14 | |
| CTU-13 | 29 positive (scenario, IP) series, 10 bot IPs vs 592 negative series | n/a (labels constant per host) | |
| UNSW-NB15 | 4 attacker vs 15 benign-only hosts | n/a | |
| CIC-2017 (60 s, Tue-Fri) | 10 hosts with any attack of 473 | 15 on 9 hosts | |

* **AUROC detection floor.** Hanley-McNeil, 80% power, two-sided 5%, vs 0.5: with 12 positive / 12 negative independent units the smallest detectable AUROC gap is **0.34**
  (the true AUROC would have to be about 0.84 for 80% power; with 12/12 units an observed AUROC is significantly above 0.5 only if it exceeds about 0.74); 12/60: 0.26; CTU 10 hosts vs 301: 0.26; UNSW 4 vs 15: **0.47**; 50/50: 0.16; 200/200: 0.08.
* **Comparing two models** across test days (paired, observed seed-to-seed SD 0.024 per day): minimum detectable per-day AUROC difference **0.076 with 3 days, 0.041 with 5, 0.024 with 10, 0.016 with 20**.
  This ignores day-to-day heterogeneity of the true difference, so it is a floor; with the day-level SD of 0.195 seen in LODO the real-world number is larger.
* **Early warning.** 0/12 has an exact 95% upper bound 26.5% and 0/15 21.8%; 0/27 would give 12.8%. To exclude a true early rate of 30%, 9 independent episodes with zero events suffice; 25% needs 11;
  10% needs 29. To *show* a rate above 10% when the truth is 30%, 25 independent episodes are needed (80% power); to show above 20% when the truth is 50%, 17.
  The current 12 episodes sit on 3 pseudo-hosts of which 8 are the 02-23 flicker (F2), so the evidence available today is about as informative as ~5 independent episodes.

### F10. Hypothesis scorecard

| ID | Verdict | Evidence |
|---|---|---|
| H1 | **Confirmed** | day-constant AUROC 0.715; val per-model day AUROC range 0.23-0.69 vs test 0.01-0.03 SD (F1, F5) |
| H2 | **Partly**: sign flip confirmed for UNSW (total_packets 0.05); for CTU volume is not the cause (0.155 to 0.147) - protocol mix + identity features + series weighting are | F4 |
| H3 | **Refuted**: MSE falls, CE/BCE rise | F5 |
| H4 | **Mostly confirmed**: flow_count = 0.99 on 02-16, beats all models on val; it inverts on UNSW (0.29) but not on CTU (0.49); HGB within noise of the Transformer | F6 |
| H5 | **Refuted as stated** (symmetrical 7% noise caps at 0.88/0.76) but not the limiter on the sparse days | F7 |
| H6 | **Confirmed** | F9 |

## 3. Ranked plan of 12 actions

Ranking = expected effect on *credibility and real held-out performance* per unit of effort, with data dependencies respected. "Expected gain" is stated only as far as the diagnostics support it;
a "success test" is written to pass or fail on data never used to choose anything.

| # | Action | Expected gain | Effort | Risk | Data needed | Leakage-free success test |
|---|---|---|---|---|---|---|
| 1 | **Change the reporting.** Headline table = per-day (per-unit) AUROC/AUPRC with the persistence oracle and the flow_count / HGB rows beside the model; unit-balanced AUROC for CTU/UNSW; episode counts everywhere; retire pooled AUROC and sequence-level cross-dataset AUROC as headlines. Add the per-day table to README and docs/04 | Credibility; changes no model. Removes the 0.80-vs-0.755 ambiguity and the "0.97 on UNSW" claim | 0.5 day | None (only risk: the headline looks smaller) | Existing arrays | Re-running `eval.diagnostics.exp1_perday` + `exp12_weighting` reproduces every figure in the new table to 3 decimals |
| 2 | **Redesign validation: leave-one-day-out / day-grouped, family-aware.** 10 folds over the CIC-2018 days (02-20 split by host groups), score = mean within-day AUROC (and AUPRC) of out-of-fold predictions, report per-day spread; epoch / early-stop chosen by that, not by val loss; ensemble 3-5 seeds | Removes the 2-day val coin-flip (rank corr 0.18 now); the seed-spread SD 0.04 shrinks under averaging (7-model average: 0.801 pooled, 03-01 0.822 vs seed range 0.78-0.85) | 2 days code + ~1 h GPU/seed (80k+10k sequences, ~10 s/epoch) | Moderate: with 10 days, family-LODO folds leave C2 (1 day) with no training example | Existing data | Selection inside folds only; success = OOF within-day mean AUROC of the selected recipe beats the HGB-LODO mean (0.72) and flow_count by more than the paired MDE (0.04 at 5 days); then run once on a sealed set (#6/#7) |
| 3 | **Make "beat the tree and the one-liner" a gate.** Add HGB (last and stacked window), LR and flow_count to `eval/benchmark.py` output for every split; a Transformer claim needs a per-day gain over HGB larger than the MDE | If HGB >= Transformer (it is now), a smaller, faster, easier-to-explain model can ship; at minimum an ensemble (average Transformer + HGB scores) | 1 day | None | Existing | The same LODO folds as #2; paired per-day differences with a day-level bootstrap |
| 4 | **Remove shortcuts and dead features.** Drop the 9 always-zero packet features; drop `has_ip_data`, graph, graph_embed, `unique_dst_ips` for any model trained/evaluated on pseudo-host days (or train a separate per-host model on 02-20 only); log-transform volume features and fit the scaler per host-type; keep the old scheme as the comparison | No pooled-AUROC gain expected on the current test (the B family already shows scaling is not the limiter); removes the flow_count dependence (0.989 to 0.078 under ablation), the has_ip prior (-0.07 to -0.09) and the 34% clipping on 02-16 | 1-2 days | Low-moderate: ablating 24 constant features changes nothing on val/test by construction; the gain is on other networks | Existing | LODO as in #2: per-day AUROC no worse by more than the MDE; ablating flow_count moves 02-16 by < 0.05; clip rate < 1% on every day |
| 5 | **Pre-register secondary label definitions, do not replace the primary one.** Keep "any attack flow" as primary; add (a) window positive when attack flows >= 5 and >= 5% of flows, (b) flow-level detection for sparse application-layer attacks (web brute force/XSS/SQLi) where windows are the wrong unit, (c) forecasting evaluated only on sustained campaigns (>= 6 consecutive positive windows). Thresholds fixed from the attack-flow counts of the TRAIN days only | Separates "cannot see 2 flows in 250" from "cannot forecast"; makes 02-22/02-23 interpretable; aims to put the early-warning question on episodes that have a precursor | 2 days | Definition shopping: mitigated by registering the three definitions now, reporting all, and using the primary for headlines | Raw CIC-2018 CSVs (present) | Definitions and cut-offs fixed before looking at test; success = definitions (a)/(c) give per-day AUROC on volumetric days within +/-0.03 of primary (sanity) and a non-chance value on at least one previously-chance day, else report as unresolved |
| 6 | **CIC-2017 PCAP re-extraction at seconds resolution** (owner downloading) with the Engelen et al. flow fixes and corrected labels (check the repo's licence first; docs/05 says none): gives true 10 s windows on Tue-Fri, real per-host series (attacker 172.16.0.1, victims 192.168.10.x), 15 episodes, and removes the minute-timestamp blur | The first real per-host, multi-family, seconds-level set; unlocks a 2017-to-2018 cross-year test and a defensible joint model (docs/15 could not mix 60 s days) | 3-5 days compute + 2 days code; disk for flows only | Moderate: Engelen's pipeline is slow and licence-unclear; 9 attack hosts only | PCAPs (being downloaded; not touched here) | Train 2018 (+2017 Mon-Wed), test 2017 Thu-Fri day-disjoint; success = unit-balanced (host-level) AUROC lower bound > 0.5 at n = 9-10 hosts AND beats the HGB gate (#3) |
| 7 | **Record lab campaigns with known start times.** 20-30 scripted multi-stage episodes (recon, initial access, lateral movement, C2) over varied benign background, each with an independent timestamp log, PCAPs, and a held-out half | The only way to measure early warning: ground truth not derived from flow labels, no flicker, per-host series. 25 independent episodes is what a 10%-vs-30% early-rate claim needs; 17 for 20%-vs-50% | 1-2 weeks (design, run, label) | Moderate: lab traffic is easy and unlike production; state it as such | Own testbed; Velociraptor / Security Onion boxes if available | Alarm rule and threshold frozen on the training campaigns; success = early-warning rate on the held-out campaigns whose exact lower bound exceeds 10%, with false alarms per benign hour reported with a CI |
| 8 | **Per-network unlabeled normalisation + a common-feature subset for cross-dataset claims.** Standardise each network with statistics of its own first N hours of (unlabeled) traffic, restrict features to the ~13 that exist in every dataset (flow_count, unique_dst_ports, bytes, packets, mean_duration, tcp/udp ratio, bidir, ...), and test transfer at host level only | May turn the CTU/UNSW "inversion" into "uninformative", which is honest; real gain unproven (UNSW volume sign is a property of the generators) | 2-3 days | Moderate: may show no transfer at all | Existing CTU/UNSW/CIC-2017 arrays | Normalisation statistics from the target's own first hours only (no labels); success = unit-balanced AUROC lower CI > 0.5 on CTU (10 bot IPs) and UNSW (4 attackers) simultaneously; otherwise report "no transfer" |
| 9 | **Operating point and calibration without val tuning.** Choose the alert threshold from pooled out-of-fold predictions on benign-throughout sequences at a stated false-alarm budget per benign hour, report alarms/hour with a day-clustered CI; replace "0.40" by an alarm budget; add temperature/isotonic calibration fit on OOF data only; show score-vs-rate per day (now 0.094 vs 0.274 on 03-01) | Predictable false alarm rate; recall at fixed budget becomes a comparable number across models | 1 day (after #2) | Low | OOF predictions from #2 | Threshold from folds that exclude the evaluated day; success = realised alarms/hour on a held-out day within the CI of the target |
| 10 | **Use the real-IP day properly.** 02-20 has 6,810 hosts, 10 attackers, 39 episodes: run host-grouped CV (GroupKFold by `src_ip`) and report host-level AUROC / onset metrics there as a *separate* per-host benchmark; note it is DDoS-only | The only place with enough independent hosts for per-host forecasting statistics (10 attacking hosts is still small) | 1-2 days | Low-moderate: single family, single day | Existing | Folds by host with all of a host's windows together; success = held-out-host onset AUROC with a host-bootstrap CI above 0.5 |
| 11 | **Audit the CSV truncation and label provenance.** Seven of the ten CIC-2018 files stop at 1,048,575 rows; obtain full-day flow files or regenerate from PCAP slices for at least the three test/val days with the most weight (02-16, 02-22, 02-23); for 02-22/02-23 verify a sample of the 1-2 flow windows against PCAP; add a noise-sensitivity band (exp13 simulation) to every headline | Determines whether the chance days are signal-free or label-corrupt; may enlarge 02-16 from 483 sequences | 2-3 days | Low; PCAPs are huge (37 GB/day) | CIC-2018 PCAPs for 3 days or the full CSVs from the dataset owner | Compare rebuilt windows with the current ones before training anything; no model is trained on the new files until the audit is written up |
| 12 | **Causal windows.** Key windows by flow *end* time (or only completed flows) and use the live 30 s timeout in training (or 120 s in serving), so the 10 s-ahead claim is available at decision time; compare against the current view | Removes an unquantified optimism (77-98% of windows contain still-running flows); makes offline numbers equal to live numbers | 2-3 days | Moderate: changes every feature | Raw flow CSVs (present) | Re-extract, retrain recipe of #2, evaluate with LODO; success = per-day AUROC within the MDE of the non-causal view (then the optimism is bounded), otherwise report the lower number |

Items 1-5 need only data already on disk and should be done before any more training; 6, 7 and 11 are data acquisition that decides whether a forecasting claim can ever be supported.

## 4. Recommended next 1-2 weeks

Week 1 (all on existing data; owner-sized steps)
1. Day 1: action 1 (reporting) and action 3 (benchmark gate): add per-day columns, oracle, flow_count, HGB to the README/docs/04 tables; this is what the pitch needs.
2. Days 2-4: action 2 (LODO harness) with HGB first (minutes per fold), then the Transformer B recipe for 10 folds x 3 seeds (about 3 GPU-hours); lock the selection rule before running.
3. Day 3-4: action 5 (register the three label definitions in a doc before computing) and action 4 (feature hygiene run as an ablation arm inside the same LODO).
4. Day 5: action 9 on the OOF predictions; freeze the alarm budget and write it down.

Week 2
5. Action 11 audit of the truncated files (confirm with the dataset owner/PCAP slice) in parallel with the CIC-2017 PCAP download finishing.
6. Action 6 on CIC-2017: re-extract Monday-Wednesday first (day-disjoint, small), build the 10 s per-host dataset, run the same LODO harness, hold Thu-Fri sealed.
7. Action 7: design the campaign script list and the timestamp log format (even before recording) so it can be run when the lab is free.
8. Decision point at the end of week 2: if LODO says HGB >= Transformer, say so and put the Transformer's contribution as the explainability/rollout/world-model framing rather than a better detector.

## 5. What to say in the SIH pitch right now

Say (each line is backed by a measurement above):

* "We built an end-to-end, offline pipeline: flow and PCAP ingestion, windowing, a Transformer world model with a K-step rollout, MITRE stage mapping, explanations, a tamper-evident log and a live path." (not about accuracy)
* "On CIC-IDS-2018, on days the model never saw, it ranks next-10-second attack windows with AUROC 0.80 overall. We break that down by day because it is not uniform: 0.99 on a volumetric DoS day, 0.78 on an infiltration day, and chance (0.50) on a day whose attacks are 1-2 web requests among about 250 benign flows - where even an oracle that knows the current label reaches only 0.61."
* "A default gradient-boosted tree on the same features gets the same pooled number (0.76-0.78), so we do not claim the Transformer is a better detector; its value here is the forecasting/explanation framework."
* "The model is conservative: precision about 0.9, recall about 0.3 at the 0.5 threshold of docs/04 (docs/15 reports the same conservative profile)."
* "Early warning is not demonstrated: 0 of 12 test episodes were flagged before they began (exact 95% upper bound 26%), and 8 of those 12 are single-flow bursts that cannot be forecast from aggregate features. We are building the measurement that would settle it: seconds-resolution CIC-2017 PCAP re-extraction and recorded lab campaigns with known start times."
* "We found no consistent transfer across networks: on CTU-13 (about 10 bot hosts) and UNSW-NB15 (4 attackers) the AUROC changes sign with how hosts are weighted and with the training seed (UNSW 0.56-0.97), so we report it as unresolved rather than selecting a favourable seed."
* "We found and removed our own inflated numbers (a 0.92 F1 from a leaking split) and now report per-day results with the number of independent episodes beside every figure."

Do not say: "forecasts attacks 60 seconds ahead" (the 60 s rollout does not beat reusing step 1; docs/04 frozen-state); "early warning" or "lead time" as a result; "generalises to unseen attacks/datasets"; any single cross-dataset AUROC (UNSW 0.97, CTU 0.78, CTU 0.84 host-level, or CTU 0.15) without the host count (4 and about 10) and the weighting; "AUROC 0.80" without the per-day split; "detects 80% of attacks" (recall is 0.31 at threshold 0.5); "label-noise-free ground truth".

## 6. Limits and what was not verified

* Mean-ablation counterfactuals change the input distribution; they show *dependence*, not causal importance, and were not combined into any recommendation to flip scores. Gradient x input was not run; mean-ablation and per-feature univariate AUROC were used instead.
* The "host" in CIC-2018 val/test is one network-wide series per day; every day-level number has n = 1 series per day.
* The 02-20 real-IP day was evaluated only through HGB LODO (200k-sequence sample) and the univariate table; no Transformer was trained or re-trained anywhere in this work.
* The CIC-2018 test split was used for diagnosis (per day, best vs final, ablations). No decision rule above was fitted on it; the recommended selection rules are defined on out-of-fold data.
* Test coverage: `eval/diagnostics/core.py` (all statistics and the loader) is covered by `tests/test_diagnostics_core.py`; `harness.py` (model/scaler loading, cache building) and the `exp*` scripts are untested I/O scripts whose outputs are kept under `docs/diagnostics16/` for inspection.
* The CSV-truncation cause (spreadsheet row cap) is inferred from the row count alone. The published error rates (6.7-7.5%) are quoted from docs/AUDIT.md, not re-derived.
* HGB used scikit-learn's `HistGradientBoostingClassifier` with fixed defaults (lightgbm/xgboost are not installed); seed-1-train baselines used a stratified subsample (all 10,373 pseudo-host sequences plus 30,000 of 02-20).
* Persistence is a label oracle and is shown only as an upper reference.
* The AM/PM and CIC-2017 timestamp notes of docs/15 are unchanged; CIC-2017 numbers here are the 60 s scale-mismatched zero-shot set.

## 7. Reproduce

```text
# from the project root; results go to docs/diagnostics16/, the train-array caches to the OS temp dir
python -m eval.diagnostics.exp1_perday              # per-day / day-constant AUROC, val-loss decomposition, best vs final (14 checkpoints)
python -m eval.diagnostics.exp2_univariate          # univariate AUROC table (needs the train cache; first call builds it, ~2 min)
python -m eval.diagnostics.exp2b_scores             # score levels, Spearman with volume features, host/label structure
python -m eval.diagnostics.exp3_ablate              # mean-ablation of feature groups on 4 datasets x 3 models
python -m eval.diagnostics.exp4_shift               # scaler clip rates, mean z, medians, duration share, SMD/KS
python -m eval.diagnostics.exp5_ctu_unsw_weighting  # host-level AUROC + combined ablations
python -m eval.diagnostics.exp6_baselines           # LR / HGB / zero-training / persistence arms
python -m eval.diagnostics.exp7_lodo_hgb            # leave-one-day-out HGB over the 10 CIC-2018 days
python -m eval.diagnostics.exp8_units_redundancy    # episodes per day, constant / collinear features
python -m eval.diagnostics.exp9_label_dilution      # attack flows per positive window from the raw CSVs
python -m eval.diagnostics.exp10_calib_stack        # calibration per day, per-day ablation spread, stacked-history HGB
python -m eval.diagnostics.exp11_perday_ablation    # per-day effect of ablating flow_count etc.
python -m eval.diagnostics.exp12_weighting          # sequence-weighted vs unit-balanced AUROC (CTU, UNSW)
python -m eval.diagnostics.exp13_units_mde_noise    # clopper-pearson, MDE, label-noise ceiling (needs exp1 output)
python -m eval.diagnostics.exp14_ensemble           # 7-model score average
python -m eval.diagnostics.exp15_ctu_negatives      # CTU-13 with the negatives restricted to the bots' subnet
wc -l V:/Datasets/CIC-IDS-2018-flows/*.csv          # row counts: 7 of 10 files at 1,048,576 lines
python -m pytest tests/test_diagnostics_core.py -q
```
