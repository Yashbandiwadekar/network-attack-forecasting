# 15 - Retrain: CIC-2018 contiguous (B) and CIC-2018 contiguous + CIC-2017 Monday (B+)

**Run 2026-10-17** on branch `test/session-2026-10-10` (nothing committed). Training used the GPU only; no existing checkpoint,
`data/processed*` directory, config, `pipeline/mitre_mapping.py`, `dist/models/seed1`, the server default or production was
modified. Raw results: `docs/joint_v3/*.json`, `docs/onset_eval/joint_v3/*.json`, `docs/stage_forecast/joint_v3_det_*.json`;
logs: `logs/joint_v3/`.

## 0. Pre-stated serving rule (fixed before looking at any test result)

*This section is the text written to this file before training finished and before any test result of the new models was looked at (restored after an overwrite; one parenthetical, "selected before test", is the only addition). Everything from section 1 onward was written after the results were known.*

A new model may only be *recommended* to replace the served seed 1 (`checkpoints_real_v2_converged/seed1`) if, on the EXISTING
`data/processed_real_v2_converged/test.npz` (CIC-2018 v2 test, the same 7,191 sequences; days 02-16, 02-23, 03-01),

1. its AUROC is higher than seed 1's 0.800, **and**
2. its false-alarm rate on benign-throughout sequences (docs/13 protocol, score = max over the K rollout probabilities,
   threshold 0.40) is no worse than seed 1's 1.5% (74 of 5,080),

and among new seeds the candidate is the one with the **lowest validation loss** (selected before test). The server default,
`dist/models/seed1` and production are not changed by this work; this document only recommends. The contiguous rebuilt test (6,881 sequences) is
a secondary table. Because the AUROC differences between seeds are of the order of 0.04 (docs/04 seeds), the rule is also reported with the
seed-1 vs new-seed spread so that "higher" can be read against noise.

## 1. Data audit and the CIC-2017 timestamp question

**CIC-2017 cannot be windowed at 10 s except Monday.** Tuesday to Friday (7 files) carry minute-resolution timestamps, so all
flows of a minute fall in the :00 10 s slot: 10 s and 60 s windowing give identical window and sequence counts on those files, and
with `require_contiguous_windows` the 10 s count is exactly 0 (Fri DDoS 1,088 sequences non-contiguous / 0 contiguous; PortScan
2,326 / 0; Fri Morning 4,122 / 0; Thu Infiltration 4,974 / 0; Thu Web 4,005 / 0; Tue 12,373 / 0; Wed 12,825 / 0). Monday has seconds
resolution (35,539 / 4,861). Mixing the 60 s-step days into a 10 s model would present 60 s cadence as 10 s, so only Monday
(benign) is used for training, as the owner decided; Tue-Fri stay a zero-shot test at 60 s.

**AM/PM heuristic (hours 1-7 add 12 h): checked, consistent, no change.** After adjustment every file lies in 08:42-17:10 of its
own date; raw hours present are only 1-5 and 8-12 (no 6-7, no 0), so it is unambiguous; morning files end 12:59 and afternoon
files start 13:00; attack spans match the published schedule (FTP-Patator 09:17, SSH-Patator 14:09-15:11, Hulk 10:43-11:07,
GoldenEye 11:10, Heartbleed 15:12-15:32, web attacks 09:15-10:42, Infiltration 14:19-15:45, DDoS 15:56-16:16). Not verified
against the PCAPs. Stray labels (5 slowloris flows at 14:xx, Bot from 09:34) look like known label noise. The Thursday-Morning file
has ~288k empty trailing rows that the adapter drops. The stale "unmapped labels" caveat in `pipeline/adapters/cicids2017_adapter.py`
was rewritten (labels are mapped; the 10 s limitation and the heuristic check are stated) with a test.

**CIC-2018, day-disjoint split of `real_data_v2_converged`, 10 s, contiguity on** (my non-contiguous rebuild reproduces the
current metadata exactly, 1,239,090 / 6,685 / 7,191):

| split | current build | contiguous (B) | B+ (B + Monday 4,861) |
|---|---|---|---|
| train | 1,239,090 seq, 7,973 positives (0.6%), 44 onsets | **80,243**, 7,786 positives (9.7%), 39 onsets, 468 hosts | **85,104**, 7,786 positives (9.1%) |
| val | 6,685 / 505 positives | 6,651 / 505 | same |
| test | 7,191 / 1,482 | 6,881 / 1,451 | same |

Train drops 94%, almost all from 02-20 (1,228,717 -> 70,296 sequences). New dirs: `data/processed_adapter/cic18c_v3` (B),
`data/processed_adapter/cic18c_mon17_v3` (B+: B's train plus Monday, val/test copied; built by `scripts/build_joint_v3.py`).
The scaler is fit by `models.dataset.build_datasets` on each variant's own train split only.

### Confound check: `has_ip_data` in the new train split

| train subset | n | next-step positive rate |
|---|---:|---:|
| B, has_ip_data = 0 (pseudo-host days 02-14, 02-21, 02-28, 03-02) | 9,947 | **42.2%** |
| B, has_ip_data = 1 (02-20 only) | 70,296 | 5.1% (3,587 positives) |
| B+, has_ip_data = 1 (02-20 + Monday) | 75,157 | 4.8% (Monday: 0 positives) |

Monday raises the has_ip_data = 1 population by 6.9% and lowers its positive rate from 5.1% to 4.8%. The shortcut
"has_ip_data = 1 implies mostly benign" already exists in B (and was stronger in the original build, 0.6% positives); Monday only
strengthens it marginally. It cannot be a hard rule (02-20 supplies 3,587 real-IP positives), and **val and test are 100%
has_ip_data = 0** (3 and 2 network-wide pseudo-hosts), so the shortcut never fires at evaluation; the risk is rather that the model
uses has_ip_data = 0 as an attack prior (42% vs 5%), which is equally true of the pre-existing build. Judged not severe, so training
went ahead. It is also a reason to expect little B+ vs B difference on pseudo-host test data.

## 2. Training

Same architecture and hyperparameters as `real_data_v2_converged` (d_model 64, 4 heads, 3 layers, batch 64, lr 3e-4, 30 epochs, best-val-loss
checkpoint kept); configs `configs/joint_v3_B.yaml`, `configs/joint_v3_Bplus.yaml`, seeds 1-3 each, checkpoints
`checkpoints_joint_v3/{B,Bplus}/seed{1,2,3}/`, logs `logs/joint_v3/train_*.log`. All 6 runs completed (about 10 s per epoch uncontended).

| run | best val loss | best epoch | val loss at epoch 1 | val loss at epoch 30 |
|---|---:|---:|---:|---:|
| **B+ seed 1** | **0.6286** | 1 | 0.629 | 1.011 |
| B+ seed 2 | 0.6897 | 2 | 0.815 | 1.086 |
| B+ seed 3 | 0.6467 | 1 | 0.647 | 1.093 |
| B seed 1 | 0.6956 | 3 | 0.812 | 1.197 |
| B seed 2 | 0.6460 | 1 | 0.646 | 1.008 |
| B seed 3 | 0.6380 | 2 | 1.328 | 0.983 |
| (old seed 1, served; different val set) | 0.7579 | 2 | 0.894 | 0.972 |

Train loss falls from about 0.35 to 0.11 while val loss rises after epoch 1-3 in every run, so **validation-loss checkpoint
selection picks an essentially untrained epoch-1-to-3 model, here and for the served seed 1 too (epoch 2)**. The val set (02-15,
02-22, two days) is a poor guide: the val AUROC of the selected checkpoints is 0.34-0.64 while their test AUROC is 0.75-0.82
(`docs/joint_v3/t1_metrics.json`, dataset `cic18_val_contig`). B and B+ share the same val split, so their val losses are comparable.

## 3. Results

### 3.1 Serving-rule table (CIC-2018 v2 test, 7,191 sequences, 1,482 t+1 positives; AUROC with block-bootstrap 95% CI)

False alarms: docs/13 protocol at 0.40 (`eval.onset_eval`, `docs/onset_eval/joint_v3/*_cic2018_v2test.json`), of 5,080 benign-throughout
sequences, cluster-bootstrap CI over benign stretches. seed1 reproduces docs/13 exactly (AUROC 0.8003; 74/5,080).

| model | val loss | AUROC [CI] | AUPRC | F1@0.5 / P / R | false alarms @0.40 [CI] | AUROC > 0.800 | FA <= 1.5% |
|---|---:|---|---|---|---|---|---|
| **seed1 (served)** | 0.7579 | 0.800 [0.736-0.861] | 0.651 | 0.466 / 0.903 / 0.314 | 74 = 1.46% [0.1-2.9] | - | - |
| **B+ s1 (lowest val loss of B+ and of all six)** | **0.6286** | **0.765 [0.688-0.841]** | 0.560 | 0.354 / 0.915 / 0.219 | 28 = 0.55% [0.0-1.1] | **no** | yes |
| B+ s2 | 0.6897 | 0.810 [0.734-0.872] | 0.669 | 0.467 / 0.954 / 0.309 | 40 = 0.79% [0.3-1.3] | yes | yes |
| B+ s3 | 0.6467 | 0.807 [0.736-0.871] | 0.612 | 0.361 / 0.856 / 0.229 | 81 = 1.59% [0.5-2.6] | yes | no |
| B s1 | 0.6956 | 0.786 [0.709-0.854] | 0.629 | 0.497 / 0.935 / 0.339 | 106 = 2.09% [1.3-2.8] | no | no |
| B s2 | 0.6460 | 0.774 [0.695-0.850] | 0.575 | 0.457 / 0.911 / 0.305 | 40 = 0.79% [0.0-1.4] | no | yes |
| **B s3 (lowest val loss of B)** | 0.6380 | **0.820 [0.744-0.878]** | 0.670 | 0.461 / 0.944 / 0.305 | 22 = 0.43% [0.0-1.2] | yes | yes |

Secondary: contiguous rebuilt test (6,881 sequences, 1,451 positives; the same days minus the sequences that span gaps):

| model | AUROC [CI] | AUPRC | FA @0.40 (of 4,813) |
|---|---|---|---|
| seed1 | 0.794 [0.724-0.850] | 0.651 | 54 = 1.12% |
| B+ s1 / s2 / s3 | 0.754 / 0.803 / 0.802 | 0.565 / 0.677 / 0.620 | 19 = 0.39% / 21 = 0.44% / 67 = 1.39% |
| B s1 / s2 / s3 | 0.775 / 0.763 / 0.819 | 0.632 / 0.582 / 0.693 | 94 = 1.95% / 31 = 0.64% / 12 = 0.25% |

**Ablation (3 seeds per arm, mean +/- SD):** AUROC on the v2 test: old trio 0.794 +/- 0.043, B 0.793 +/- 0.024, B+ 0.794 +/- 0.025. False
alarms at 0.40: old trio 1.5 / 2.0 / 3.0% (docs/13), B 2.1 / 0.8 / 0.4%, B+ 0.6 / 0.8 / 1.6%. B vs B+ (what Monday adds) is not separable on either
metric. The old-trio vs B comparison is **not a contiguity ablation**: B differs from the old trio in three things at once (contiguity; the loss of 94% of the
02-20 real-IP training sequences, 1,228,717 -> 70,296; and a different builder, `prepare_dataset`, which reproduces the old arrays only in the
non-contiguous case). AUROC is the same; false alarms of the new runs (0.4-2.1%) overlap the old trio's (1.5-3.0%: B s1 at 2.1% is above old seeds 1 and 2),
so a lower false-alarm rate is at most suggestive and, with n = 3 per arm, cannot be attributed to any one of the three changes.

### 3.2 Onset evaluation (docs/13), threshold 0.40, episode counts; "early" = alarm before the episode starts

| data | model | episodes (hosts) | early | on-time | late | missed | onset-vs-benign AUROC [CI] |
|---|---|---|---|---|---|---|---|
| CIC-2018 v2 test | seed1 | 12 (3) | 0/12 | 1 | 5 | 6 | 0.34 [0.19-0.49] |
| | B+ s1 | 12 (3) | 0/12 | 1 | 4 | 7 | 0.59 [0.45-0.73] |
| | B+ s2 / s3 | 12 (3) | 0/12 each | 1 / 1 | 4 / 5 | 7 / 6 | 0.42 / 0.56 |
| | B s1 / s2 / s3 | 12 (3) | 0/12 each | 1 each | 5 / 5 / 4 | 6 / 6 / 7 | 0.51 / 0.62 / 0.49 |
| CIC-2018 contiguous test | seed1; B+ s1; B s3 | 10 (2) | 0/10 each | 0 each | 4; 3; 3 | 6; 7; 7 | 0.34; 0.58; 0.49 |
| CIC-2017 Tue-Fri, 60 s (scale-mismatched zero-shot, Monday removed) | seed1 | 15 (9) | 0/15 | 3 | 1 | 11 | 0.67 naive, 0.46 same-host |
| | B+ s1 / s2 / s3 | 15 (9) | 0 / 0 / **2** | 0 / 1 / 1 | 3 / 2 / 3 | 12 / 12 / 9 | same-host 0.48 / 0.52 / 0.49 |
| | B s1 / s2 / s3 | 15 (9) | **2** / 0 / **1** | 1 / 1 / 1 | 2 / 2 / 3 | 10 / 12 / 10 | same-host 0.46 / 0.50 / 0.49 |

No new model warns early on CIC-2018 (0/12, exact 95% upper bound 26%). On CIC-2017 (per-episode records in the JSON) three of the six new runs have
"early" episodes, and they are **not only the docs/13 DoS-victim host**: B+ s3 and B s1 each flag the same two episodes of the attacker NAT address
172.16.0.1 (an `impact` episode, contiguous, lead 300 s, all 6 of 6 pre-onset origins already alarmed, i.e. the host was already in the alarming
regime; and an `initial_access` episode, gapped, lead 840 s, 2 of 6 origins, beyond the nominal 6-window horizon because the timeline has silent minutes), and
B s3 flags the victim 192.168.10.50 (`impact`, lead 300 s, 2 of 6). Seed 1 scored the first two as missed and the victim as on-time. These are 3 episodes of
15 on 2 hosts in 3 of 6 runs (the two 172.16.0.1 episodes are shared by two runs, so they are not independent evidence); the same-host onset
AUROC is 0.46-0.52, i.e. chance, so the ranking does not support a forecasting reading. Minute-resolution timestamps blur an onset by up to a minute.
The retrain did not create advance warning. Onset-origin AUROC is 0.42-0.62 for every new run (intervals include 0.5).
False alarms of the new runs on CIC-2017 benign-throughout (of 40,511): seed1 28 (0.07%), B+ 42 / 9 / 110, B 138 / 36 / 87.

### 3.3 Zero-shot cross-dataset (t+1 AUROC; all splits concatenated; nothing trained on them)

CIC-2017 Tue-Fri at **60 s windows against 10 s training: a scale-mismatched zero-shot test** (41,713 sequences, 901 positives; Monday
removed because B+ trains on it). UNSW-NB15 and CTU-13 rebuilt at 10 s with the fixed ICMP/protocol adapters, same 41 features, both with and
without `require_contiguous_windows`; as held-out tests only (`data/processed_adapter/{unsw,ctu13}_10s_{contig,noncontig}`).

| model | CIC-2017 60 s | UNSW 10 s contig (96,299 seq / 9,997 pos) | UNSW non-contig (117,264 / 18,057) | CTU-13 contig (355,302 / 21,066) | CTU-13 non-contig (1,554,369 / 25,364) |
|---|---|---|---|---|---|
| seed1 | 0.690 [0.614-0.775] | 0.454 [0.412-0.497] | 0.292 | 0.155 [0.140-0.172] | 0.395 |
| B+ s1 | 0.359 [0.250-0.474] | 0.920 [0.907-0.931] | 0.870 | 0.117 | 0.329 |
| B+ s2 | 0.477 [0.349-0.612] | 0.636 | 0.474 | 0.299 | 0.515 |
| B+ s3 | 0.390 | 0.940 | 0.910 | 0.113 | 0.311 |
| B s1 | 0.428 | 0.967 | 0.942 | 0.240 | 0.361 |
| B s2 | 0.402 | 0.561 | 0.415 | 0.144 | 0.376 |
| B s3 | 0.410 | 0.968 | 0.942 | 0.162 | 0.298 |

CIC-2017 transfer got **worse** for every new run (0.36-0.48 vs seed 1's 0.69, intervals mostly below 0.5), even for B+, which saw benign 2017
traffic. UNSW swings between 0.42 and 0.97 across seeds of one configuration, so the high values (0.87-0.97) are not a property of the recipe, and
F1@0.5 on UNSW is about 0 for those models (precision 0.5-1.0, recall under 8%): the ranking carries information, the probabilities are not calibrated for that data.

**CTU-13 and UNSW AUROCs below 0.5 are inverted rankings, and a reference check shows the rebuild is not the cause** (`docs/joint_v3/reference_check.json`):
the old day-disjoint v2 checkpoint (`checkpoints_real_v2`) scores 0.7804 on the OLD CTU-13 test split (186,520 sequences), which reproduces
`docs/04-evaluation-ctu13_cross_from_real_data_v2_postD1.md`, so the scoring code is sound; the same checkpoint scores 0.508 on the old build's three splits together
(1,491,560 sequences) and 0.527 on the rebuilt non-contiguous set, so the 0.78 was a property of that three-scenario test split and the rebuild agrees with the old build. The
served seed 1, which docs/README say was never scored on CTU-13, gets **0.353 on the old CTU test split and 0.393 on the old build overall**, and 0.283 on the old
UNSW v2 build (0.292 on the rebuild): it was already inverted on the old builds. So the converged-family models (seed 1 and all six new ones) rank CTU-13 botnet windows
BELOW background windows, and UNSW attack windows below normal ones for seed 1 and some seeds; the retraining did not change that. (The cause was not investigated; likely
volume-driven scores: botnet and background hosts there are low-volume and low-rate relative to the DDoS-dominated CIC-2018 training attacks.) CIs for
the bundled models and seed 1 are in `docs/joint_v3/t1_metrics*.json`: CTU-13 contiguous, seed 1 0.155 [0.140-0.172], B+ s1 0.117 [0.105-0.130], B s3 0.162 [0.150-0.176];
UNSW contiguous, seed 1 0.454 [0.412-0.497], B+ s1 0.920 [0.907-0.931], B s3 0.968 [0.960-0.974].

### 3.4 Stage forecaster on detector output, CIC-2017 (docs/14 `events_from_detections` path, first run on real model output)

Detector table = t+1 stage prediction of each model at 60 s windows over Tue-Fri (`eval/joint_v3_detections.py`; alarm = p >= 0.40, stage = argmax over the
non-benign classes), attacker view, merge gap 300 s, chain gap 2 h, horizon 10,800 s, leave-one-chain-out, alarm threshold 0.25. The detector cannot emit
reconnaissance or impact (no such head classes), so the reconnaissance headline of docs/14 cannot be reproduced from detector events; the check is the
initial_access focus.

| detector | events / chains / entities | first-onset items (positives) | early / positives (exact CI) | false alarms | top-1 next stage | paired log-loss order1 - order0 (independent chains) |
|---|---|---|---|---|---|---|
| seed1 | 12 / 6 / 5 | 8 (2) | 2/2 [16-100%] | 4/4 | 0/2 | +0.014 nats (4) |
| B+ s1 | 13 / 5 / 4 | 9 (4) | 4/4 [40-100%] | 3/3 | 2/4 | -0.215 (3) |
| B s3 | 12 / 6 / 5 | 10 (4) | 4/4 [40-100%] | 4/4 | 3/4 | -0.042 (6) |

"Early" is satisfied by the always-alarm rule in every row (identical counts) and every negative chain alarms, so these numbers carry no evidence of
foresight; n is 2-4 first-onset positives on 3-6 independent chains. Nothing here changes docs/14's conclusion.

### 3.5 Leave-one-attack-family-out (B recipe, contiguous CIC-2018, 3 seeds per fold)

Held-out family = all of its days as test; val = the last day of one other family; the rest trains (B recipe, 30 epochs, best-val checkpoint,
`eval/lofo_v3.py`, `docs/joint_v3/lofo_v3.json`). t+1 AUROC per seed 1/2/3 and mean +/- SD (old = `docs/04-evaluation-lofo-seeds.md`, non-contiguous windows):

| held-out family (days) | test seq / positives | AUROC seeds 1 / 2 / 3 | mean +/- SD | old mean +/- SD |
|---|---|---|---|---|
| initial_access (02-14, 02-22, 02-23) | 9,778 / 1,549 | 0.548 / 0.571 / 0.538 | 0.552 +/- 0.017 | 0.685 +/- 0.087 |
| lateral_movement (02-28, 03-01) | 6,630 / 1,728 | 0.508 / 0.607 / 0.481 | 0.532 +/- 0.066 | 0.528 +/- 0.129 |
| command_and_control (03-02) | 3,109 / 2,028 | 0.934 / 0.898 / 0.939 | 0.924 +/- 0.022 | 0.646 +/- 0.131 |
| impact (02-15, 02-16, 02-20, 02-21) | 74,258 / 4,437 | 0.794 / 0.368 / 0.832 | 0.665 +/- 0.258 | 0.819 +/- 0.128 |

Not comparable with the old table: the old folds used non-contiguous windows and added the fabricated benign day 04-02 to every test set, and
these folds have no benign-only day. Specific cautions: the command_and_control test is **one day, one network-wide pseudo-host, 65% positive**, so
the 0.92 is a within-day contrast of a single autocorrelated series, not evidence of transfer to a new family; the impact fold's test contains 02-20
(about 70,000 real-IP, has_ip_data = 1 sequences) while its training data has no has_ip_data = 1 sequences at all, so its AUROC mixes family
generalisation with a has_ip_data distribution shift (and one seed collapses to 0.368). Initial access and lateral movement remain at chance (0.55 and
0.53, the same conclusion as before): **no evidence that the retrained recipe generalises to unseen attack families**, and the one high number is a single-day artefact.

## 4. Recommendation under the pre-stated rule

* **The rule-selected candidate is B+ s1** (lowest validation loss among the B+ seeds and among all six: 0.6286). It has AUROC 0.765 < 0.800, so it
  **fails condition 1** (its false alarms, 0.55%, would pass). **No B+ model is recommended to replace seed 1.**
* Plain B s3 (lowest val loss of the B arm) clears both numbers (AUROC 0.820, 0.43% false alarms). It is **not** the val-loss pick of the pool of six,
  it is the ablation arm rather than the owner's B+ design, and its edge over seed 1 is 0.020 AUROC with overlapping intervals ([0.744-0.878] vs
  [0.736-0.861]) inside a same-recipe seed spread of 0.77-0.82 (old trio 0.748-0.833). Selection by validation loss also picks an epoch 1-3
  checkpoint (section 2). **Recommendation: do not replace seed 1.** If the owner reads the rule as "per arm", B s3 is the only qualifier; I would
  still not deploy it on this evidence: it is worse than seed 1 on CIC-2017 zero-shot (0.41 vs 0.69), has the same onset record as seed 1 (0/12 early),
  and nothing in section 3.3 favours it except UNSW, whose seed-to-seed range (0.56-0.97) says that number is luck.
* Bundles built (not deployed): `dist/models/joint_v3_Bplus_seed1` (rule-selected, fails the rule) and `dist/models/joint_v3_B_seed3` (the per-arm
  qualifier), each with a `.tar.gz`; archive SHA256 `95b072b379a7aaad1a195845d89a859d38dcaeb6293b6b7523a9f050c5d6024b` and
  `69502eb2db1b7e4e257ed7528127226382f6bdc04b3de19f0a51192a2514e3f4`. Configs `configs/joint_v3_Bplus_seed1.yaml`, `configs/joint_v3_B_seed3.yaml`
  point at the seed directories (as `real_data_v2_converged_seed1.yaml` does). `dist/models/seed1` was not touched.

## 5. What retraining did NOT fix

* Early warning: still 0 of 12 (CIC-2018) for every new model; the onset-origin ranking is at chance (0.42-0.62).
* Recall: F1@0.5 stays 0.35-0.50 with precision 0.86-0.95 and recall 0.22-0.34; the conservative detector profile is unchanged.
* CIC-2017 zero-shot transfer: worse than seed 1, not better, despite contiguous training and Monday.
* Cross-network transfer (UNSW, CTU-13): no consistent gain; CTU-13 is an inverted ranking (0.11-0.30) for every converged-family model including seed 1 (0.15), already so on the old build; UNSW is seed luck (0.42-0.97).
* Validation-based model selection: val loss is minimal at epoch 1-3 and does not track test AUROC; the 2-day val set cannot rank seeds.
* The stage-forecaster limits of docs/14 (no recon or impact from a detector; the alarm is constant per state).
* Monday adds no attack family, only benign real-IP traffic; B+ vs B shows no measurable effect.

## 6. Cost of the LOFO adaptation

`eval/lofo.py` is bound to `configs/real_data_v2.yaml`, `data/processed_real_v2` and the fabricated benign days 04-01/04-02 (absent from the contiguous
build). `eval/lofo_v3.py` reuses its fold definitions and evaluation on the contiguous B data (new dirs `data/processed_adapter/lofo_v3/<family>`,
`checkpoints_joint_v3/lofo/<family>/seed<N>`). Cost: 12 small trainings (4 families x 3 seeds, 30 epochs); about 64 minutes wall clock (the machine was also running other jobs for the first half) wall clock with the machine also busy
with other jobs, under the 2 h budget.

## 7. Not verified / limits

* The AM/PM heuristic against the original PCAPs; why the converged-family models invert on CTU-13/UNSW (not investigated).
* The block-bootstrap AUROC intervals treat blocks of 50 consecutive sequences of one host as independent and are indicative only (the CIC-2018 test has
  3 pseudo-hosts and 12 onset episodes); the 7-model CTU-13 non-contiguous intervals use 20 resamples of 200-sequence blocks.
* B+ val and test are B's contiguous val/test; B+ differs from B only in its train split and scaler.
* The CIC-2017 zero-shot set excludes Monday (new dir `cic2017_zeroshot_60s_noMon`); docs/13 figures include it, so numbers differ slightly from docs/13.
* The UNSW/CTU sets are held-out tests only; seed 1 was not retrained, only re-scored on them.
* No change to the server, `dist/models/seed1`, or production. Nothing committed.
* The CIC-2017 PCAPs (being downloaded by the owner) were not touched or waited for; they are the route to a true 10 s joint model.

## 8. Reproduce

```text
python -m scripts.prepare_dataset data/raw/flows_real --out data/processed_adapter/cic18c_v3 --config configs/joint_v3_B.yaml --adapter cicids2018 --split by_day
python -m scripts.build_joint_v3 --base data/processed_adapter/cic18c_v3 --out data/processed_adapter/cic18c_mon17_v3 --config configs/joint_v3_Bplus.yaml
python -m models.train --config configs/joint_v3_Bplus.yaml --seed 1      # likewise joint_v3_B.yaml, seeds 2 and 3
python -m eval.joint_v3_eval --models seed1=configs/real_data_v2_converged_seed1.yaml \
    Bplus_s1=configs/joint_v3_Bplus.yaml@checkpoints_joint_v3/Bplus/seed1/world_model_best.pt \
    --datasets cic18_v2_test=data/processed_real_v2_converged:test --out docs/joint_v3/t1_metrics.json
python -m eval.onset_eval --config configs/joint_v3_Bplus.yaml --checkpoint checkpoints_joint_v3/Bplus/seed1/world_model_best.pt \
    --data-dir data/processed_real_v2_converged --splits test --label x
python -m eval.lofo_v3 --seeds 1 2 3
python -m scripts.make_model_bundle --config configs/joint_v3_Bplus_seed1.yaml --out dist/models/joint_v3_Bplus_seed1 --archive
```
