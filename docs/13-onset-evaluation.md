# 13 - Onset-only, episode-level evaluation (docs/09 B1, docs/05 R-2)

**Written 2026-10-17** on branch `test/session-2026-10-10` (base `4b0410f`, nothing committed). Inference only: no model
was trained, no checkpoint or existing `data/processed*` directory was modified. Code: `eval/onset_eval.py`
(`python -m eval.onset_eval --config <yaml> [--checkpoint ...]`), tests: `tests/test_onset_eval.py`, raw results:
`docs/onset_eval/*.json` (one file per run, including every per-episode outcome).

The point of this document is one yardstick that every future model change is measured against, with the number of
independent episodes printed beside every figure. **Bottom line first: on the data we have, the served model has not been shown to give advance warning of an
attack.** CIC-IDS-2018 test: 0 of 12 episodes were alarmed before they began, for every model (seeds 1-3 and the
unseeded checkpoint) at every threshold. CIC-IDS-2017, zero-shot: 0 of 15 for the served seed 1 and for seed 3; seed 2
and the unseeded checkpoint each score 1 of 15, and it is the same episode (a DoS victim server whose nearly every
pre-onset window already alarms, so it is the flood ramping up, not a forecast). The exact 95% upper bounds on the
early-warning rate are 26% (n = 12, 3 hosts) and 22% (n = 15, 9 hosts): a modest warning rate is not excluded, but
nothing finer can be said from 12-15 events.

---

## 1. Definitions (fixed before any result was looked at)

**Sequence / origin.** One model input: L = 12 windows ending at the *current* window `c`, with the observed label of
the K = 6 following windows. `c` is the sequence's *origin*. Window length is `window_seconds` (10 s for CIC-2018, 60 s
for the CIC-2017 run, whose timestamps have minute resolution).

**Three populations of sequences**, from observed labels only (non-benign = any stage including `impact`):

| population | rule |
|---|---|
| **already-attacking** | the current window is non-benign |
| **onset** | the current window is benign and some window k = 1..K ahead is non-benign |
| **benign-throughout** | the current window and all K windows ahead are benign |

**Onset window.** A window that is non-benign while the previous window of the same host is benign. Every onset
sequence has exactly one onset window: its first non-benign future window.

**Host.** `scenario_id` (where present) + `src_ip`. On CIC-2018 9 of 10 days have no IPs, so a "host" is a
network-wide pseudo-host, one per day (`NETWORK-2018-02-16`, ...). Hosts are printed next to every episode count.

**Episode.** All the onset windows of one host that belong together. A later onset window joins the previous episode
when it has the same stage at onset and fewer than `merge_gap` (default K = 6) benign windows separate it from the end
of the previous attack run. The episode's **onset time T0** is the real start time of its first onset window. Raw
onset events (`--merge-gap 0`) are reported separately; they are not independent and are shown only to explain how
628 sequences become 12 episodes.

**Alarm.** `score >= threshold`, where the score is the **maximum over the K rollout infiltration probabilities** of a
sequence, the same quantity `app/server.py` compares with `ALERT_THRESHOLD`. The alarm is *issued* at
`issue time = start of the current window + window_seconds` (the window is complete).

**Outcome of an episode.** Take the first alarm (by issue time) among (a) the benign origins up to K windows before the
onset window, which are the only ones that can see it, and (b) the origins from the onset window to the end of the
episode's attack span. Then:

| outcome | rule |
|---|---|
| **early** | issue time < T0. Lead time = T0 - issue time, in **real seconds from the stored window timestamps** |
| **on-time** | T0 <= issue time <= T0 + window_seconds (the alarm comes when the attack starts, no warning) |
| **late** | issue time > T0 + window_seconds (delay = issue time - T0) |
| **missed** | no alarm anywhere in (a) or (b) |
| unresolved | T0 is not stored (the onset lies in the last K windows of a host's timeline). Counted and printed, excluded from the rates. Zero cases in every headline run |

**Contiguous vs gapped (QC-1).** An episode is *contiguous* when every window step from the first input window of its
earliest eligible origin to the onset window is exactly `window_seconds`; otherwise it is *gapped* (a host with no
flows in a slot has no window, so "K steps ahead" can be minutes or hours). A benign-throughout sequence is
contiguous only if its L input and K target windows are verifiably exactly `window_seconds` apart; a sequence whose
target windows lie beyond the last stored timestamp is counted as "gapped/unverifiable".

**Timestamps of future windows.** The `.npz` splits store `window_times` for the L input windows only. The time of the
k-th future window is reconstructed from the overlap of consecutive sequences of the same host (sequence j+1 is
sequence j shifted by one window), never from `k * window_seconds`. The reconstruction is checked on every run: the
stored future labels of every sequence must equal the labels the reconstructed timeline holds (**0 mismatches in all
runs**), and every onset sequence must belong to exactly one episode (asserted).

**Thresholds.** Reported at three operating points, never tuned on the evaluated data:

* `served_0.40`: `app.service.ALERT_THRESHOLD`.
* `val_fixed_fa0.05` and `val_fixed_fa0.01`: the smallest threshold whose alarm rate on the **CIC-2018 v2 validation**
  split's benign-throughout sequences is at most 5% (1%), computed with the same model and the same score. For
  seed 1 these are 0.397 and 0.797. The CIC-2017 run uses the same source-domain thresholds (zero-shot: no
  target-domain tuning at all).

**Confidence intervals.** Episode proportions: exact Clopper-Pearson 95%. False-alarm rates and AUROCs: cluster
bootstrap (benign sequences resampled by *stretch*, i.e. maximal runs of consecutive benign-throughout origins;
onset sequences by episode), because overlapping sliding sequences are not independent and a binomial CI would be
optimistic.

---

## 2. Datasets and what was run

| run | data | model | what it is |
|---|---|---|---|
| CIC-2018 | `data/processed_real_v2_converged/test.npz` (02-16, 02-23, 03-01; 7,191 sequences) | served seed 1 (`configs/real_data_v2_converged_seed1.yaml`; md5 `e075bffc...`, identical to `dist/models/seed1`), seeds 2 and 3, and the unseeded `checkpoints_real_v2_converged/world_model_best.pt` | day-disjoint held-out test. Val and test contain 17-27% fabricated benign traffic (README) |
| CIC-2017 | `V:\Datasets\CIC-IDS-2017`, all 8 files, prepared with `scripts.prepare_dataset` into the **new** dir `data/processed_adapter/cic2017_zeroshot_60s` (config `configs/cic2017_60s_zeroshot.yaml`: the serving config with `window_seconds: 60`); 56,334 sequences, 626 hosts | the same four checkpoints | **Zero-shot cross-dataset test.** Nothing was trained on it. The by_unit train/val/test split of the prepared dir is a formality; all three splits are concatenated for evaluation |
| CTU-13 | not evaluated | - | see section 7 |

Caveats specific to the CIC-2017 run, all of which make it a harder and less comparable test than CIC-2018:
60 s windows against a model trained on 10 s windows (volume features are about 6x larger); `has_ip_data = 1` here
against mostly 0 in training; the adapter is `experimental` (minute-resolution `d/m/Y H:MM` timestamps, AM/PM
heuristic unverified); each file (day or half-day) is windowed separately, so a host's history never crosses files;
label noise is documented for this dataset (Engelen 2021; Lanvin 2023); the attacker is a single NAT address
(172.16.0.1).

---

## 3. Headline: CIC-2018 test, served seed-1 model

Populations: 5,080 benign-throughout, **628 onset**, 1,483 already-attacking sequences, on **3 hosts**.
The 628 onset sequences (the figure behind the old README lead-time numbers, and docs/05 D-3's 628) are
**181 raw onset events = 12 independent episodes** (docs/05 estimated "~15, an upper bound"):

| host (pseudo) | episodes | stages | contiguous |
|---|---:|---|---:|
| NETWORK-2018-02-16 | 2 | impact (DoS) | 0 of 2 |
| NETWORK-2018-02-23 | 8 | initial_access | 8 of 8 |
| NETWORK-2018-03-01 | 2 | lateral_movement | 2 of 2 |
| **total** | **12 (3 hosts)** | impact 2, initial_access 8, lateral_movement 2 | **10 contiguous, 2 gapped**; 9 have a clean (known-benign) input history |

The 02-23 pseudo-host is already attacking at its first observed window (a left-censored run, so its first
attack is not an onset); no host is benign-throughout. Outcomes (n = number of episodes; exact 95% CI):

| threshold | n episodes | early | on-time | late | missed | false alarms on benign-throughout (cluster CI) |
|---|---:|---|---|---|---|---|
| served 0.40 | 12 | **0/12 (0-26%)** | 1/12 (0-38%) | 5/12 (15-72%) | 6/12 (21-79%) | 74/5,080 = 1.5% (0.1-2.9%), 13 stretches |
| val-fixed 5% FA (0.397) | 12 | 0/12 | 1/12 | 5/12 | 6/12 | 75/5,080 = 1.5% (0.1-3.0%) |
| val-fixed 1% FA (0.797) | 12 | 0/12 | 1/12 | 4/12 | 7/12 | 28/5,080 = 0.6% (0.0-0.9%) |

Detection delays of the six episodes caught on time or late (served threshold): 10 s (the on-time one), then 20, 110, 1,040, 1,830 and 2,170 s for the five late ones (20 s to about 36 min). Pre-onset origins
alarmed: **0 of 71** (the episodes have 5-6 eligible origins each).

**Contiguous vs gapped** (served 0.40):

| group | n episodes (hosts) | early | on-time | late | missed | false alarms on benign-throughout |
|---|---|---|---|---|---|---|
| contiguous | 10 (2) | 0/10 (0-31%) | 0/10 | 4/10 | 6/10 | 54/4,801 = 1.1% (0.1-2.3%) |
| gapped / unverifiable | 2 (1) | 0/2 (0-84%) | 1/2 | 1/2 | 0/2 | 20/279 = 7.2% (0.0-19.4%) |

The gapped group is two episodes on one host: its conclusions are not worth more than "no contradiction". The
false-alarm rate is higher on gapped sequences, but 279 sequences in 7 stretches carry a very wide CI.

**Does a warning come from forecasting or from the threshold?** Base-rate check at 0.40: the alarm rate on onset
sequences (the 628 sequences from which an onset is visible) is 16/628 = 2.5% (cluster CI 0-6.1%, 12 episodes),
against 1.5% on benign-throughout sequences, a ratio of about 1.7 with overlapping intervals. All 16 of those alarms
come from re-onsets inside an ongoing attack, none from the pre-onset origins of an episode's first onset. By steps
to the onset window the onset-sequence alarm rate is 4.4% (k=1, n=181 sequences), 2.7%, 2.5%, 1.0%, 0%, 0% (k=6,
n=11). AUROC of onset origins vs benign-throughout origins, threshold-free, is 0.34 (cluster CI 0.19-0.49;
12 episodes vs 13 benign stretches), 0.42 (0.20-0.65) if only sequences with a known-benign input history are used.
That is at or below chance: the score does not rank the sequences that precede an onset above benign ones.

Where the model does work is **detection of an attack already in progress**: 523 of 1,483 already-attacking sequences
(35%) alarm at 0.40, and the 5 "late" episodes are found by this route.

---

## 4. Seed variance (CIC-2018, same 12 episodes, 3 hosts)

| model | threshold | early | on-time | late | missed | false alarms (benign-throughout, of 5,080) | alarm rate on onset seqs (of 628) | AUROC onset vs benign-throughout (cluster CI) |
|---|---|---|---|---|---|---|---|---|
| seed 1 (served) | 0.40 | 0/12 | 1/12 | 5/12 | 6/12 | 74 = 1.5% | 16 | 0.34 (0.19-0.49) |
| | val 5% = 0.397 / 1% = 0.797 | 0/12 | 1/12 | 5/12 \| 4/12 | 6/12 \| 7/12 | 75 \| 28 | 16 \| 8 | |
| seed 2 | 0.40 | 0/12 | 1/12 | 5/12 | 6/12 | 101 = 2.0% | 13 | 0.49 (0.33-0.58) |
| | val 5% = 0.389 / 1% = 0.967 | 0/12 | 1/12 \| 0/12 | 5/12 | 6/12 \| 7/12 | 104 \| 46 | 13 \| 8 | |
| seed 3 | 0.40 | 0/12 | 0/12 | 6/12 | 6/12 | 152 = 3.0% | 33 | 0.53 (0.46-0.60) |
| | val 5% = 0.739 / 1% = 0.987 | 0/12 | 0/12 | 6/12 \| 5/12 | 6/12 \| 7/12 | 68 \| 1 | 23 \| 3 | |
| unseeded checkpoint | 0.40 | 0/12 | 2/12 | 5/12 | 5/12 | 127 = 2.5% | 15 | 0.55 (0.44-0.69) |
| | val 5% = 0.373 / 1% = 0.674 | 0/12 | 2/12 \| 1/12 | 5/12 \| 4/12 | 5/12 \| 7/12 | 140 \| 46 | 21 \| 9 | |

(`a | b` = the 5% and the 1% val-fixed thresholds respectively.) The episode outcomes differ by at most one or two
episodes between seeds, which is below the resolution of 12 events: **seed-to-seed variation is invisible at the
episode level but clearly visible in the false-alarm rate (1.5% to 3.0% at the same 0.40) and in the AUROC point
estimates (0.34 to 0.55, all with intervals overlapping 0.5 except seed 1's, whose upper bound is 0.49).** Note the
served seed was chosen on validation loss before any test metric was consulted; it happens to have the lowest test
AUROC here and the lowest false-alarm rate, so neither direction is a reason to re-select it.

---

## 5. Raw onset events vs episodes

The same seed-1 run with `--merge-gap 0` (every onset window its own event):

| view | n | early | on-time | late | missed |
|---|---:|---|---|---|---|
| merged episodes | 12 | 0 (0-26%) | 1 | 5 | 6 |
| raw onset events | 181 (3 hosts) | 6 (1-7%) | 7 | 3 | 165 |

The six raw "early" events are all re-onsets inside an attack that is already under way (the model has attack
windows in its input), median lead 20 s (range 10-30 s, all within the K-window nominal horizon). They disappear
under merging because the episode's first onset is not warned. This is why 628 sequences / 181 events look like a
test set and 12 episodes are. Reporting the 181 as independent would shrink every CI by a factor of about four for no
real gain.

---

## 6. CIC-IDS-2017, zero-shot (60 s windows, all 8 files)

Populations: 55,132 benign-throughout, **302 onset**, 900 already-attacking sequences; **626 hosts**, of which 616
never attack. The 302 onset sequences are **220 raw events = 15 episodes on 9 hosts**: 7 command_and_control
(the internal Bot hosts 192.168.10.x), 3 lateral_movement (Infiltration), 3 impact (DoS), 1 reconnaissance
(PortScan), 1 initial_access, with 11 having a clean input history. docs/09 counted 12 source-keyed onsets with a
stricter history rule (at least 12 benign non-empty windows); under this document's definition there are 15.
7 episodes (6 hosts) are contiguous, 8 (4 hosts) gapped.

Served seed 1 (`served_0.40`; the 5% val-fixed threshold 0.397 gives identical numbers):

| group | n (hosts) | early | on-time | late | missed |
|---|---|---|---|---|---|
| all | 15 (9) | **0/15 (0-22%)** | 3/15 (4-48%) | 1/15 (0-32%) | 11/15 (45-92%) |
| contiguous | 7 (6) | 0/7 (0-41%) | 2/7 | 0/7 | 5/7 |
| gapped / unverifiable | 8 (4) | 0/8 (0-37%) | 1/8 | 1/8 | 6/8 |
| clean input history | 11 (8) | 0/11 (0-28%) | 1/11 | 1/11 | 9/11 |
| val-fixed 1% (0.797), all | 15 (9) | 0/15 | 1/15 | 2/15 | 12/15 |

False alarms: 28 of 55,132 benign-throughout sequences (0.05%, CI 0.0-0.1%); restricted to the 9 hosts that have
episodes, 21 of 15,405 (0.1%, CI 0.0-0.3%).

Per seed at 0.40: seed 1 0/15 early, seed 2 **1/15**, seed 3 0/15, unseeded **1/15**. Both "early" cases are the same
episode: the victim web server 192.168.10.50 (DoS onset), alarmed from 6 of 6 (seed 2) and 5 of 6 (unseeded) pre-onset
origins, lead 300 s and 240 s. Because every pre-onset window of that server already alarms, this reads as the
beginning of the flood being visible in windows still labelled benign (minute-resolution timestamps blur the onset
by up to a minute, and a flood ramps up), not as a forecast. It is one episode on one host and appears in 2 of 4
models only.

Ranking: AUROC of onset origins vs *all* benign-throughout origins is 0.69 / 0.79 / 0.53 / 0.75 (seeds 1, 2, 3,
unseeded), which looks like signal. It is not: restricting the negatives to benign sequences **from the same 9
hosts** gives 0.47 (0.37-0.60) / 0.57 (0.49-0.69) / 0.49 (0.39-0.63) / 0.48 (0.40-0.60), i.e. chance. Hosts that
will become attackers simply have heavier traffic than the 616 benign-only hosts, which inflates the naive number.
Use the same-host figure.

---

## 7. CTU-13: not evaluated, and why

The C2 -> ICMP-DDoS progressions of docs/09 (13 bots: scenario 10 x10, scenario 4 x1, scenario 11 x2) cannot be
scored with the served model, even with an evaluation-only relabel inside eval code:

1. **No score distinguishes the two states.** The infiltration head's target is "stage != benign". A bot in C2 and
   the same bot flooding are both positive, so there is no benign -> attack onset at all (docs/09 section 0.3: every
   infected CTU-13 IP is botnet-labelled from its first flow). The stage head has no `impact` class
   (`STAGE_CLASSIFICATION_LABELS` excludes it and `future_stages` masks it to -1), so relabelling the flood windows as
   impact in eval code would define the episodes but remove them from the only output that could express "flood
   coming". Evaluating them needs a model with an impact output, i.e. training, which was out of scope.
2. **History is too sparse.** Per docs/09, only about 2 of the 13 bots have the 12 non-empty windows the sequence
   length demands, and none are contiguous (6-12 non-empty windows spread over 1.2-1.7 h).
3. The existing processed CTU-13 splits predate the ICMP-drop fix (the flood flows are missing from them), so a fresh
   CTU-13 build would be needed first. Not done: with (1) it would not change the conclusion.

`pipeline/mitre_mapping.py` was not edited and `V:\Datasets\CTU-13-pcaps` was not touched.

---

## 8. Re-run of the QC-3 lead-time metric (README step)

`eval.metrics.lead_time_metrics`, served seed 1, CIC-2018 test, **628 transitions = 12 episodes on 3 hosts**.
Window-step based: it compares the rollout step of the first alarm with the step of the true onset *inside one
sequence*. It is kept here so the README numbers are re-run, not as the measure to use.

| threshold | early (alarm step < onset step) | on-time | late | never alarmed | mean / median lead of the early ones | false alarms (of 5,080) | alarm precision |
|---|---|---|---|---|---|---|---|
| benchmark's own: 5% FPR on val t+1 probs (0.280) | 6 / 628 (1.0%) | 5 | 8 | 609 | 16.7 s / 15 s (n=6) | 116 = 2.3% | 4.4% |
| served 0.40 | 6 / 628 (1.0%) | 4 | 6 | 612 | 16.7 s / 15 s (n=6) | 74 = 1.5% | 6.7% |

Early detections at 0.40 for the other models: seed 2 4/628, seed 3 11/628, unseeded 6/628 (at their own benchmark
thresholds: 11, 11 and 26). These "early" counts are a rollout predicting the attack one or two steps before it
happens inside the same sequence, which is a statement about the rollout, not about warning time: the episode-level
test above, which uses real issue times and real onset times, finds none for the first onset of any CIC-2018 episode.
The README lines that said "pending re-run" now quote these figures.

---

## 9. What the numbers do and do not support

**Supported**

* The served model detects attacks that are already under way (35% of already-attacking sequences alarm at 0.40 on
  CIC-2018; 5 of 12 episodes are caught after onset), with a 1.5% (CIC-2018) and about 0.05-0.1% (CIC-2017)
  false-alarm rate on benign-throughout sequences at 0.40.
* On 12 (CIC-2018) and 15 (CIC-2017, zero-shot) independent episodes there is no advance warning at the served
  threshold: 0/12 (exact upper 95% bound 26%) and 0/15 (22%). The one early alarm anywhere (CIC-2017, victim
  server, two of four models) is not a forecast of a new event.
* The raw sequence-level evidence (628 or 302 onset sequences, 181 or 220 events) overstates the evidence by a factor
  of 15-50. Any future claim must quote the episode count.

**Not supported**

* Any statement of a lead time or warning rate other than "none observed". With n = 12 the CI on a rate of 0 is
  0-26%, so a model that warns a quarter of the time would not be distinguished from this one.
* Any claim that one seed or one change is better: seed-to-seed spread (false alarms 1.5-3.0%, AUROC 0.34-0.55) is
  larger than any episode-level difference.
* Generalisation of anything beyond "an attack is already visible in the traffic": the CIC-2018 events are 3
  network-wide pseudo-hosts (one per day, 8 of 12 episodes on one day) and the CIC-2017 events are 9 hosts of
  which several share one attacker and one victim.
* Equivalence of the 628 / 12-episode "transitions" to host compromise: with network-wide pseudo-hosts an "onset" is
  the whole network's traffic turning hostile, not a host being compromised.

**Bottom line.** The model does not currently give advance warning. It works as a detector that raises the alarm
after, not before, the first attacked window, and when it alarms before a labelled onset the evidence is a single
DoS-victim host. A future model change should be judged by `python -m eval.onset_eval` on exactly these inputs, episode by
episode (which episodes become early, and at what false-alarm rate). At n = 12 the exact interval for 0 early is
0-26%, and 7 of 12 would be needed for the interval to clear it, so a change that warns one or two more episodes is
not distinguishable from noise and should be reported as such.

---

## 10. Not done

* The frozen-state (t+1) ablation re-run under this protocol, per-k AUROC tables for the baselines (LR,
  persistence), and the `impact`-excluded variant (stage counts are in the JSON; impact is 2 of 12 and 3 of 15
  episodes).
* CTU-13 (section 7), victim-keyed onsets (the pipeline keys on `src_ip`; docs/09 counts 18 victim-keyed CIC-2017
  onsets, 12 on one victim), CIC-2018 real-IP days (no onsets there, D-3).
* Retraining with `require_contiguous_windows` (QC-1 / B5): this protocol reports the split instead.
* `merge_gap` is a judgement call (K = 6 windows). `--merge-gap 0` gives the other extreme; neither changes the
  "no early warning" result.

## 11. Reproduce

```text
python -m eval.onset_eval --config configs/real_data_v2_converged_seed1.yaml --label cic2018_seed1
python -m eval.onset_eval --config configs/real_data_v2_converged_seed1.yaml \
    --checkpoint checkpoints_real_v2_converged/seed2/world_model_best.pt --label cic2018_seed2     # seed3 likewise
python -m eval.onset_eval --config configs/real_data_v2_converged.yaml --label cic2018_unseeded
python -m scripts.prepare_dataset V:/Datasets/CIC-IDS-2017 --out data/processed_adapter/cic2017_zeroshot_60s \
    --config configs/cic2017_60s_zeroshot.yaml --split by_unit --allow-experimental \
    --train-units Monday-WorkingHours.pcap_ISCX,Tuesday-WorkingHours.pcap_ISCX,Wednesday-workingHours.pcap_ISCX,Friday-WorkingHours-Morning.pcap_ISCX \
    --val-units Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX \
    --test-units Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX,Friday-WorkingHours-Afternoon-DDos.pcap_ISCX,Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX
python -m eval.onset_eval --config configs/real_data_v2_converged_seed1.yaml \
    --data-dir data/processed_adapter/cic2017_zeroshot_60s --splits train,val,test --label cic2017_zeroshot_seed1
```

Each run takes seconds on GPU or CPU. Results: `docs/onset_eval/<label>.json` (labels: `cic2018_seed1|2|3|unseeded`,
`cic2017_zeroshot_seed1|2|3|unseeded`, and `*_rawevents` for `--merge-gap 0`). Note that `data/processed_adapter` is a
junction into `V:\Datasets\NAF-processed`, so the prepared CIC-2017 dir lives on `V:`.
