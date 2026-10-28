# 14 - Stage forecasting: the first layer of the redesign

**Written 2026-10-17** on branch `test/session-2026-10-10` (nothing committed). No model was trained, no checkpoint,
no existing `data/processed*` directory, `pipeline/mitre_mapping.py`, `eval/onset_eval.py`, `app/server.py` or
`V:\Datasets\CTU-13-pcaps` was touched. New code: `pipeline/stage_events.py`, `models/stage_forecaster.py`,
`eval/stage_forecast_eval.py`, `eval/synthetic_campaigns.py`; tests: `tests/test_stage_events.py`,
`tests/test_stage_forecaster.py`; results: `docs/stage_forecast/*.json` (+ `models/*.json`); events:
`data/processed_adapter/stage_events_*` (a junction into `V:`).

**Bottom line first.** The machinery works and is checked against a known answer on synthetic campaigns. On real data
there is almost nothing to forecast *from*: CIC-2017 contains **one** held-out chain that starts with reconnaissance
(PortScan, then DDoS 171 minutes later), and the forecaster, which has never seen a reconnaissance transition in
training, returns its smoothed prior (log-loss = ln 6, the uniform value). CTU-13 gives C2 -> impact in 3 scenarios;
the leave-one-day-out early-warning rate for first onsets is 1 of 13 [0%-36%] (13 first onsets in 3 scenarios, one training bot).
The 22/34 an order-2 model reaches counts re-onsets inside floods that were already under way. **No
number in this document is evidence that the forecaster predicts real attacks.** It is an honest baseline and the
place to plug in recorded lab campaigns (section 7).

---

## 1. Two-layer design

```
 layer 1  DETECTOR (existing, unchanged)          layer 2  STAGE FORECASTER (this task)
 10 s windows, Transformer world model            minutes-scale, per entity, no learning beyond counting
 current stage per (host, window)  ------------>  stage events  ---->  chains  ---->  Markov next-stage model
 labelled flows / sidecar (ground truth) ------>  (pipeline/stage_events.py)          (models/stage_forecaster.py)
                                                                          P(next = s within H), time to next,
                                                                          likely victims, evidence
```

* The detector stays what docs/13 says it is: it finds attacks already under way (0/12 and 0/15 early warnings on its own).
* A **stage event** is one maximal run of one stage for one entity. Two sources: `label` (ground truth from an adapter or a
  labels sidecar) and `detector` (windows labelled by a model, with a confidence). The forecaster does not care which; the
  `source` column travels with the event so results can be split by it.
* A **chain** is the time-ordered events of one entity with no silence longer than `max_chain_gap` (default 2 h).
  Adjacent events of the same stage inside a chain are collapsed (the stage persisted; it is not a transition).
* The forecaster is a first-order (optionally second-order with backoff) Markov model on stages with an END outcome and an
  exponential time-to-next. It is JSON, pure Python, and loadable by the server later; it is **not** wired into `app/server.py`.

## 2. Entity model (why there are four views)

A kill chain flips direction. Recon and initial access run attacker -> victim; after compromise c2, exfiltration and
lateral movement run victim -> outside. Keying only on source (as the detector does) breaks the chain at the compromise.

| view | entity | sees |
|---|---|---|
| `attacker` | src IP | what one source does to others; its reconnaissance event carries **the targets touched** |
| `victim` | dst IP | what is done to one host |
| `pair` | `src->dst` | one attacker-victim relationship (the reverse direction is a different pair) |
| `host` | dst for reconnaissance / initial_access / impact, src for lateral_movement / command_and_control / exfiltration | the compromised-host chain: recon -> initial access -> c2 -> exfil follows the victim |

Every event stores `srcs` and `dsts` as {ip: flow count} (top 50, true distinct counts in `n_src` / `n_dst`). The forecaster
ranks likely next victims by share of reconnaissance flows per target (attacker/pair views only; `already_targeted_after_recon`
is flagged), and stores the learned share of cases in which the next stage hit a recon target (`p_next_victim_in_recon_targets`).
Which view a result uses is always printed and stored. The synthetic test below shows the attacker view
cannot link initial_access -> c2 (0 of 1,055) while the host view recovers it.

**IP-less data is refused, not repaired.** Per unit (a file / scenario): a row is "pseudo" when `has_ip_data == 0`, the source
starts with `NETWORK-`, or the destination is `UNKNOWN`. A unit with under 50% usable rows is refused (no entity is invented;
`report.json` lists the unit and its usable fraction); stray pseudo rows inside a usable unit are dropped and counted. The CLI
exits with code 2 when nothing is usable. Checked on real files (first 100,000 rows of each CIC-2018 day,
`data/processed_adapter/stage_events_cic2018_flows_check`): **9 of 10 days refused (usable fraction 0.0), Tuesday 20-02 (real IPs)
accepted**. Detector tables are checked the same way (pseudo-host sources refused).

## 3. Definitions

* **Event**: run of one stage for one entity; consecutive items closer than `merge_gap` (default 300 s) join (gap `<=` merges).
  `start` = first item, `end` = last item start (flows carry no end here; detector windows add the window length). Events with
  `duration < min_duration` or fewer than `min_flows` items are dropped and counted (`runs_dropped_by_filters`).
* **Stage** = `pipeline.mitre_mapping.label_to_stage` unchanged: recon, initial_access, lateral_movement, command_and_control,
  exfiltration, **impact** (explicit DoS/DDoS entries *and* every unknown label, see the table in section 6).
* **Transition** a -> b: b is the next event in the chain by *start* time (concurrent events stay visible as overlaps);
  **time to next** = onset-to-onset.
* **END**: the chain provably ended (nothing followed within `max_chain_gap` and the data lasted longer than that after it).
  A chain still open at the end of the data is **censored**: it adds exposure, no transition.
* **Model.** P(next = b | a) = (n_ab + alpha) / (n_a + alpha * |outcomes|) (alpha = 1; outcomes = the 5 other stages + END).
  Given a next stage, onset-to-onset time ~ Exp(mu_a), mu_a = (n_a + 1) / (E_a + 1/mu_pool) with E_a the summed onset-to-onset
  time of followed events plus the elapsed time of censored ones (chains that ended contribute only to P(END): counting their
  silent gap as exposure too would count END twice). **P(next stage = b within H) = P(b|a) * (1 - exp(-mu_a * H))**; what is
  left is "no further stage within H". Second order: P2 = (n2_b + beta * P1_b) / (n2 + beta), used when the (previous, current)
  context has at least `min_support2` observations, otherwise the first-order estimate exactly. `order=0` is the marginal
  (state-blind) baseline with the same machinery.
* **Re-onset**: an item whose next stage already occurred earlier in the same chain. Reported separately everywhere
  (`*_first_onset` / `*_reonset` groups in the JSON); lead with first onsets.
* **Output** (`Forecast.as_dict()`): per-stage P within H, P(next) incl. END, P(any stage within H), expected time to next
  stage, ranked victims, and `evidence` (current event id, order used, the raw transition counts the estimate rests on, END
  probability, the recon events used, training sizes).

## 4. Evaluation protocol (fixed before the results below were produced, except where marked)

Scored item = an event of a held-out chain (headline: each reconnaissance event; CTU-13: each C2 event). Issue time
`t_i = event start + confirm_s` (0 here), `T0` = start of the next event of the chain. The model is fitted **without** the
held-out chain (`fold=chain`), without any chain of its entity (`entity`) or of its calendar day (`day`); leave-out is done by
exact count subtraction, tested to equal a refit. Alarm = P(any next stage within H) >= threshold (0.25 and 0.5, set before
looking). Outcomes use the vocabulary of docs/13 with exact Clopper-Pearson intervals:
`early` (T0 - t_i in (0, H] and alarm; lead = T0 - t_i, real seconds, and whether the model's top stage was the true next
stage), `missed`, `already_started`, `beyond_horizon` / `no_followup` (negatives; alarmed negatives are the false alarms),
`unresolved` (chain censored). Every table also has the order-0 baseline and the trivial always-alarm rule, because with a
state-conditioned alarm that is constant per state, "early" alone means nothing. Also reported: log-loss of the next outcome
(next stage or END), Brier of P(any within H), top-1 next stage. **Horizons H = 3,600 s and 10,800 s are both reported; the
second was added after seeing that the only CIC-2017 recon -> next-stage gap is 171 minutes**, so neither is a prediction made
in advance.

## 5. Results

### 5.1 CIC-IDS-2017 (real labels, all 8 files merged by time, merge gap 300 s, min 5 flows, chain gap 2 h)

Events: attacker view 23 events / 7 entities (recon 6, initial_access 5, lateral 2, c2 6, exfiltration 0, impact 4); the
same 29 -> 23 after `min_flows 5` (6 stray 1-4 flow runs dropped; `min_flows 1` kept in `stage_events_cic2017_minflows1`).
Timestamps have minute resolution, so every lead is quantised to 60 s; the "attacker" is the single NAT address 172.16.0.1.

Merged event list that matters (attacker view, min_flows 1; times are the adapter's, with its AM/PM heuristic):

| entity | stage | start - end | flows |
|---|---|---|---:|
| 172.16.0.1 | initial_access (FTP-Patator) | 07-04 09:17 - 10:20 | 7,937 |
| 172.16.0.1 | initial_access (SSH-Patator) | 07-04 14:09 - 15:11 | 5,897 |
| 172.16.0.1 | impact (DoS Slowhttptest, then Hulk/GoldenEye: events 09:48-10:37 and 10:43-11:19, collapsed; two stray runs of 1 and 5 flows dropped by `min_flows`) | 07-05 09:48 - 11:19 | 252,655 |
| 172.16.0.1 | initial_access (Web Attack) | 07-06 09:15 - 10:42 | 2,180 |
| 192.168.10.8 | lateral_movement (Infiltration) | 07-06 14:19 - 15:45 | 36 |
| 172.16.0.1 | **reconnaissance (PortScan), 6 raw events** (13:05, 13:52, 14:14, 14:51, 15:03, 15:21) | 07-07 13:05 - 15:23 | 158,930 |
| 172.16.0.1 | **impact (DDoS)** | 07-07 15:56 - 16:16 | 128,024 |
| 192.168.10.5/8/9/14/15 (+205.174.165.73 as reverse flows) | command_and_control (Bot) | 07-07 10:04 - 12:59 | 180-371 each |

The six PortScan events collapse into **one** recon event (13:05) whose successor is the DDoS 171 minutes later. This is the
only reconnaissance-originated transition in the whole dataset. Other adjacent pairs (impact -> initial_access on 07-05,
48 min) are artefacts of the lab schedule. Linking across nights needs `max_chain_gap` of about 19 h or more and makes every chain
"censored" (nothing terminates inside a 4-day capture); that variant is reported only to show it changes the answer.

**Transition counts (attacker view, all 13 chains, in-sample and descriptive only):** recon -> impact 1; initial_access -> END 4;
lateral_movement -> END 1; command_and_control -> END 6; impact -> END 1, impact -> initial_access 1. Host view: the same except
impact -> END 2. 15 events, 2 transitions that are not END; chain lengths: 11 chains of 1 event, 2 chains of 2.

**Held-out recon -> next stage (leave-one-chain-out; leave-one-entity-out gives the same outcomes but a different probability, see below):**

| setting | held-out recon chains | result |
|---|---:|---|
| H = 3,600 s, either threshold | **1** | next stage starts 10,260 s later: `beyond_horizon`, 0 positives, so no early-warning rate exists; the alarm at 0.25 counts as a false alarm (1/1) |
| H = 10,800 s, thr 0.25 and 0.5 | **1** | early 1/1 = 100% **[3%-100%]**, lead 10,260 s (171 min), **top stage wrong** (stage-correct 0/1), log-loss 1.792 nats = ln 6 (uniform prior), P(any within H) = 0.81 |
| H = 10,800 s, leave-one-ENTITY-out (all 172.16.0.1 chains removed) | **1** | same outcome (early 1/1 at both thresholds, top stage wrong, log-loss ln 6), but P(any within H) = 0.65 instead of 0.81 because the pooled rate changes; Brier 0.124 vs 0.035 |
| same, order-0 baseline | 1 | early at 0.25, missed at 0.5; always-alarm rule: early 1/1 |
| overnight linking (chain gap 48 h) | 1 | missed (the pooled rate over day-long gaps makes P(any within H) < 0.25) |
| `min_flows 1` | 1 | same as the main row |

The 171 minutes are measured from the 13:05 recon run, which is only 7 flows and survives `min_flows 5`; the bulk of the scan
starts at 13:52 (lead 124 min) and the heavy 138,493-flow burst at 14:51 (65 min). Read it as: one held-out chain, an interval of 3%-100%, and a model with no data on reconnaissance. The "early" is the prior
saying "something probably follows" (any stage, at 0.81), which the always-alarm rule also gets. Likely-victim ranking: 1/1
trivially (one victim, 192.168.10.50); note the ranking uses the destination counts of the completed recon event, i.e.
information that only exists after the issue time, so hit@k is an upper bound on what a live forecast could rank. Over all 15 events the pooled state-conditioned model is no better than the baseline
(paired log-loss order1 - order0 = +0.17 nats at H = 10,800 for leave-one-chain-out, n = 14 events, 13 chains).

### 5.2 CTU-13, C2 -> impact (evaluation relabel, 13 scenarios, attacker view)

`pipeline.stage_events.ctu13_icmp_flood_as_impact`: botnet-labelled ICMP flows of scenarios 4, 10, 11 are 'impact' (the ICMP
DDoS). It lives only in the new module, is printed in the report notes, and `label_to_stage` is untouched (a test asserts
both). ICMP rows survive the ctu13 adapter (scenario 11: 12,805 ICMP flows through `read_flows`, 8,143 botnet ICMP, equal to
the raw `.binetflow`). Entities are scoped per scenario (the same bot IPs recur). Merge gap 300 s, min 5 flows: 128 events (84
c2, 44 impact), 35 bot entities, 46 chains (43 terminated, 3 censored in scenario 12).

Fold = calendar day (scenarios 10 and 11 share 2011-08-18). 34 C2 events are followed by impact, but they are **not 34
episodes**. Scenario 10's bots alternate c2, impact, c2, impact, c2, impact, and most of those C2 events are heartbeats
*between flood bursts*: the impact already happened in that chain. So every item is split (`reonset` = the next stage already
occurred earlier in the same chain; the same discount as docs/13 section 5):

* **first onsets: 13 events** = scenario 10 x10 (one per bot), scenario 11 x2, scenario 4 x1 (3 independent scenarios; the 10 bots of
  scenario 10 run one botmaster schedule, so the real n is smaller than 13 and every interval below is too narrow);
* **re-onsets: 21 events** (scenario 10 x20, scenario 4 x1).

Leave-one-day-out, alarm threshold 0.25 (0.5 gives the same first-onset numbers):

| group | H | order | early / positives | exact 95% CI | alarms on never-followed C2 events |
|---|---|---|---|---|---|
| **first onset** | 10,800 s | 1, 0 and 2 (identical) | **1/13** | **0%-36%** | 30/31 |
| first onset | 3,600 s | 1, 0 and 2 | 0/2 | 0%-84% | 31/42 |
| re-onset | 10,800 s | 1 | 1/21 | 0%-24% | - |
| re-onset | 10,800 s | **2** | **21/21** | 84%-100% | - |
| all 34 (not an independent-episode count) | 10,800 s | 1 / 2 | 2/34 / 22/34 | 1%-20% / 46%-80% | 30/31 |

The headline is the first row: **1 of 13 first onsets (a lead of 97 minutes, scenario 4, trained on scenario 10/11 data), the
other 12 not warned (0 of 10 in scenario 10, 0 of 2 in scenario 11) because with 08-18 held out the training set contains one
bot of scenario 4 with 1 first and 1 re-onset against 31 C2 events that were never followed.** Order 2's 22/34 is not a
forecast of an attack: it scores re-onsets by construction (the context "previous stage = impact" appears only after a flood has
begun) and learned that context from a single bot of scenario 4. For first onsets order 2 backs off to order 1 and the paired
log-loss against the marginal baseline is **+0.011 nats** (1.518 vs 1.507, n = 44, i.e. state does not help), and the Brier score
of P(any within H) is worse than the baseline's (0.510 vs 0.463). The alarm fires on 30 of the 31 C2 events that are never
followed: P(any stage) is one number per state, so the threshold cannot separate chains that continue from chains that stop.
That separation needs a signal beyond the stage (volume, rate of new targets, detector confidence). In-sample counts
(descriptive): c2 -> impact 34, c2 -> END 31; impact -> c2 22, impact -> END 12.

### 5.3 Synthetic campaigns (a correctness check of the machinery, NOT evidence about real data)

`eval/synthetic_campaigns.py`: recon (PortScan, A -> V and 3 decoy targets) -> p=0.70 initial_access (A -> V) -> p=0.60 c2
(V -> C2 server: the direction flips) -> p=0.50 exfiltration (V -> drop server), gaps Exp(420, 600, 480 s), distinct IPs per
campaign, 60 benign background flows per campaign. Seed 0, 1,500 campaigns, host view (no decoys), through event building ->
chains -> fit:

| transition | n | observed | truth | exact 95% CI | truth inside | mean gap est / truth |
|---|---:|---:|---:|---|---|---|
| recon -> initial_access | 1,500 | 0.680 | 0.70 | 0.656-0.704 | yes | 419 / 420 s |
| initial_access -> c2 | 1,020 | 0.606 | 0.60 | 0.575-0.636 | yes | 554 / 600 s |
| c2 -> exfiltration | 618 | 0.487 | 0.50 | 0.447-0.527 | yes | 480 / 480 s |

Further checks (all in `tests/test_stage_forecaster.py`): in the **attacker** view recon -> initial_access is recovered
(0.704) but initial_access -> c2 is 0 of 1,055, i.e. the link is invisible without the host view; with 3 decoy targets the
**host** view dilutes recon -> initial_access to about 0.7/4 while the attacker view keeps 0.70; when half the chains end after
recon P(END) is recovered as 0.5 and the mean gap stays 200 s (END does not distort the rate); right-censoring adds exposure
only; second order separates two contexts the first order averages; the held-out chain is provably absent from its own
training set (smoothed prior 1/16 vs 2/16 when included); victim ranking by recon share has hit@1 0.29 / hit@3 0.79 on
4 equiprobable targets, which is chance by construction (the generator gives no signal there). On held-out synthetic chains the
state-conditioned model beats the marginal baseline on log-loss (0.61 vs 0.99 nats, attacker view), as it must.

## 6. What the numbers do and do not support

**Supported.** (0) Splitting first onsets from re-onsets changes the CTU-13 headline from 22/34 to 1/13; report it that way.
(1) The pipeline turns labelled flows, sidecar-labelled captures and detector tables into stage events and chains
with per-entity target sets, and refuses IP-less units. (2) The estimator recovers known transition probabilities and
timing on synthetic data, including the direction flip and chain endings. (3) On CIC-2017 reconnaissance is followed by impact
exactly once; on CTU-13 C2 is followed by an ICMP flood in 3 scenarios.

**Not supported.** Any statement of a warning rate or lead time for real attacks: n = 1 held-out chain for recon (interval
3%-100%); 13 first onsets in 3 scenarios for C2 -> impact (1/13, 0%-36%); a threshold rule that alarms on 97% of the chains
that go nowhere. Not supported: any reading of the order-2 CTU-13 figure (21 of 21 re-onsets from one training bot) as foresight. The "early" outcomes quoted for the prior-only
model show the metric is satisfiable by a model that knows nothing. Nothing here says the Transformer is, or is not, worth
adding.

**Label vocabulary for lab recordings.** `label_to_stage` is the only gate; a spelling it does not know becomes **impact**
silently (`Exfiltration`, `exfil`, `recon` all do). Asserted in `tests/test_stage_events.py`:

| stage | sidecar `label` strings that map to it |
|---|---|
| reconnaissance | `PortScan` |
| initial_access | `SSH-Bruteforce`, `FTP-BruteForce`, `Brute Force -Web`, `SQL Injection`, `FTP-Patator`, `SSH-Patator` |
| lateral_movement | `Infiltration` (`Infilteration`) |
| command_and_control | `Bot` |
| exfiltration | `SYNTH-Exfiltration` (the only exfiltration label; `nf=...exfil...` for NetFlow datasets) |
| impact | `DDoS attacks-LOIC-HTTP`, `DoS attacks-Hulk`, ... and anything unknown |

Detector input is aggregated per original window (destination fan-out does not inflate `n_flows` or the confidence mean;
tested). Detector tables: the world model's stage head has no impact class and reconnaissance comes from a heuristic
(`stage_is_heuristic`); a detector's predicted stage is for t+k, so shift `window_start` accordingly. **The detector path
(`events_from_detections`) is unit-tested only; it was not run on real model output in this task.**

## 7. Plugging in recorded lab campaigns

1. Record a PCAP per scripted campaign (IPv4 TCP/UDP; ICMP is skipped by the PCAP adapter). 2. Write the labels sidecar
(`pipeline/adapters/sidecar.py`): one row per scripted action, a flow matches in either direction when its start time is in
`[start, end]`, a blank IP is a wildcard, epoch seconds or ISO accepted, labels from the table above:

```text
src_ip,dst_ip,start,end,label
10.0.0.66,10.0.0.5,2026-11-02 14:00:00,2026-11-02 14:03:30,PortScan
10.0.0.66,10.0.0.5,2026-11-02 14:08:00,2026-11-02 14:12:00,SSH-Bruteforce
10.0.0.5,203.0.113.9,2026-11-02 14:20:00,2026-11-02 14:40:00,Bot
10.0.0.5,203.0.113.50,2026-11-02 14:45:00,2026-11-02 14:50:00,SYNTH-Exfiltration
```

3. Build the events (use short gaps for minutes-long campaigns) and 4. evaluate, many campaigns with distinct victims, then
hold out whole campaigns:

```text
python -m pipeline.stage_events --input captures/lab1 --adapter pcap --labels-sidecar captures/lab1/labels.csv \
    --name lab1 --views host,attacker,pair --merge-gap 30 --min-flows 5
python -m eval.stage_forecast_eval --events-dir data/processed_adapter/stage_events_lab1 --view host \
    --fold entity --horizon 600 --thresholds 0.25,0.5 --max-chain-gap 3600 --label lab1_host
```

Merge several captures by concatenating the sidecars and giving each campaign its own IPs (or time separation above
`max_chain_gap`); use `--unit-scoped` when scenarios reuse addresses. Detector output instead: `--detections table.csv`
(columns `host,window_start,stage,confidence[,window_s,dst_ips]`). Re-run section 5.3's check (`--synthetic`) after any
change to the estimator.

Reproduce this document:

```text
python -m pipeline.stage_events --input V:/Datasets/CIC-IDS-2017 --adapter cicids2017 --name cic2017 --merge-gap 300 --min-flows 5
python -m eval.stage_forecast_eval --events-dir data/processed_adapter/stage_events_cic2017 --view attacker --fold chain --horizon 10800
python -m pipeline.stage_events --input V:/Datasets/CTU-13 --adapter ctu13 --name ctu13_icmp_impact --relabel ctu13-icmp-impact \
    --views attacker --unit-scoped --merge-gap 300 --min-flows 5
python -m eval.stage_forecast_eval --events-dir data/processed_adapter/stage_events_ctu13_icmp_impact --view attacker \
    --fold day --horizon 10800 --focus-stage command_and_control
python -m eval.stage_forecast_eval --synthetic --view host --n-campaigns 1500
```

## 8. Next steps

* Record 30-100 scripted campaigns (varying stage subsets, orders, victims, speeds); the Markov baseline needs transition
  counts it cannot get from public data. Report held-out campaigns with their count, as in docs/13.
* Add a *continuation* signal so the alarm can separate chains that go on from chains that end (recent volume, number of
  targets, detector confidence); today P(any within H) is constant per state.
* Only then consider a sequence model (Transformer over event sequences) -- and only if it beats the order-1/2 Markov model
  and the order-0 baseline on held-out campaigns by a margin its interval clears.
* Run the detector path on real model output (LiveEngine `collect_final`, stage predictions shifted by their step) and
  compare detector-sourced with label-sourced events on the same capture; wire the JSON model into the server last.

## 9. Decisions and limitations

`merge_gap` 300 s, `min_flows` 5, `max_chain_gap` 2 h, H and thresholds are judgement calls (sensitivity shown where it
changes the answer). Event end = last flow *start*. Bot flows are bidirectional in CIC-2017, so the reverse direction creates
a spurious "c2" entity for 205.174.165.73 in the attacker/host views. Exposure is truncated at `max_chain_gap`, so mu is
biased slightly high for slow transitions. Alpha-smoothing gives every impossible-looking transition at least 1/(n+6), which
is why a prior-only model still scores a "positive" probability. The CTU-13 relabel is an evaluation device, not a mapping change.
