# 20 - Research: options to improve detection and forecasting (SIH 2026, PS 26153)

Written 2026-10-19 by a research subagent (web search and fetch, about 45 lookups) after reading
docs/13, 14, 16, 18, 19, parts of docs/05 and the README layout. No repo files were modified by
the research itself; this file records its report.

## Reading guide: how each source was checked

Every citation carries one of three tags:

- **[FULL]**: the text was read (arXiv HTML or the official page).
- **[ABS]**: only the abstract or a catalogue record was read.
- **[SNIP]**: seen only in a search-result snippet. Treat it as a lead, not a fact.

Paragraphs headed "Inference" are the researcher's own reasoning, not the literature's. Numbers
that could not be obtained are listed in section 10; none were filled in from memory.

## 0. Executive summary

1. **Both failure modes are data problems, not model problems.** The repo's own diagnostics
   (docs/16, 18, 19) already show this.
   - docs/19 tried 13 arms: feature hygiene, causal temporal features, nested tuning, RF/ET/LR,
     calibration, secondary labels. None beat the incumbent (`HGB_stacked` 0.818) or `flow_count`
     (0.812) by the pre-registered margin.
   - The next gains must come from new data and a different unit of analysis (flows, real hosts,
     real chains), not from more modelling on the 7 spent or truncated CIC-2018 days.
2. **Question 1 has little direct literature.**
   - No paper was found that directly compares per-flow scoring plus per-host aggregation against
     window-aggregate features for sparse web or brute-force attacks.
   - The case for flow-level scoring rests on the repo's own measurement (docs/16 F2): median 2
     attack flows among about 250 per positive window on 02-22/02-23, persistence oracle 0.61-0.68.
   - Treat it as a justified experiment, not an established result.
   - The one aggregation paper opened ([FULL], section 1) points the other way for slow DoS.
3. **Cross-dataset transfer is poor in the literature too.**
   - Layeghy & Portmann [FULL]: no model generalised across four NetFlow-v2 datasets. Average F1
     decay was 56.3% for supervised and 28.3% for semi-supervised models, and transfer was strongly
     asymmetric.
   - So the CTU-13/UNSW non-transfer in docs/16 is the expected outcome, not a sign of a bug.
   - The practical lesson: include attack data from the deployment network in training (Apruzzese
     et al. [ABS]). That is the same lab-recording plan that forecasting needs.
4. **Forecasting literature predicts over IDS alert sequences, not raw flows.**
   - Evidence: Tiresias [ABS], Băbălău & Nadeem [ABS], AIDA [SNIP], Kholidy et al. [SNIP].
   - This supports the repo's two-layer design (docs/14) and suggests adding signature-IDS alerts
     (Suricata, already in the lab via Security Onion) as an event source.
5. **No public dataset gives enough independent multi-stage chains.**
   - DARPA 2000 has 2 scenarios. DAPT2020 has 1 campaign with one stage per day. Unraveled has 1
     scenario. CIC-2017/2018 have about 1-2 recon-led chains. LANL and OpTC are not network chains
     and are not realistic this month.
   - docs/16 F9 says about 25 independent episodes are needed to show a 30% early-warning rate
     against a 10% null. Only recorded lab campaigns can reach that.
   - If the early-warning claim is to exist at all, lab campaigns are the critical path. Start them
     in week 1.
6. **A possible fix for the pseudo-host problem needs verification first.**
   - NF-CSE-CIC-IDS2018-v3 (UQ) is regenerated from the original PCAPs with nProbe. Per its paper
     [FULL] it carries source/destination IPs and `FLOW_START_MILLISECONDS`/`FLOW_END_MILLISECONDS`.
   - The UQ page [FULL] says v3 is "the only version incorporating temporal features". So v2 files
     cannot be windowed, which is why `pipeline/adapters/netflow_v2_adapter.py` rejects them.
   - The download page and CSV header could not be opened (403 and an empty record). Confirm the
     columns before committing time.
   - Caveat: labels were matched by 5-tuple and time against the original ground truth, with no
     correction step mentioned, so they inherit CIC's label errors.
7. **Ranked options.**
   - Detection: D1 (CIC-2017 PCAP re-extraction with the live extractor), D2 (flow-level scorer
     with per-host aggregation), D3 (alert-budget thresholds), D4 (NF-v3 per-host CIC-2018 as a
     diagnostic), D5 (benign-only anomaly score as a second opinion).
   - Forecasting: F1 (randomised lab campaigns, critical path), F2 (Suricata alerts as an event
     source), F3 (continuation/hazard signal), F4 (campaign-level lead-time metric), F5 (target
     forecasting), F6 (DARPA 2000 as a regression test only).
   - Details in section 7.

## 1. Detection at flow level vs window aggregates, and what generalises

### What the literature shows

- **Flow aggregation helped one narrow case [FULL].** "Utilising Flow Aggregation to Classify
  Benign Imitating Attacks" (https://pmc.ncbi.nlm.nih.gov/articles/PMC7961933/; journal and year
  not confirmed).
  - It adds bundle-level features on CIC-IDS-2017.
  - Only the benign-mimicking slow DoS attacks improved: Slowloris recall 83.69% to 91.31% (binary),
    SlowHTTPTest 65.94% to 70.03%.
  - PortScan and Hulk were already about 99%.
  - Caveats stated in the paper: huge standard deviations (up to ±47%), 5-fold vs 10-fold
    inconsistency, one dataset.
  - Relevance: aggregation helps when many weak flows add up, the opposite of our sparse case.
- **NetFlow standard feature sets [FULL].** Sarhan, Layeghy, Portmann, "Towards a Standard Feature
  Set of NIDS Datasets" (https://arxiv.org/abs/2101.11315).
  - Regenerates UNSW-NB15, BoT-IoT, ToN-IoT and CSE-CIC-IDS2018 as NF-*-v2 with 43 NetFlow features.
  - In-dataset Extra Trees F1 is 0.97 on NF-UNSW-NB15-v2 and NF-CSE-CIC-IDS2018-v2.
  - IPs are in the schema but dropped before training.
  - It reports **no cross-dataset experiment**.
- **Temporal NetFlow [FULL].** Luay et al., "Temporal Analysis of NetFlow Datasets for NIDS"
  (https://arxiv.org/abs/2503.04404).
  - v3 adds 10 temporal features, including `FLOW_START_MILLISECONDS`/`FLOW_END_MILLISECONDS` and
    inter-arrival-time statistics.
  - Built with nProbe from the official PCAPs using `--dont-reforge-time`.
  - Labels come from 5-tuple plus time matching against each dataset's ground truth; no label
    correction is mentioned.
  - It reports no classifier results.
  - The UQ page [FULL] (https://staff.itee.uq.edu.au/marius/NIDS_datasets/) lists
    NF-CSE-CIC-IDS2018-v3 at 20,115,529 flows and v2 at 18,893,708. It states no licence or file
    sizes.
- **Label and flow-construction errors [FULL/ABS].**
  - Engelen, Rimmer, Joosen (WTMC 2021, https://intrusion-detection.distrinet-research.be/WTMC2021/)
    [FULL page]: errors in traffic generation, flow construction, feature extraction and labelling;
    "more than 20 percent of original traffic traces are reconstructed or relabelled" for
    CIC-IDS-2017.
  - Liu, Engelen, Lynar, Essam, Joosen (IEEE CNS 2022; https://archive.cps-vo.org/node/97449) [ABS]:
    many undocumented errors across attack orchestration, feature generation, documentation and
    labelling; recreated data released with corrected labelling logic. No error-rate number was
    obtained from the paper itself.
  - Code `GintsEngelen/CNS2022_Code` [FULL page]: labelling notebooks only, no corrected CSV on the
    page, **no licence stated**, described as research code. Their fixed CICFlowMeter is a separate
    repo.
  - Search snippets [SNIP] also mention a regenerated CIC-2017 at
    `downloads.distrinet-research.be/WTMC2021`, LYCOS-IDS2017, and BCCC-CSE-CIC-IDS2018.
- **BCCC-CSE-CIC-IDS2018 [FULL page].** https://www.yorku.ca/research/bccc/?p=2839
  - 46M labelled records, 300 features.
  - DoS labels realigned by attacker IP instead of timestamp; attacks with too few flows kept but
    excluded from analysis.
  - Access by request form. No licence stated; the page does not say whether Src IP or timestamp
    columns exist.
- **The flow exporter changes results [ABS].** "Flow Exporter Impact on Intelligent IDS"
  (https://arxiv.org/abs/2412.14021).
  - Models trained on data re-exported from PCAP with the HERA exporter did better than on the
    original UNSW-NB15 and CIC-IDS2017 CSVs.
  - Better generalisation is also reported; how it was tested was not seen.
- **Cross-dataset generalisation.**
  - Layeghy & Portmann, "On Generalisability of ML-based NIDS" (https://arxiv.org/abs/2205.04112)
    [FULL via ar5iv]. Seven models (Extra Tree, RF, FFNN, LSTM supervised; Isolation Forest,
    One-Class SVM, SGD-oSVM semi-supervised) on NFv2 BoT-IoT, CIC-2018, ToN-IoT and UNSW-NB15, with
    1M-flow samples.
    - Best supervised transfer: Extra Tree UNSW-NB15 to BoT-IoT at F1 94.83%. The reverse
      direction gave 4.90%.
    - Several pairs scored 0.00%.
    - Average decay: supervised 56.28%, unsupervised 28.33%. Isolation Forest decayed 49.73%,
      oSVM and SGD-oSVM 17.90% and 17.36%.
    - SHAP points to reliance on one or a few dataset-specific features (for example MAX_TTL).
    - No remedy is offered; future work targets methods that compensate for feature shift.
  - Apruzzese, Pajola, Conti, TNSM 2022 (https://arxiv.org/abs/2203.04686) [ABS]: across six
    datasets, attack traffic from the operational network at training time is "crucial" to avoid
    F1 degradation when the network changes. No per-dataset numbers seen.
  - DI-NIDS (https://arxiv.org/abs/2210.08252) [ABS]: domain-adversarial feature extractor plus
    One-Class SVM on NFv2-CIC-2018 and NFv2-UNSW-NB15. Claims superior cross-domain performance;
    the abstract gives no numbers.
  - Anomal-E (https://arxiv.org/abs/2207.06819) [FULL]: self-supervised E-GraphSAGE plus
    unsupervised detectors. NF-CSE-CIC-IDS2018-v2 macro-F1 95.39% with Isolation Forest, 10%
    downsampled, trained and tested within each dataset. **No cross-dataset experiment.**

### Inference (not literature)

- The per-flow idea: score each flow, then raise a window or host alert from the top-k flow scores
  or the count of flows above a threshold. It targets docs/16 F2 directly.
- Expect it to help sparse application-layer attacks (brute-force web, XSS, SQLi), where the signal
  is in a few flows rather than in aggregates dominated by about 250 benign flows.
- Expect it **not** to fix transfer (Layeghy) or the volumetric days.
- Risks:
  - Flows of one attack session split across train and test.
  - Label noise on exactly these web-attack classes (Engelen/Liu).
  - Drop IPs and ports from features. 02-22 and 02-23 share attacker 18.218.115.60 and the same
    tools (CIC page [FULL]), so training on one and testing on the other is a replay, not
    generalisation.

## 2. Detection without good labels (one-class, anomaly, self-supervised)

- **Kitsune** (Mirsky et al., NDSS 2018, https://arxiv.org/abs/1802.09089) [ABS].
  - An ensemble of autoencoders (KitNET) over per-channel incremental statistics; learns online and
    unsupervised; claims performance comparable to offline anomaly detectors, on a Raspberry Pi.
  - Repo `ymirsky/Kitsune-py` [FULL page]: MIT licence; the example uses FMgrace 5000 and ADgrace
    50000; the author says the pure-Python version "is not optimal" and the paper's speed needs
    Cython or C++.
  - **The paper's results were not read, so no EER/AUC is quoted.** It works at packet level with
    its own statistics, so it does not drop into the flow-window pipeline without a new extractor.
- **DAPT2020 benchmark** (paper mirror:
  https://www.readkong.com/page/dapt-2020-constructing-a-benchmark-dataset-for-advanced-9939780)
  [FULL].
  - Benign-only stacked autoencoder, LSTM-SAE and One-Class SVM.
  - SAE AUC-ROC 0.641 (reconnaissance) and 0.846 (foothold); poor on lateral movement (AUC-PR
    0.0136) and exfiltration. The text and Table 5 conflict on which model is best.
  - So benign-only detectors are weak on the later, low-volume stages, the ones forecasting needs.
- **Layeghy & Portmann** [FULL]: semi-supervised models degraded less across datasets (28.3% vs
  56.3% average F1 decay) but start lower; Isolation Forest was the unstable one.
- **Repo evidence.** docs/19: the label-free adaptive threshold rule (alarm above the 99th
  percentile of the previous 360 scores) held FPR within 3x of target on 5-6 of 6 pseudo-host days,
  with recall 0.4-17%. Rolling-baseline features (S6) did not raise AUROC.
- **False-alarm behaviour.** Sommer & Paxson 2010 (DOI 10.1109/SP.2010.25) [ABS/SNIP] is the
  standard argument that error costs and the semantic gap make anomaly detection hard to operate.
  Its text was not read.
- **Inference.** An anomaly score will not rescue the sparse days or forecasting. Its most
  defensible role is a second opinion and an alarm-budget control. Its cross-network false-alarm
  behaviour on our data is unmeasured until D3 and D5 run.

## 3. Attack forecasting and early-warning literature

- **Survey.** Husák, Komárková, Bou-Harb, Čeleda, "Survey of Attack Projection, Prediction, and
  Forecasting in Cyber Security", IEEE Commun. Surveys & Tutorials 21(1), 2019, DOI
  10.1109/COMST.2018.2871866. Record: https://www.ics.muni.cz/en/research/publications/1434138
  [ABS].
  - Three tasks: projection/intention recognition, intrusion prediction, situation forecasting.
  - Discrete models (attack graphs, Bayesian networks, Markov) versus continuous ones (time series,
    grey models), plus ML; also covers evaluation difficulties.
  - **The full text could not be read**, so the inputs and lead times it tabulates are unknown.
  - Husák et al., "Predictive Methods in Cyber Defense" (Future Gener. Comput. Syst., DOI
    10.1016/j.future.2020.10.006; https://ics.muni.cz/en/research/publications/1682977) [ABS]:
    three methods run in an alert-sharing platform; time-series forecasting is accurate but does not
    say which events.
- **Inputs actually used.**
  - Tiresias, CCS 2018 (https://arxiv.org/abs/1905.10328) [ABS]: RNN over about 3.4 billion IPS
    events; predicts the next event on a machine; precision up to 0.93.
  - Băbălău & Nadeem (https://arxiv.org/abs/2408.09888) [ABS]: next-action forecasting from alert
    datasets with a suffix automaton; 67.27% average top-3 accuracy over three alert/endpoint
    datasets (not named in the abstract); no horizon stated.
  - AIDA, Husák & Kašpar, ARES 2019 (https://ics.muni.cz/en/research/publications/1540256) [SNIP]:
    sequential-rule mining of IDS alerts, deployed on an alert-sharing platform.
  - Kholidy et al. (https://archive.cps-vo.org/node/19443) [SNIP]: an HMM predictor claims warnings
    "39.6 minutes before the launching of the LLDOS 1.0 attack"; a companion variable-order Markov
    paper claims 58.98 minutes.
    - Treat these as self-reported lead times on a scripted five-phase chain, measured to the final
      DDoS.
    - They do not show that the final attack was forecast from independent evidence; the early
      phases are themselves detectable.
  - PARD-SSM (https://arxiv.org/abs/2604.02299) [ABS]: claims F1 98.2% on CICIDS2017 and 97.1% on
    UNSW-NB15, with warnings about 8 minutes before onset. The abstract does not define lead time,
    and it is a single unreviewed preprint.
- **Pattern.** Nearly all of this work forecasts over alerts or typed events, evaluates on one or
  two campaigns or on proprietary telemetry, and reports lead time to a scripted final stage.
- **What is realistic in 2-3 weeks on our data (inference).**
  - Not a forecaster that warns before a first onset on public data: docs/13 and 14 show 0/12, 0/15
    and 1/13 first-onset warnings, and public data has about 1-2 recon-led chains.
  - Realistic: (a) a stage-event layer over detector plus alert events, evaluated on 30+ randomised
    lab campaigns with negative chains; (b) a campaign-level lead time (alarm at stage k before a
    later stage m) with false alarms per benign hour; (c) a hazard or continuation signal beyond a
    per-state constant.
  - Any claim beyond that needs the held-out count printed next to it.

## 4. Datasets with multi-stage chains (verified status)

| Dataset | What it holds | Independent chains | Access / size / licence (as seen) | Realistic this month? |
|---|---|---|---|---|
| DARPA 2000 LLDOS 1.0 and 2.0.2 [FULL page: https://www.ll.mit.edu/r-d/datasets/2000-darpa-intrusion-detection-scenario-specific-datasets] | Five-phase DDoS scenario (probe, sadmind exploit, mstream install, DDoS); data and labels per scenario; NT dataset with event logs, tcpdump and truth file | 2 scenarios | Downloads via archive.ll.mit.edu links; no sizes or terms stated | Yes (small), as a **regression test only**. Synthetic and 2000-era. Phase 1 is an ICMP sweep (inference), which the PCAP adapter skips |
| DAPT2020 [FULL: paper mirror; COMIDDS row https://fkie-cad.github.io/COMIDDS/content/all_datasets/] | Five days: baseline, recon (day 2), foothold (3), lateral movement (4), exfiltration (5); pcap and host logs; COMIDDS lists NetFlows and logs, 460 MB packed | 1 campaign, **one stage per day** | Paper points to GitLab (gitlab.thothlab.org); untested, may be gone. No licence seen | Maybe. Stage = day, so no within-chain per-host timing |
| Unraveled (Myneni et al. 2023) [COMIDDS row + SNIP] | Cloud APT emulation; pcaps, syslog, audit, auth, Snort; about 22 GB unpacked; snippet suggests about 6.86M flows over about 40 days | 1 scenario | No download link found | Unknown |
| CPTC-2018 (Munaiah et al. 2019) [SNIP] | Suricata alerts and other events from six teams (snippet: over 500M events) | 6 team chains, alert-level | huggingface.co/globalcptc [FULL] showed "None public yet"; cp.tc/research returned 404 | Unverified. Worth one email, not a plan dependency |
| LANL multi-source [FULL: https://csr.lanl.gov/data/cyber1/] | 58 days, 1.65B events; auth, process, DNS, router flows; `redteam.txt.gz` 4.8 KB | Red-team **authentication** events, not network chains | CC0 1.0; email and use description required; about 12 GB | Downloadable but low relevance (1 s flow resolution; labels are auth events) |
| OpTC [FULL: https://github.com/FiveDirections/OpTC-data] | About 1 TB, 500 hosts, endpoint eCAR plus Bro, red-team ground-truth PDF | Few campaigns, endpoint-centric | Google Drive; "Distribution A", public release | **No** (size, endpoint data) |
| CIC-IDS-2017 [FULL: https://www.unb.ca/cic/datasets/ids-2017.html] | Daily PCAPs about 7.8-13 GB (about 51 GB total); one attacker NAT 172.16.0.1, victims 192.168.10.x; per-day schedule | About 1-2 recon-led chains (PortScan then DDoS on Friday) | No licence or registration stated on the page | Yes (being downloaded) |
| CSE-CIC-IDS2018 [FULL: https://www.unb.ca/cic/datasets/ids-2018.html] | PCAP per day plus CSVs; AWS bucket (no-sign-request); per-day schedule and attacker IPs | Near zero chains (one attack family per day) | Redistribution allowed with citation; sizes not stated | PCAPs impractical (36-55 GB per day) |
| CTU-13 [FULL: https://www.stratosphereips.org/datasets-ctu13] | 13 botnet captures; 1.9 GB tar.bz2; botnet-only pcaps and bidirectional NetFlows (full pcap withheld for privacy) | Bot behaviour; C2 then flood in a few scenarios | No licence stated | Already in repo |
| CasinoLimit, DEDALE (COMIDDS rows) [FULL row only] | CasinoLimit 2025: NetFlows, syslog, auditd; MITRE-labelled; "no benign behavior"; 3.6 GB packed. DEDALE 2025: APT against 55 machines over four weeks, 2.96 TB packed | CasinoLimit: possibly many player chains (inference) | Not opened beyond the row | CasinoLimit: check; DEDALE: no |

**Conclusion.** No public set reaches about 25 independent episodes with per-host timing. Recorded
lab campaigns are the only route to a defensible early-warning rate. Public sets are regression
tests, not evidence.

## 5. Lab data generation best practice

What could be verified:

- **Benign realism.** CIC-IDS-2017 used a B-Profile system that profiled 25 users' abstract
  behaviour (HTTP, HTTPS, FTP, SSH, email) to generate background traffic ([FULL page]). A 2025
  survey (https://arxiv.org/abs/2502.06688) [SNIP] distinguishes real, emulated and synthetic
  traffic and notes real traffic cannot be declared purely benign.
- **Adversary emulation tooling.** MITRE Caldera (https://caldera.readthedocs.io) [SNIP] runs
  ATT&CK-mapped abilities and adversary profiles through agents. Whether it randomises ability
  order was not confirmed.
- **DAPT2020** [FULL mirror]: a red team told to stay stealthy ran the attacks, mirroring real APT
  groups' techniques; students generated normal traffic. The authors note real APTs are slower than
  their five days.
- **The lesson from failures [FULL].** Arp et al., "Dos and Don'ts of ML in Computer Security"
  (https://arxiv.org/abs/2010.09470, read via ar5iv): sampling bias is at least partly present in
  90% of 30 reviewed papers, data snooping in 73%, and every paper has at least three pitfalls.
  Spurious correlations (P4) are the pitfall that bites scripted traffic: the model learns the
  script.

**Inference (recommended design rules).** These follow from Arp P1/P4/P9, docs/14 and docs/16,
not from a paper on lab generation.

1. Randomise everything a model could memorise: attacker and victim IPs per campaign, inter-stage
   gaps (drawn from distributions, not constants), stage subsets and order, tool and wordlist per
   stage, and rate options.
2. Include **negative chains** at a known rate: recon that goes nowhere, admin scans, benign bursts,
   an attacker that stops. docs/14 showed the always-alarm rule alarms on 30/31 never-followed C2
   events; without negatives, "early warning" is trivially satisfiable.
3. Hold out whole tool or variant families (for example train on nmap + hydra, test on masscan +
   medusa), and report in-variant and out-of-variant results separately.
4. Use the exact `label_to_stage` vocabulary from docs/14 section 6. A misspelling silently becomes
   `impact`.
5. Use the same extractor for training and serving. The live path is dumpcap ring files, so process
   lab PCAPs through the same code (docs/16 F8 flags the 30 s vs 120 s timeout skew).
6. Keep a second, independent timestamp log from the driver script. Do not rely on flow-derived
   labels for stage start times.
7. Time-separate campaigns, or use distinct IPs, so chains do not merge. Keep each campaign's PCAP
   in its own file.

**How many campaigns.** Exact Clopper-Pearson computations, the same rule as docs/13 and docs/16 F9.
The arithmetic was approximate; recheck with scipy before quoting.

| Held-out campaigns eligible for early warning | 95% upper bound if 0 early | Interval if 60% early |
|---|---|---|
| 12 | 26% (matches docs/13) | n/a |
| 20 | about 17% | about 36-81% (12/20) |
| 30 | about 11.6% | about 41-77% (18/30) |
| 50 | about 7% | n/a |

Plan 40-60 campaigns recorded, at least 30 held out, with at least 15 containing a negative or
truncated chain.

## 6. Evaluation methodology and leakage

- **Arp et al. [FULL].** Ten pitfalls: P1 Sampling Bias, P2 Label Inaccuracy, P3 Data Snooping, P4
  Spurious Correlations, P5 Biased Parameter Selection, P6 Inappropriate Baseline, P7 Inappropriate
  Performance Measures, P8 Base Rate Fallacy, P9 Lab-Only Evaluation, P10 Inappropriate Threat
  Model. Recommendations: split test data early and respect temporal order; use explanation
  techniques to find shortcut features; report precision, recall and PR curves, and limit ROC/AUC to
  tractable false-positive rates; never remove uncertain instances from the test set.
- **TESSERACT** (USENIX Security 2019) [docs/05, partly verified, not re-opened]: spatial and
  temporal bias; its AUT metric is a candidate.
- **Range-based metrics.** Tatbul et al., "Precision and Recall for Time Series" (NeurIPS 2018,
  https://arxiv.org/abs/1803.03639) [SNIP]: only the title, venue and the idea of range-based
  precision and recall were confirmed. Relevant to scoring windows inside an attack episode.
- **Mapping to this repo.**
  - Day-grouped and host-grouped folds already exist in `eval/lodo_v4.py`.
  - The sealed CIC-2018 test days (02-16, 02-23, 03-01) are spent (docs/18 section 3, docs/19
    section 0.1). Any new CIC-2018 result is diagnostic.
  - Fresh sealed evidence has to come from re-extracted CIC-2017 and lab campaigns.
- **Alert budgets.** Thresholds did not transfer (docs/18: realised FPR 0-3.45% at a 1% budget).
  Report alarms per benign hour with a day-clustered CI, as docs/16 action 9 proposes.
- **Flow-level leakage specifics (inference).** Group flow splits by capture day and attacker, never
  by random flow. Remove IPs, ports and timestamps from features. Keep one capture run in one fold.

## 7. Ranked options

Effort figures are estimates for one person. "Leakage-free test" is written so it passes or fails on
data no choice was made on.

### Detection

**D1. Re-extract CIC-2017 from PCAP with the same extractor the live pipeline uses (rank 1).**
- *What:* Process the CIC-2017 PCAPs through `pipeline/adapters/pcap_adapter.py` (IPv4 TCP/UDP only;
  it skips ICMP) at 10 s windows, with real IPs and seconds timestamps.
  - Try the DistriNet-regenerated CIC-2017 first (https://downloads.distrinet-research.be/WTMC2021,
    a search-snippet URL, not opened) as a shortcut. Check that it carries IPs and timestamps.
  - Do not vendor Engelen's code: no licence is stated.
- *Benefit:* The first per-host, seconds-resolution, day-disjoint set. Removes the minute-timestamp
  blur (docs/13 section 6) and the extractor mismatch of docs/16 F8 and docs/11. Evidence: docs/16
  action 6, and the exporter finding of the HERA paper [ABS]. No accuracy gain is claimed in advance.
- *Effort:* 4-5 days (compute-heavy: about 51 GB of PCAP).
- *Data:* CIC-2017 PCAPs (being downloaded).
- *Risk:* Only about 9-10 attacking hosts (docs/16 F9), one attacker NAT, and label errors
  (Engelen/Liu). The extractor can disagree with CICFlowMeter's labels.
- *Leakage-free test:* Train on 2018 plus 2017 Mon-Wed; test on 2017 Thu-Fri. Success: host-level
  (unit-balanced) AUROC with a host-bootstrap CI whose lower bound exceeds 0.5, beating `flow_count`
  and `HGB_stacked` from docs/18.

**D2. Flow-level scorer with per-host aggregation for sparse attacks (rank 2).**
- *What:* New `models/flow_scorer.py`: a HistGradientBoosting classifier on single-flow features
  (NetFlow-common subset: duration, bytes, packets, flags, protocol; no IPs, ports or timestamps),
  exported with `models/tree_export.py` to keep the pickle-free bundle. New
  `pipeline/flow_aggregate.py`: window or host alert from top-k mean, noisy-OR, or the count of flows
  above threshold. Evaluate on the sparse days with the `eval/benchmark.py` baseline-gate rows plus a
  flow-level AUPRC.
- *Benefit:* Targets docs/16 F2 (2 flows in about 250). Evidence is the repo's measurement plus the
  mechanism; **no paper was found that tests it**, and cross-dataset flow classifiers collapse in the
  literature (Layeghy [FULL]). Expected to help sparse web attacks only, within a lab family.
- *Effort:* 3-4 days.
- *Data:* Raw flow rows from the CIC-2018 CSVs (present, truncated) and D1 output.
- *Risk:* Same-attacker replay between 02-22 and 02-23; label noise on exactly these classes; a
  flow-level label is only as good as its matching rule.
- *Leakage-free test:* Train on one family and day; test on a different day or dataset (for example
  the 2018 web-attack day against 2017 Thursday web attacks), with a drop-IP/port ablation. Report
  flow-level AUPRC and window-level recall at a fixed alarm budget. Gate against `HGB_stacked` using
  the docs/18 paired MDE.

**D3. Alert-budget threshold in place of a fixed 0.40 (rank 3).**
- *What:* Wire the rolling-quantile rule evaluated in docs/19 (`adaptive_q99`) into `app/service.py`
  as a cap, with a per-network calibration period from the first N hours of unlabelled traffic.
- *Benefit:* docs/19 section 3: FPR within 3x of target on 5-6 of 6 pseudo-host days versus 2-4 of 7
  for fixed thresholds (min-max 0.00-6.18%). It controls alarm volume; **it does not raise recall**
  (0.4-17%).
- *Effort:* 1-2 days.
- *Data:* Existing OOF scores; later, lab benign hours.
- *Risk:* The attack itself sets the quantile (02-21 FPR 0.0-0.6%); under a flood the rule
  under-alarms.
- *Leakage-free test:* Held-out benign lab hours: realised alarms per hour within a factor of 3 of
  target, with a CI.

**D4. NF-CSE-CIC-IDS2018-v3 per-host rebuild (verify first; rank 4, diagnostic only).**
- *What:* Confirm the v3 CSV header has IPs and start times, then validate with the existing
  `pipeline/adapters/netflow_v2_adapter.py` (experimental, unverified on real files; requires
  `FLOW_START_MILLISECONDS`).
- *Benefit:* If confirmed, it removes the pseudo-host problem on 9 of 10 days (24 of 41 features
  constant, docs/16 F8) and probably the row truncation (about 20M flows). **Unverified.** Per-host
  units stay few (about 15 distinct attacker IPs across CIC-2018 days, per the CIC page).
- *Effort:* 1 day to verify, 2-3 days to adapt.
- *Data:* UQ v3 (licence and file size not stated on the pages opened).
- *Risk:* Labels inherit CIC's matching (no correction mentioned); the NetFlow schema differs from
  the 41-feature schema; the CIC-2018 test days are spent, so results are diagnostic only.
- *Leakage-free test:* No sealed claim. Pass condition: more than 30 non-constant features on every
  day, with the number of hosts having at least 12 non-empty windows reported.

**D5. Benign-only anomaly score as a second opinion (rank 5, low expectation).**
- *What:* Isolation Forest or a small autoencoder on per-host windows, trained on the first benign
  hours of the target network, added as a feature or a second alarm channel next to the tree.
- *Benefit:* Literature: less cross-dataset decay than supervised (28% vs 56% F1) but weak on late
  stages (DAPT2020 AUC-PR 0.0136 on lateral movement). Repo: rolling-baseline features did not lift
  AUROC (docs/19). Expect threshold stability, not recall.
- *Effort:* 2 days.
- *Leakage-free test:* Fit on benign-only hours of one day or network, evaluate on another; a pass
  only if the paired per-day gain exceeds the docs/18 MDE, otherwise "not demonstrated".

### Forecasting

**F1. Randomised lab-campaign recorder, 40-60 campaigns (rank 1, critical path).**
- *What:* A driver script that runs ATT&CK-style chains (recon, initial access, lateral movement,
  C2, exfiltration) over varied benign background, with randomised gaps, IPs, stage subsets and
  tools, plus negative chains. Write sidecar labels in the docs/14 section 7 format, using only the
  vocabulary in docs/14 section 6. Record each campaign to its own PCAP with a second timestamp log.
- *Benefit:* The only way to produce a held-out early-warning rate. With 30 held-out campaigns the
  0-early upper bound is about 11.6%, against 26% now. Evidence: docs/16 F9 and section 5.
- *Effort:* 5-8 days (design, run, label, QC).
- *Data:* The owner's isolated lab (own machines).
- *Risk:* Lab traffic is easier than production (Arp P9); the model can still learn the script if
  variation is small.
- *Leakage-free test:* Alarm rule and threshold frozen on training campaigns; held-out campaigns
  include whole unseen variants. Report early / on-time / late / missed with exact CIs as in docs/13,
  plus false alarms per benign hour, against the order-0 and always-alarm baselines on the same
  budget.

**F2. Suricata/Snort alerts as a second event source for the stage layer (rank 2).**
- *What:* Extend `pipeline/stage_events.py` with a `suricata` source (the `source` column already
  exists; `events_from_detections` is the detector precedent). Run Suricata over lab and CIC-2017
  PCAPs and map rule classes to stages through a table kept beside `pipeline/mitre_mapping.py`.
- *Benefit:* This is the input the forecasting literature uses (Tiresias, Băbălău, AIDA;
  [ABS/SNIP]), richer than "stage != benign" from 41 window features. Benefit unquantified;
  inference.
- *Effort:* 3-4 days.
- *Data:* Lab PCAPs; Security Onion already in the lab.
- *Risk:* Signature coverage of the lab tools; alert floods.
- *Leakage-free test:* Compare detector-sourced, alert-sourced and label-sourced events on the same
  held-out campaigns (`eval/stage_forecast_eval.py`), with the order-0 baseline beside them.

**F3. Continuation/hazard signal instead of a per-state constant (rank 3).**
- *What:* In `models/stage_forecaster.py`, add event-level covariates (distinct targets in recon,
  new-target rate, detector confidence, volume) to a small hazard model (logistic or HGB) for
  P(next stage within H). Keep the Markov table as a baseline. Do not train a sequence Transformer
  until this beats the baselines.
- *Benefit:* docs/14 showed P(any within H) is constant per state and alarms on 30 of 31
  never-followed C2 events; docs/14 section 8 suggests exactly this fix. No external evidence;
  inference.
- *Effort:* 3 days (once F1 data exists).
- *Leakage-free test:* Leave-whole-campaign-out; Brier and log-loss paired against order-0 on the
  held-out set; early warning at equal false alarms per hour.

**F4. Campaign-level lead-time metric (rank 4, cheap).**
- *What:* Add to `eval/onset_eval.py` a lead time to the final stage (and to impact) of a labelled
  campaign, separate from first-onset warning. State plainly that alarming at stage 1 is detection.
- *Benefit:* Makes lead-time claims comparable with the literature (Kholidy-style numbers are
  measured to the final stage) without overclaiming forecasting.
- *Effort:* 1 day.
- *Leakage-free test:* Computed only on held-out campaigns; reported with n.

**F5. Next-target forecasting (rank 5).**
- *What:* Given a recon event, rank which host is attacked next. The recon-share ranking already
  exists in `models/stage_forecaster.py`; docs/14 reports hit@1 0.29 / hit@3 0.79, at chance on 4
  targets. In the lab, vary target value and service exposure so there is signal.
- *Benefit:* A forecast that does not depend on timing, similar to predictive blacklisting in Husák
  2021 [ABS]. Unmeasured here.
- *Effort:* 2 days.
- *Leakage-free test:* hit@k on held-out campaigns, using only recon information available at issue
  time (docs/14 notes the current ranking uses completed-event counts, an upper bound).

**F6. DARPA 2000 as a regression test (rank 6, not evidence).**
- *What:* Run LLDOS 1.0/2.0.2 through the adapter and stage layer; compare qualitatively with
  Kholidy's claim.
- *Effort:* 2 days. Phase 1 is an ICMP sweep, which the PCAP adapter skips (inference from docs/14),
  so recon needs an ICMP path.
- *Leakage-free test:* none applicable (n = 2 scenarios). Report as a pipeline sanity check only.

## 8. Plan for 2-3 weeks

**Week 1: start the long poles in parallel.**
- Days 1-2: write the F1 driver and negative-chain design; record the first batch of campaigns.
  Verify D4 (UQ v3 header).
- Days 1-4: D1 extraction of CIC-2017 (compute runs in the background).
- Day 3: F2 prototype on one lab campaign.
- Day 5: freeze the label vocabulary and evaluation protocol in a pre-registration note (as in
  docs/18 section 0).

**Week 2: build and measure.**
- Days 6-8: record the remaining campaigns (target 40-60 by day 8; hold out at least 30).
- Days 6-9: D2 flow scorer and aggregation on existing data; D3 alert-budget wiring.
- Days 9-10: F3 hazard model; F4 metric.

**Week 3: freeze, test once, write up.**
- Days 11-12: freeze thresholds and recipes on training campaigns; evaluate once on held-out
  campaigns and on CIC-2017 Thu-Fri.
- Days 13-14: write results with n beside every figure; dashboard text; the honest pitch.
- Day 15: buffer. If recording slips, cut D5, F5 and F6 first.

Deployment note: the exported numpy tree predictor measured 4.8 ms per row and 49 ms per 5,000 rows
(docs/18), so per-flow scoring on an old CPU is feasible.

## 9. Honest framing for the SIH pitch

Say:
- "We built an end-to-end pipeline from live packet capture to flow windows, a detector, MITRE-stage
  events and a stage forecaster."
- "Detection: on CIC-IDS-2018 held-out days, a gradient-boosted tree and the Transformer are tied at
  roughly 0.75-0.82 within-day AUROC, and a single volume feature ties them. We report per-day
  results because they range from chance to 0.99."
- "We found why: nine of ten days have no host identities, and on the web-attack days an attack
  window is about 2 flows among 250. We are testing per-flow scoring and real per-host data."
- "Forecasting is not yet demonstrated on public data: 0 of 12 and 0 of 15 first-onset warnings. We
  are recording randomised lab campaigns, including negative chains, so the early-warning rate can be
  measured with a stated number of held-out episodes."
- "Published cross-dataset results are also poor (a 56% average F1 decay for supervised models), so
  we calibrate on the deployment network."

Do not say:
- "Forecasts attacks N seconds ahead", or any lead time, until F1 results exist.
- Any single cross-dataset AUROC without the host count.
- Any claim that cites DARPA 2000 lead times as comparable.
- "Beats published methods": none of those papers share our data or protocol.

## 10. What could not be verified

- Full text of the Husák 2019 survey (inputs, lead times and datasets it tabulates), Kitsune's
  results (no EER/AUC quoted), Tiresias, Băbălău & Nadeem (datasets and horizon), Liu et al. (error
  rates), TESSERACT.
- Download pages for NF-CSE-CIC-IDS2018-v3 (403/no content), the DistriNet "Dataset Download" page
  (403), CPTC-2018 and DAPT2020 hosting (404 or unreachable), and the Unraveled link.
- Dataset licences: none of the CIC-2017, CTU-13, DARPA 2000 or NF-v2/v3 pages state one. CIC-2018
  states that redistribution is allowed with citation.
- Sizes: CIC-2018 and NF-v3 file sizes are not on the pages opened (CIC-2018 per-day PCAP archives
  were measured separately at 35.9-55 GB from the AWS bucket listing).
- Caldera's randomisation behaviour, Tatbul's definitions, Sommer & Paxson's text, ID2T, and the
  Gharib et al. criteria were seen only in snippets.
- Whether flow-level scoring plus aggregation beats window aggregation on sparse attacks: no paper
  found. It is an experiment (D2), not a result.

## Sources

Opened in full or as a full record:
- Arp et al. (ar5iv): https://ar5iv.labs.arxiv.org/html/2010.09470
- Layeghy & Portmann (ar5iv): https://ar5iv.labs.arxiv.org/html/2205.04112
- Sarhan et al. (ar5iv): https://ar5iv.labs.arxiv.org/html/2101.11315
- Luay et al. (ar5iv): https://ar5iv.labs.arxiv.org/html/2503.04404
- Anomal-E (ar5iv): https://ar5iv.labs.arxiv.org/html/2207.06819
- UQ NIDS datasets page: https://staff.itee.uq.edu.au/marius/NIDS_datasets/
- Flow aggregation: https://pmc.ncbi.nlm.nih.gov/articles/PMC7961933/
- Engelen WTMC page: https://intrusion-detection.distrinet-research.be/WTMC2021/
- CNS2022 documentation page: https://intrusion-detection.distrinet-research.be/CNS2022/
- CNS2022 code repo: https://github.com/GintsEngelen/CNS2022_Code
- BCCC page: https://www.yorku.ca/research/bccc/?p=2839
- CIC-2017 page: https://www.unb.ca/cic/datasets/ids-2017.html
- CIC-2018 page: https://www.unb.ca/cic/datasets/ids-2018.html
- CTU-13: https://www.stratosphereips.org/datasets-ctu13
- DARPA 2000 (MIT LL): https://www.ll.mit.edu/r-d/datasets/2000-darpa-intrusion-detection-scenario-specific-datasets
- LANL: https://csr.lanl.gov/data/cyber1/
- OpTC: https://github.com/FiveDirections/OpTC-data
- COMIDDS dataset table: https://fkie-cad.github.io/COMIDDS/content/all_datasets/
- DAPT2020 paper mirror: https://www.readkong.com/page/dapt-2020-constructing-a-benchmark-dataset-for-advanced-9939780
- Kitsune-py: https://github.com/ymirsky/Kitsune-py

Abstracts or records only:
- Kitsune: https://arxiv.org/abs/1802.09089
- Husák 2019: https://www.ics.muni.cz/en/research/publications/1434138
- Husák 2021: https://ics.muni.cz/en/research/publications/1682977
- Tiresias: https://arxiv.org/abs/1905.10328
- Băbălău & Nadeem: https://arxiv.org/abs/2408.09888
- PARD-SSM: https://arxiv.org/abs/2604.02299
- Apruzzese et al.: https://arxiv.org/abs/2203.04686
- DI-NIDS: https://arxiv.org/abs/2210.08252
- HERA exporter: https://arxiv.org/abs/2412.14021
- Liu et al.: https://archive.cps-vo.org/node/97449

Search snippets only:
- Kholidy et al.: https://archive.cps-vo.org/node/19443
- AIDA: https://ics.muni.cz/en/research/publications/1540256
- Tatbul et al.: https://arxiv.org/abs/1803.03639
- Caldera docs: https://caldera.readthedocs.io
- Survey of datasets: https://arxiv.org/abs/2502.06688

Repo files read: `docs/13-onset-evaluation.md`, `docs/14-stage-forecasting.md`,
`docs/16-diagnosis-and-improvement-plan.md`, `docs/18-validation-and-baseline-gate.md`,
`docs/19-baseline-improvements.md`, parts of `docs/05-related-work-and-expansion-roadmap.md`,
`README.md` (project layout), and `pipeline/adapters/netflow_v2_adapter.py` (header only).
