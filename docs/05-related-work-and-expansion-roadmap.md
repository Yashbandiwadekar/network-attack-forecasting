# Related work and expansion roadmap

**Compiled 2026-10-10.** Literature and open-source inventory for this project, plus a ranked set
of expansion directions constrained to the datasets already in hand (CIC-IDS-2018, UNSW-NB15,
CTU-13).

Two findings in here are **defects in this repository**, not literature. They are stated first
because one of them makes a currently-published number false.

## Verification convention

Research is only useful if its provenance is legible, so every citation carries a marker:

- **[VERIFIED]** — confirmed on a primary page (arXiv abstract, publisher page, GitHub API, repo BibTeX).
- **[PARTLY VERIFIED]** — the citation is consistent across independent secondary reference lists, but no publisher page was reached.
- **[UNVERIFIED]** — from a search snippet only. **Do not cite these in a submission without fetching them first.**

Three obstacles limited verification depth and explain the remaining gaps: DBLP serves an Anubis
bot-check, IEEE Xplore and Semantic Scholar's web pages return 403 to automated fetches, and the
Semantic Scholar Graph API rate-limited on roughly half the queries. A retry pass with backoff
would clear most [PARTLY VERIFIED] markers.

---

# Part 1 — Defects found in this repository

## D-1. CTU-13 label mapping sends benign traffic to a positive label

**Confirmed by running the mapper and counting the raw data, not inferred.**

`pipeline/mitre_mapping.py::ctu13_label_to_stage` returns `BENIGN` for labels starting
`flow=background`, `flow=to-background` and `flow=from-normal`. It does **not** handle
`flow=from-background`, `flow=to-normal`, or bare `flow=normal`. Those reach the final
`return IMPACT` fallthrough. Because `pipeline/windowing.py` builds the target as
`0.0 if stage == BENIGN else 1.0`, an `impact` window is a **positive**.

Measured output of `label_to_stage` on real CTU-13 labels:

| Label | Mapped stage |
|---|---|
| `flow=From-Background-CVUT-Proxy` | **impact** → positive |
| `flow=To-Normal-V4x-UDP-NTP-server` | **impact** → positive |
| `flow=Normal-V4x-HTTP-windowsupdate` | **impact** → positive |
| `flow=Background` | benign ✓ |
| `flow=To-Background-UDP-CVUT-DNS-Server` | benign ✓ |
| `flow=From-Normal-V4-UDP-CVUT-DNS-Server` | benign ✓ |

Counted across all raw `.binetflow` files:

```
  6,399  flow=From-Background-CVUT-Proxy
  1,331  flow=To-Normal-V4x-UDP-NTP-server      (summed over version variants V42-V54)
     24  flow=Normal-V45-HTTP-windowsupdate
  7,754  TOTAL benign flows carrying an ATTACK label
```

All three families are benign in CTU-13's own taxonomy — university proxy background traffic, NTP
servers, and Windows Update.

**Consequence.** The published zero-shot CTU-13 result (**AUROC 0.517**, cited as evidence of
non-generalisation) is scored against these labels. Its test `n` of 186,520 matches
`final_splits` exactly, so it is this build. Some unknown part of that 0.517 is the model
correctly calling benign NTP and proxy traffic benign while the label said attack, so **the score
may improve once fixed**. Every CTU-13 number must be regenerated.

**Fix.** Add the three prefixes to the benign branch, and make the unknown-label fallthrough log
or raise rather than silently emitting a positive. A silent catch-all default is the root cause
here, not the missing prefixes.

## D-2. A published results file reports AUROC 1.000 with zero recall

`docs/cic_pkt_results.json` reports, for all three seeds on 371,915 test sequences with 529
positives:

| Metric | Value |
|---|---|
| AUROC | **1.000** |
| AUPRC | **1.000** |
| F1 @ 5% FPR threshold | **0.0** |
| Precision / recall @ 5% and 1% FPR | **0.0 / 0.0** |
| Selected threshold | 0.9999988 |

Perfect ranking with zero recall at any usable operating point is an internal contradiction, and
`BUILD_REPORT.md` already notes the val-chosen thresholds give recall 0 on test. **The flow-only
control also scores AUROC 1.000**, so the packet features are not the shortcut — the split is.
The likely cause is one day, one victim, and a time split where train is FTP-Patator and test is
SSH-Patator, making brute-force trivially separable by volume.

**Cheapest diagnostic:** score a `flow_count` z-score rule alone on the same split. If that also
reaches ~1.0, the pilots measure the split and must be captioned so. An unexplained 1.000 in a
published file is a reviewer liability.

## D-3. The project holds roughly 15 forecastable events in total

An **onset** — a host observed benign now whose label turns non-benign within k=1..6 — is the only
event class a forecaster can be scored on. Counted from the processed `.npz` files and raw data:

| Split | onset windows | non-`impact` | onset hosts | independent episodes |
|---|---|---|---|---|
| CIC test (02-16 / 02-23 / 03-01) | 628 | 616 | 3 — **all pseudo-hosts** | ~15 (upper bound) |
| CIC train, real-IP hosts only | **0** | 0 | 0 | 0 |
| CTU-13 test (scen. 12–13) | 551 | **0** | 15 | 0 |
| CTU-13 train (scen. 1–9) | 3,893 | **0** | 30 | 0 |
| UNSW test | 14 | 8 | — | — |

Three consequences, each computed rather than assumed:

1. **Every one of CTU-13's 4,444 apparent onsets is defect D-1.** Recounted with the fallthrough
   treated as benign and a real botnet stage required: **0 onsets in train, 1 in val, 0 in test**
   across all of CTU-13.
2. **On CIC, real-IP hosts never have a benign history.** Of 6,810 real-IP hosts in training data
   only 10 ever carry an attack window, and the 8 largest are attack-labelled in 100% of their
   windows (376/376, 375/375, …) — the 02-20 DDoS bots. `build_sequences` keys on `src_ip`, so the
   project models **attackers**, who are hostile from their first window. Re-splitting to put the
   one Src-IP day in test yields per-host sequences but still zero onsets.
3. **Keying on the victim helps, barely.** Re-counting 02-20 keyed on `Dst IP`: 1,823,823
   victim-windows, but exactly **1 victim** (172.31.69.25) is ever attacked, with **6
   benign→attack transitions**.

**This is the binding constraint on the whole project.** It explains why
`docs/04-dos-forecast-demo.md` found only 2 onsets, and why that demo's headline was never going
to become a statistic. No architecture change fixes it. The highest-value work is correcting what
is measured, not building a better forecaster.

## D-4. Corrections to claims made elsewhere in these docs

- **Packet features are not universally zero-filled.** True of the headline `real_v2_converged`
  checkpoint only. `data/processed_cic_pkt/`, `processed_cic_fri_pkt/` and `processed_unsw_pkt/`
  all carry `has_packet_features ≈ 1.0` and populated `port_scan_score` (mean 0.31 / 0.28 /
  0.036), with trained checkpoints in `checkpoints_cic_pkt/` and `checkpoints_unsw_pkt/`.
- **"k=6 is not 60 seconds" is a property of one day, not the pipeline.** 97.8% of consecutive
  window gaps in the CIC test split are exactly 10 s. On 02-16 it is 69.8% with a mean step of
  86 s, which is why that day measured k=6 ≈ 370–400 s. The framing in
  `docs/04-dos-forecast-demo.md` overgeneralises and should be narrowed.
- **No CTU-13 checkpoint exists.** `docs/04-evaluation-ctu13.md` is pre-audit (persistence F1
  0.990, since corrected by finding E6) and built from an older split (223,754 test sequences vs
  186,520 in `final_splits`). Anything "on CTU-13" requires training first.
- **k=2..6 targets are built and discarded.** `models/train.py:52,59` trains only on
  `future_stages[:, 0]` and `infiltration[:, 0]`. This matters for roadmap item R-6.
- **`processed_cic_fri_pkt`'s day is unverified.** Its metadata says 14-02-2018 but its window
  count differs from `processed_cic_pkt` (1,136,861 vs 1,030,654), and `BUILD_REPORT.md` never
  mentions `fri_pkt`.

---

# Part 2 — Literature inventory

## 2.1 Multi-step forecasting of attack progression

1. **Tiresias: Predicting Security Events Through Deep Learning** — Shen, Mariconti, Vervier,
   Stringhini. ACM CCS 2018, pp. 592–605. <https://arxiv.org/abs/1905.10328> **[VERIFIED]**
   The canonical "predict the next event rather than classify the current one" paper; RNN over
   3.4B IPS events, precision up to 0.93. Closest prior art to this project's framing. Its
   finding that long-term memory is essential is a direct comparison point for a 3-layer,
   4-head Transformer, and it includes a precision-decay retraining trigger this project lacks.

2. **Survey of Attack Projection, Prediction, and Forecasting in Cyber Security** — Husák,
   Komárková, Bou-Harb, Čeleda. IEEE Communications Surveys & Tutorials 21(1):640–660, 2019.
   **[PARTLY VERIFIED — DOI 10.1109/COMST.2018.2871866 unverified, publisher page not reached]**
   The field's taxonomy paper. Separates *attack projection* (next adversary step) from attack
   prediction and network situation forecasting. This project is "attack projection" in its terms,
   and it argues projection and detection require different evaluation — the basis for item R-2.

3. **Forecasting Attacker Actions using Alert-driven Attack Graphs** — Băbălău, Nadeem.
   arXiv:2408.09888, 2024. <https://arxiv.org/abs/2408.09888> **[VERIFIED]**
   Forecasts the next attacker action via EM over a reversed suffix-based PDFA; 67.27% top-3
   accuracy on three real alert datasets, plus a six-analyst user study. The strongest direct
   competitor on the forecasting axis, and a useful non-neural baseline.

4. **SAGE: Intrusion Alert-driven Attack Graph Extractor** — Nadeem, Verwer, Yang. VizSec 2021.
   arXiv:2107.02783, DOI 10.1109/VizSec53666.2021.00009 **[VERIFIED]**
   The framework item 3 builds on. Learns attack graphs from alerts with no expert knowledge —
   the alert-level alternative to flow-level state.

5. **Multi-stage Attack Detection and Prediction Using Graph Neural Networks: An IoT Feasibility
   Study** — Friji, Mavromatis, Sanchez-Mompo, Carnelli, Olivereau, Khan. arXiv:2404.18328, 2024
   (preprint). <https://arxiv.org/abs/2404.18328> **[VERIFIED]**
   Kill-chain-structured three-stage IDS on ToN-IoT, using stage 1–2 outputs to test whether
   stage-3 attacks are predictable; ~94% average F1. Methodologically close to this project's
   stage head, and an example of solving stage-coverage by dataset choice rather than heuristics.

6. **PARD-SSM: Probabilistic Cyber-Attack Regime Detection via Variational Switching State-Space
   Models** — Hiremath, Bagawan, Bhekane. arXiv:2604.02299, 2026.
   <https://arxiv.org/abs/2604.02299> **[VERIFIED]**
   Four hidden regimes (recon / lateral movement / intrusion / exfiltration) over network
   telemetry, on CICIDS2017 and UNSW-NB15, obtaining multi-step forecasts from **powers of a
   stage transition matrix** rather than autoregressive rollout. The most important single hit
   for this project: same problem, and a direct-multi-horizon alternative to the rollout that
   `docs/04-evaluation-frozen-state-ablation.md` shows is not earning its keep. Treat its claimed
   F1 98.2%/97.1% and "8 minutes early" with suspicion given §2.5.

**Found but not fetched — [UNVERIFIED], flagged for a second pass:** KillChainGraph
(arXiv:2508.18230); StageFinder (arXiv:2603.07560, APT stage probabilities from provenance,
GNN+LSTM, macro-F1 0.96 on DARPA TC/OpTC); **Multi-Stage Attack Detection via Kill Chain State
Machines (arXiv:2103.14628)** — notable because it *injects a hand-crafted APT campaign into
CSE-CIC-IDS2018*, one answer to the missing-stage problem; arXiv:2511.23000.

## 2.2 Autoregressive rollout losing to a one-step baseline

The best-covered sub-heading, and the one that speaks directly to this project's largest negative
result (genuine rollout AUROC 0.7549 vs frozen 0.7853 at k=6).

- **Scheduled Sampling for Sequence Prediction with Recurrent Neural Networks** — Bengio,
  Vinyals, Jaitly, Shazeer. NIPS 2015. arXiv:1506.03099 **[VERIFIED]**
  The canonical fix for exactly this train/inference mismatch — trained one-step with teacher
  forcing, then rolled out on its own predictions. Curriculum from ground-truth to self-generated
  inputs. The obvious first intervention if the rollout is kept.
- **A review and comparison of strategies for multi-step ahead time series forecasting** — Ben
  Taieb, Bontempi, Atiya, Sorjamaa. arXiv:1108.3259 **[VERIFIED]**
  The recursive / direct / DirRec / MIMO / DIRMO taxonomy with bias–variance framing. Its stated
  finding that **multiple-output** strategies performed best is why R-6 proposes one shared head
  with a horizon embedding rather than six independent direct heads.
- **Investigating Compounding Prediction Errors in Learned Dynamics Models** — Lambert, Pister,
  Calandra. arXiv:2203.09637, 2022. **[VERIFIED]**
  Empirical study of precisely the measured phenomenon. The paper to cite for "the rollout
  degrades monotonically with k".
- **Data as Demonstrator (DaD)** — Venkatraman, Boots, Hebert, Bagnell.
  **[UNVERIFIED venue — the AAAI 2015 attribution did not confirm; locatable as the workshop
  paper "Data as Demonstrator with Applications to System Identification" and in Venkatraman's
  2017 CMU thesis "Training Strategies for Time Series"]**
  A no-regret method that reuses training data to make a model robust to its own multi-step
  errors. Conceptually the closest match; **verify the venue before citing.**
- Also surfaced, **[UNVERIFIED]**: Any-step Dynamics Model (arXiv:2405.17031); "Learning with
  Imperfect Models" (arXiv:2504.01766 — theory on single-step vs direct multi-step error under
  model misspecification, relevant because partial observability is exactly the case where direct
  predictors win); Asadi et al. 2018 Lipschitz bound on O(εL^H) error growth.

## 2.3 Graph encoding (the encoder here is frozen random-init)

- **E-GraphSAGE: A GNN based Intrusion Detection System for IoT** — Lo, Layeghy, Sarhan,
  Gallagher, Portmann. IEEE/IFIP NOMS 2022, DOI 10.1109/NOMS54207.2022.9789878.
  arXiv:2103.16329 **[VERIFIED]**
  The reference *trained* edge-feature GNN for flow data, and the direct comparator. Important
  detail: it is edge-centric because node features on flow graphs carry little signal — a
  plausible explanation for why the 8 `graph_embed_*` columns do nothing here.
- **Anomal-E: A Self-Supervised Network Intrusion Detection System based on GNNs** — Caville, Lo,
  Layeghy, Portmann. arXiv:2207.06819 **[VERIFIED]**
  E-GraphSAGE + Deep Graph Infomax trained by corrupting edge features; **requires no labels**.
  The cheapest realistic path from "frozen random" to "trained".
- **EULER: Detecting Network Lateral Movement via Scalable Temporal Graph Link Prediction** —
  King, Huang. **NDSS 2022**, with an ACM TOPS 2023 extension (DOI 10.1145/3588771).
  <https://par.nsf.gov/biblio/10344243> **[VERIFIED via NSF PAR records 10344243 / 10440905]**
  **Correction worth noting: this is NDSS 2022, not 2023** — sources citing 2023 mean the journal
  extension. GNN stacked on a sequence encoder over discrete temporal graph snapshots:
  architecturally the closest published analogue to a GNN+Transformer stack. Note it frames the
  task as anomalous-edge **detection**.
- **GraphIDS** — NeurIPS 2025 per repo. <https://github.com/lorenzo9uerra/GraphIDS>
  **[repo VERIFIED; paper UNVERIFIED]**
- **[UNVERIFIED]**: STEG (arXiv:2404.10800 — a modified E-GraphSAGE whose only change is Node2Vec
  node-feature initialisation instead of the uniform constant; near-identical to the
  frozen-random-init question here); arXiv:2509.16625.

**Gap, stated explicitly.** No paper was found isolating *frozen random-init vs trained* graph
encoders on network flow data. The general "untrained GNN / random features as a baseline"
literature exists outside security; nothing security-specific surfaced. The null result in
`docs/06-gnn-ablation.md` appears unaddressed in the literature.

## 2.4 Incomplete kill-chain label coverage

The thinnest sub-heading. Recorded as thin rather than padded with tangential class-imbalance work.

- **Towards a Standard Feature Set for Network Intrusion Detection System Datasets** — Sarhan,
  Layeghy, Portmann. 2021, DOI 10.1007/s11036-021-01843-0. arXiv:2101.11315 **[VERIFIED]**
  Proposes 12- and 43-feature NetFlow standard sets and republishes UNSW-NB15, BoT-IoT, ToN-IoT
  and CSE-CIC-IDS2018 as the NF-*-v2 datasets. *The* cross-dataset harmonisation line, directly
  relevant to the UNSW-NB15 and CTU-13 adapters.
  **Highest-value open question in this document:** whether `NF-CSE-CIC-IDS2018-v2` carries
  source/destination IPs on **every** day. The arXiv abstract does not list features. If it does,
  it would dissolve defect D-3's "9 of 10 days have no real IPs" bind — the only route in hand to
  genuine per-host sequences. **Needs confirming from the paper PDF or the dataset itself.**
- **NetFlow Datasets for Machine Learning-based NIDS** — Sarhan, Layeghy, Moustafa, Portmann.
  BDTA/WiCON 2020, DOI 10.1007/978-3-030-72802-1_9. arXiv:2011.09144 **[VERIFIED]**
  The v1 NF-* datasets. Reports NetFlow features giving similar binary but **weaker multi-class**
  results — a caution for the 6-class stage head.
- **Network Intrusion Datasets: A Survey, Limitations, and Recommendations** — Goldschmidt, Chudá.
  Computers & Security 156 (2025) 104510. arXiv:2502.06688 **[VERIFIED]**
  Systematic review of 89 NIDS datasets across 13 properties. The right place to look for a
  dataset that actually contains labelled reconnaissance and exfiltration.

**Gap, stated explicitly.** Nothing was found treating incomplete kill-chain label coverage as a
research problem — no paper studying what happens when a stage classifier is trained with a stage
absent, nor formalising the "exclude `impact` from the stage head" decision. The closest work does
not concern labels at all: arXiv:2103.14628 injects a synthetic APT campaign into
CSE-CIC-IDS2018, and Friji et al. pick a dataset spanning the stages. The S6/S7 finding here —
DoS windows classified `command_and_control` 570/684 times — appears undocumented.

## 2.5 Dataset and evaluation critiques

1. **Error Prevalence in NIDS Datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018** —
   Liu, Engelen, Lynar, Essam, Joosen. IEEE CNS 2022, DOI 10.1109/CNS56114.2022.9947235.
   **[VERIFIED twice — BibTeX in the authors' released repo and the Semantic Scholar API]**
   **The most important entry in this section: it covers CSE-CIC-IDS-2018 directly**, the dataset
   behind every headline number in `docs/`. Reports mislabelled FTP-Bruteforce and
   DoS-SlowHTTPTest traffic, a **misimplemented DoS Hulk attack**, corrupted attack samples and
   label inaccuracies. Corrected labelling and a fixed CICFlowMeter are released.
   **Direct bearing on this project:** `docs/04-dos-forecast-demo.md` runs on 02-16, whose
   attacks are **Hulk and SlowHTTPTest** — precisely the traffic this paper says is broken. That
   does not reverse the demo's conclusion (a model cannot forecast from bad labels either) but it
   means the *explanation* may be the dataset rather than the model.
2. **Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study** — Engelen,
   Rimmer, Joosen. IEEE SPW 2021, pp. 7–12. **[PARTLY VERIFIED]**
   Origin of the CICFlowMeter critique: a TCP-termination timing flaw producing incorrect flow
   construction, plus feature duplication, miscalculation, wrong protocol detection and labelling
   errors.
3. **Errors in the CICIDS2017 Dataset and the Significant Differences in Detection Performances
   it Makes** — Lanvin, Gimenez, Han, Majorczyk, Mé, Totel. Springer LNCS 13857, pp. 18–33, 2023.
   **[PARTLY VERIFIED — venue unresolved; the LNCS volume does not name the conference]**
   Reports incorrectly labelled **port-scan** attacks and duplicated traffic. The port-scan
   finding bears directly on `apply_reconnaissance_heuristic`, which keys on `port_scan_score`.
4. **Network Intrusion Datasets: A Survey** — Goldschmidt, Chudá (as §2.4). **[VERIFIED]**
   Consolidates the error catalogue: duplicated features and packets, incorrect flow
   construction, incoherent timestamps, labelling issues, deprecated attack tooling.
5. **The Arp et al. line beyond the already-cited paper.** "Dos and Don'ts of Machine Learning in
   Computer Security", USENIX Security 2022, arXiv:2010.09470 **[VERIFIED — already cited]**. Two
   uncited follow-ups by the same group: "Lessons Learned on Machine Learning for Computer
   Security", IEEE S&P Magazine 2023 (10 generic pitfalls), and "Pitfalls in Machine Learning for
   Computer Security", CACM 67(11), Nov 2024. **[PARTLY VERIFIED via UCL Discovery 10133161 /
   10212285]** The **temporal snooping** pitfall is what the day-disjoint split defends against;
   cite it by name.
6. **TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time** —
   Pendlebury, Pierazzi, Jordaney, Kinder, Cavallaro. USENIX Security 2019.
   <https://s2lab.cs.ucl.ac.uk/downloads/tesseract.pdf> **[PARTLY VERIFIED]**
   Formalises spatial and temporal bias and "impossible configurations" from incorrect time
   splits. Its **AUT** metric is a candidate addition to this project's evaluation.

## 2.6 Open-source projects

Stars, last-push and licence from the GitHub API on **2026-10-10** (stars drift). The
**detection vs forecasting** distinction is recorded per entry, because most "IDS" repos are
classifiers and are not comparable to this project.

### Genuine forecasters — the short list

| Repo | Stars | Last push | Licence | What it is |
|---|---|---|---|---|
| `tudelft-cda-lab/SAGE` | 39 | 2024-06-28 | MIT | Forecasting-adjacent. Alert-driven attack-graph extractor; the forecasting extension is Băbălău & Nadeem. Alerts, not flow telemetry. |
| `mayank02raj/MITRE-ATTACK-based-Attack-Chain-Prediction` | 6 | 2026-06-23 | **none detected** | Genuine forecaster, wrong modality: hybrid LSTM–Markov over 4,849 ATT&CK-mapped CTI campaign chains. Not network telemetry. |
| `Thijsvanede/Tiresias` | 10 | 2024-07-25 | MIT | PyTorch reimplementation of Tiresias — **third-party, not Shen et al.'s own code.** |
| `Thijsvanede/DeepCASE` | 109 | 2023-08-01 | MIT | Official DeepCASE (IEEE S&P 2022). **Alert triage** with next-event prediction as a component — do not label it a forecaster without reading the paper. |

### Detection only — checked so they need not be re-checked

| Repo | Stars | Last push | Licence | Note |
|---|---|---|---|---|
| `waimorris/E-GraphSAGE` | 108 | 2022-06-30 | Apache-2.0 | NF-* NetFlow. Edge-feature GNN classifier. |
| `waimorris/Anomal-E` | 47 | 2022-12-16 | Apache-2.0 | Self-supervised graph anomaly detection. |
| `iHeartGraph/Euler` | 62 | 2023-11-06 | **none — do not vendor code from it** | LANL auth-log temporal link prediction. |
| `lorenzo9uerra/GraphIDS` | 58 | 2026-08-16 | Apache-2.0 | Self-supervised GNN NIDS; CICIDS2018 in topics. |
| `erikmurtaj/DeepReTiNA` | 3 | 2026-02-02 | MIT | CSE-CIC-IDS2018 real-time classifier wired into CICFlowMeter. |
| `arbaouihamza/tgn-cyberattack-detection` | 0 | 2026-09-12 | none | Temporal Graph Network over dynamic IP graphs. |
| `lemonadeaumiel/Hybrid-IDS_CICIDS2018` | 14 | 2022-05-18 | MIT | CSE-CIC-IDS2018 + ToN-IoT hybrid IDS. |

### Reusable tooling

- **`GintsEngelen/CNS2022_Code`** — 29★, 2023-10-10, **no licence**. Relabelling and benchmarking
  code for CIC-IDS-2017 and CSE-CIC-IDS-2018, paired with `GintsEngelen/CICFlowMeter` (their
  fixed exporter). **The highest-value repo here** — it is the corrected labelling for the dataset
  behind this project's headline numbers. The licence absence is a real blocker for reuse.
- `s2labres/tesseract-ml-release` — 21★, 2024-12-10, BSD-3-Clause. Temporal/spatial bias-free
  evaluation; relevant to the day-disjoint split.
- `reml-lab/mTAN` 149★ MIT · `YuliaRubanova/latent_ode` 599★ MIT · `patrick-kidger/torchcde` 493★
  Apache-2.0 — the three irregular-time-series reference implementations.
- `lorenzo9uerra/theseus` — 7★, 2026-09-05, Apache-2.0. On how benchmarks and evaluation
  protocols shape conclusions in provenance-based IDS (NDSS 2027 per description).

HuggingFace was not searched and no model-hub results surfaced via web search.

## 2.7 Irregular and gappy time series

Fit caveat: the problem here is **dropped empty windows**, not classical irregular sampling. The
point-process line models inter-event gaps directly and is the better match; the ODE/attention
line is the better-known framing.

- **Transformer Hawkes Process** — Zuo, Jiang, Li, Zhao, Zha. ICML 2020. arXiv:2002.09291
  **[VERIFIED]** Self-attention over continuous-time event sequences. The closest architectural
  match: same self-attention, but the gap between events is **part of the model** rather than
  silently discarded.
- **The Neural Hawkes Process** — Mei, Eisner. NIPS 2017. arXiv:1612.09328 **[VERIFIED]**
  Continuous-time LSTM driving event intensities. The standard baseline.
- **Multi-Time Attention Networks (mTAN)** — Shukla, Marlin. ICLR 2021. arXiv:2101.10318
  **[VERIFIED]** Learned continuous-time embeddings mapping a variable number of observations to
  a fixed-length representation, no imputation. A drop-in replacement for the fixed 12-step
  positional scheme. Successor **HeTVAE** fixes mTAN's normalising-away of sparsity information —
  which matters here, because window emptiness *is* signal.
- **Latent ODEs for Irregularly-Sampled Time Series** — Rubanova, Chen, Duvenaud. NeurIPS 2019.
  arXiv:1907.03907 **[VERIFIED]** Caveat per arXiv:2012.00168: the encoder runs backwards in time only.
- **Neural Controlled Differential Equations for Irregular Time Series** — Kidger, Morrill,
  Foster, Lyons. NeurIPS 2020. arXiv:2005.08926 **[VERIFIED]**
  **Deployment caveat relevant to `scripts/live_forecast.py`:** arXiv:2106.11028 notes Neural CDEs
  cannot do real-time online prediction because the trajectory depends on future data; ODE-RNN can.
- **Recurrent Neural Networks for Multivariate Time Series with Missing Values** — Che,
  Purushotham, Cho, Sontag, Liu. Scientific Reports 8:6085, 2018,
  DOI 10.1038/s41598-018-24271-9 **[VERIFIED]** Masking plus time-interval inputs, and
  "informative missingness" — the reference for a dense-grid rewrite.

## 2.8 A negative result that supports the novelty claim

A targeted search for a released **world model over network telemetry** found **none**. Queries
included `"world model" network traffic telemetry forecasting`, GitHub API searches for
`"attack prediction" network`, `"attack stage prediction"`, `"MITRE ATT&CK" prediction`,
`"alert correlation"`, `"attack graph" security`, `"CTU-13"`, and
`topic:intrusion-detection topic:graph-neural-networks`.

Nearest misses, each failing on at least one axis: **netFound** (arXiv:2310.17025 — classification,
not forecasting) [UNVERIFIED]; **Time-Series Foundation Models for ISP Traffic Forecasting**
(arXiv:2511.17529 — forecasting, but traffic volume not attack state) [UNVERIFIED]; **Mobile
Network Control with a World Model** (arXiv:2607.17747 — networks, not security) [UNVERIFIED];
**PARD-SSM** (§2.1 item 6 — the genuine closest competitor, and a switching state-space model
rather than a learned world model).

So a Transformer world model rolled forward over per-host network state with a MITRE stage head
has no published equivalent or released code found. **Caveat: this is a web-search negative, not
an exhaustive database sweep**, and it should be stated that way rather than as priority.

---

# Part 3 — Ranked expansion roadmap

Ranked by (likely gain) / (effort). Constrained to CIC-IDS-2018, UNSW-NB15 and CTU-13; "collect
new data" is out of scope except where noted.

| Rank | Item | Effort | Gain |
|---|---|---|---|
| 1 | **R-1** Fix the CTU-13 label fallthrough, regenerate its numbers | ~1.5 d | very high |
| 2 | **R-2** Onset-conditioned, episode-level evaluation protocol | 1–2 d | very high |
| 3 | **R-3** Victim-keyed windowing on 02-20 | 2–3 d | high |
| 4 | **R-4** Split `impact` out of the any-attack head | 1–2 d | high |
| 5 | **R-5** Diagnose the AUROC 1.000 pilots | 1 d | high |
| 6 | **R-6** Multi-horizon head replacing the recursive rollout | 2–3 d | medium |
| 7 | **R-7** Reconnaissance as a detection class from UNSW-NB15 | 3–4 d | medium |
| — | **R-8** Dense 10 s time grid (make k mean seconds) | 2–3 d + full rebuild | low–medium |
| 8 | **R-9** Train the graph encoder | 1 w+ | ~none — **do not do** |

### R-1 — Fix the CTU-13 label fallthrough *(do this first)*
Addresses **D-1**. Add `flow=from-background`, `flow=to-normal` and bare `flow=normal` to the
benign branch; make the unknown-label fallthrough log or raise. Rebuild
`data/processed/ctu13/final_splits`; re-run the CTU-13 evaluation docs.
**Success:** test positives drop 6,438 → 5,944; the 551 artifact onsets vanish; AUROC 0.517 is
recomputed against meaningful labels. **Risk:** it will not make CTU-13 usable for forecasting —
it removes the illusion that it is.
**Evidence:** García, Grill, Stiborek, Zunino, *An empirical comparison of botnet detection
methods*, Computers & Security 45:100–123, 2014, DOI 10.1016/j.cose.2014.05.011;
<https://www.stratosphereips.org/datasets-ctu13> **[VERIFIED]**. Arp et al. 2022 on label
inaccuracy **[VERIFIED]**.

### R-2 — Onset-conditioned, episode-level evaluation
Addresses **D-3**. Score only sequences with `current_infiltration == 0` and a positive at step k;
report per-k; exclude `impact`; compute CIs at **episode** level, not window level; print the
episode count beside every figure. Re-run the frozen-state ablation under it.
**Why:** under the all-windows protocol the frozen t+1 control wins by construction, because
attack state persists — which is what the ablation measured. 604 onset windows on 02-23 collapse
to ~6 episodes.
**Success:** a published table of AUROC/AUPRC at k=1..6, onset-only, impact-excluded, with
episode-level CIs. It will be far below 0.794 with wide intervals, and that is a stronger
contribution than the current headline.
**Risk:** at ~15 episodes the CIs may be too wide to distinguish anything, making R-6
unfalsifiable. Say so rather than reporting a point estimate.
**Evidence:** Husák et al. 2019 **[PARTLY VERIFIED]**; Arp et al. 2022 on base-rate fallacy.

### R-3 — Re-key state on the victim, not only the source
Addresses **D-3**; the only direction that creates forecastable events from data in hand. Add
destination-keyed windowing to `build_flow_windows` / `build_sequences`. Victims have genuine
benign history before being hit; attackers do not.
**Dataset:** CIC 02-20 only — the one day with both `Src IP` and `Dst IP`.
**Measured ceiling before starting: 1 victim, 6 benign→attack transitions.** An existence proof,
not a statistic. And that victim is a DDoS target, so the thing forecast is a volumetric flood —
the case the DoS demo already showed is only detected. Moderate chance it reproduces that
negative per-host.
**Evidence:** Moustafa & Slay, *UNSW-NB15: a comprehensive data set for network intrusion
detection systems*, MilCIS 2015, DOI 10.1109/MilCIS.2015.7348942 **[VERIFIED]** — documents the
few-attacker/many-victim generator structure this exploits.

### R-4 — Split `impact` out of the any-attack head
Addresses **D-3** and the misnamed head. Report infiltration AUROC three ways by default (all
positives / impact-only / impact-excluded) instead of burying the 0.794 → 0.744 drop in a
limitations section. Separately, add `impact` as a 7th stage class rather than masking to −1: the
DoS demo shows the masked head calls 43% of active-flood windows `benign` and 28%
`initial_access`, with only `_heuristic_stage_override` producing a correct label.
**Dataset:** CIC only. **Do not** use CTU-13's `impact` — on CIC it is real DoS, on CTU-13 it is
defect D-1.
**Risk:** low technically; the headline gets worse. That is the point, and it pre-empts the
obvious reviewer attack.

### R-5 — Diagnose the AUROC 1.000 pilots
Addresses **D-2**. Score a `flow_count` z-score rule alone on the same split; if it also reaches
~1.0, the pilots measure the split, not the model, and must be captioned so. Note `eval/lofo.py`
is leave-one-attack-*family*-out, not a feature ablation — the needed ablation is the existing
`checkpoints_cic_pkt_flowonly` plus a trivial-rule control.
**Evidence:** Arp et al. 2022 on spurious correlations and sampling bias **[VERIFIED]**.

### R-6 — Multi-horizon head replacing the recursive rollout
Addresses the frozen-state result. The targets already exist (`infiltration[:, 0..5]`); training
uses column 0 only (`models/train.py:52,59`). Train **one** head conditioned on a horizon
embedding — multi-output, not six independent heads — on all six columns. Keep the recursive
rollout as a secondary output for the trajectory, `transition_magnitude` and the counterfactual
path, none of which a multi-horizon head can produce.
**Success:** beats the frozen t+1 control at k=4 and k=6 under R-2's protocol — the first positive
result against the project's largest published negative.
**Risk:** it may simply reproduce the frozen baseline. The control being nearly flat
(0.794 → 0.785 across the full minute) is what you would see if the model reads current volume
only — the same conclusion the DoS demo reached from flat pre-onset traces. If so, the honest
finding is "the horizon is not learnable from these features on this data", which is cheap to
establish and worth publishing.
**Evidence:** Ben Taieb et al. (multiple-output best) and Bengio et al. (scheduled sampling), both
**[VERIFIED]**.

### R-7 — Reconnaissance as a detection class from UNSW-NB15
Addresses the empty `reconnaissance` class. Joint or sequential training so the stage head sees
UNSW's **2,022 real recon-labelled windows** (verified in `processed_unsw_v2/train.npz`). CIC has
none; CTU-13 has none.
**Honest limits, all verified:**
- UNSW attack traffic comes from exactly **4 IXIA generator IPs** (`175.45.176.0–3`), essentially
  never benign. This trains recon **detection**, not recon→exploit **forecasting**. The apparent
  chain (852 + 505 of recon windows' 6-step futures containing `initial_access`) is the generator
  interleaving attack categories on one host, not an attacker progressing.
- `lateral_movement` has **21** training windows in UNSW. It cannot be learned.
- The packet-aware UNSW build with real `port_scan_score` already exists, and per
  `BUILD_REPORT.md` feeding the recon heuristic real packet features added **3 windows**. The
  heuristic is not the route; UNSW's native labels are.
- Raw UNSW files are on an external drive. Training from `processed_unsw_v2` works as-is, but any
  re-windowing needs that drive.
**Risk:** cross-dataset transfer has never worked in this project (CIC→CTU is chance); joint
training may degrade CIC without buying usable recon.

### R-8 — Dense 10 s grid *(deliberately ranked low)*
Dense per-host grid with a `has_traffic` sentinel (the convention already used for packet and
graph features), plus Δt-since-previous-window as a feature. **But** it invalidates every
checkpoint and forces a rebuild of 7.7 GB+ of `data/processed*`, and it fixes the x-axis label
rather than a predictive weakness — 97.8% of CIC test steps are already exactly 10 s (D-4).
**Cheap test worth doing first:** whether a host going quiet before a flood is signal the pipeline
currently deletes. **Evidence:** Che et al. 2018 **[VERIFIED]**.

### R-9 — Train the graph encoder *(not recommended)*
**Plain answer: this will not help.** On CIC the test split is three pseudo-hosts, so the graph is
a single node — a trained encoder on a one-node graph cannot beat a random projection, and
`docs/06-gnn-ablation.md` already measured no benefit. CTU-13 has 1,787 real hosts but ~0 onsets
after R-1. UNSW has 34 hosts of which 4 attack. The architecture is not the bottleneck; the
absence of onsets is. If attempted anyway, CTU-13 is the only sensible substrate, for *detection*.
**Evidence:** King & Huang, EULER, NDSS 2022 **[VERIFIED]** — note it frames the task as
anomalous-edge detection.

## Explicitly not recommended

- **Expanding `exfiltration`.** No dataset in hand has a real exfiltration label.
  `SYNTH-Exfiltration` cannot be validated and inflates apparent five-stage coverage.
  **Remove it from the real-data stage head** — a subtraction, and the honest move.
- **"The headline is t+1" as a research direction.** It is a documentation correction. Fix the
  README and slides; an hour, not a workstream.
- **More CIC-IDS-2018 days.** All 10 are downloaded; 9 lack `Src IP`, and the one that has it
  contains only attacker hosts with no benign history. Adding days creates neither hosts nor
  onsets.

## The one thing genuinely blocked on new data

A statistically supportable forecasting claim needs a dataset with per-host 5-tuples **and** hosts
observed benign before being attacked, at a scale giving dozens of independent onset episodes.
R-3 extracts 6 from 02-20. CIC-IDS-2017 keeps the 5-tuple every day; LANL or OpTC would be
stronger. This is out of scope under the stated constraint, but it is the only route to a
defensible forecasting claim and the project should say so plainly rather than implying the
current data supports one.

---

## Provenance

Parts 2 and 3 were produced by two delegated research agents on 2026-10-10 and are retained with
their verification markers intact. Part 1's defects D-1 and D-2 were **independently reproduced**
before being recorded here: the CTU-13 mapper was run directly on real labels and the 7,754
mislabelled flows counted from the raw `.binetflow` files; the AUROC 1.000 / recall 0.0 figures
were read from `docs/cic_pkt_results.json`. The onset counts in D-3 were computed from the
processed `.npz` files and raw CSV, not quoted from any doc.

Nothing in this document was invented. Where a detail could not be confirmed on a primary source
it is marked [UNVERIFIED] or [PARTLY VERIFIED], and those must be fetched before use in a
submission.
