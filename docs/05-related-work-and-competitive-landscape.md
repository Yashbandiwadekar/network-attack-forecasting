# Related Work & Competitive Landscape

Research survey compiled 2026-09-17; **Section 4 (competing teams) re-surveyed 2026-09-27**, and
the project's own self-assessment throughout corrected on the same date to match `docs/AUDIT.md`
Part G (the cross-dataset generalisation claim this document previously leaned on is withdrawn).
Covers three questions: what does the open academic
literature say about this exact problem, what do commercial vendors already ship, and what stands
between a prototype like this one and a real business deployment. A fourth section surveys every
other SIH team building the identical problem statement (PS 26153) found on GitHub as of this
date — that field is much larger than the 3 teams reviewed in the original Round 2 competitive
pass, so treat this as the current, fuller picture.

This is a point-in-time snapshot — GitHub repo lists in particular will drift daily as more teams
push code before submission deadlines.

---

## 1. Academic research directly relevant to this project

### Attack-stage / MITRE ATT&CK forecasting — the closest match to this project's core idea

- **[A Modular Framework for Rapidly Building Intrusion Predictors](https://arxiv.org/abs/2511.23000)**
  (Nov 2025). The single closest paper to this project's framing: real-time attack-stage
  prediction, with an explicit timeliness-vs-accuracy tradeoff dial. Its central problem is one
  this project hasn't had to face yet at scale: MITRE catalogs hundreds of individual techniques,
  so training one monolithic predictor per technique is infeasible. Their answer is a library of
  reusable, composable prediction components assembled per-technique rather than one giant model.
  Worth reading closely before trying to extend past the current 5-stage classification head to
  technique-level granularity.
- **[DeepOP: Hybrid Framework for MITRE ATT&CK Sequence Prediction](https://www.researchgate.net/publication/387885657_DeepOP_A_Hybrid_Framework_for_MITRE_ATTCK_Sequence_Prediction_via_Deep_Learning_and_Ontology)** —
  combines deep learning with an explicit ontology (structured domain knowledge about how
  techniques relate) specifically to generalize multi-step attack prediction across scenarios with
  limited training data per scenario. Relevant to the "reconnaissance has no real CIC-IDS-2018
  label, exfiltration has no real-data label at all" gap already documented in
  `03-mitre-mapping.md` — an ontology-informed prior could be one way to handle sparsely-labeled
  stages instead of pure data-driven learning.
- **[ATTAXML](https://link.springer.com/chapter/10.1007/978-3-032-19099-4_37)** — applies extreme
  multi-label learning to predict MITRE ATT&CK techniques specifically within ransomware behavior.
  Narrower scope (one malware family) but a useful reference for technique-level (not just
  stage-level) labeling schemes.

### Transformer-based NIDS — architecture validation

- **[A novel multi-scale network intrusion detection model with transformer (IDS-MTran)](https://www.nature.com/articles/s41598-024-74214-w)**
  — uses multiple convolutional kernel scales feeding a transformer backbone, arguing multi-scale
  traffic features broaden detection coverage. Suggests one concrete architecture extension: this
  project's flow/graph/packet feature split could similarly benefit from being processed at
  different temporal granularities before the shared self-attention encoder.
- **[Time Series Based NIDS using MTF-Aided Transformer](https://arxiv.org/pdf/2508.16035)** —
  converts flow sequences into Markov Transition Field images before the transformer, reporting
  competitive accuracy with limited training data — relevant given this project's own real-data
  windows are sparse for some MITRE stages (reconnaissance, exfiltration).
- General takeaway: attention-based architectures are now the mainstream choice for flow-level
  detection in recent (2024-2026) literature, which supports the project's own Round 1 decision to
  use a Transformer over GNN/LSTM alternatives.

### World models / Dreamer / RSSM — searched specifically, found a gap

Searching directly for "world model" / "Dreamer" / "RSSM" combined with cybersecurity or network
traffic returned essentially nothing — the RSSM/Dreamer/latent-imagination literature
([Dreaming: Model-based RL by Latent Imagination](https://arxiv.org/pdf/2007.14535), DreamerV3)
is exclusively applied to robotics/control/game-playing RL. **No open academic paper was found
applying an RSSM-style latent world model to network security specifically** — the closest thing
is the competitor team `HowSuyash/AttackForecast` (see Section 4), which builds exactly this
(GRU + prior/posterior latent dynamics) but is a hackathon prototype, not published research. This
is either a genuine open research gap or a naming-convention gap (the technique may exist under a
different name in the security literature) — worth a targeted follow-up search using security-side
terminology ("latent dynamics network telemetry", "generative traffic model") rather than
RL-side terminology if this becomes a direction worth pursuing.

### Cross-dataset generalization — this literature now *explains* this project's own negative result

- **[On the Cross-Dataset Generalization of Machine Learning for Network Intrusion Detection](https://arxiv.org/pdf/2402.10974)**
  (Cantone, Marrocco, Bria — Univ. of Cassino and Southern Latium, Feb 2024). Read in full. 1,728
  experiments across CIC-IDS-2017, CSE-CIC-IDS2018, and two corrected variants
  (LycoS-IDS2017, LycoS-Unicas-IDS2018).
  - **Headline finding**: within-dataset (train and test on the same dataset), models hit
    near-perfect accuracy. Cross-dataset, accuracy collapses to **near random chance** for most
    model/dataset combinations. Cited prior work in the same paper reports similarly severe drops:
    an average 30.45% AUROC decrease cross-dataset for unsupervised models, and federated-learning
    setups sometimes swinging from 94.91% F1 (within-dataset) to as low as 9.36% F1 cross-dataset
    depending on the source/target pair.
  - **Why this matters for this project specifically**: this project ran the *same experiment*
    (train on CIC-IDS-2018, zero-shot test on CTU-13, see `04-evaluation-ctu13_cross_from_real_data.md`)
    and got **no transfer**: the regenerated report shows F1 0.009 and AUROC 0.517 (chance level) on
    CTU-13, with attack-class stage F1 of 0.000. (An earlier version of this note claimed a partial
    transfer, F1 0.534; that number is withdrawn -- see `docs/AUDIT.md` G1.) This is consistent with
    the paper's baseline of "usually total collapse", not an exception to it, and should be stated
    plainly against this citation in the submission rather than presented as a strength.
  - **A second, separate finding buried in this paper's related-work section is a real risk for
    this project**: cited studies on CIC dataset integrity found **labeling error rates of
    6.67% (CIC-IDS2017) and 7.53% (CSE-CIC-IDS2018)**, with label corruption **exceeding 75% for
    some individual attack classes**, plus documented issues with feature duplication, feature
    miscalculation, and incorrect protocol detection in the raw CICFlowMeter extraction pipeline
    itself. Since CIC-IDS-2018 is this project's primary training set, this is a concrete, citable
    caveat worth preempting in the submission ("we are aware of known labeling-quality issues in
    the CIC dataset family; a production deployment would need a data-quality validation layer
    before trusting labels at face value") rather than leaving it for a judge to raise first.

### Adversarial robustness in NIDS — directly validates this project's own Feature #5 result

- **[Adversarial Challenges in Network Intrusion Detection Systems: Research Insights and Future Prospects](https://arxiv.org/pdf/2409.18736)**
  (Ennaji, De Gaspari, Hitaj, Kbidi, Mancini — Sapienza University of Rome, Oct 2024, 35-page
  survey). Read in full. Its central thesis, stated directly in the abstract: adversarial evasion
  is extensively studied for images and text, but **"their impact on structured data like network
  traffic is less explored."** The introduction goes further — most published NIDS research
  doesn't even include adversarial attacks in its threat model at all, and feature
  interdependencies/constraints in structured flow data make naive image-style adversarial
  perturbation techniques not directly transferable.
  - **Why this matters for this project specifically**: the PGD-style evasion test in
    `scripts/check_adversarial_robustness.py` isn't a routine checkbox — per this survey it is
    addressing a genuinely under-covered gap in the field, not a well-trodden one. That the test
    found and honestly reported a real vulnerability (evasion succeeding by suppressing
    `flow_count`/`total_packets`) is a stronger, more citable result than most published NIDS work
    currently offers, since most of that work doesn't test for this at all.

---

## 2. Enterprise / commercial implementations

| Product | What it actually does | How it differs from this project |
|---|---|---|
| **Darktrace** | Self-learning per-device behavioral baseline ("Enterprise Immune System") + autonomous response (Antigena) that acts in milliseconds | Anomaly-against-baseline detection, not explicit multi-step forecasting — reactive in mechanism despite "predictive" marketing language |
| **Vectra AI** | Purpose-built attacker-behavior models correlated across network/identity/cloud, explicitly tuned to minimize alert volume and maximize per-alert confidence | Detection-and-prioritization, not K-step forecasting — but philosophically closest of the group to this project's narrative+response-playbook framing (both prioritize analyst trust and reduced triage load over raw detection rate) |
| **CrowdStrike** | "Predictive Path Analysis" (Falcon Exposure Management) forecasts *attack paths* from vulnerability/exposure graph structure; separate AI-driven Indicators of Attack (IoA) for real-time behavioral detection | "Prediction" here means graph-structural attack-path forecasting from known vulnerabilities, not traffic-dynamics forecasting from live flow telemetry — a genuinely different notion of "predictive" than this project's |
| **Palo Alto Cortex XSIAM** | Converges SIEM + XDR + SOAR + attack surface management into one AI-driven platform, explicitly marketed as moving the SOC "from reactive to proactive security to prevent breaches before they happen" | A platform-consolidation play, not a specific forecasting model — useful primarily as market validation that this project's stated goal (proactive vs. reactive SOC posture) is exactly the direction the commercial market is already moving |
| **Corelight / ExtraHop** | Network detection & response (NDR) platforms; unsupervised + supervised ML for novel/evasive threat detection; deep CrowdStrike threat-intel integration | Detection-focused rather than forecasting-focused, but the strongest reference point in this table for what production-grade flow ingestion at real enterprise scale actually requires |
| **IBM QRadar** | Long-standing SIEM; as of late 2024, its SaaS assets were acquired by Palo Alto Networks and are being migrated into Cortex XSIAM (on-prem QRadar continues under IBM support through at least 2029) | Notable mainly as a signal about market consolidation — standalone SIEM vendors are being absorbed into unified AI-driven SOC platforms industry-wide |
| **Google SecOps (Chronicle)** | Petabyte-scale SIEM with native Gemini AI for guided investigation; ranked highest on Gartner's "Completeness of Vision" axis in 2025 | LLM-assisted investigation rather than a forecasting model — a different way of addressing the same "reduce analyst burden" goal this project addresses via its attack-narrative generator |

---

## 3. What actually needs solving for a business implementation

Drawn from the deployment-challenges literature plus what the enterprise products above are
visibly optimizing hardest for — this is the gap between a validated prototype and a fieldable
product.

1. **Cross-network generalization at customer-onboarding time.** Every per-customer vendor above
   (Darktrace, Vectra) baselines *per deployed network* rather than shipping one static model,
   because the Cantone et al. finding above is real: a model trained on one network's traffic does
   not reliably transfer to another's out of the box. This project's own CIC→CTU-13 result (AUROC
   0.517, chance level — re-measured 2026-09-23, see `docs/AUDIT.md` G1) is a textbook instance of
   exactly that collapse, not an exception to it. An earlier version of this section called the
   result "encouraging (partial transfer, not collapse)" on the strength of the withdrawn F1 0.534
   figure; that reading is retracted. A real product would need a per-deployment fine-tuning step or
   an explicit domain-adaptation mechanism — a single frozen checkpoint is not commercially viable
   as-is, and this project's own numbers now demonstrate why rather than hint at an exception.
2. **False-positive economics at enterprise scale.** At the ~9,150-host scale this project's own
   dashboard has already demonstrated live, even a small false-positive rate produces dozens of
   daily alerts an analyst must triage — Vectra's entire product philosophy ("signal over noise")
   is built around exactly this constraint. The fixed-FPR calibration already built into
   `eval/benchmark.py` is the right mechanism; a product would need it tunable per-deployment
   rather than a single hardcoded 5% operating point.
3. **Continuous retraining and drift detection.** Attacker behavior and normal-traffic baselines
   both shift over time; a static checkpoint decays. The MLOps literature treats automated drift
   detection plus scheduled retraining as table stakes, not optional — this project currently has
   no such infrastructure (every retrain in this project's history has been manually triggered).
4. **Explainability as a compliance requirement, not a UX nice-to-have.** In finance, healthcare,
   and government deployments, an unexplainable alert creates real regulatory exposure, not just
   analyst friction. This project's three-method explainability stack (attention + SHAP +
   gradient×input) plus the narrative/response-playbook layer is already ahead of most of the
   commercial products surveyed above on this specific axis — worth stating as a differentiator
   directly, not just describing the features.
5. **Dataset and label quality as a foundational risk, not an academic footnote.** The 6.67-75%
   labeling corruption figures cited above are a genuine, citable risk for any commercial system
   built on the CIC-IDS-2018 family. A production deployment would need an explicit data-quality
   validation layer (outlier/relabeling checks) before fully trusting any label-derived ground
   truth, rather than assuming public benchmark labels are correct by default.
6. **Integration alongside existing infrastructure, not replacement of it.** Every enterprise
   product surveyed sits next to existing SIEM/NDR/XDR tooling, ingesting the same flow-export
   formats already common in production networks (NetFlow, CICFlowMeter-style, Zeek). This
   project's dataset-agnostic pipeline (already proven across two independently-sourced datasets
   without redesign) is a real strength here, provided it is positioned as augmenting a SOC's
   existing stack rather than replacing it.
7. **Adversarial robustness as a first-class, ongoing requirement.** The Ennaji et al. survey
   confirms most published NIDS research doesn't model this threat at all. This project already
   found and honestly reported one real evasion path (Feature #5). A production system needs a
   hardening/retraining loop built around findings like this on an ongoing basis, not a one-time
   test-and-document exercise.

---

## 4. Competing SIH teams building the same problem statement (PS 26153)

### Field size, re-measured 2026-09-27

Searched via the GitHub REST search API (`gh api search/repositories`), 10 queries:
`SIH26153`, `PS26153`, `sih 26153`, `"network attack forecasting"`, `"attack forecasting"`,
`"attack stage" prediction network`, `"world model" cybersecurity`, `"world model" network traffic`,
`forecasting CICIDS`, `"attacker progression"`. 148 unique repositories returned. Excluded: this
project's own repo; 6 off-topic keyword collisions (heart-attack prediction, a RuneScape overlay,
two Global-Terrorism-Database dashboards, a steering-wheel monitor); 8 repos created before
2026-06-01, outside the SIH 2026 team-formation window; and 5 real projects solving a *different*
task (the contrast bucket at the end of this section). One repo documented on 2026-09-17 and still
alive, `reginaroselin0223-spec/Peri-Tech-Titans`, was returned by none of the 10 queries and has
been added back by hand.

| Measure | Count |
|---|---|
| Repos in the field | **123** |
| Distinct owners | **116** |
| **Distinct projects** (the honest team-count proxy) | **115** |
| — high confidence: name or description cites SIH / 26153 / NTRO | 52 repos |
| — lower confidence: topic match only, may not be SIH submissions | 71 repos |
| Pushed to since the last survey (2026-09-17) | 40 of 123 |
| Created since the last survey | 27 |
| New to this document | 55 |

**Repos are not teams.** Four owners hold 2–3 repos each (`Manishdhangar0047` ×3, `madhavgorla` ×3,
`GauravKrBhagat` ×2, `krishnashahane` ×2 — code plus a separate research-paper repo), and
`verpejas` / `cyber-laboratory` publish the same Visual_Analytics_Tool under two accounts, which is
why the project count (115) is lower than the owner count (116). The 71 lower-confidence entries
match on topic alone; some are certainly not SIH submissions.

**On the ~128 figure — this needs confirming, not assuming.** It depends entirely on what that
number counts, and the two possibilities are not interchangeable:

- *If it is the SIH portal's idea-submission count for PS 26153*, it is a **different population**
  from public GitHub repos. Teams submit without ever publishing code, and several repos counted
  here are not submissions. The two numbers landing near each other would then be coincidence, and
  quoting them as one figure would be wrong.
- *If it is a GitHub search count*, it is consistent with what this pass measured: 123 in-field
  repos, plus the 5 contrast-bucket projects, equals 128 returned-and-plausible repositories.

Ask before citing either reading in the submission.

**Growth is partly a method artefact.** The 2026-09-17 pass used 5 queries and named 72 repos (its
own text said "roughly 80"); this pass used 10 queries and found 123. Of the 72 named previously,
68 still exist; 4 have been deleted or made private (`GAMERMADXDAT/CYBERBAT`,
`Wahulaniket/AI-based-Network-Attack-Forecasting-from-Network-Traffic-Data`,
`ghantaakashchowdary/AI-based-...` — the same owner now has an `Al-based-...` spelling variant, so
probably a rename rather than an abandonment — and `venkatpavan8806/Network-attack-forecasting`).
**27 of the 123 were created after 2026-09-17**, so genuine growth is roughly 27 repos in 10 days;
the rest of the jump from 72 to 123 is the wider query set, not new competitors.

Everything below is **self-described from repo metadata, plus two READMEs read directly
(`ShadowCat`, `TheRedKeep`) — not independently verified**. Descriptions are paraphrased, and a
claim in a README is a claim, not a working feature.

### Most differentiated approaches found (assessed 2026-09-17)

> **Stale-comparison warning.** The "why it stands out" column below was written on 2026-09-17 and
> several rows contrast against a version of this project that no longer exists. Corrected
> 2026-09-27: CVE/NVD enrichment and CERT-In reporting now exist (`models/cve_lookup.py`,
> `models/compliance.py`), a hash-chained audit ledger exists (`models/audit_ledger.py`), a
> lead-time metric exists (`eval/metrics.py::lead_time_metrics`), and the benchmark now includes
> Markov, LSTM and Transformer arms. Individual rows are annotated where they are affected.

| Repo | Stars | Created | Why it stands out |
|---|---|---|---|
| **[ErenSnowh/Argus](https://github.com/ErenSnowh/Argus)** | 4 (most-starred of the field) | 2026-06-23 | "Autonomous... Multi-Agent SOC Co-Pilot powered by Temporal World Models, MITRE ATT&CK, **CAPEC, CVE/NVD**, and **Dual Statutory Reporting (CERT-In + NCIIPC)**." The only team found integrating specific vulnerability databases (CVE/NVD) and, notably, actual **Indian regulatory compliance reporting** (CERT-In, NCIIPC) — a genuinely different differentiation axis (regulatory/statutory framing) than this project's five differentiator features as they stood in September. Given the PS issuer is NTRO, this angle may resonate with judges. **Stale as of 2026-09-27**: this project now has both CVE/NVD enrichment (`models/cve_lookup.py`) and CERT-In-style reporting (`models/compliance.py`), so the gap is narrower than this row implies. Argus remains the most-starred entry (4) but has not been pushed to since 2026-09-08. |
| **[raushankumarsah07](https://github.com/raushankumarsah07/aI-based-network-attack-forecasting-from-network-traffic-data)** | 0 | 2026-08-26 | GRU-based world model plus **counterfactual "what-if" rollout simulation** (this project independently built the same capability, see Feature #4) — AND **Solidity smart contracts on Ethereum for tamper-proof prediction auditing**. The blockchain-audit angle answers the PS's stated theme ("Blockchain & Cybersecurity"). **Partly stale as of 2026-09-27**: this project now ships a hash-chained tamper-evident ledger (`models/audit_ledger.py`) — blockchain's core primitive without a distributed ledger — so the remaining difference is on-chain verifiability, not tamper evidence as such. |
| **[ayushshandilya-dev/netsight](https://github.com/ayushshandilya-dev/netsight)** | 0 | 2026-09-06 | "Model-internal XAI, novelty callout, **SHA-256 audit ledger**. Runs 100% offline." Another tamper-evidence angle (hash-chained audit log rather than blockchain), combined with an explicit "novelty callout" signal — conceptually similar to this project's own reconstruction-error novelty metric. |
| **[SuhithZ-dreambot/Precursor](https://github.com/SuhithZ-dreambot/Precursor)** | 0 | 2026-09-10 | Fuses a classical **EWMA/CUSUM statistical drift detector** with a GRU/LSTM sequence model, and reports an explicit **"lead-time" evaluation metric** — i.e., directly measures how many seconds/windows of advance warning the system provides, rather than only F1/precision/recall. This is a meaningfully different and arguably more PS-aligned evaluation methodology (the PS explicitly asks for forecasting *before* compromise, i.e., lead time is the point). **Addressed as of 2026-09-27**: this project now reports lead time with false-alarm accounting (`eval/metrics.py::lead_time_metrics`), which is what prompted the change. Precursor was last pushed 2026-09-23. |
| **[raghuraj72/Vanguard-GWM](https://github.com/raghuraj72/Vanguard-GWM)** | 0 | 2026-08-27 | "**Generative Graph World Model**" — a GNN-based world model. This project explicitly chose Transformer over GNN in Round 1 for timeline/complexity reasons (documented in `01-architecture.md`); this is a live example of a competing team taking the GNN path instead. |
| **[mithun-afk/ST-WM-Cyber](https://github.com/mithun-afk/ST-WM-Cyber)** | 0 | 2026-09-09 | "Spatial-Temporal World Model" — another graph/spatial variant of the same core idea, independent confirmation that graph-augmented world models are a common alternative direction among competing teams. |
| **[csxzor-devcs](https://github.com/csxzor-devcs/sih26153-network-attack-forecasting)** | 0 | 2026-09-15 | Explicitly benchmarks **Markov, LSTM, and Transformer** models against each other for stage prediction — a three-way architecture comparison this project's benchmark lacked in September. **Stale as of 2026-09-27**: the benchmark now carries Markov, LSTM and Transformer arms alongside the LR and persistence baselines (`models/markov_baseline.py`, `models/lstm_model.py`). |
| **[ShipraSharma08](https://github.com/ShipraSharma08/AI-Network-Attack-Forecasting)** | 0 | 2026-09-03 | Temporal network state modeling plus **blockchain-based evidence integrity** — second team (after raushankumarsah07) independently landing on blockchain for evidence/audit purposes, suggesting this is a recognized way other teams are satisfying the PS's "Blockchain & Cybersecurity" theme requirement. |
| **[Impala04/sih26153-attack-chain-detection](https://github.com/Impala04/sih26153-attack-chain-detection)** | 0 | 2026-08-31 | "Adaptive behavioural attack-chain detection for identifying **non-IoC** network compromises" — explicitly framed around detecting attacks that *don't* match known indicators of compromise, a different framing angle from this project's MITRE-stage-classification approach. |
| **[NotVivek12/AegisTwin](https://github.com/NotVivek12/AegisTwin)** | 0 | 2026-09-06 | Framed explicitly as a "**digital twin**" of the network rather than a "world model" — same underlying concept, different vocabulary; worth noting since "digital twin" may be a more judge-legible term than "world model" depending on the panel's background. |
| **[krishnashahane/sentinel-sih](https://github.com/krishnashahane/sentinel-sih)** + **[krishnashahane/Sentinel---Research-paper](https://github.com/krishnashahane/Sentinel---Research-paper)** | 2 | 2026-08-21 / 09-02 | Previously known (Round 2 competitive pass) as "Sentinel" — an LSTM-based world model. Notably, this team has since split out a **dedicated research-paper repo**, suggesting they intend to publish/formalize their approach separately from the code — a submission-strategy signal worth being aware of. |
| **[HowSuyash/AttackForecast](https://github.com/HowSuyash/AttackForecast)** | 0 | 2026-08-23 | Previously known (Round 2) as the most architecturally sophisticated competitor — true RSSM/Dreamer-style latent world model over CTU-13. Still the closest thing to an actual academic-style world-model implementation found anywhere in this search, including the broader literature search in Section 1. |
| **[hasim2006/PhantomGrid-Predictive-Defense-SIH26153](https://github.com/hasim2006/PhantomGrid-Predictive-Defense-SIH26153)** | 0 | 2026-08-22 | Previously known (Round 2) — thin, suspicious identical-precision baseline-vs-model numbers noted at the time. Unchanged assessment. |

### New to this document (first recorded 2026-09-27)

55 repos here were not in the 2026-09-17 pass; 27 of them were created after that date, and the
rest existed but were missed by the narrower query set. Featured below are the 10 whose own
description or README signals a specific technical approach.

| Repo | Stars | Created / last push | Why it matters |
|---|---|---|---|
| **[muthukkumaranb/ShadowCat](https://github.com/muthukkumaranb/ShadowCat)** | 0 | 09-11 / **09-27** | **The most direct competitor found in either survey.** Its README claims the same three things this project treats as differentiators — "quantified lead time, empirical leakage protection, and tamper-evident cryptographic provenance" — plus LSTM + graph fusion, MITRE mapping, per-prediction explanations and fully offline operation. The repo is large and actively pushed (separate `ml1`, `ml2-full`, `backend`, `frontend`, `data-engineering`, `fabric-experiment` trees). "Empirical leakage protection" is the audit's own E1 concern claimed as a feature. README read directly; the claims are not verified. |
| **[mainpratyushhoon/TheRedKeep](https://github.com/mainpratyushhoon/TheRedKeep)** | 0 | 08-30 / 09-04 | Describes a **latent world model (PyTorch RSSM)**, the second such claim after `HowSuyash/AttackForecast`. Its README is an unusually careful reading of the PS, arguing explicitly for model-based latent state tracking over conventional NIDS ML, and the file listing includes `baseline.py`, `baseline_xgb.py`, `evaluate.py`, `inspect_timeline.py` — a baseline-comparison habit most of the field's descriptions show no sign of. README and file list read; the RSSM implementation itself is not verified. |
| **[axorarbxy/network-digital-twin](https://github.com/axorarbxy/network-digital-twin)** | 0 | 09-18 / 09-18 | "Offline-first" **digital-twin** framing with world modelling, MITRE mapping and explainability — the second team after `NotVivek12/AegisTwin` to prefer "digital twin" over "world model". |
| **[Radhika-coder46/Blockchain-Cybersecurity](https://github.com/Radhika-coder46/Blockchain-Cybersecurity)** | 0 | 09-02 / 09-02 | Fourth independent team using **blockchain/ledger framing** for prediction integrity, and the only one to put the PS theme ("Blockchain & Cybersecurity") in the repo title. |
| **[NAMAN-THAKUR-1944/SIH26-127364](https://github.com/NAMAN-THAKUR-1944/SIH26-127364)** | 0 | 09-21 / 09-21 | Temporal world model with **Input×Gradient explainability** — the same attribution family this project uses — and a claim to forecast **zero-day** attacks, a far stronger generalisation claim than any published evidence in this field supports. |
| **[verpejas](https://github.com/verpejas/Visual_Analytics_Tool)** / **[cyber-laboratory](https://github.com/cyber-laboratory/Visual_Analytics_Tool)** | 0 | 07-30, 08-03 | One tool published under two accounts: **DTW sequence alignment + RNN** forecasting behind a visual-analytics front end. DTW alignment is a genuinely different temporal-modelling primitive from anything else in the field. |
| **[clustercoder/nidra](https://github.com/clustercoder/nidra)** | 0 | 09-06 / 09-19 | "Network Infiltration & Dynamics Recurrent Analyzer" — recurrent dynamics model, actively developed. |
| **[piyushkashyap160-spec/CyberForecaster](https://github.com/piyushkashyap160-spec/CyberForecaster)** | 0 | 08-25 / 09-07 | Restates the PS's own framing almost verbatim (temporal network-state dynamics, forecasting before compromise completes). |
| **[sjeevitha2106/network-attack-forecasting](https://github.com/sjeevitha2106/network-attack-forecasting)** | 0 | 09-19 / 09-19 | **Random Forest** benign/attack classifier with a Streamlit dashboard — i.e. exactly the static per-flow classification the PS says to move beyond. A reminder that a sizeable share of the field is not attempting the forecasting task at all. |

**Also new, with a real description but no distinguishing technical claim (20):**
`71382502061harshana-dotcom/HARSHANA-K` · `Aditya-Coder477/NEXUS-Forecast` (actively pushed) ·
`Gaurav123b/AI-based-...` (1 star) · `GauravKrBhagat/NETRA.AI` ·
`Low-Level-Strivers/Network-Attack-Forecast-System` (LSTM world model) ·
`SaarthakManocha/DRISHTI-...` · `Tkc12344/netanomaly` · `Tony274772/CYBER-PULSE-...` ·
`Zam-za/HarpocratesEngine` (Java) · `adizyachamp/cybornix` · `anirudhmkdev/NetForeSight` ·
`buildwithanish2/GuardianX-AI-Network-Attack-Forecasting` · `gokullaxman/AI-based-...` ·
`manansheth296-tech/sentinel-net` (2 stars) · `prasanth-09/predictive-cyber-defence-sih26153`
(temporal world model + risk scoring + asset analysis) · `reginaroselin0223-spec/NetGuard-AI` ·
`sawantvinayak473-cyber/cyberworld-network-attack-forecasting` · `sejalpunwatkar/NetPulseWorld` ·
`sivaharish-R/AI-Based-Network-Attack-Forecasting` · `yuvarani163/cyber-attack-forecasting-system`.

**Also new, with no or near-empty description (25):**
`Digitalspy12/AI-based-...` · `Fareedcoder/SIH26153-Network-Attack-Forecasting` ·
`GauravKrBhagat/NETRA---AI-Network-Attack-Forecasting` ·
`Manishdhangar0047/AI-Network-attack-forecasting` · `Manishdhangar0047/Network-attack-forecasting-` ·
`Nikazuto/SIH-26153-Trikal` · `PrajaRavi/CyberPredict-...` ·
`Prasad14-cyber/network_attack_forecasting` · `Pravin1419/INNOVIXUS-SIH26153` ·
`RaghiniGK/network-attack-forecasting-my-work` · `Tarun-015/CyberCast` · `Team-M3OW/SIH-26153` ·
`UmaraNoor/cyber-attack-forecasting-repo` · `adityaroman07-hue/SIH26153-NetVision-AI` ·
`anshuman2810/Neural_StealthOps_SIH26153` · `bikram-341/AI-Based-...` ·
`devanshkatkar246/AI-Based-Network-Attack-Forecasting` · `ghantaakashchowdary/Al-based-...` ·
`hsh62804-droid/network-traffic-attack-forecasting` · `nehin17/network-attack-forecasting` ·
`prakhar14-op/Cyber-Attack-Forecasting-SIH-2026` · `priyagautam18/network-attack-forecasting` ·
`satyamforge/SIH-26153` · `syednzaheer/SIH-P.S.-26153-Defender` ·
`tariksk786/NetworkAttackForcasting`.

### Deep dive, 2026-09-29: where Argus's and TheRedKeep's numbers actually come from

The two most-cited competitors after ShadowCat were examined at source (README, repository tree,
training code, results files) rather than from their descriptions. The conclusions differ sharply.

#### ErenSnowh/Argus — the headline 99.97% is on self-generated synthetic data

Argus's README table reports **accuracy 99.975%, macro-F1 99.97%, infiltration AUC 0.983** for its
World Model Transformer against a Random Forest at 93.00% / 92.99%, under a row reading
"Split Strategy: Temporal (no future leakage)".

Read at source, the provenance is stated two lines above the table and is easy to miss:

> Training Set: 1,600 sequences × 10 timesteps · Test Set: 400 sequences × 10 timesteps
> "Trained with 2,000 temporal sequences (**8 attack scenarios + random kill-chain patterns**)"

Corroborating evidence from the code:

- `argus/ml/world_model/train.py` takes `--dataset` with **`default="synthetic"`**, `--sequences`
  default 500; its docstring says "Trains on either synthetic temporal data or real
  CIC-IDS-2018/CTU-13 datasets", and its usage example is `python -m ml.world_model.train  # synthetic data`.
- The bundled CIC-IDS-2018 and CIC-IDS-2017 fixtures are **5 KB and 4 KB** — tens of rows, sample
  fixtures for loader tests, not training corpora.
- The README's own "Training Time: 57.9s, Convergence: 24 epochs" is consistent with ~2,000 short
  synthetic sequences and not with a real CIC-IDS-2018 build.

**So 99.97% is a model learning the rules of its authors' own scenario generator, measured on 400
synthetic sequences.** It is not a real-traffic result and is not comparable to any number in this
project's evaluation reports, which are measured on 194,632 (v1) and 7,191 (v2, day-disjoint) real
CIC-IDS-2018 test sequences. Argus is not dishonest about this — the sequence counts are printed —
but the number will read as a real-data benchmark to anyone skimming, and it should not be treated
as a bar to clear. Argus's genuine strengths are elsewhere: breadth of dataset loaders (8 public
datasets normalised to one 38-feature schema), the multi-agent SOC framing, and CERT-In/NCIIPC
statutory reporting.

#### mainpratyushhoon/TheRedKeep — no world-model results yet, but the best methodology writing in the field

TheRedKeep's repository is 28 files. Its only results artefact is
`results/xgboost_baseline_results.txt`: an **XGBoost baseline** on UNSW-NB15's official pre-split
train/test files — accuracy 0.9004, ROC-AUC 0.9840, **PR-AUC 0.9882**, **FPR 0.1838**, on 82,332
test rows. Trained `.pth` world models exist in `models/`, but **no world-model metrics are
published**. So TheRedKeep currently has a baseline, not a result.

What makes it worth studying anyway is `markdown/UNSW_NB15_RSSM_Data_Problems.md`, which lists, in
advance of building, the same evaluation traps this project had to discover by measurement:

| TheRedKeep's stated risk | This project's finding |
|---|---|
| #18 "Random train/test splitting can cause temporal leakage — nearly identical or adjacent network behavior can appear in both train and test, producing overly optimistic results" | **E1** (per-host split shared attack sessions; F1 0.917 → 0.370 once fixed) |
| #19 "Sequence boundaries can cause leakage — if sliding windows overlap across train/test boundaries" | **E8** (no embargo between splits) |
| #12 "Potential data leakage during preprocessing — if normalization statistics are calculated using test data" | **S3 / E9** (scaler fitted on the test split) |
| #4 "Raw timestamps shouldn't be directly fed to the model — could memorize absolute time" | Not a finding here, but the same class of concern |

Its README also prescribes a **rigid temporal boundary** ("train on Days 1–3, validate on Day 4,
test on Day 5") — the day-disjoint split this project only adopted under W7 — and prioritises
**PR-AUC over ROC-AUC** on the grounds that ROC-AUC is misleading under class imbalance, which is
correct and is a reporting habit worth copying.

#### What this means for positioning

- **Do not benchmark against Argus's 99.97%.** It is synthetic. Stating that plainly, with the
  sequence counts, is fair comment and is more useful than trying to match it.
- **TheRedKeep shows the methodology bar is being set publicly by others.** The distinction this
  project can still defend is that it *executed and published* the measurements — LOFO, adversarial
  evasion, a retracted headline number — where TheRedKeep has so far listed the risks and shipped a
  baseline.
- **Free credibility win:** TheRedKeep cites **Arp et al., "Dos and Don'ts of Machine Learning in
  Computer Security" (USENIX Security 2022)**, the standard reference for exactly these evaluation
  flaws. This project's audit independently rediscovered several of its "don'ts" — data snooping via
  session overlap (E1), base-rate fallacy in the 5%-FPR operating point (E5), and inappropriate
  baselines (E6, the label oracles). Citing it in the architecture document and the deck reframes
  those findings as textbook-recognised failure modes the team caught and fixed, rather than
  idiosyncratic self-criticism.

### Contrast bucket — real projects, different task (excluded from the 123)

Kept here so they are neither miscounted as competitors nor rediscovered and misclassified later.

| Repo | Why it is not in the field |
|---|---|
| [Mouliprasad2002/cyber-attack-forecasting-arima](https://github.com/Mouliprasad2002/cyber-attack-forecasting-arima) | ARIMA over CISA's Known Exploited Vulnerabilities catalogue — forecasts global exploitation activity, not network state. |
| [metaordo/StarCore](https://github.com/metaordo/StarCore) | "Cyberspace World Model that learns from system state-chains" — host/system telemetry rather than flow records. |
| [TraceHanami/AIVA-Ks](https://github.com/TraceHanami/AIVA-Ks) | Kernel-level attack simulation with behavioural graphs and attacker-intent prediction — the endpoint analogue of this problem. |
| [sharmaronit/Defnet](https://github.com/sharmaronit/Defnet) | World Models + multi-agent RL whose output is a *patch recommendation*, not an alert. Created 2026-06-13 and untouched since; likely not an SIH submission. |
| [cyberbeko/Cyber-Defense-Incident-Response-...](https://github.com/cyberbeko/Cyber-Defense-Incident-Response-Azure-Sentinel-KQL-Threat-Hunting-) | An Azure Sentinel KQL threat-hunting write-up, not a forecasting model. |

### Full list of other repos found as of 2026-09-17 (lower signal from description alone - not independently verified)

Grouped alphabetically by owner. Most have generic or empty descriptions and may be early-stage
scaffolding rather than substantive prototypes; listed for completeness since the request was for
every matching repo, not a pre-filtered subset.

24r01a05n3/Network-Attack-Forecasting · Aashijain-coder/Network-Attack-Forecasting-system ·
abdulmuqeeth-ai/AI-Network-Attack-Forecasting · adharsh0713/network-attack-forecasting ·
adhithya123456433/AI-Based-Network-Attack-Forecasting-from-Network-Traffic-Data ·
animeshmishra786/network-attack-forecasting (CICIDS2017-based) · AnirudhRao-24/Network-Attack-Forecasting ·
anshm0493-ux/ThreatLens---SIH26153 · arpitchakladar/netwatron · Atishayjain2463/SIH26153-Attack-Forecasting ·
bansalanikait/SIH26153 · cattolatte/foresight ("learns P(S_t+1|S_t)" — same notation this project's own
docs use) · devi1207459/NetGuard-AI · dikshaasudha29/NAF · GAMERMADXDAT/CYBERBAT ·
Gangireddy2401/network-attack-forecasting · GaneshChowdary7/SIH26153-network-data-pipeline ·
ghantaakashchowdary/AI-based-Network-Attack-Forecasting-from-Network-Traffic-Data ·
GMinnu/SIH26153_AI-based-Network-Attack-Forecasting-from-Network-Traffic-Data ·
Harsh33t/Sunniva-anti-ddos · jagdish-15/netforec · jeffreyfeoder/SIH-prototype ("TraceForge") ·
Keshav-Verma-06/Hybrid-Network---Attack-Forecasting-System · kodurumeghana3/Threatcast-AI
(explicitly "Built with Manus" — likely a no-code/low-code prototype) · Malini-art/sih26153 ·
Manishdhangar0047/network-attack-forecasting (and two similarly-named variant repos by the same
owner — possibly abandoned/restarted attempts) · madhavgorla/SentinelAI-SIH26153 ·
madhavgorla/SIH26153-Module2-Module3-Connected · madhavgorla/SIH26153-Module3 · mohdayaan99/Network-Attack-Forecasting
(CIC-IDS2017-based) · mohdsubhan1756/network-attack-forecasting · mubeenuddin03/Network-Attack-Forecasting ·
Nikethan10/trinetra-sih2026-ps26153 ("TRINETRA") · Omkar-Phalke/Network-Attack-Forecasting ·
overhyped-pratham/cybersentinel-ai ("Autoregressive Campaign Trajectory Simulation" — same
autoregressive-rollout concept this project uses) · PhaNtoM-GHosT-11101/SIH-26153 ·
pragathie21/network-attack-forecasting · Praveenkumar9-hub/SIH26153-AI-Network-Attack-Forecasting ·
prateek-kumar007/SIH26153-Network-Attack-Forecasting · pulkitokte/SIH26153-Network-Attack-Forecasting ·
RAJANKUMAR2327/SIH26153-Team-Application · reginaroselin0223-spec/Peri-Tech-Titans ·
Rijja-explore/Network-Attack-Forecasting · rishikrishnan357-svg/SIH26153 · SabarishR08/ai-network-attack-forecasting ·
sanjayn29/NetForecaster-AI · sanjayz7/AI-based-Network-Attack-Forecasting-from-Network-Traffic-Data ·
sashankgurumoorthyg-gif/-SIH26153-AttackForecast- (unusually explicit README: file-upload risk
scoring across 4 fixed scenarios — portscan/quiet-baseline/active-intrusion/exfiltration — rather
than live traffic forecasting) · sasukeee2324/Network_Attack_Forecast · Shivani06hub/network-attack-forecasting ·
Sneha-4219/SIH26153-ML · Srimullaiharinie/TRINETRA (name collision with Nikethan10's repo above —
likely coincidental, not the same team) · trinesh1666/cyber-ai-forecasting ("cybersecurity LLM" —
possibly using an LLM in the loop, unlike this project's deliberately offline/no-LLM-in-pipeline design
prior to the planned narrative-generation fine-tune) · utkarshkhampar/ThreatCast-AI-Network-Attack-Forecasting ·
utsav-singh46/SIH26153-network-attack-forecasting · venkatpavan8806/Network-attack-forecasting ·
Wahulaniket/AI-based-Network-Attack-Forecasting-from-Network-Traffic-Data ·
xarjunpatil/SIH26153-AI-based-Network-Attack-Forecasting-from-Network-Traffic-Data

**Not SIH-related despite matching keywords** (excluded from competitive analysis, listed to avoid
re-discovering and misclassifying later): `venkat15vk/network-attack-forecasting` — a per-host
attack-volume forecasting study on the public Loghub OpenSSH server log corpus, dated 2026-05-21
(predates SIH 2026's typical team-formation window and uses an unrelated dataset).

### Takeaways for this project specifically

- **Field size (re-measured 2026-09-27)**: **123 repos across 115 distinct projects**, of which 52
  explicitly cite SIH / 26153 / NTRO. 27 were created in the 10 days since the previous pass, so the
  field is still growing by roughly 3 repos a day this close to submission. Treat any
  single-competitor comparison as necessarily incomplete, and re-run the survey rather than reusing
  these counts.
- **Most of the field is not a threat; a few are.** A large share is empty scaffolding, and at least
  one entrant (`sjeevitha2106`) ships a Random Forest per-flow classifier - the very approach the PS
  says to move beyond. The serious entries are few: `ShadowCat`, `TheRedKeep`, `Argus`,
  `HowSuyash/AttackForecast`, `Precursor`, `csxzor-devcs`.
- **The field has caught up on this project's differentiators.** `ShadowCat` alone claims lead-time
  quantification, leakage protection and tamper-evident provenance; `netsight` and
  `Radhika-coder46` cover audit ledgers; `axorarbxy` and `AegisTwin` cover the digital-twin framing;
  `TheRedKeep` and `AttackForecast` describe deeper latent (RSSM-style) world models than this
  project's Transformer.

  **Correction, 2026-09-29 (ShadowCat re-examined).** An earlier version of this bullet said no
  surveyed repo reports a negative result about itself. That is **false**, and the exception is the
  strongest competitor in the field. `muthukkumaranb/ShadowCat` publishes: a 37-fold cross-validated
  benchmark against a logistic-regression baseline; an explicit disclosure that its own baseline
  scores **0.0 F1 on fold 16 (SSH-Bruteforce) — 0% recall, every attack window missed** — inside the
  headline table rather than a footnote; a `gate0_leakage_report.md` and a "0 label leakage" claim
  with a verification report behind it; a `ctu13_diagnostic_results.md`; a measured
  `real_pipeline_latency_report.json`; and a README section titled **"Known Limitations & Scope
  Disclosures"**. It also ships `SIH26153_Architecture_Final.md` and `Shadowcat_PPT_Final_Slide_Content.md`
  — two of the graded deliverables — inside the repo, plus **Hyperledger Fabric** notarization, which
  is a real distributed ledger rather than this project's single-writer hash chain. Repo is ~291 MB
  and was pushed 2026-09-28.

  Measurement honesty is therefore **no longer an unmatched axis**. What remains distinctive here,
  on the evidence read so far, is narrower and should be claimed narrowly: a leave-one-attack-family-
  out evaluation, adversarial evasion testing with a stated threat model, and an audit trail that
  retracted the project's own headline number. ShadowCat's disclosed negative is about its
  *baseline's* fold failure, not its own model's generalisation; no repo read in this survey has
  published a negative result about its own model's transfer. That is a real but much smaller gap
  than this document previously claimed.
- **Stars are not activity**: `Argus`, still the most-starred entry at 4, has not been pushed to
  since 2026-09-08.
- **Recurring differentiation axes across many teams**: (1) blockchain/hash-chain audit trails for
  tamper-evident predictions (at least 3 independent teams), (2) graph/spatial-temporal world-model
  variants instead of a plain Transformer (at least 2 teams), (3) explicit lead-time-focused
  evaluation metrics rather than only classification metrics (at least 1 team, and arguably the
  most PS-aligned metric choice found in this whole survey), (4) regulatory/statutory compliance
  framing tied to Indian cyber authorities specifically (1 team, but a strong, distinctive angle
  given NTRO is the PS issuer).
- **Where this project still leads** (revised 2026-09-27, after the Part G audit): not on
  generalisation — the CTU-13 transfer is chance-level, the UNSW-NB15 transfer is worse, and the
  leave-one-family-out folds are negative for three of four attack families (`docs/AUDIT.md` G1,
  S8). What remains genuinely differentiating is **measurement honesty**: a leave-one-attack-
  family-out evaluation, a lead-time metric with false-alarm accounting, label-oracle baselines
  named as oracles, a documented *and fixed* robustness bug, a documented and *unfixed* adversarial
  vulnerability with its threat model stated, and an independent audit trail (`docs/AUDIT.md`) that
  retracts the project's own headline number when it failed to reproduce. No surveyed repo describes
  adversarial testing, false-positive robustness work, or a negative result of its own. The
  response-playbook/attack-narrative pairing also remains unobserved elsewhere.
- **Two differentiators have been matched by others since the last survey**: the hash-chained audit
  ledger (ayushshandilya-dev/netsight describes a SHA-256 audit ledger; Radhika-coder46 and two
  earlier teams use blockchain for the same purpose) and the digital-twin/world-model framing
  (axorarbxy/network-digital-twin, NotVivek12/AegisTwin). Neither is a unique axis any more.
- **The lead-time metric takeaway from the 2026-09-17 survey is now DONE** — implemented in
  `eval/metrics.py::lead_time_metrics`, with the false-alarm accounting the first version lacked
  (`docs/AUDIT.md` E3). On the day-disjoint split it reports 93.5% of transitions missed and 1.5%
  alarm precision: the metric earned its place by contradicting the project's earlier optimism.
  Quote those two figures with their caveats — the transitions behind them are 181 episodes on 3
  day-level pseudo-hosts, 96% from one day (G2), and the operating threshold they use does not
  transfer across days (G8, 5% budgeted FPR on val → ~36% achieved on test).
