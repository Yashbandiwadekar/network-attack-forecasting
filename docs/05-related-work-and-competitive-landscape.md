# Related Work & Competitive Landscape

Research survey compiled 2026-09-17. Covers three questions: what does the open academic
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

### Cross-dataset generalization — directly validates this project's own Feature #1 result

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
    and got a **partial transfer**, not collapse — binary infiltration detection held up at a
    properly calibrated threshold (F1 0.534 vs. native-trained baselines' 0.045), while MITRE stage
    classification did degrade (macro-F1 0.328 vs ~0.52 for native baselines). Against this paper's
    baseline of "usually total collapse," a result of "binary signal transfers, fine-grained
    labels don't" is meaningfully above the field's typical outcome and worth stating explicitly
    against this citation in the submission rather than just reporting the raw numbers alone.
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
   not reliably transfer to another's out of the box. This project's CIC→CTU-13 result is
   encouraging (partial transfer, not collapse) but a real product would need either a per-deployment
   fine-tuning step or an explicit domain-adaptation mechanism — a single frozen checkpoint is not
   commercially viable as-is.
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

GitHub search performed 2026-09-17 for repos matching "network attack forecasting", "SIH26153",
"PS26153", "MITRE ATT&CK forecasting", and "world model" + "SIH". This surfaced roughly 80 distinct
public repositories (plus this project's own, which is excluded below) — dramatically more than
the 3 teams reviewed in the original Round 2 competitive pass. Most are early-stage or have no
description at all (likely near-empty scaffolding); the subset below is filtered to repos whose
own description signals a specific, non-generic technical approach worth knowing about.

### Most differentiated approaches found

| Repo | Stars | Created | Why it stands out |
|---|---|---|---|
| **[ErenSnowh/Argus](https://github.com/ErenSnowh/Argus)** | 4 (most-starred of the field) | 2026-06-23 | "Autonomous... Multi-Agent SOC Co-Pilot powered by Temporal World Models, MITRE ATT&CK, **CAPEC, CVE/NVD**, and **Dual Statutory Reporting (CERT-In + NCIIPC)**." The only team found integrating specific vulnerability databases (CVE/NVD) and, notably, actual **Indian regulatory compliance reporting** (CERT-In, NCIIPC) — a genuinely different differentiation axis (regulatory/statutory framing) than any of this project's own five differentiator features. Given the PS issuer is NTRO, this angle may resonate strongly with judges. |
| **[raushankumarsah07](https://github.com/raushankumarsah07/aI-based-network-attack-forecasting-from-network-traffic-data)** | 0 | 2026-08-26 | GRU-based world model plus **counterfactual "what-if" rollout simulation** (this project independently built the same capability, see Feature #4) — AND **Solidity smart contracts on Ethereum for tamper-proof prediction auditing**. The blockchain-audit angle directly answers the PS's stated theme ("Blockchain & Cybersecurity") in a way this project currently does not. |
| **[ayushshandilya-dev/netsight](https://github.com/ayushshandilya-dev/netsight)** | 0 | 2026-09-06 | "Model-internal XAI, novelty callout, **SHA-256 audit ledger**. Runs 100% offline." Another tamper-evidence angle (hash-chained audit log rather than blockchain), combined with an explicit "novelty callout" signal — conceptually similar to this project's own reconstruction-error novelty metric. |
| **[SuhithZ-dreambot/Precursor](https://github.com/SuhithZ-dreambot/Precursor)** | 0 | 2026-09-10 | Fuses a classical **EWMA/CUSUM statistical drift detector** with a GRU/LSTM sequence model, and reports an explicit **"lead-time" evaluation metric** — i.e., directly measures how many seconds/windows of advance warning the system provides, rather than only F1/precision/recall. This is a meaningfully different and arguably more PS-aligned evaluation methodology (the PS explicitly asks for forecasting *before* compromise, i.e., lead time is the point) than this project's current benchmark suite reports. |
| **[raghuraj72/Vanguard-GWM](https://github.com/raghuraj72/Vanguard-GWM)** | 0 | 2026-08-27 | "**Generative Graph World Model**" — a GNN-based world model. This project explicitly chose Transformer over GNN in Round 1 for timeline/complexity reasons (documented in `01-architecture.md`); this is a live example of a competing team taking the GNN path instead. |
| **[mithun-afk/ST-WM-Cyber](https://github.com/mithun-afk/ST-WM-Cyber)** | 0 | 2026-09-09 | "Spatial-Temporal World Model" — another graph/spatial variant of the same core idea, independent confirmation that graph-augmented world models are a common alternative direction among competing teams. |
| **[csxzor-devcs](https://github.com/csxzor-devcs/sih26153-network-attack-forecasting)** | 0 | 2026-09-15 | Explicitly benchmarks **Markov, LSTM, and Transformer** models against each other for stage prediction — a three-way architecture comparison this project's own benchmark suite doesn't currently include (it compares Transformer against non-sequential/persistence baselines, not against other sequence-model architectures). |
| **[ShipraSharma08](https://github.com/ShipraSharma08/AI-Network-Attack-Forecasting)** | 0 | 2026-09-03 | Temporal network state modeling plus **blockchain-based evidence integrity** — second team (after raushankumarsah07) independently landing on blockchain for evidence/audit purposes, suggesting this is a recognized way other teams are satisfying the PS's "Blockchain & Cybersecurity" theme requirement. |
| **[Impala04/sih26153-attack-chain-detection](https://github.com/Impala04/sih26153-attack-chain-detection)** | 0 | 2026-08-31 | "Adaptive behavioural attack-chain detection for identifying **non-IoC** network compromises" — explicitly framed around detecting attacks that *don't* match known indicators of compromise, a different framing angle from this project's MITRE-stage-classification approach. |
| **[NotVivek12/AegisTwin](https://github.com/NotVivek12/AegisTwin)** | 0 | 2026-09-06 | Framed explicitly as a "**digital twin**" of the network rather than a "world model" — same underlying concept, different vocabulary; worth noting since "digital twin" may be a more judge-legible term than "world model" depending on the panel's background. |
| **[krishnashahane/sentinel-sih](https://github.com/krishnashahane/sentinel-sih)** + **[krishnashahane/Sentinel---Research-paper](https://github.com/krishnashahane/Sentinel---Research-paper)** | 2 | 2026-08-21 / 09-02 | Previously known (Round 2 competitive pass) as "Sentinel" — an LSTM-based world model. Notably, this team has since split out a **dedicated research-paper repo**, suggesting they intend to publish/formalize their approach separately from the code — a submission-strategy signal worth being aware of. |
| **[HowSuyash/AttackForecast](https://github.com/HowSuyash/AttackForecast)** | 0 | 2026-08-23 | Previously known (Round 2) as the most architecturally sophisticated competitor — true RSSM/Dreamer-style latent world model over CTU-13. Still the closest thing to an actual academic-style world-model implementation found anywhere in this search, including the broader literature search in Section 1. |
| **[hasim2006/PhantomGrid-Predictive-Defense-SIH26153](https://github.com/hasim2006/PhantomGrid-Predictive-Defense-SIH26153)** | 0 | 2026-08-22 | Previously known (Round 2) — thin, suspicious identical-precision baseline-vs-model numbers noted at the time. Unchanged assessment. |

### Full list of other repos found (lower signal from description alone — not independently verified)

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

- **Field size**: this is a much larger competitive field than previously assessed (roughly 80
  teams found vs. 3 in the original Round 2 pass) — treat any single-competitor comparison as
  necessarily incomplete going forward.
- **Recurring differentiation axes across many teams**: (1) blockchain/hash-chain audit trails for
  tamper-evident predictions (at least 3 independent teams), (2) graph/spatial-temporal world-model
  variants instead of a plain Transformer (at least 2 teams), (3) explicit lead-time-focused
  evaluation metrics rather than only classification metrics (at least 1 team, and arguably the
  most PS-aligned metric choice found in this whole survey), (4) regulatory/statutory compliance
  framing tied to Indian cyber authorities specifically (1 team, but a strong, distinctive angle
  given NTRO is the PS issuer).
- **Where this project still leads**: the combination of (a) validation on two independent
  real-world datasets with an honestly-reported cross-dataset transfer result, (b) a documented and
  fixed robustness bug plus a documented and *unfixed* adversarial vulnerability (most competing
  repos' descriptions make no mention of adversarial testing or false-positive robustness work at
  all), and (c) the response-playbook/attack-narrative pairing that closes the loop from forecast to
  recommended action was not observed as a described feature in any other repo surveyed here.
- **Worth considering as a result of this survey**: adding an explicit lead-time metric (à la
  SuhithZ-dreambot/Precursor) to `eval/benchmark.py` alongside the existing F1/precision/recall
  suite, since it's arguably a more direct measurement of what the PS is actually asking for
  ("forecast before compromise completes") than classification metrics alone.
