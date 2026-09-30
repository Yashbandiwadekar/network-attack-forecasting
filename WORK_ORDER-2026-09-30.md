# WORK ORDER — 2026-09-30 (competitive-response)

**From:** Auditor agent · **To:** Builder agent
**Supersedes:** nothing. Runs *alongside* `docs/last-minute-build-order-2026-09-30.md`, and
**re-prioritises it** — see "Against the existing build order" at the end.
**Source of findings:** source-level examination of three competitor repositories on 2026-09-30
(`shonaxx/sih-26153-cyberpulse`, `Impala04/sih26153-attack-chain-detection`,
`ShipraSharma08/AI-Network-Attack-Forecasting`), plus the 2026-09-30 re-read of
`muthukkumaranb/ShadowCat` and `ErenSnowh/Argus`. Evidence for each item is stated in the item.
**Branch:** see "Where to work" below.

## Ground rules

- **Acceptance criteria are binding.** An item is FIXED only when its check has been run and the
  actual output pasted into `BUILD_REPORT.md`.
- **Re-measure, never carry forward.** If you did not run it after your change, write "not measured".
- **A competitor's claim is a claim.** Everything below was read at source (README, results files,
  training code, repository tree) and is cited as such; none of it was executed or reproduced.

---

## W21 — Frozen-state rollout ablation  ·  **DO THIS FIRST**

**Why.** `ShipraSharma08/AI-Network-Attack-Forecasting` publishes an ablation this project does not
have, and it is the one experiment that defends the project's central architectural premise.
They score the same K-step rollout two ways — **genuine state** (roll the world model forward) and
**frozen state** (hold the state still and re-score) — from `reports/kstep_worldmodel_rollout_metrics.json`:

| Horizon | Genuine AUROC | Frozen AUROC |
|---|---|---|
| 1 | 0.870 | 0.870 |
| 5 | 0.818 | 0.794 |
| 10 | **0.817** | 0.630 |
| 15 | **0.860** | 0.619 |

Identical at t+1 (as they must be), then divergent. That is a direct measurement of whether the
world model earns its keep. Their sample sizes are small (74–88 windows), so the result is
suggestive rather than conclusive — but the design is correct and this project can run it on
7,191 test sequences.

**The gap.** This project cannot currently answer "does the world model actually do anything, or
would a static classifier score the same?" Every published number here — F1 0.481, AUROC 0.794,
the LOFO folds — measures the *whole system*. Nothing isolates the rollout. A judge asking that
question gets no answer, and the entire "world model" framing rests on it.

**What to build.** A frozen-state control in `models/forecast.py::ForecastEngine`: roll out K steps
without advancing the latent state (re-apply the heads to the step-0 state), scored on the same
day-disjoint test split as `docs/04-evaluation-real-v2-seeds.md`, across all 3 seeds.

**Acceptance:**
- `scripts/ablate_frozen_state.py` exists and runs to completion.
- `docs/04-evaluation-frozen-state-ablation.md` reports, per step k = 1..6, genuine vs frozen
  AUROC/AUPRC/F1, with n stated and mean ± SD over the 3 existing seeds.
- The conclusion is stated plainly **in whichever direction the numbers land.** If frozen matches
  genuine, that is a finding about this architecture and must be published as one, not buried.
- Numbers pasted into `BUILD_REPORT.md`.

---

## W22 — Move the measured limitations into the README

**Why.** `shonaxx/sih-26153-cyberpulse` (created 09-28, 108 MB, real project) puts its negative
results in the README's opening summary, where a judge reads them:

> "**It is not** a demonstrated early-warning system. On a held-out evaluation, the model matches a
> trivial 'persistence' baseline and does not flag attacks before they begin (onset recall of at
> most 0.5%)."

> "The horizons t+1 to t+4 are **the next 1 to 4 rows of the dataset**... They are not seconds or
> minutes of future time."

Their published table shows their GRU (F1 0.924–0.932) **losing to logistic regression**
(0.940–0.944) and tying persistence (0.921–0.936), and they state it. They also disclose that the
committed dashboard weights were trained on all rows with no held-out split.

This project's equivalent disclosures exist and are more thorough — but they live in
`docs/AUDIT.md`, which a judge will not open. The README currently leads with the honest headline
figure but does not state the limitations.

**What to build.** A "What this system does not do" section in `README.md`, near the results, in
plain language: recall 0.325 (misses roughly two-thirds of attack windows), measured lead time
−0.5 s mean / +0.0 s median (alarms at onset, not before), LOFO chance-level on three of four
families, single-dataset training. Link `docs/AUDIT.md` for the full trail.

**Acceptance:** the section exists, each claim carries its measured number, and every number in it
matches its source file. No new measurement required.

---

## W23 — Publish a measured latency figure

**Why.** `muthukkumaranb/ShadowCat` (pushed 2026-09-30, 291 MB) publishes a real wall-clock
benchmark of its deployed pipeline in `docs/real_pipeline_latency_report.json` — P50 **1,630.87 ms**
per 30-window evaluation, 0.61 sequences/second, broken down by stage, 20 timed passes after 3
warmups. They explicitly **retired their own earlier benchmark** for being synthetic
(`np.random.randn` inputs, untrained model) and replaced it with the real one.

This project publishes **no latency figure at all**. "Forecasts 60 seconds ahead" invites "how long
does inference take?", and there is currently no answer.

**What to build.** `scripts/benchmark_latency.py` timing the real deployed path
(`app/service.process_uploads` → `score_all_hosts` → `ForecastEngine.rollout`) on a real capture,
reporting per-stage P50/P95/mean ± SD over ≥20 passes after warmups.

**Acceptance:** numbers in `BUILD_REPORT.md` and a one-line figure in `README.md`. Inputs must be
real captured traffic, not generated noise — the failure mode ShadowCat corrected in itself.

---

## W24 — Retract the "no competitor publishes a negative result" claim

**Why.** `docs/05-related-work-and-competitive-landscape.md` states that no surveyed repo has
published a negative result about its own model. **That is false, and this is the second time the
claim has needed retracting** (it was already narrowed on 09-29 after ShadowCat's baseline
disclosure). Two counter-examples, both read at source:

1. **ShadowCat** ran a 37-fold leave-one-entity-out evaluation of its GraphSAGE fusion, found
   **F1 0.0000 in 3 of 18 DDOS-LOIC-UDP folds** (macro 0.9157 vs 0.9971 for plain LSTM),
   diagnosed the cause as over-smoothing in dense bipartite attack subgraphs, and issued an
   **unequivocal NO-GO retiring the architecture**. That is a negative result about their own
   model, with a root cause and a decision attached.
2. **CyberPulse** states in its README that its model matches a trivial baseline and shows no
   early-warning ability (see W22).

**Important caveat to record alongside it, because it cuts the other way.** ShadowCat's 0.9971
macro-F1 is across only three attack categories, and the fold names
(`21-02-2018_DDOS-LOIC-UDP_17`) with per-category reporting indicate folds withhold *one episode
while training on other episodes of the same attack type*. That is **not** leave-one-family-out:
this project's LOFO withholds an entire family, so the model never sees `lateral_movement` at all.
The two numbers measure different difficulties and must not be compared directly. This reading is
from fold naming and reporting structure; it was **not verified against their split code**.

**What to change.** Replace the claim with the two named counter-examples, and state what remains
distinctive narrowly: leave-one-attack-*family*-out (not episode-out), adversarial evasion testing
with a stated threat model, and an audit trail that retracted this project's own headline number.

**Acceptance:** `grep -rn "no surveyed repo\|no repo read in this survey" docs/` returns nothing
that still asserts the retracted claim.

---

## W25 — Fix the "Feature #4" reference (the capability now exists; the citation does not)

**Why.** `docs/05-related-work-and-competitive-landscape.md:320` (the `raushankumarsah07` row)
says *"this project independently built the same capability [counterfactual what-if rollout], see
**Feature #4**."*

**State as of this order, re-checked at branch HEAD `93f6bcc`.** When
`docs/last-minute-build-order-2026-09-30.md` raised this as its item 0, the claim was false —
nothing in the codebase implemented counterfactual rollout. That is **no longer true**: item 4
shipped in `2c4474b` and item 5 in `93f6bcc`, both committed while this order was being written.
`app/server.py` now carries `POST /api/v1/forecast/what-if`,
`GET /api/v1/forecast/what-if/features` and `POST /api/v1/response/simulate-isolation`, with
`tests/test_what_if_endpoint.py` and `tests/test_simulate_isolation.py`.

So the *substance* of the claim is now correct and the *citation* is still wrong: there is no
"Feature #4" anywhere in this repository. Leaving a dangling reference in the one document whose
entire value is its accuracy is the defect worth fixing.

**What to change.** Replace "see Feature #4" with the real endpoint and its date — e.g.
"implemented 2026-09-30, `POST /api/v1/forecast/what-if`" — and drop the word "independently",
which is unsupportable: this capability was built *after* the competitor was surveyed and
explicitly in response to it (build-order item 4). Say that plainly; it is a legitimate reason to
build something, and misrepresenting the order of events is the kind of small dishonesty this
document exists to avoid.

**Acceptance:** `grep -n "Feature #4" docs/05-related-work-and-competitive-landscape.md` returns
nothing, and the replacement text names an endpoint that exists.

---

## Not a threat — recorded so it is not re-investigated

**`Impala04/sih26153-attack-chain-detection`** (28 MB, pushed 09-29) markets "AI-Based Network
Attack Forecasting & Behavioural Attack-Chain Detection". At source: its only results artefact,
`report.json`, is the output of a **3-packet, 210-byte test fixture** (`mixed_test.pcap`);
`models/` contains an **Isolation Forest** (`isolation_forest.joblib`) and an **empty
`world_model/` directory**; `docs/` holds a single API document. Repository size is data and
frontend, not evidence. No evaluation report was found. Size is not substance.

---

## Against the existing build order

**All six items (0–5) of `docs/last-minute-build-order-2026-09-30.md` are now shipped** on
`feature/competitive-parity-1-3-2026-09-30` (`9bdb9d8`, `2c4474b`, `93f6bcc`), so this section is
no longer a re-prioritisation — it is a note on what those items did and did not buy.

Items 4 and 5 added capabilities that several competitors already claim, and one of them does
better:

- **Item 4** (counterfactual what-if) is claimed by at least three other teams
  (`raushankumarsah07`, `TARUN-AM/cybera-ai`, `axorarbxy`). `cybera-ai` is 149 KB of TypeScript,
  so the claim is cheap to make and correspondingly cheap for a judge to discount. Shipping a
  working one with a test is worth more than the claim — but it is parity, not lead.
- **Item 5** (simulated isolation) is deliberately and visibly simulated, which is the honest
  way to ship it. Note that ShadowCat does this for real: Hyperledger Fabric chaincode that
  autonomously commits `ISOLATE_HOST:<node_id>` on-chain in the same transaction as the alert.
  Expect the comparison; the defensible answer is that a simulated action is labelled as such,
  not that it is equivalent.

**W21–W23 remain the higher-value work, and are now the only open items.** They differ in kind
from items 0–5: they do not add claimed features, they add **evidence for claims already made**.
W21 in particular defends the "world model" framing itself — something no competitor can remove
by shipping a feature, and which nothing in this project's evaluation currently supports.

## Where to work

`feature/competitive-parity-1-3-2026-09-30`, which is where this order is filed. The tree was
mid-flight from another session while this order was written (build-order items 4 and 5 landed
during it, as `2c4474b` and `93f6bcc`); it is committed and clean as of HEAD `93f6bcc`. Re-check
`git status` before starting — a second session has been active in this repository today.

Note that build-order item 3's intent — labelling the rollout curve `t+1..t+K` — was already
substantially shipped on `master`: the curve renders `t+10s … t+60s` from `step_seconds`, and the
per-step stage and heuristic markers were added with it. Confirm before re-doing it.

**Disclosure.** While orienting in this repository, this auditor merged
`docs/competitive-survey-2026-09-30` into this branch (`760a35d`) before recognising that another
session owned it. The merge was clean and additive, touching only
`docs/05-related-work-and-competitive-landscape.md` and `README.md`. Recorded here rather than
left to be discovered.
