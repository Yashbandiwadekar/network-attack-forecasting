# Plan: raising the score

**Written 2026-09-29 by the auditor**, from the evidence in `docs/AUDIT.md` (Parts A–H) and the
competitive survey in `docs/05-related-work-and-competitive-landscape.md`. No code was changed to
produce this.

**Two different scoreboards** are in play, and they reward different work:

- **The SIH judging rubric** — deliverables, demo, clarity, PS compliance, differentiation.
- **The model's own benchmark numbers** — F1, AUROC, lead time, false-alarm rate.

Most of the available points are on the first board, and most of the project's effort so far has
gone to the second. That gap is the plan.

---

## Tier 1 — Things whose absence costs guaranteed marks

These are gradeable artefacts that do not exist. No model improvement compensates for a missing
deliverable, and each is bounded work.

**Corrected 2026-09-29** after the owner challenged this section. Two of the three items below were
overstated, and the correction matters because it changes what is actually on the critical path.

| Item | State | Action |
|---|---|---|
| **Technical presentation (≤5 slides)** | **Done** — built by a teammate. Not in `Documents\Presentations\` locally (nothing there is newer than 2026-09-13), so the audit has not seen it. | Point the audit at wherever it lives, so the deliverable can be checked off against evidence rather than assertion. |
| **Architecture document (≤2 pages)** | **Exists and probably already complies.** `docs/01-architecture.md` is **1,045 words / 126 lines** across 7 sections with no figures. At normal formatted density that is roughly two pages. | **Not a trimming job.** Render it to PDF/A4 once and confirm it fits. Minutes, not authoring. If it spills, §6 "Known limitations" is the section to cut, since `docs/AUDIT.md` covers it in more depth. |
| **Demo video (≤2 min)** | Missing, and **deliberately gated by the owner on improving the demo UI first.** | This makes UI quality the critical path to a graded deliverable — see Tier 1b. |

### Where the 2-page rule comes from

`docs/problem-statement.md:121`, in the official deliverables list: *"Architecture Document (Max 2
Pages)"*. The earlier wording here — "has never been trimmed or laid out to the page limit" — was an
unverified inference. The measured facts are that the document exists, is 1,045 words, and has never
been *rendered* to confirm the limit. The first audit graded this "⚠️ Check"; this plan escalated it
to a missing deliverable without new evidence. That was wrong, and is corrected here.

## Tier 1b — The demo UI, now the critical path

The video is the highest-value missing deliverable and it is blocked on the UI, so UI work is no
longer cosmetic — it gates a graded artefact. It is also what a judge sees first, and it is the one
place this project's honest-measurement story either lands visually or does not.

What the video needs the UI to show, in order, and what exists today:

| Beat | Exists? | Note |
|---|---|---|
| Upload a PCAP or CSV and get a result | Yes (S4/S5, W3) | Works for both models; "Scored by" caption present. |
| 60-second forecast timeline | Yes | Already plots "seconds ahead"; the 60-second horizon is real, not aspirational. |
| MITRE stage annotation with its heuristic disclosure | Yes (S6/S7, W8) | Impact renders as its own badge; recon is currently unreachable (W17). |
| Driving features (attention / SHAP) | Yes | SHAP background now cached (S9). |
| Tamper-evident ledger detecting a simulated tamper | Yes | A strong, demonstrable moment. |
| Lead time and false-alarm honesty | **Weakest link** | The project's best differentiator is currently a number in a report, not something the UI shows. |

**Recommendation:** before recording, have the auditor review the UI against these six beats and
report what a judge would see, rather than guessing at improvements. The single highest-leverage
addition is surfacing lead time and alarm precision in the interface, because that is the claim the
pitch should lead with (Tier 2) and it is the one thing the field has not matched.

**For the video specifically**, the strongest two minutes available: upload a PCAP → the 60-second
forecast timeline with seconds on the axis → the ATT&CK stage badge with its heuristic disclosure →
the SHAP/attention panel → the tamper-evident ledger detecting a simulated tamper. That sequence
demonstrates six PS requirements without a word of narration about metrics.

---

## Tier 2 — Framing, which is free and currently working against you

The competitive survey found **123 repos / 115 projects** on this PS, and the differentiators this
project used to lead on have been matched: `ShadowCat` alone claims lead-time quantification,
leakage protection and tamper-evident provenance. Blockchain/ledger framing appears in at least four
teams; digital-twin framing in two; deeper RSSM world models in two.

**Revised 2026-09-29, after re-examining ShadowCat: this axis is contested, not free.**
`muthukkumaranb/ShadowCat` already does measurement honesty well — a 37-fold benchmark, its own
baseline's 0.0-F1 fold disclosed in the headline table, a leakage gate report, CTU-13 diagnostics, a
measured latency report, and a "Known Limitations & Scope Disclosures" README section. It also has
its architecture document and slide content committed, and Hyperledger Fabric notarization (a real
ledger, against this project's single-writer hash chain).

So "we are the honest ones" is no longer a claim that separates this project by itself. What still
does, stated narrowly and defensibly:

1. **Leave-one-attack-family-out evaluation** with a published negative result — no surveyed repo
   has one.
2. **Adversarial evasion testing** with a stated threat model and an unfixed weakness disclosed —
   unobserved elsewhere.
3. **An audit trail that retracted the project's own headline number** (`docs/AUDIT.md`, Parts A–I).
   ShadowCat discloses its *baseline's* failure; this project disclosed that its own flagship
   generalisation number did not reproduce, and left the retraction in the record.

Claim those three specifically. Do not claim honesty in general — a judge comparing side by side
will find ShadowCat's disclosures just as rigorous, and an overclaim costs more than the point
gains.

**Lead with that.** The pitch line is not "our model generalises" — the evidence says it does not —
it is *"we are the only team here that can tell you when our model fails, and we measured it."*
Concretely:

1. Open on the lead-time metric with false-alarm accounting, because the PS asks for forecasting
   *before* compromise and F1 does not measure that.
2. Show the LOFO result honestly (AUROC 0.612 / 0.432 / 0.531 / 0.872) and say what it means: the
   model transfers to a held-out DDoS day, not to low-data attack families.
3. Show the audit trail as a process artefact. A judge who finds a flaw you have already documented
   scores you differently from one who finds a flaw you hid.

This costs nothing to implement and changes what the same evidence sounds like.

---

## Tier 3 — Model work where the numbers can actually move

Ranked by measured-value-per-hour, not by interest.

### 3a. Verify the packet-aware pilots that are already trained *(highest value: the compute is spent)*
`checkpoints_cic_pkt/` and `checkpoints_unsw_pkt/` each hold **three seeds**, with matching
`_flowonly` arms — that is a matched, seed-repeated comparison of packet-aware versus flow-only
training, sitting on disk unverified (`5d95cda`, `1065ddd`; Part H, H.8). Two consequences if it
holds up:
- It is the project's **first result with seeds**, which is exactly what **E10** (no seeds, no
  confidence intervals) has been open for since the first audit.
- Packet-level features are a PS requirement currently satisfied only in code, because the shipped
  model is flow-only. A verified packet-aware arm converts a documented gap into a result.

**Do:** re-measure all six runs, report mean ± spread across seeds, and state whether packet
features helped. A verified negative here is still worth more than an unverified positive.

### 3b. Fix the operating point *(cheap, and currently costing real precision)*
G8 measured a threshold tuned for 5% FPR on validation producing **~36% FPR on test** — off by
roughly 7×. Every operating-point number in the v2 report inherits that. Per-day or per-host
threshold recalibration, or a simple prevalence correction, could improve usable precision with **no
retraining at all**. This is the single cheapest metric improvement available.

### 3c. Close W19 properly, then retrain nothing
See the merge verdict below: the feature-schema guard is inert on all 47 existing checkpoints. A
one-off backfill script makes it real. Not a score item directly, but it protects every number above
from the failure mode that has already bitten this project four times.

### 3d. If time remains: LOFO-aware training
The LOFO folds fail worst on the families with least data (lateral movement, C2). Class-balanced
sampling or per-family augmentation is the honest lever, and it can be measured with the LOFO
harness that already exists.

---

## Tier 4 — Do not spend time here

- **More architecture variants.** The GNN ablation showed no measurable benefit, and the field has
  two teams doing RSSM properly. Architecture is not where marks are left.
- **Chasing a generalisation claim.** Three independent lines (LOFO, UNSW, corrected CTU-13) say the
  model does not transfer. Presenting that honestly scores better than a fourth attempt to make it
  look otherwise.
- **The LLM narrative fine-tune.** Still gated, still a scope addition, and the template narrative
  already satisfies the PS.

---

## Guardrails that protect the score

Two rules, both learned the hard way in this project:

1. **No retracted number may reappear.** The CTU-13 F1 0.534 is withdrawn and recomputes to 0.009 at
   chance-level AUROC. It was quoted in the README, this audit and the project notes before anyone
   checked it.
2. **No unverified result may enter a slide.** The packet-aware pilots, the "threshold-shift
   finding", and the truncated scale-invariance run are all currently unverified. Verify, or do not
   cite.

The credibility trail is the strongest asset this submission has. Every item above is worth less
than the habit that produced it.
