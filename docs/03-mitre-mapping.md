# MITRE ATT&CK Stage Mapping

The problem statement asks for predictions mapped to five MITRE ATT&CK stages: Reconnaissance,
Initial Access, Lateral Movement, Command & Control, Exfiltration. CIC-IDS-2018's labels don't
correspond to these 1:1. This document makes the mapping explicit and honest about where it's a
judgment call, rather than letting the code silently imply the dataset has ground truth it doesn't.
Source of truth: `pipeline/mitre_mapping.py`.

## Mapping table

| CIC-IDS-2018 label | MITRE stage | Reasoning |
|---|---|---|
| `BENIGN` | benign | — |
| `FTP-BruteForce`, `SSH-Bruteforce` | Initial Access | Credential attack attempting entry (MITRE T1110) |
| `Brute Force -Web`, `Brute Force -XSS`, `SQL Injection` | Initial Access | Exploiting a public-facing web app to gain access (MITRE T1190) |
| `Infilteration` (dataset's spelling) | Lateral Movement | CIC-IDS-2018's infiltration scenario is literally an attacker who already has a foothold moving inside the network |
| `Bot` | Command & Control | Botnet C2 beacon traffic |
| `DoS attacks-*`, `DDOS attack-*` | *(impact — see below)* | Volumetric/availability attacks are MITRE **Impact**, not one of the five requested stages |

## The two gaps

**`impact` is not one of the five requested stages.** DoS/DDoS traffic is real attack traffic and
worth forecasting, but forcing it into one of Recon/Initial-Access/Lateral-Movement/C2/Exfiltration
would be a worse misrepresentation than admitting the mismatch. `pipeline/mitre_mapping.py` keeps
it in a separate `impact` bucket: included in the binary infiltration-probability target (it's
still "an attack is happening"), excluded from the 5-way stage classification loss and metric
(`models/train.py`, `eval/metrics.py`). An unknown/future label also falls back to `impact` rather
than silently becoming `benign` — a mapping bug should show up as a visible "attack of unknown
stage," not vanish into the benign class.

**`reconnaissance` has no CIC-IDS-2018 label at all.** No scenario in the dataset is explicitly
labelled as a port scan or probing phase. Rather than fabricate labels, `reconnaissance` is
**derived**, not assigned from the raw `Label` column: in `pipeline/windowing.py`'s
`apply_reconnaissance_heuristic`, a window is relabeled `reconnaissance` if it was originally
`benign` AND its packet-level `port_scan_score` exceeds a threshold (0.5, configurable in
`configs/default.yaml`) AND an actual attack from the same source IP follows within
`forecast_horizon` windows. This is a genuine, temporally-grounded signal (traffic that looks like
scanning and precedes a real attack from the same host) rather than an invented label — but it is a
heuristic, and it depends on packet-level features being available (PCAP present for that capture
window). In flow-only mode (no PCAP), `port_scan_score` is zero-filled and no window will ever be
relabeled `reconnaissance` — this is a known limitation, not a silent failure: the model will simply
never predict reconnaissance if trained without any PCAP coverage.

## `Exfiltration` in the synthetic sample only

For the same reason, no CIC-IDS-2018 label maps to `exfiltration` either. Rather than leaving the
class entirely untrained-on in the demo, `scripts/make_synthetic_sample.py` includes a
`SYNTH-Exfiltration` synthetic label (sustained large outbound byte counts) purely so the pipeline,
model, and demo can exercise all five stages end-to-end before real training. **This label only
exists in the synthetic sample** — `pipeline/mitre_mapping.py` documents it as synthetic-only, and
it must not be treated as validating real-world exfiltration detection.

## Implication for evaluation

`docs/04-evaluation.md`'s stage-classification metrics are macro-averaged over the classes actually
present in the (synthetic, currently) test set — `exfiltration` and `reconnaissance` have low
support even there, and would need the real dataset's Infiltration/Bot days plus PCAP coverage to
be evaluated with any statistical confidence.
