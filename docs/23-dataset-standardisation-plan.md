# 23 - Plan: one standard, fully labelled dataset (packets and flows, MITRE-mapped)

Written 2026-11-03. Status: plan, nothing built yet.

## 1. Goal

Turn every dataset we collect (PCAPs and flow CSVs) into **one standard format** where:

- every **packet** and every **flow** carries the same label fields;
- every label says **what kind of attack** it is (DoS, DDoS, brute force, port scan, C2, ...)
  **and** where it sits in **MITRE ATT&CK** (tactic + technique) **and** in our kill-chain stages;
- every label says **where it came from** and **how sure we are**, so training and evaluation can
  filter on it;
- all datasets are produced by **one extractor**, so a flow from CIC-2017 and a flow from our lab
  look exactly alike to the model (same features, same units, same timeouts).

The model then learns from one consistent vocabulary instead of five datasets' private label names.

## 2. The label schema

Every packet row and every flow row gets these columns.

| Column | Example | Meaning |
|---|---|---|
| `attack_family` | `ddos`, `dos`, `bruteforce`, `portscan`, `web_exploit`, `botnet_c2`, `infiltration`, `exfiltration`, `benign`, `unknown` | Normalised attack type |
| `attack_variant` | `loic_http`, `hoic`, `slowhttptest`, `hulk`, `ftp_patator`, `ssh_patator`, `xss`, `sqli`, `neris` | Tool or sub-type, when known |
| `mitre_tactic` | `TA0043` | ATT&CK tactic ID |
| `mitre_technique` | `T1046` | ATT&CK technique ID (sub-technique if known, e.g. `T1110.001`) |
| `kill_chain_stage` | `reconnaissance` | Our existing stages from `pipeline/mitre_mapping.py`, so current models keep working |
| `role` | `attacker_to_victim`, `victim_to_attacker`, `c2_beacon`, `background` | Direction relative to the attack |
| `campaign_id` | `cic2017_fri_ddos_01` | Groups everything that belongs to one attack run (needed for chains and for leakage-safe splits) |
| `label_source` | `dataset_flow_label`, `ground_truth_schedule`, `lab_driver_log`, `heuristic` | Where the label came from |
| `label_confidence` | `exact`, `window`, `heuristic` | `exact` = per-flow label from the dataset authors; `window` = matched by IP + time window; `heuristic` = rule-based |
| `original_label` | `DoS attacks-Hulk` | The dataset's own label, kept verbatim |

### Family → MITRE mapping (the standard table)

Kept in one file, `pipeline/label_standard.py` (new), next to `pipeline/mitre_mapping.py`.

| Family | MITRE tactic | MITRE technique | Our stage |
|---|---|---|---|
| Port scan / host discovery | Reconnaissance TA0043 / Discovery TA0007 | T1595 Active Scanning / T1046 Network Service Discovery | reconnaissance |
| Brute force (FTP, SSH, web login) | Credential Access TA0006 | T1110 Brute Force (T1110.001 password guessing) | initial_access |
| Web exploit (SQLi, XSS, Heartbleed) | Initial Access TA0001 | T1190 Exploit Public-Facing Application | initial_access |
| Infiltration / internal movement | Lateral Movement TA0008 | T1021 Remote Services (or as documented per dataset) | lateral_movement |
| Botnet C2 / beaconing | Command and Control TA0011 | T1071 Application Layer Protocol | command_and_control |
| Exfiltration | Exfiltration TA0010 | T1041 Exfiltration Over C2 Channel / T1048 | exfiltration |
| DoS (Hulk, GoldenEye, Slowloris, SlowHTTPTest) | Impact TA0040 | T1499 Endpoint Denial of Service | impact |
| DDoS (LOIC, HOIC, UDP floods) | Impact TA0040 | T1498 Network Denial of Service | impact |

Note: MITRE puts brute force under **Credential Access**, not Initial Access. We store the real MITRE
tactic and keep our own `kill_chain_stage` alongside it, so nothing in the current pipeline breaks.

## 3. The standard data layout

Three tables per dataset, stored as Parquet (compressed, fast, typed):

1. **Ground-truth events** (`events.parquet`): one row per attack activity:
   `campaign_id, attacker_ip, victim_ip, dst_port (optional), start_ts, end_ts, attack_family,
   attack_variant, mitre_tactic, mitre_technique, label_source, label_confidence, original_label,
   citation`.
   This is the **single source of truth**. It extends the existing labels sidecar format
   (`pipeline/adapters/sidecar.py`), so lab recordings and public datasets use the same file.
2. **Packets** (`packets.parquet`, only when PCAPs exist): one row per packet:
   `capture_id, frame_no, ts_ns, src_ip, dst_ip, src_port, dst_port, proto, tcp_flags,
   wire_len, ip_total_len, flow_id` + the label columns.
3. **Flows** (`flows.parquet`): one row per flow from **our** extractor
   (`pipeline/fast_packet_windows.py`, the same code the live pipeline uses):
   the 41-feature schema inputs + a **NetFlow-core** subset (bytes, packets, duration, flags,
   ports, protocol) + the label columns. For datasets that ship only CSVs, the dataset's own
   features are kept in a separate `native_*` column group, mapped onto NetFlow-core where possible.

Labels are attached by **joining** packets and flows to the events table (IP pair + time window +
port when known). Packets inherit their flow's label, so packet and flow labels never disagree.

Folder layout on the dataset drive:

```
V:\Datasets\NAF-standard\v1\
  <dataset>\events.parquet
  <dataset>\packets\<capture>.parquet
  <dataset>\flows.parquet
  <dataset>\DATASHEET.md      (source, licence, citation, coverage, known issues, label stats)
  MANIFEST.json               (file list, sha256, row counts, extractor version)
```

## 4. Pipeline (one command per stage)

| Stage | Tool | What it does |
|---|---|---|
| 1. Acquire | manual / `aws s3` | Download into `V:\Datasets\<name>\raw\`; record sizes and checksums |
| 2. Inventory | `scripts/inventory_raw.py` (new) | List every file, type, size, sha256, time span; flag truncation (e.g. CIC-2018 CSVs capped at 1,048,575 rows) |
| 3. Ground truth | `scripts/build_events.py` (new) | Build `events.parquet` from the dataset's official labels/schedule (per-dataset recipe, section 5) |
| 4. Extract | `scripts/extract_standard.py` (new, wraps `pipeline/fast_packet_windows.py` and the PCAP adapter) | PCAP → packets.parquet + flows.parquet, one fixed flow timeout for every dataset |
| 5. Label | `pipeline/label_join.py` (new) | Join packets/flows to events; fill all label columns; unmatched traffic → `benign` only where the dataset documents full coverage, else `unknown` |
| 6. Validate | `scripts/validate_dataset.py` (extend) | Label counts, unknown rate, cross-check against original labels, unit checks, NaN/inf, per-class examples |
| 7. Publish | `scripts/publish_standard.py` (new) | Write MANIFEST + DATASHEET, version it (`v1`, `v2`, ...) |

Existing adapters in `pipeline/adapters/` stay the readers for CSV-only data; the new stages sit on
top of them.

## 5. Per-dataset recipe

| Dataset | Have now | Packets? | Ground truth for events.parquet | Notes |
|---|---|---|---|---|
| **CIC-IDS-2017** | CSVs on V:, PCAPs downloading (~51 GB) | Yes | Official attack schedule (attacker 172.16.0.1/NAT, victims 192.168.10.x, times per day) + original CSV labels for cross-check | Re-extracting from PCAP fixes the minute-resolution timestamps |
| **CSE-CIC-IDS2018** | CSVs on V: (7 of 10 truncated); full PCAPs for Wed 14-02 (449 files, 45 GB) and Fri 23-02 (446 files, 64 GB) | Yes for those 2 days; other days on AWS, 36–55 GB each | Official schedule + attacker IPs per day; original CSV labels for cross-check | v1 uses Wed 14-02 (FTP/SSH brute force). Fri 23-02 is a spent test day: evaluation only |
| **UNSW-NB15** | CSVs + official ground truth `NUSW-NB15_GT.csv` on V:; PCAPs 63 files (67 GB): 22-1-2015 complete (1–53), 17-2-2015 has 1–17 and 27, **missing 18–26** | Yes | Official ground-truth CSV (start/end time, category, subcategory, proto, src/dst IP and port) | Best ground truth of the set. Its categories (Fuzzers, Generic, Shellcode, Worms, Backdoors, Analysis) need rows in the family table |
| **CTU-13** | binetflow + PCAPs on V: for all 13 scenarios incl. scenario 10 (87 GB) | Yes (botnet-only + mixed truncated) | binetflow per-flow labels (Botnet / Background / Normal) + infected-host IPs per scenario | Background label = "not verified benign" → `unknown`, not `benign` |
| **NF-UNSW-NB15-v3 / NF-CSE-CIC-IDS2018-v3** | Not downloaded | No (flows only) | Per-flow Label / Attack columns | Flows-only datasets get flow labels, no packet table |
| **CICIoT2023** | Not downloaded | Yes | Per-attack PCAP files (each file = one attack type) | Labels by file; IoT devices differ from enterprise traffic |
| **DAPT2020 / DARPA 2000** | Not downloaded | Yes | Published stage schedule | Few campaigns, but real multi-stage chains |
| **Our lab recordings** | Tooling ready | Yes | Driver timestamp log → events.parquet directly (`label_confidence = exact`) | The only source with chains we control |

## 6. Labelling rules

1. **Events first, labels second.** No label is typed by hand onto rows; every label comes from a
   row in `events.parquet` with a citation.
2. **Match order:** exact flow label from the dataset → (attacker, victim, port, time window) →
   (attacker, victim, time window) → (attacker, time window). The first match wins and is recorded
   in `label_confidence`.
3. **Both directions:** replies from the victim get the same event with `role = victim_to_attacker`.
4. **Overlaps:** when two events match, the more specific one wins (port-level beats host-level).
5. **Benign vs unknown:** traffic is `benign` only if the dataset documents that everything outside
   its schedule is benign; otherwise `unknown`. Training can then use or drop `unknown`.
6. **Keep the original label** in `original_label` for every row, so any decision can be audited.

## 7. Quality checks (each dataset must pass before publishing)

- Agreement with the dataset's own labels where both exist (target ≥ 95%; every disagreement class
  listed in the DATASHEET).
- Per-family counts of packets, flows, campaigns, attacker IPs and victim IPs.
- `unknown` rate per capture.
- 20 random flows per family checked by hand against the schedule (packet times, ports, IPs).
- Unit checks from the existing validator (IAT in microseconds, no negative durations, flag counts ≤
  packet counts).
- Same extractor version and flow timeout across all datasets (recorded in MANIFEST).
- Splits for training are made by **campaign / day / attacker**, never by random row, using
  `campaign_id`.

## 8. Work plan and split

| Week | Yash | Amin |
|---|---|---|
| 1 | Label standard (`label_standard.py`, family→MITRE table), events schema, `label_join.py` | Finish CIC-2017 PCAPs, fetch the 9 missing UNSW-NB15 PCAPs; `inventory_raw.py` + checksums |
| 2 | `extract_standard.py` + validator extensions; pilot on UNSW-NB15 (best ground truth) | CIC-2017 events from the official schedule; UNSW-NB15 events from its ground-truth CSV |
| 3 | Run CIC-2017 end to end; fix what the QC checks find | CTU-13 events; CIC-2018 Wed 14-02 events (PCAPs already on V:) |
| 4 | Publish `NAF-standard v1` (UNSW, CIC-2017, CTU-13, CIC-2018 Wed 14-02); retrain and re-run the per-day and onset evaluations on it | Lab recordings into the same format; DATASHEETs |

Amin's step-by-step tasks are in `docs/24-handover-amin-dataset-standardisation.md`.

Events written by hand from a published schedule (CIC-2017, CIC-2018, lab) are small and
reviewed line by line, so they live in git as CSV under `ground_truth/<dataset>/events.csv`
(outside the ignored `data/` folder). Events generated from an official per-flow ground-truth file
(UNSW-NB15's `NUSW-NB15_GT.csv`, CTU-13's binetflow) are too large for git: the recipe in
`scripts/build_events.py` is committed and its output stays on V:. Packets and flows never go in git.

Disk: the raw PCAPs for v1 come to about 330 GB, of which 263 GB is already on V: (UNSW 67,
CIC-2018 two days 109, CTU-13 87 GB; CIC-2017 ~51 GB and UNSW's 9 missing files still to come),
plus 20–60 GB of Parquet output. V: had 540 GB free on 2026-11-04; check before each download.

## 9. What this fixes, and what it doesn't

Fixes:
- One label vocabulary with real MITRE tactics and techniques across every dataset.
- Packet-level and flow-level labels that always agree.
- Real host IPs and second-level timestamps for CIC-2017 and CIC-2018 (from the PCAPs), removing
  the pseudo-host and minute-resolution problems found in docs/15 and docs/16.
- The truncated CIC-2018 CSVs (rebuilt from the full PCAPs).
- Training and live data come from the same extractor, so the model sees the same features at
  inference as in training.

Limits to keep in mind:
- Labels are only as accurate as each dataset's published ground truth (CIC-2017/2018 are known to
  have labelling errors; the cross-check in section 7 measures how much).
- A packet's label says which attack activity it belongs to; most individual packets look ordinary
  on their own, so packet labels help most when the model looks at sequences of packets or flows.
- A clean dataset improves training and evaluation, but accuracy on new networks still depends on
  how varied the data is. That is why the lab recordings are in the plan.

## 10. Decisions needed

1. Which datasets go into `v1` (proposal: UNSW-NB15, CIC-2017, CTU-13, one CIC-2018 day, lab).
2. Flow timeout for the standard extractor (proposal: 120 s, matching current training data).
3. Whether `unknown` traffic is excluded from training or treated as benign.
4. Whether to store full packet tables for all datasets (large) or only for the datasets used for
   packet-level models.
