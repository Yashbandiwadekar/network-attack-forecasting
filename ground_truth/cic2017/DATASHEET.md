# Dataset Datasheet: CIC-IDS-2017

**Standardized Target Path**: `ground_truth/cic2017/events.csv`  
**Dataset Identifier**: `cic2017`

---

## 1. Source and Licensing

* **Dataset Name**: Canadian Institute for Cybersecurity Intrusion Detection Evaluation Dataset 2017 (CIC-IDS-2017).
* **Official Source URL**: https://www.unb.ca/cic/datasets/ids-2017.html
* **Dataset Authors / Organisation**: Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani (Canadian Institute for Cybersecurity, University of New Brunswick).
* **Citation Requested**:
  > Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, "Toward Generating a New Dataset for IDS Evaluation", IEEE International Conference on Information Science and Security (ICISS), 2018.
* **Licence**: Publicly released by UNB for academic, research, and educational cybersecurity evaluation purposes.
* **Download Date**: Flow CSVs on drive `V:` (validated 2026-10-10); PCAP captures downloaded (~51 GB).

---

## 2. Coverage

* **Duration**: 5 consecutive days (Monday 3 July 2017 to Friday 7 July 2017), 09:00 to 17:00 daily.
* **Days Covered**: Monday (Benign), Tuesday (Patator Brute Force), Wednesday (DoS Slowloris/Slowhttptest/Hulk/GoldenEye, Heartbleed), Thursday (Web Attacks, Infiltration), Friday (Botnet ARES, PortScan, DDoS LOIC HTTP).
* **Hosts**: Victim subnet `192.168.10.0/24` (Web server `.50`, Ubuntu `.51`, internal hosts `.5`, `.8`, `.9`, `.14`, `.15`, `.25`); attacker network `205.174.165.73` translated via NAT `172.16.0.1`.
* **Attack Families**: `bruteforce`, `dos`, `web_exploit`, `infiltration`, `botnet_c2`, `portscan`, `ddos`.
* **Available Data**: Both packet data (full PCAPs) and flow data (8 `TrafficLabelling` CSVs, 2,830,743 flows).

---

## 3. Event Construction Methodology

* **Single Source of Truth**: Events manually constructed in `ground_truth/cic2017/events.csv` from Table 4 of the official UNB attack schedule.
* **Endpoint Identification**: Preserves the published external attacker `205.174.165.73` and internal victim IPs; internal firewall NAT translation (`172.16.0.1`) handled in PCAP validation.
* **Time Alignment**: Nominal published times recorded in UTC ISO 8601 ending in `Z`. Timezone offset (Canadian Atlantic ADT UTC-3 / AST UTC-4) is resolved by `scripts/check_events_in_pcap.py` searching $\pm$6-hour windows in raw PCAPs.
* **Validation Tool**: `scripts/check_events_in_pcap.py` verifies bidirectional packet matching and computes time offsets.

---

## 4. Label Counts and Statistics

* **Canonical Event Count**: **50 events** in `ground_truth/cic2017/events.csv`.
* **Events per Attack Family**:
  * `bruteforce`: 3 events (FTP-Patator, SSH-Patator, Web Attack – Brute Force)
  * `dos`: 4 events (Slowloris, Slowhttptest, Hulk, GoldenEye)
  * `web_exploit`: 3 events (Heartbleed, XSS, SQL Injection)
  * `infiltration`: 4 events (external infiltration stages toward 192.168.10.8 and 192.168.10.25)
  * `botnet_c2`: 5 events (ARES C2 across 5 infected bots, 10:02–11:02)
  * `portscan`: 28 events (1 internal reconnaissance sweep from Vista host on Thursday; 27 discrete PortScan probe windows on Friday)
  * `ddos`: 3 events (LOIC HTTP flood from the three Win 8.1 attackers 205.174.165.69, .70, .71)
* **Events per Campaign**:
  * `cic2017_tue_bruteforce_01`, `cic2017_tue_bruteforce_02`, `cic2017_wed_dos_01`, `cic2017_wed_dos_02`, `cic2017_wed_web_01`, `cic2017_thu_web_01`, `cic2017_thu_infiltration_01`, `cic2017_fri_bot_01`, `cic2017_fri_portscan_01`, `cic2017_fri_ddos_01`.
* **Flow Counts (Official Flow CSVs)**: 2,830,743 flows total; 557,646 attack flows (PortScan 158,930, DDoS 128,024, DoS Hulk 231,073, GoldenEye 10,293, Slowloris 5,796, Slowhttptest 5,499, Patator 13,835, Web Attacks 2,180, Bot 1,966, Infiltration 36, Heartbleed 11).
* **Unknown Label Rate in Events**: 0% (all 50 events map to standard families). Unmatched background flows outside attack windows are treated as `unknown`.

---

## 5. Known Issues

1. **Minute Timestamp Precision in Flow CSVs**: Tue–Fri flow CSVs record timestamps with minute-level precision only; packet re-extraction from PCAPs restores microsecond accuracy.
2. **Internal NAT Boundary**: Traffic originating from external attacker `205.174.165.73` appears as `172.16.0.1` inside the captured network segment.
3. **Thursday Morning Truncation**: The Thursday Morning WebAttacks flow CSV contains ~288,000 empty trailing rows.
4. **Documented Labelling Artefacts**: Published literature (e.g. Lanvin et al.) notes mislabelled attack spans in the released flow CSVs.

---

## 6. Open Questions

1. **UTC Offset Confirmation**: Awaiting `check.csv` from Yash after running `scripts/check_events_in_pcap.py` against Monday–Friday PCAPs.
2. **NAT Gateway Scope**: Final confirmation whether any capture files were taken outside the NAT firewall where `205.174.165.73` appears directly as `ip.src`.

