# Dataset Datasheet: CSE-CIC-IDS2018

**Standardized Target Path**: `ground_truth/cic2018/events.csv`  
**Dataset Identifier**: `cic2018`

---

## 1. Source and Licensing

* **Dataset Name**: Communications Security Establishment & Canadian Institute for Cybersecurity IDS Dataset 2018 (CSE-CIC-IDS2018).
* **Official Source URL**: https://www.unb.ca/cic/datasets/ids-2018.html
* **Dataset Authors / Organisation**: Communications Security Establishment (CSE) & Canadian Institute for Cybersecurity (CIC), University of New Brunswick.
* **Citation Requested**:
  > Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, "Toward Generating a New Dataset for IDS Evaluation", IEEE International Conference on Information Science and Security (ICISS), 2018.
* **Licence**: Publicly hosted for academic and research evaluation of network security systems.
* **Download Date**: Flow CSVs on drive `V:` (validated 2026-09-23); full PCAPs present for `Wednesday-14-02-2018` (449 files, 45 GB) and `Friday-23-02-2018` (446 files, 64 GB).

---

## 2. Coverage

* **Duration**: 10 recording days in February and March 2018.
* **Target Scope for Standardization**: All 8 non-held-out attack days:
  * Wednesday 14-02-2018 (FTP & SSH brute force)
  * Thursday 15-02-2018 (DoS-GoldenEye, DoS-Slowloris)
  * Friday 16-02-2018 (DoS-SlowHTTPTest, DoS-Hulk)
  * Tuesday 20-02-2018 (DDoS LOIC-HTTP, LOIC-UDP)
  * Wednesday 21-02-2018 (DDoS LOIC-UDP, HOIC)
  * Thursday 22-02-2018 (Brute Force -Web, Brute Force -XSS, SQL Injection)
  * Wednesday 28-02-2018 (Infiltration morning & afternoon)
  * Thursday 01-03-2018 (Infiltration morning & afternoon)
  * Friday 02-03-2018 (Botnet Ares morning & afternoon)
* **Hosts**: AWS VPC infrastructure; external attackers (e.g. `18.221.219.4`, `13.58.98.64`, `18.219.211.138`, `18.217.165.70`, `13.59.126.31`, `18.219.193.20`, `18.218.115.60`, `13.58.225.34`); internal victim servers (`172.31.69.25`, `172.31.69.28`, `172.31.69.24`, `172.31.69.13`, `172.31.69.23`).
* **Attack Families**: `bruteforce`, `dos`, `ddos`, `web_exploit`, `infiltration`, `botnet_c2`.
* **Available Data**: Full packet PCAPs for Wednesday 14-02 (449 files) and Friday 23-02; flow CSVs for all 10 days on drive `V:`.

---

## 3. Event Construction Methodology

* **Single Source of Truth**: Events in `ground_truth/cic2018/events.csv` are constructed from official UNB schedule tables (Table 2).
* **Attack Classification**:
  * FTP-BruteForce, SSH-Bruteforce, Brute Force -Web mapped to `bruteforce` (`TA0006` / `T1110`).
  * GoldenEye, Slowloris, SlowHTTPTest, Hulk mapped to `dos` (`TA0040` / `T1499`).
  * LOIC-HTTP, LOIC-UDP, HOIC mapped to `ddos` (`TA0040` / `T1498`).
  * Brute Force -XSS, SQL Injection mapped to `web_exploit` (`TA0001` / `T1190`).
  * Infiltration mapped to `infiltration` (`TA0008` / `T1021`).
  * Bot mapped to `botnet_c2` (`TA0011` / `T1071`).
* **PCAP Validation**: `scripts/check_events_in_pcap.py` verifies packet existence and timestamps on victim-specific capture files.
* **Strict Test Day Protection**: Friday 23-02-2018 is a spent test day; it is strictly excluded from training event generation.

---

## 4. Label Counts and Statistics

* **Canonical Event Count**: **19 events** across 8 non-held-out attack days in `ground_truth/cic2018/events.csv`.
* **Events per Attack Family**:
  * `bruteforce`: 3 events (FTP-BruteForce, SSH-Bruteforce, Brute Force -Web)
  * `dos`: 4 events (GoldenEye, Slowloris, SlowHTTPTest, Hulk)
  * `ddos`: 4 events (LOIC-HTTP, LOIC-UDP x2, HOIC)
  * `web_exploit`: 2 events (Brute Force -XSS, SQL Injection)
  * `infiltration`: 4 events (2 on 28-02, 2 on 01-03)
  * `botnet_c2`: 2 events (2 on 02-03)
* **Events per Campaign**: 19 distinct, deterministic campaigns.
* **Unknown Label Rate in Events**: 0% (all 19 events map to approved standard families).

---

## 5. Known Issues

1. **Excel Row Cap Bug**: 7 of 10 flow CSVs in the release were exported using Microsoft Excel and truncated at exactly 1,048,575 rows.
2. **Missing IP Addresses**: 9 of 10 days in the flow CSV release completely omit IP addresses (`Source IP` and `Destination IP` are absent), preventing IP-based flow grouping.
3. **Victim-Specific PCAP Layout**: PCAPs are split across 449 individual endpoint files per day rather than a single interface stream.
4. **Timezone Uncertainty**: Published times reflect local Canadian AST (UTC-4); Wednesday 14-02 has verified UTC timestamps (+4h), while remaining days keep blank UTC fields pending PCAP validation on Yash's workstation.

---

## 6. Open Questions

1. **Measured UTC Timestamp Offset**: Awaiting Yash's execution of `scripts/check_events_in_pcap.py` against PCAPs for days 15-02 through 02-03 on drive `V:`.
2. **Internal vs Public Attacker IPs**: Confirm whether packets on remaining capture days carry external Elastic IPs or internal AWS private IPs on the capture interfaces.
