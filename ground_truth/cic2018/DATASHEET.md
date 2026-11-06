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
* **Target Scope for Standardization**: Wednesday, 14 February 2018 (FTP and SSH brute-force campaigns).
* **Hosts**: AWS VPC infrastructure; external attacker `18.221.219.4`; internal victim server `172.31.69.25`.
* **Attack Families**: `bruteforce` (FTP-BruteForce, SSH-Bruteforce).
* **Available Data**: Full packet PCAPs for Wednesday 14-02 (449 files) and Friday 23-02; flow CSVs for all 10 days.

---

## 3. Event Construction Methodology

* **Single Source of Truth**: Events in `ground_truth/cic2018/events.csv` are constructed from official UNB schedule tables for Wednesday 14-02-2018.
* **Attack Classification**: FTP and SSH brute force mapped to standard family `bruteforce`, MITRE Tactic `TA0006` (Credential Access), Technique `T1110`, kill-chain stage `initial_access`.
* **PCAP Validation**: `scripts/check_events_in_pcap.py` verifies packet existence and timestamps on victim-specific capture files (e.g. captures for `172.31.69.25`).
* **Strict Test Day Protection**: Friday 23-02-2018 is a spent test day; it is strictly excluded from training event generation.

---

## 4. Label Counts and Statistics

* **Canonical Event Count**: **2 events** for Wednesday 14-02 in `ground_truth/cic2018/events.csv`.
* **Events per Attack Family**:
  * `bruteforce`: 2 events (FTP-BruteForce at 10:30, SSH-Bruteforce at 14:00).
* **Events per Campaign**:
  * `cic2018_wed_bruteforce_01` (FTP brute force)
  * `cic2018_wed_bruteforce_02` (SSH brute force)
* **Flow Counts in Wednesday 14-02 CSV**: 1,048,575 rows (193,360 FTP-BruteForce, 187,589 SSH-Bruteforce, 667,626 Benign).
* **Unknown Label Rate in Events**: 0% (both events map to `bruteforce`).

---

## 5. Known Issues

1. **Excel Row Cap Bug**: 7 of 10 flow CSVs in the release were exported using Microsoft Excel and truncated at exactly 1,048,575 rows (including Wednesday 14-02).
2. **Missing IP Addresses**: 9 of 10 days in the flow CSV release completely omit IP addresses (`Source IP` and `Destination IP` are absent), preventing IP-based flow grouping.
3. **Victim-Specific PCAP Layout**: PCAPs are split across 449 individual endpoint files per day rather than a single interface stream.
4. **Timezone Uncertainty**: Published times reflect local Canadian time, requiring PCAP timestamp validation before final UTC conversion.

---

## 6. Open Questions

1. **Measured UTC Timestamp Offset**: Awaiting Yash's execution of `scripts/check_events_in_pcap.py` against `172.31.69.25` PCAPs.
2. **Victim Capture Confirmation**: Specific confirmation of the exact filename matching the target server capture.

