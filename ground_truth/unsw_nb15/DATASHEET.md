# Dataset Datasheet: UNSW-NB15

**Standardized Target Path**: `ground_truth/unsw_nb15/events.parquet`  
**Dataset Identifier**: `unsw_nb15`

---

## 1. Source and Licensing

* **Dataset Name**: UNSW-NB15 Dataset.
* **Official Source URL**: https://research.unsw.edu.au/projects/unsw-nb15-dataset
* **Dataset Authors / Organisation**: Nour Moustafa and Jill Slay (Cyber Range Lab, Australian Centre for Cyber Security, UNSW Canberra).
* **Citation Requested**:
  > Nour Moustafa and Jill Slay, "UNSW-NB15: a comprehensive data set for network intrusion detection systems (UNSW-NB15 network data set)", Military Communications and Information Systems Conference (MilCIS), 2015.
* **Licence**: Freely available for non-commercial academic and research purposes.
* **Download Date**: Ground-truth file `NUSW-NB15_GT.csv` and 63 PCAP files present on drive `V:` (validated 2026-10-10).

---

## 2. Coverage

* **Duration**: 31 hours of network traffic recorded across two days: 22 January 2015 and 17 February 2015.
* **Days Covered**: 22-01-2015 (complete PCAPs 1–53) and 17-02-2015 (PCAPs 1–17, 27; files 18–26 missing).
* **Hosts**: 4 distinct attacker IP addresses (`175.45.176.0`, `.1`, `.2`, `.3`) targeting internal servers in subnet `149.171.126.0/24`.
* **Attack Families**: `portscan`, `web_exploit`, `dos` (plus unmapped categories awaiting review).
* **Available Data**: Full packet PCAPs (67 GB total) and flow data with explicit ground-truth event table `NUSW-NB15_GT.csv` (86 MB).

---

## 3. Event Construction Methodology

* **Automated Generation**: Built directly from `NUSW-NB15_GT.csv` using `scripts/build_events.py --dataset unsw_nb15`.
* **Duplicate Dropping**: Identical duplicate ground-truth rows are detected and removed.
* **Timestamp Handling**: Unix epoch timestamps converted to UTC ISO 8601 ending in `Z`.
* **Campaign Grouping**: Grouped deterministically by `unsw_<YYYYMMDD>_<Source IP>`.
* **Strict Unmapped Enforcement**: Generation stops if unmapped categories (`Fuzzers`, `Generic`, `Shellcode`, `Worms`, `Backdoors`, `Analysis`) are encountered, preventing guessed labels.

---

## 4. Label Counts and Statistics

* **Input Rows in Ground Truth**: ~86 MB table (~150,000+ attack event entries).
* **Standard Mapped Families**:
  * `portscan`: maps `Reconnaissance` (TA0043, T1595)
  * `web_exploit`: maps `Exploits` (TA0001, T1190)
  * `dos`: maps `DoS` (TA0040, T1499)
* **Flow Statistics in Raw CSVs**: 2,540,044 flows across the 4 CSV files (UNSW-NB15_1.csv to _4.csv); real IP addresses and Unix timestamps present on every flow.
* **Unknown Label Handling**: Flows outside ground-truth events remain `unknown` unless verified normal.

---

## 5. Known Issues

1. **Missing Capture Files**: PCAPs 18 through 26 for 17 February 2015 are absent from the primary dataset download mirror.
2. **Unmapped Attack Categories**: 8 of the 9 UNSW attack categories (`Reconnaissance`, `Exploits`, `Fuzzers`, `Generic`, `Shellcode`, `Worms`, `Backdoors`, `Analysis`) are currently unmapped pending project lead taxonomy decisions.
3. **Argus Protocol Handling**: ~130 protocols reported by Argus; non-TCP/UDP/ICMP flows are normalized onto protocol 255 to prevent silent row dropping.

---

## 6. Open Questions

1. **Category Mapping Approval**: Yash to review and confirm standard family and MITRE mappings for the 8 unmapped categories (including Reconnaissance and Exploits).
2. **Missing PCAP Recovery**: Confirmation whether UNSW PCAPs 18–26 for 17-02-2015 can be retrieved from alternative UNSW archives.

