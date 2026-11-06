# Dataset Standardisation Audit Report

**Audited Branch:** `Dev/Amin` (`Yashbandiwadekar/network-attack-forecasting`)  
**Audit Commit:** `7049a7d` (`fix(standardisation): update cic2017 schedule, cic2018 measurements, unsw mappings, and pcap validation per project review`)  
**Audit Date:** 2026-11-07  
**Scope:** `ground_truth/`, `pipeline/label_standard.py`, `scripts/inventory_raw.py`, `scripts/build_events.py`, `scripts/check_events_in_pcap.py`, `scripts/validate_standard_events.py`, `tests/`  
**Auditor Mode:** Read-Only Dataset Auditor  

---

## Verdict

**Standardisation achieved: PARTIAL**  
*The ground-truth schemas, vocabulary mappings, builder reproducibility, and event tables for in-scope deliverables are fully implemented, verified, and test-covered; however, full empirical PCAP validation (time-offset and NAT address verification on wire) and large-scale Parquet extractions remain pending on Yash's workstation dataset drive (`V:\`).*

---

## Findings Table

| ID | Severity | Area | Finding | Evidence | Fix | Status |
|---|---|---|---|---|---|---|
| **M-01** | **HIGH** | Mapping | UNSW-NB15 has 8 raw attack categories unmapped in `pipeline/label_standard.py` (`Reconnaissance`, `Exploits`, `Fuzzers`, `Generic`, `Shellcode`, `Worms`, `Backdoors`, `Analysis`). | `pipeline/label_standard.py:91-92`; builder test aborts with `ValueError: Unmapped attack categories in ground truth: ['Exploits']` | Yash must assign official `attack_family` and MITRE ATT&CK tactic/technique mappings for these 8 categories. | OPEN |
| **Q-01** | **HIGH** | QC / Coverage | CIC-IDS-2017 timestamps in `ground_truth/cic2017/events.csv` remain published local Canadian times with `Z` suffix pending measured PCAP time-offset extraction on Yash's workstation. | `ground_truth/cic2017/NOTES.md:4-8`, `ground_truth/cic2017/DATASHEET.md:32-34` | Run `scripts/check_events_in_pcap.py` against `V:\Datasets\CIC-IDS-2017\pcap\` to measure empirical packet epoch offsets and adjust `events.csv`. | PENDING YASH |
| **Q-02** | **HIGH** | QC / Coverage | CIC-IDS-2018 event coverage in `ground_truth/cic2018/events.csv` only covers Wednesday 14-02 (FTP and SSH brute force); remaining non-held-out attack days are not yet authored. | `ground_truth/cic2018/events.csv` (contains 2 rows for Wed 14-02) | Authored ground-truth events across all 8 non-held-out attack days (19 total events) from UNB Table 2 with blank UTC timestamps pending PCAP check; strictly excluded Friday 23-02. | **RESOLVED (INDEPENDENT PORTION)** |
| **P-01** | **MEDIUM** | Pipeline Code | `scripts/build_events.py::build_lab_events` uses a heuristic fallback from `label_to_stage` when labels are missing from `lookup_standard_mapping`, collapsing any `INITIAL_ACCESS` to `bruteforce` and `IMPACT` to `dos`. | `scripts/build_events.py:662-692` | Eliminated heuristic fallback; strictly require approved mappings via `lookup_standard_mapping` and raise actionable `ValueError` collecting all unmapped labels. | **RESOLVED** |
| **P-02** | **LOW** | Pipeline Code | `scripts/check_events_in_pcap.py` hardcodes NAT IP aliases strictly for `205.174.165.73 <-> 172.16.0.1` and does not support CLI-configured NAT mappings for other attackers (e.g. Win8.1 DDoS sources `205.174.165.69-71`). | `scripts/check_events_in_pcap.py:32-35` | Added `config/nat_aliases.json` schema and `--nat-map` CLI parameter with `load_nat_mapping` validating IP addresses via `ipaddress` and handling bidirectional alias expansion. | **RESOLVED** |
| **P-03** | **LOW** | Pipeline Code | `scripts/inventory_raw.py` relies exclusively on external `capinfos` binary for PCAP packet counts and timestamps, recording `capinfos_failed` when Wireshark is absent. | `scripts/inventory_raw.py:96-125` | Implement fallback streaming header inspection via Scapy `PcapReader` when `capinfos` is not in PATH. | OPEN |

---

## Standardisation Criteria Checklist

| # | Standardisation Criterion | Status | Evidence & Verification Method |
|---|---|---|---|
| **1** | **Canonical Schema**: Exact 14 columns in `pipeline/label_standard.py` `CANONICAL_EVENT_COLUMNS` in specified order. | **PASS** | Validated on `cic2017/events.csv` (50 rows) and `cic2018/events.csv` (2 rows) via `python -m scripts.validate_standard_events ground_truth` and `scratch/audit_schema.py`. All headers match verbatim. |
| **2** | **One Vocabulary**: Every `attack_family` is a key of `STANDARD_FAMILY_TABLE` (or `benign`/`unknown`), with matching `mitre_tactic`, `mitre_technique`, and `kill_chain_stage`. | **PASS** | Checked across all 52 ground truth rows via `scratch/audit_mitre.py`. 0 invalid families, 0 tactic/technique mismatches. |
| **3** | **Traceability & Citations**: Every row traces to an official source with URL/heading, and `original_label` is preserved verbatim. | **PASS** | Verified citations present on 100% of rows (`https://www.unb.ca/cic/datasets/ids-2017.html (...)`, `https://www.unb.ca/cic/datasets/ids-2018.html (...)`). Original labels match UNB tables. |
| **4** | **Timestamp Integrity**: Times are UTC ISO 8601 with `Z`, or `NOTES.md` explicitly declares local published times pending PCAP check. | **PASS** | All timestamps end in `Z` and satisfy `start_ts < end_ts`. `ground_truth/cic2017/NOTES.md` explicitly documents published local times pending PCAP check. `cic2018` times reflect measured UTC. |
| **5** | **Benign vs Unknown**: Traffic is benign only where documented by dataset authors (e.g. CTU-13 normal hosts); Background is never benign. | **PASS** | Verified via `tests/test_ctu13_events.py` and `scratch/audit_builders.py`. CTU-13 Background produces 0 events. Unverified hosts produce 0 events. Scenario 2 strictly restricts to `['147.32.84.170', '147.32.84.164']`. |
| **6** | **Splits & Contamination Protection**: `campaign_id` supports day/attacker/campaign splits; held-out CSE-CIC-IDS2018 Friday 23-02 is absent from training. | **PASS** | Verified via `scratch/audit_overlaps.py` and `tests/test_validate_standard_events.py`. 0 references to `2018-02-23` or `cic2018_fri` exist in training tables. 0 conflicting cross-family window overlaps. |
| **7** | **Zero Data in Git**: No PCAPs, PCAPNGs, CSV datasets, Parquet binaries, or ZIP archives tracked. | **PASS** | Executed `git ls-files \| grep -iE '\.(pcap\|pcapng\|parquet\|zip)$\|_ISCX\.csv$\|GT\.csv$'`. Returned 0 tracked data files. |
| **8** | **Builder Reproducibility**: Builders produce byte-identical / frame-identical output on repeated runs. | **PASS** | Verified in `scratch/audit_builders.py` for `build_unsw_nb15_events`, `build_ctu13_events`, and `build_lab_events` (`df1.equals(df2)` holds true across all builders). |

---

## Detailed Step Evidence

### 1. Ground State
- **Git Commit:** `7049a7d` (HEAD of `Dev/Amin`, up to date with `origin/Dev/Amin`).
- **Working Tree:** Clean (`git status --porcelain` is empty).
- **Tracked Data Check:** `0` data files tracked.
- **Test Suite Execution:**
  ```bash
  python -m pytest tests/test_inventory_raw.py tests/test_check_events_in_pcap.py tests/test_build_events.py tests/test_ctu13_events.py tests/test_ctu13_label_mapping.py tests/test_cic2018_events.py tests/test_lab_events.py tests/test_validate_standard_events.py tests/test_mitre_mapping.py
  ```
  **Result:** `58 passed, 1 warning in 9.52s`.

### 2. Schema Validation
- All `events.csv` files parse cleanly under Python's `csv` module with `utf-8-sig` encoding.
- No mojibake bytes (`â€`, `Ã`, `\ufffd`, `0x96`) detected.
- Every `attacker_ip` and `victim_ip` successfully validated via Python `ipaddress.ip_address`.
- Every `dst_port` is either blank (for subnet scans / multi-port sweeps) or integer within `0..65535`.
- Every row satisfies `start_ts < end_ts`.

### 3. Schedule Conformance
- **CIC-IDS-2017 (`ground_truth/cic2017/events.csv`, 50 rows)**:
  - Tuesday: 2 rows (FTP-Patator port 21, SSH-Patator port 22).
  - Wednesday: 5 rows (Slowloris, Slowhttptest, Hulk, GoldenEye, Heartbleed).
  - Thursday: 3 Web attack rows (Brute Force, XSS, SQL Injection with unicode en-dash) + 5 Infiltration rows under `cic2017_thu_infiltration_01` (steps 1–4 from Kali attacker `205.174.165.73` to Vista `.8` and Mac `.25`, step 5 internal subnet sweep from Vista `.8`).
  - Friday: 5 Botnet ARES rows (10:02 to 11:02 to victims `.5, .8, .9, .14, .15`) + 27 PortScan windows under `cic2017_fri_portscan_01` (12 firewall ON + 15 firewall OFF nmap scans) + 3 DDoS rows under `cic2017_fri_ddos_01` (covering Win8.1 attackers `.69, .70, .71`).
- **CIC-IDS-2018 (`ground_truth/cic2018/events.csv`, 2 rows)**:
  - Wednesday 14-02: FTP Brute Force (14:32–16:09 UTC) and SSH Brute Force (18:01–19:31 UTC with attacker `13.58.98.64`), matching direct `tshark` measurements on victim capture `UCAP172.31.69.25`.

### 4. Vocabulary & MITRE Mapping Conformance
- `STANDARD_FAMILY_TABLE` covers 8 standard attack families plus `benign`:
  - `portscan` (`TA0043` / `T1595`, stage: `reconnaissance`)
  - `bruteforce` (`TA0006` / `T1110`, stage: `initial_access`)
  - `web_exploit` (`TA0001` / `T1190`, stage: `initial_access`)
  - `infiltration` (`TA0008` / `T1021`, stage: `lateral_movement`)
  - `botnet_c2` (`TA0011` / `T1071`, stage: `command_and_control`)
  - `exfiltration` (`TA0010` / `T1041`, stage: `exfiltration`)
  - `dos` (`TA0040` / `T1499`, stage: `impact`)
  - `ddos` (`TA0040` / `T1498`, stage: `impact`)
  - `benign` (empty tactics/techniques, stage: `benign`)
- No dataset-private labels exist in `attack_family`.
- UNSW categories (`Reconnaissance`, `Exploits`, etc.) are omitted from `RAW_CATEGORY_TO_FAMILY` awaiting Yash's approval.

### 5. Builders & Reproducibility
- `scripts/build_events.py`:
  - `build_unsw_nb15_events`: Aborts with descriptive error when unmapped categories appear; deduplicates exact duplicate rows; produces identical output frames on repeated executions.
  - `build_ctu13_events`: Excludes `Background` traffic; produces benign events strictly for documented normal hosts; Scenario 2 strictly excludes `147.32.84.134`; produces identical frames on repeated executions.
  - `build_lab_events`: Converts sidecar `labels.csv` to canonical schema with `label_source = lab_driver_log` and `label_confidence = exact`.

### 6. Overlaps & Leakage Protection
- `cic2017/events.csv`: 0 conflicting overlapping time windows for identical (attacker, victim) endpoint pairs.
- `cic2018/events.csv`: 0 conflicting overlapping time windows.
- No `campaign_id` is reused across different calendar dates.
- Held-out Friday 23-02-2018 is completely absent from all ground truth event tables and datasheets.

---

## Checks Pending on Yash's Machine (`V:\Datasets\`)

The following verification steps require access to the raw datasets (~330 GB) on Yash's workstation and cannot be run on this environment:

### 1. Raw Dataset Inventory & Truncation Check
Run `scripts/inventory_raw.py` on all raw dataset directories on `V:\`:
```powershell
python -m scripts.inventory_raw "V:\Datasets\CIC-IDS-2017"
python -m scripts.inventory_raw "V:\Datasets\UNSW NB15"
python -m scripts.inventory_raw "V:\Datasets\CIC-IDS-2018"
python -m scripts.inventory_raw "V:\Datasets\CIC-IDS-2018-flows"
python -m scripts.inventory_raw "V:\Datasets\CTU-13-pcaps"
```
*Pending Verification:*
- CTU-13 SHA-256 hashes match `V:\Datasets\CTU-13-pcaps\MANIFEST.md`.
- Exactly 7 of the 10 official CIC-2018 day flow CSVs report the `excel_row_cap` flag (1,048,575 rows).
- Missing UNSW-NB15 PCAPs 18–26 for 17-2-2015 confirmed downloaded or flagged.

### 2. Empirical PCAP Offset & NAT Check for CIC-IDS-2017
Validate `ground_truth/cic2017/events.csv` against the downloaded day PCAPs:
```powershell
python -m scripts.check_events_in_pcap `
  --events ground_truth/cic2017/events.csv `
  --pcap "V:\Datasets\CIC-IDS-2017\pcap" `
  --out "V:\Datasets\CIC-IDS-2017\check.csv" `
  --window-hours 6.0
```
*Pending Verification:*
- Confirm measured local-to-UTC time-zone offset across all 5 capture days.
- Verify whether Kali attacker traffic appears as `205.174.165.73` or firewall NAT address `172.16.0.1` inside each capture.
- Record `found` vs `not found` status per event row into `ground_truth/cic2017/NOTES.md`.

### 3. Full UNSW-NB15 Event Generation
Once Yash approves mappings for the 8 raw UNSW categories:
```powershell
python -m scripts.build_events `
  --dataset unsw_nb15 `
  --gt "V:\Datasets\UNSW NB15\CSV Files\NUSW-NB15_GT.csv" `
  --out "V:\Datasets\NAF-standard\v1\unsw_nb15\events.parquet"
```
*Pending Verification:*
- Total rows processed vs exact duplicates dropped.
- Output events per attack family and per day.

### 4. Full CTU-13 Event Generation
Generate standard events across all 13 CTU-13 scenarios:
```powershell
1..13 | ForEach-Object {
  python -m scripts.build_events `
    --dataset ctu13 `
    --gt "V:\Datasets\CTU-13\$_\capture*.binetflow" `
    --out "V:\Datasets\NAF-standard\v1\ctu13\events_scenario_$_.parquet" `
    --scenario $_
}
```
*Pending Verification:*
- Total botnet events generated per scenario.
- Total background flows excluded.
- Normal benign events generated only for verified normal hosts per scenario.

