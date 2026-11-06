# CSE-CIC-IDS2018 Ground-Truth Events Documentation and Notes

**File**: `ground_truth/cic2018/events.csv`  
**Dataset**: CSE-CIC-IDS2018 (Communications Security Establishment & Canadian Institute for Cybersecurity)  
**Target Scope**: Wednesday, 14 February 2018 (FTP and SSH Brute Force)  
**Official Reference**: https://www.unb.ca/cic/datasets/ids-2018.html  
**Documentation**: `docs/23-dataset-standardisation-plan.md`, `docs/24-handover-amin-dataset-standardisation.md`, `docs/16-diagnosis-and-improvement-plan.md`

---

## 1. Attack Schedule & Scope (Wednesday 14-02-2018)

According to the official UNB CSE-CIC-IDS2018 dataset schedule:
* **Morning Attack**:
  * **Attack**: FTP-BruteForce
  * **Nominal Published Time**: 10:30 – 11:30 local Canadian time
  * **Attacker IP**: `18.221.219.4` (External Kali attacker machine on AWS)
  * **Victim IP**: `172.31.69.25` (Ubuntu 16.04 server hosting FTP service)
  * **Destination Port**: `21`
  * **Campaign ID**: `cic2018_wed_bruteforce_01`
  * **Standard Mapping**: Family `bruteforce`, MITRE Tactic `TA0006` (Credential Access), Technique `T1110` (Brute Force), Stage `initial_access`.
* **Afternoon Attack**:
  * **Attack**: SSH-Bruteforce
  * **Nominal Published Time**: 14:00 – 15:00 local Canadian time
  * **Attacker IP**: `18.221.219.4`
  * **Victim IP**: `172.31.69.25`
  * **Destination Port**: `22`
  * **Campaign ID**: `cic2018_wed_bruteforce_02`
  * **Standard Mapping**: Family `bruteforce`, MITRE Tactic `TA0006`, Technique `T1110`, Stage `initial_access`.

---

## 2. Victim-Specific PCAP File Structure

Unlike datasets that package traffic into a single monolithic capture per day, the CSE-CIC-IDS2018 PCAP release for Wednesday 14-02-2018 consists of **449 individual PCAP files** (~45 GB), organised per captured endpoint/victim machine.
* File naming pattern: `cap<HOSTNAME>-<IP>`, e.g., `capDESKTOP-AN3U28N-172.31.64.111`.
* The brute-force attacks on 14-02 targeted the internal server at `172.31.69.25`.
* **Action for Yash**: Run `scripts/check_events_in_pcap.py` targeting the PCAP files corresponding to victim IP `172.31.69.25`:
  ```bash
  python -m scripts.check_events_in_pcap --events ground_truth/cic2018/events.csv --pcap "V:\Datasets\CSE-CIC-IDS2018\Wednesday-14-02-2018" --out check_cic2018.csv
  ```

---

## 3. Time Zone & NAT Considerations

* **Timezone Offset**: Published times reflect local Canadian time (UTC-4 / AST or UTC-5 / EST depending on AWS region configuration). Event timestamps in `events.csv` reflect nominal published times with a `Z` suffix. Final UTC offset resolution is pending Yash's `check_events_in_pcap.py` output.
* **NAT Differences**: In AWS VPC network captures, external traffic originating from `18.221.219.4` may appear with private gateway/NAT interfaces or direct public IP headers depending on whether the capture was positioned at the host interface or internet gateway. `scripts/check_events_in_pcap.py` supports endpoint pair searches in both directions.

---

## 4. Flow CSV Limitations

* **Missing IP Addresses**: 9 of the 10 daily CSV releases in CSE-CIC-IDS2018 do not contain `Source IP` or `Destination IP` columns. Therefore, flow CSVs cannot be windowed by host or joined by IP.
* **Excel Row Cap**: 7 of the 10 flow CSVs were truncated at 1,048,575 rows due to an Excel export bug by the dataset authors (flagged as `excel_row_cap` by `scripts/inventory_raw.py`).
* **Conclusion**: Ground-truth event matching and standardisation for CIC-IDS-2018 relies strictly on the official PCAP captures where real IPs and timestamps are preserved.

---

## 5. Held-Out Test Day Protection (Friday 23-02-2018)

* Friday 23-02-2018 is a spent test day reserved strictly for evaluation.
* **Enforcement**: Friday 23-02 is excluded from training ground-truth generation and will never be processed into training events.

---

## 6. Open Questions & Coordination Items

1. **Measured UTC Offset**: Awaiting `check_cic2018.csv` from Yash after executing the PCAP validation tool.
2. **Victim PCAP Confirmation**: Confirmation from Yash of the exact filename matching the `172.31.69.25` victim capture.
