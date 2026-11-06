# CSE-CIC-IDS2018 Ground-Truth Events Documentation and Notes

**File**: `ground_truth/cic2018/events.csv`  
**Dataset**: CSE-CIC-IDS2018 (Communications Security Establishment & Canadian Institute for Cybersecurity)  
**Target Scope**: Wednesday, 14 February 2018 (FTP and SSH Brute Force)  
**Official Reference**: https://www.unb.ca/cic/datasets/ids-2018.html  
**Documentation**: `docs/23-dataset-standardisation-plan.md`, `docs/24-handover-amin-dataset-standardisation.md`, `docs/16-diagnosis-and-improvement-plan.md`

---

## 1. Attack Schedule & Direct PCAP Measurements (Wednesday 14-02-2018)

Measurements performed directly on drive `V:` via `tshark` on the victim capture file `UCAP172.31.69.25`:

* **Timezone Offset**:
  Published CSE-CIC-IDS2018 times are in Canadian Atlantic Standard Time (**AST = UTC-4**).
  The measured PCAP timestamps demonstrate an exact **+4 hour offset** from published schedule times to UTC.
  *(Important: Do NOT apply this offset to CIC-IDS-2017; CIC-2017 was recorded in July under Daylight Saving Time and has its own distinct offset).*

* **IP Addressing (Public vs Internal)**:
  Inside the raw PCAP capture, the external attackers carry their **PUBLIC IP addresses**, while the victim carries its **INTERNAL IP address** (`172.31.69.25`).

### 1.1 FTP Brute Force (`cic2018_wed_bruteforce_01`)
* **Published Schedule Time**: 10:32 – 12:09 (nominal local AST)
* **Direct PCAP Measurement (tshark)**:
  * Traffic: `18.221.219.4` $\rightarrow$ `172.31.69.25:21`
  * First Packet Observed: `14:33:27Z`
  * Last Packet Observed: `16:10:32Z`
* **Canonical Event Window**: `2018-02-14T14:32:00Z` to `2018-02-14T16:09:00Z` (+4 hours offset).
* **Attacker IP**: `18.221.219.4` (Public IP)
* **Victim IP**: `172.31.69.25` (Internal IP)
* **Port**: `21`
* **Classification**: Family `bruteforce`, MITRE Tactic `TA0006`, Technique `T1110`, Stage `initial_access`.

### 1.2 SSH Brute Force (`cic2018_wed_bruteforce_02`)
* **Published Schedule Time**: 14:01 – 15:31 (nominal local AST)
* **Direct PCAP Measurement (tshark)**:
  * Traffic: `13.58.98.64` $\rightarrow$ `172.31.69.25:22`
  * First Packet Observed: `18:01:50Z`
  * Last Packet Observed: `19:32:31Z`
* **Canonical Event Window**: `2018-02-14T18:01:00Z` to `2018-02-14T19:31:00Z` (+4 hours offset).
* **Attacker IP**: `13.58.98.64` (Public IP — Note: this is a distinct attacker machine from FTP's `18.221.219.4`).
* **Victim IP**: `172.31.69.25` (Internal IP)
* **Port**: `22`
* **Classification**: Family `bruteforce`, MITRE Tactic `TA0006`, Technique `T1110`, Stage `initial_access`.

---

## 2. Victim-Specific PCAP Layout

* The PCAP capture for Wednesday 14-02 consists of 449 per-endpoint capture files.
* The victim capture containing both brute-force attacks is `UCAP172.31.69.25`.
* Captures are cut short at the end (tshark exit code 14), handled gracefully by `scripts/check_events_in_pcap.py`.

---

## 3. Flow CSV Limitations

* 9 of the 10 daily CSV releases in CSE-CIC-IDS2018 omit IP addresses entirely.
* 7 of 10 flow CSVs suffer from the 1,048,575 Excel row cap.
* Standardisation relies on PCAP ground truth where real IPs and timestamps are preserved.

---

## 4. Held-Out Test Day Protection (Friday 23-02-2018)

* Friday 23-02-2018 is a held-out test day and is strictly excluded from training event generation.
