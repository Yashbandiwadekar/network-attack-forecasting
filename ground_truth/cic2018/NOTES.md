# CSE-CIC-IDS2018 Ground-Truth Events Documentation and Notes

**File**: `ground_truth/cic2018/events.csv`  
**Dataset**: CSE-CIC-IDS2018 (Communications Security Establishment & Canadian Institute for Cybersecurity)  
**Target Scope**: Multi-Day Ground Truth covering all 8 non-held-out attack days (19 total events)  
**Official Reference**: https://www.unb.ca/cic/datasets/ids-2018.html  
**Documentation**: `docs/23-dataset-standardisation-plan.md`, `docs/24-handover-amin-dataset-standardisation.md`, `docs/16-diagnosis-and-improvement-plan.md`

---

## 1. Overview of Capture Days and Scope

The CSE-CIC-IDS2018 dataset spans 10 recording days in February and March 2018 on AWS infrastructure.

| Date | Day | Scheduled Attacks | Target Server | Status in Ground Truth |
|---|---|---|---|---|
| **14-02-2018** | Wednesday | FTP-BruteForce, SSH-Bruteforce | `172.31.69.25` | **PCAP-Validated UTC** (2 events) |
| **15-02-2018** | Thursday | DoS-GoldenEye, DoS-Slowloris | `172.31.69.25` | **Authored from Schedule** (2 events, UTC pending PCAP) |
| **16-02-2018** | Friday | DoS-SlowHTTPTest, DoS-Hulk | `172.31.69.25` | **Authored from Schedule** (2 events, UTC pending PCAP) |
| **20-02-2018** | Tuesday | DDoS attacks-LOIC-HTTP, DDoS-LOIC-UDP | `172.31.69.25` | **Authored from Schedule** (2 events, UTC pending PCAP) |
| **21-02-2018** | Wednesday | DDOS-LOIC-UDP, DDOS-HOIC | `172.31.69.28` | **Authored from Schedule** (2 events, UTC pending PCAP) |
| **22-02-2018** | Thursday | Brute Force -Web, Brute Force -XSS, SQL Injection | `172.31.69.28` | **Authored from Schedule** (3 events, UTC pending PCAP) |
| **23-02-2018** | Friday | Web attacks / held-out test data | `172.31.69.28` | **STRICTLY EXCLUDED** (Held-Out Test Day) |
| **28-02-2018** | Wednesday | Infiltration (runs 1 & 2) | `172.31.69.24` | **Authored from Schedule** (2 events, UTC pending PCAP) |
| **01-03-2018** | Thursday | Infiltration (morning & afternoon) | `172.31.69.13` | **Authored from Schedule** (2 events, UTC pending PCAP) |
| **02-03-2018** | Friday | Botnet (Ares C2, morning & afternoon) | `172.31.69.23` | **Authored from Schedule** (2 events, UTC pending PCAP) |

---

## 2. Evidence Levels and Timestamp Protocol

### 2.1 Evidence Levels
To prevent false precision and ensure scientific traceability, records distinguish three evidence levels:
1. **Validated against PCAP**: Empirically verified against packet timestamps using `scripts/check_events_in_pcap.py` (Wednesday 14-02).
2. **Authored from Official Schedule**: Sourced verbatim from UNB Table 2 (`https://www.unb.ca/cic/datasets/ids-2018.html`).
3. **Cross-Checked against Flow Data**: Confirmed presence of matching labels in CICFlowMeter CSVs (observing row caps and missing IPs).

### 2.2 Timezone Handling & Timezone Offset – Critical Rule
Published CSE-CIC-IDS2018 schedule times are in Canadian Atlantic Standard Time (**AST = UTC-4**).
* **Timezone Offset**: For Wednesday 14-02, PCAP measurements confirmed the exact **+4 hour offset** from published schedule times to UTC, so UTC timestamps (`start_ts`, `end_ts`) are populated ending in `Z`.
* For remaining days (15-02, 16-02, 20-02, 21-02, 22-02, 28-02, 01-03, 02-03), raw PCAPs on drive `V:` have not yet been scanned. In strict adherence to project standards, `start_ts` and `end_ts` remain **blank** in `events.csv` to avoid fabricating unverified UTC numbers. Local AST published times are preserved below.

---

## 3. Detailed Attack Campaigns

### 3.1 Wednesday 14-02-2018 (PCAP-Validated)
* **`cic2018_wed_bruteforce_01` (FTP-BruteForce)**:
  * Published Local Time: 10:32 – 12:09 AST
  * PCAP Measured UTC: `2018-02-14T14:32:00Z` – `2018-02-14T16:09:00Z`
  * Attacker IP: `18.221.219.4` (internal `172.31.70.4`) $\rightarrow$ Victim `172.31.69.25:21`
  * Classification: Family `bruteforce`, MITRE `TA0006` / `T1110`, Stage `initial_access`.
* **`cic2018_wed_bruteforce_02` (SSH-Bruteforce)**:
  * Published Local Time: 14:01 – 15:31 AST
  * PCAP Measured UTC: `2018-02-14T18:01:00Z` – `2018-02-14T19:31:00Z`
  * Attacker IP: `13.58.98.64` (internal `172.31.70.6`) $\rightarrow$ Victim `172.31.69.25:22`
  * Classification: Family `bruteforce`, MITRE `TA0006` / `T1110`, Stage `initial_access`.

### 3.2 Thursday 15-02-2018 (Thurs-15-02-2018)
* **`cic2018_thu_dos_01` (DoS-GoldenEye)**:
  * Published Local Time: 09:26 – 10:09 AST
  * Attacker IP: `18.219.211.138` (internal `172.31.70.46`) $\rightarrow$ Victim `172.31.69.25:80`
  * Classification: Family `dos`, MITRE `TA0040` / `T1499`, Stage `impact`.
* **`cic2018_thu_dos_02` (DoS-Slowloris)**:
  * Published Local Time: 10:59 – 11:40 AST
  * Attacker IP: `18.217.165.70` (internal `172.31.70.8`) $\rightarrow$ Victim `172.31.69.25:80`
  * Classification: Family `dos`, MITRE `TA0040` / `T1499`, Stage `impact`.

### 3.3 Friday 16-02-2018
* **`cic2018_fri_dos_01` (DoS-SlowHTTPTest)**:
  * Published Local Time: 10:12 – 11:08 AST
  * Attacker IP: `13.59.126.31` (internal `172.31.70.23`) $\rightarrow$ Victim `172.31.69.25:80`
  * Classification: Family `dos`, MITRE `TA0040` / `T1499`, Stage `impact`.
* **`cic2018_fri_dos_02` (DoS-Hulk)**:
  * Published Local Time: 13:45 – 14:19 AST
  * Attacker IP: `18.219.193.20` (internal `172.31.70.16`) $\rightarrow$ Victim `172.31.69.25:80`
  * Classification: Family `dos`, MITRE `TA0040` / `T1499`, Stage `impact`.

### 3.4 Tuesday 20-02-2018
* **`cic2018_tue_ddos_01` (DDoS attacks-LOIC-HTTP)**:
  * Published Local Time: 10:12 – 11:17 AST
  * Attacker IP: `18.218.115.60` (lead node of 10-node attacking pool) $\rightarrow$ Victim `172.31.69.25:80`
  * Classification: Family `ddos`, MITRE `TA0040` / `T1498`, Stage `impact`.
* **`cic2018_tue_ddos_02` (DDoS-LOIC-UDP)**:
  * Published Local Time: 13:13 – 13:32 AST
  * Attacker IP: `18.218.115.60` $\rightarrow$ Victim `172.31.69.25`
  * Classification: Family `ddos`, MITRE `TA0040` / `T1498`, Stage `impact`.

### 3.5 Wednesday 21-02-2018
* **`cic2018_wed_ddos_01` (DDOS-LOIC-UDP)**:
  * Published Local Time: 10:09 – 10:43 AST
  * Attacker IP: `18.218.115.60` $\rightarrow$ Victim `172.31.69.28` (valid `18.218.83.150`)
  * Classification: Family `ddos`, MITRE `TA0040` / `T1498`, Stage `impact`.
* **`cic2018_wed_ddos_02` (DDOS-HOIC)**:
  * Published Local Time: 14:05 – 15:05 AST
  * Attacker IP: `18.218.115.60` $\rightarrow$ Victim `172.31.69.28:80`
  * Classification: Family `ddos`, MITRE `TA0040` / `T1498`, Stage `impact`.

### 3.6 Thursday 22-02-2018
* **`cic2018_thu_web_01` (Brute Force -Web)**:
  * Published Local Time: 10:17 – 11:24 AST
  * Attacker IP: `18.218.115.60` $\rightarrow$ Victim `172.31.69.28:80`
  * Classification: Family `bruteforce`, MITRE `TA0006` / `T1110`, Stage `initial_access`.
* **`cic2018_thu_web_02` (Brute Force -XSS)**:
  * Published Local Time: 13:50 – 14:29 AST
  * Attacker IP: `18.218.115.60` $\rightarrow$ Victim `172.31.69.28:80`
  * Classification: Family `web_exploit`, MITRE `TA0001` / `T1190`, Stage `initial_access`.
* **`cic2018_thu_web_03` (SQL Injection)**:
  * Published Local Time: 16:15 – 16:29 AST
  * Attacker IP: `18.218.115.60` $\rightarrow$ Victim `172.31.69.28:80`
  * Classification: Family `web_exploit`, MITRE `TA0001` / `T1190`, Stage `initial_access`.

### 3.7 Friday 23-02-2018 (Held-Out Test Day)
* **STRICTLY EXCLUDED** from ground-truth training event generation.

### 3.8 Wednesday 28-02-2018
* **`cic2018_wed_infiltration_01` (Infiltration - Morning)**:
  * Published Local Time: 10:50 – 12:05 AST
  * Attacker IP: `13.58.225.34` $\rightarrow$ Victim `172.31.69.24`
  * Classification: Family `infiltration`, MITRE `TA0008` / `T1021`, Stage `lateral_movement`.
* **`cic2018_wed_infiltration_02` (Infiltration - Afternoon)**:
  * Published Local Time: 13:42 – 14:40 AST
  * Attacker IP: `13.58.225.34` $\rightarrow$ Victim `172.31.69.24`
  * Classification: Family `infiltration`, MITRE `TA0008` / `T1021`, Stage `lateral_movement`.

### 3.9 Thursday 01-03-2018
* **`cic2018_thu_infiltration_01` (Infiltration - Morning)**:
  * Published Local Time: 09:57 – 10:55 AST
  * Attacker IP: `13.58.225.34` $\rightarrow$ Victim `172.31.69.13`
  * Classification: Family `infiltration`, MITRE `TA0008` / `T1021`, Stage `lateral_movement`.
* **`cic2018_thu_infiltration_02` (Infiltration - Afternoon)**:
  * Published Local Time: 14:00 – 15:37 AST
  * Attacker IP: `13.58.225.34` $\rightarrow$ Victim `172.31.69.13`
  * Classification: Family `infiltration`, MITRE `TA0008` / `T1021`, Stage `lateral_movement`.

### 3.10 Friday 02-03-2018 (Friday-02-03-2018)
* **`cic2018_fri_bot_01` (Bot - Ares C2 Morning)**:
  * Published Local Time: 10:11 – 11:34 AST
  * Attacker C2 Server: `18.219.211.138` $\rightarrow$ Victim `172.31.69.23` (representative victim from bot pool)
  * Classification: Family `botnet_c2`, MITRE `TA0011` / `T1071`, Stage `command_and_control`.
* **`cic2018_fri_bot_02` (Bot - Ares C2 Afternoon)**:
  * Published Local Time: 14:24 – 15:55 AST
  * Attacker C2 Server: `18.219.211.138` $\rightarrow$ Victim `172.31.69.23`
  * Classification: Family `botnet_c2`, MITRE `TA0011` / `T1071`, Stage `command_and_control`.

---

## 4. Known Issues and Flow Limitations

1. **Excel Row Cap**: 7 of 10 flow CSVs in the official release were truncated by Microsoft Excel at exactly 1,048,575 rows.
2. **Missing Flow IPs**: 9 of 10 days omit IP addresses in CSV flow exports; standardisation relies on PCAP and official topology schedules.
3. **Victim-Specific Capture Layout**: Captures are segmented per endpoint IP (e.g. `UCAP172.31.69.25`).

---

## 5. Open Questions for Yash's Workstation

1. **PCAP Timezone Validation**: Run `scripts/check_events_in_pcap.py` against PCAPs for days 15-02 through 02-03 to confirm empirical packet arrival times and populate UTC timestamps.
2. **NAT & Interface Verification**: Confirm whether attacker traffic on remaining days appears under external Elastic IPs or internal AWS IPs inside each endpoint PCAP.
