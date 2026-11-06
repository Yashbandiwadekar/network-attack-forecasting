# CIC-IDS-2017 Ground-Truth Events Documentation and Notes

**File**: `ground_truth/cic2017/events.csv`  
**Created**: Week 2 (2026-11-06)  
**Author**: Mohammed Amin Kaifi  
**Source**: Official UNB CIC-IDS-2017 attack schedule (https://www.unb.ca/cic/datasets/ids-2017.html, Table 4) and project documentation (`docs/14-stage-forecasting.md`, `docs/15-retrain-joint-cic1718.md`).

---

## 1. Ground Truth Source & Event Construction

Events were manually constructed following the official UNB schedule and network diagram:
* **Tuesday (04/07/2017)**:
  * Morning: FTP-Patator (`cic2017_tue_bruteforce_01`), scheduled 09:20–10:20 (observed in flow CSVs: ~09:17–10:20). Target: Web Server (192.168.10.50), port 21.
  * Afternoon: SSH-Patator (`cic2017_tue_bruteforce_02`), scheduled 14:00–15:00 (observed in flow CSVs: ~14:09–15:11). Target: Web Server (192.168.10.50), port 22.
* **Wednesday (05/07/2017)**:
  * Morning DoS:
    * DoS slowloris (`cic2017_wed_dos_01`), scheduled 09:47–10:10. Target: 192.168.10.50, port 80.
    * DoS Slowhttptest (`cic2017_wed_dos_01`), scheduled 10:14–10:35. Target: 192.168.10.50, port 80.
    * DoS Hulk (`cic2017_wed_dos_02`), scheduled 10:43–11:00. Target: 192.168.10.50, port 80.
    * DoS GoldenEye (`cic2017_wed_dos_02`), scheduled 11:10–11:23. Target: 192.168.10.50, port 80.
  * Afternoon Web Exploit:
    * Heartbleed (`cic2017_wed_web_01`), scheduled 15:12–15:32. Target: Ubuntu server (192.168.10.51), port 444.
* **Thursday (06/07/2017)**:
  * Morning Web Attacks:
    * Web Attack – Brute Force (`cic2017_thu_web_01`), scheduled 09:20–10:00 (09:15–10:00). Target: 192.168.10.50, port 80.
    * Web Attack – XSS (`cic2017_thu_web_01`), scheduled 10:15–10:35. Target: 192.168.10.50, port 80.
    * Web Attack – Sql Injection (`cic2017_thu_web_01`), scheduled 10:40–10:42. Target: 192.168.10.50, port 80.
  * Afternoon Infiltration:
    * Infiltration (`cic2017_thu_infiltration_01`), scheduled 14:19–15:45. Internal victim machine `192.168.10.8` compromised via malicious file, scanning and attacking internal server `192.168.10.25`.
* **Friday (07/07/2017)**:
  * Morning Botnet (ARES):
    * 5 distinct infected internal machines (`192.168.10.5`, `192.168.10.8`, `192.168.10.9`, `192.168.10.14`, `192.168.10.15`), communicating with C2 server (`205.174.165.73`), scheduled 10:02–11:02 and 11:10–12:59. Stored as 5 distinct victim rows under `cic2017_fri_bot_01`.
  * Afternoon Reconnaissance:
    * PortScan (`cic2017_fri_portscan_01`), scheduled 13:00–15:23 (raw scans at 13:05, 13:52, 14:14, 14:51, 15:03, 15:21). Target: 192.168.10.50, broad port sweep.
  * Afternoon DDoS:
    * DDoS LOIC HTTP (`cic2017_fri_ddos_01`), scheduled 15:56–16:16. Target: 192.168.10.50, port 80.

---

## 2. Time Zone Considerations (Action Required by Yash via PCAP Script)

* **Published Times**: The times in the official UNB table are local Canadian Atlantic time (ADT / AST, UTC-3 or UTC-4).
* **Current Event Timestamps**: The initial timestamps in `events.csv` are recorded verbatim from the published schedule with a `Z` suffix pending PCAP verification.
* **Offset Resolution Procedure**:
  * Yash will run `scripts/check_events_in_pcap.py` against the actual daily PCAPs.
  * `check_events_in_pcap.py` searches within a +/- 6-hour window around the nominal start time and extracts the epoch of the first and last packets matching the attacker and victim IP addresses.
  * When Yash runs the script and provides `check.csv`, the measured time offset will be reviewed, recorded here, and used to adjust the UTC timestamps in `events.csv` if an offset exists in the packet epochs.

---

## 3. NAT IP Address Handling

* **Official Network Diagram IP**: `205.174.165.73` (Attacker outside firewall).
* **Observed Internal NAT IP**: `172.16.0.1`. In internal packet captures behind the gateway, traffic originating from the external attacker is translated to `172.16.0.1`.
* **Rule Applied**: In `events.csv`, the published attacker IP `205.174.165.73` is preserved. `scripts/check_events_in_pcap.py` checks both `205.174.165.73` and `172.16.0.1` (and reverse directions) so that whether the capture was taken outside the firewall or inside the NAT boundary, matching packets will be detected.

---

## 4. Cross-Validation Against Flow CSV Labels

The 8 flow CSVs from the official `TrafficLabelling` release contain the following attack labels:
1. `FTP-Patator` (Tuesday): Covered by `cic2017_tue_bruteforce_01`
2. `SSH-Patator` (Tuesday): Covered by `cic2017_tue_bruteforce_02`
3. `DoS slowloris` (Wednesday): Covered by `cic2017_wed_dos_01`
4. `DoS Slowhttptest` (Wednesday): Covered by `cic2017_wed_dos_01`
5. `DoS Hulk` (Wednesday): Covered by `cic2017_wed_dos_02`
6. `DoS GoldenEye` (Wednesday): Covered by `cic2017_wed_dos_02`
7. `Heartbleed` (Wednesday): Covered by `cic2017_wed_web_01`
8. `Web Attack – Brute Force` (Thursday): Covered by `cic2017_thu_web_01`
9. `Web Attack – XSS` (Thursday): Covered by `cic2017_thu_web_01`
10. `Web Attack – Sql Injection` (Thursday): Covered by `cic2017_thu_web_01`
11. `Infiltration` (Thursday): Covered by `cic2017_thu_infiltration_01`
12. `Bot` (Friday): Covered by `cic2017_fri_bot_01` (5 victim rows)
13. `PortScan` (Friday): Covered by `cic2017_fri_portscan_01`
14. `DDoS` (Friday): Covered by `cic2017_fri_ddos_01`

**Verification Status**:
* Every attack label present in the flow CSVs maps to at least one ground-truth event.
* No unsupported labels have been invented.
* Status is **PENDING PCAP VALIDATION** by Yash using `scripts/check_events_in_pcap.py`.

