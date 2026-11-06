# CIC-IDS-2017 Ground-Truth Events Documentation and Notes

**File**: `ground_truth/cic2017/events.csv`  
**Dataset**: CIC-IDS-2017 (Canadian Institute for Cybersecurity)  
**Official Reference**: https://www.unb.ca/cic/datasets/ids-2017.html  
**Updated**: Week 3/4 Revision per Project Lead Review

---

> [!IMPORTANT]
> **LOCAL TIME NOTICE (CRITICAL)**:  
> All timestamps in `ground_truth/cic2017/events.csv` currently reflect the **published local Canadian times** (with a `Z` suffix), exactly as given in the official UNB attack schedule. Do **NOT** apply an assumed timezone offset. Yash will run `scripts/check_events_in_pcap.py` on the raw daily PCAPs and produce `check.csv` with the measured offset before final UTC conversion.

---

## 1. Schedule Mapping & Structure (50 Events Total)

The event table is structured directly from the published daily schedules:

### Tuesday (July 4, 2017)
* **09:20–10:20**: FTP-Patator (`cic2017_tue_bruteforce_01`), Attacker `205.174.165.73` $\rightarrow$ Web Server `192.168.10.50:21`.
* **14:00–15:00**: SSH-Patator (`cic2017_tue_bruteforce_02`), Attacker `205.174.165.73` $\rightarrow$ Web Server `192.168.10.50:22`.

### Wednesday (July 5, 2017)
* **09:47–10:10**: DoS slowloris (`cic2017_wed_dos_01`), Attacker `205.174.165.73` $\rightarrow$ `192.168.10.50:80`.
* **10:14–10:35**: DoS Slowhttptest (`cic2017_wed_dos_01`), Attacker `205.174.165.73` $\rightarrow$ `192.168.10.50:80`.
* **10:43–11:00**: DoS Hulk (`cic2017_wed_dos_02`), Attacker `205.174.165.73` $\rightarrow$ `192.168.10.50:80`.
* **11:10–11:23**: DoS GoldenEye (`cic2017_wed_dos_02`), Attacker `205.174.165.73` $\rightarrow$ `192.168.10.50:80`.
* **15:12–15:32**: Heartbleed (`cic2017_wed_web_01`), Attacker `205.174.165.73` $\rightarrow$ Ubuntu Server `192.168.10.51:444`.

### Thursday (July 6, 2017)
* **Web Attacks** (`cic2017_thu_web_01`):
  * **09:20–10:00**: Web Attack – Brute Force (`205.174.165.73` $\rightarrow$ `192.168.10.50:80`)
  * **10:15–10:35**: Web Attack – XSS (`205.174.165.73` $\rightarrow$ `192.168.10.50:80`)
  * **10:40–10:42**: Web Attack – Sql Injection (`205.174.165.73` $\rightarrow$ `192.168.10.50:80`)
* **Infiltration** (`cic2017_thu_infiltration_01`, 5 discrete steps):
  * **14:19–14:21**: Attacker `205.174.165.73` $\rightarrow$ Vista host `192.168.10.8` (coolstuff preparation)
  * **14:33–14:35**: Attacker `205.174.165.73` $\rightarrow$ Vista host `192.168.10.8`
  * **14:53–15:00**: Attacker `205.174.165.73` $\rightarrow$ MAC server `192.168.10.25` (variant: `cool_disk`)
  * **15:04–15:45**: Attacker `205.174.165.73` $\rightarrow$ Vista host `192.168.10.8` (variant: `dropbox_download`)
  * **15:04–15:45**: Compromised host `192.168.10.8` sweeps internal network (blank victim IP). Family `portscan`, MITRE `TA0043`/`T1595`, original_label `Infiltration`.

### Friday (July 7, 2017)
* **Botnet ARES** (`cic2017_fri_bot_01`):
  * Official schedule: **10:02–11:02** across 5 infected internal victims (`192.168.10.5`, `.8`, `.9`, `.14`, `.15`).
  * Discrepancy Note: The released flow CSVs labelled flows as Bot up to 12:59, but the official ground-truth schedule explicitly specifies 10:02–11:02. The event table strictly adheres to the published schedule (10:02–11:02).
* **PortScan** (`cic2017_fri_portscan_01`, 27 discrete windows):
  * Firewall ON (12 windows): 13:55–13:57, 13:58–14:00, 14:01–14:04, 14:05–14:07, 14:08–14:10, 14:11–14:13, 14:14–14:16, 14:17–14:19, 14:20–14:21, 14:22–14:24, 14:33–14:33:59, 14:35–14:35:59.
  * Firewall OFF (15 windows with specific nmap probe flags): `nmap_sS` (14:51–14:53), `nmap_sT` (14:54–14:56), `nmap_sF` (14:57–14:59), `nmap_sX` (15:00–15:02), `nmap_sN` (15:03–15:05), `nmap_sP` (15:06–15:07), `nmap_sV` (15:08–15:10), `nmap_sU` (15:11–15:12), `nmap_sO` (15:13–15:15), `nmap_sA` (15:16–15:18), `nmap_sW` (15:19–15:21), `nmap_sR` (15:22–15:24), `nmap_sL` (15:25–15:25:59), `nmap_sI` (15:26–15:27), `nmap_b` (15:28–15:29).
  * 1-minute single-minute windows (14:33, 14:35, 15:25) have `end_ts = start_ts + 59s`.
* **DDoS LOIC HTTP** (`cic2017_fri_ddos_01`):
  * Schedule: **15:56–16:16**
  * Attackers: The three Windows 8.1 machines (`205.174.165.69`, `205.174.165.70`, `205.174.165.71`) targeting Web Server `192.168.10.50:80` (one row per attacker).

---

## 2. Encoding & NAT Handling

* **Windows-1252 Dash (0x96)**: Web attack labels in the official CSV use byte `0x96`, which becomes mojibake if read as raw UTF-8 without decoding. In `events.csv`, all entries use valid UTF-8 en dash `–` (`\u2013`), e.g. `Web Attack – Brute Force`.
* **NAT Address**: Inside internal PCAPs, traffic originating from external attackers `205.174.165.x` appears with firewall NAT address `172.16.0.1`. The events table preserves the published source IPs.

---

## 3. Open Questions for Yash

1. **PCAP Timestamp Offset**: Awaiting `check.csv` from Yash after running `scripts/check_events_in_pcap.py` on the raw Monday–Friday PCAPs.
2. **NAT Gateway Scope**: Check whether external traffic PCAPs exist where `205.174.165.x` is seen directly without NAT.
