# Synthetic Lab Campaign Recordings Documentation and Notes

**Dataset**: Synthetic Lab Attack Campaigns (SIH 2026 Research)  
**Recording Driver**: `scripts/record_lab_campaigns.py`  
**Sidecar Parser**: `scripts/build_events.py --dataset lab`  
**Target Format**: Canonical 14-column events table (`events.parquet` / `events.csv`)

---

> [!IMPORTANT]
> **SYNTHETIC PROVENANCE NOTICE**:  
> The lab recordings are synthetic. Packets are generated locally using Scapy (`wrpcap`) and no traffic is transmitted over a real network. These recordings provide a controlled stimulus with known ground truth for forecasting model validation.

---

## 1. Provenance & Generation Process

* **Driver Script**: `scripts/record_lab_campaigns.py` synthesises realistic multi-stage kill-chain campaigns over benign background traffic.
* **Outputs Generated**:
  * `<out>/pcap/campaign_XXXX.pcap`: Raw synthetic packet captures.
  * `<out>/labels.csv`: Matching sidecar ground truth (`src_ip`, `dst_ip`, `start`, `end`, `label`, `dst_port`).
  * `<out>/campaign_log.jsonl`: Second-resolution execution log.
  * `<out>/manifest.json`: Realised campaign stages, host IPs, and holdout splits.

---

## 2. Sidecar Format & Mapping Methodology

The sidecar `labels.csv` conforms to `pipeline/adapters/sidecar.py`:
* `src_ip` $\rightarrow$ `attacker_ip`
* `dst_ip` $\rightarrow$ `victim_ip`
* `dst_port` $\rightarrow$ `dst_port` (numeric string or empty)
* `start` $\rightarrow$ `start_ts` (converted to UTC ISO 8601 with `Z`)
* `end` $\rightarrow$ `end_ts` (converted to UTC ISO 8601 with `Z`)
* `label` $\rightarrow$ `original_label`
* `label_source`: `lab_driver_log`
* `label_confidence`: `exact`
* `citation`: `scripts/record_lab_campaigns.py: synthetic lab recording (controlled local research)`
* `campaign_id`: `lab_<YYYYMMDD>_<src_ip>_<label>_<index>`

Attack families and MITRE tactics/techniques are looked up using `pipeline.label_standard.lookup_standard_mapping()` and `pipeline.mitre_mapping.label_to_stage()`:
* `PortScan` $\rightarrow$ `portscan` (TA0043, T1595)
* `SSH-Bruteforce` / `FTP-BruteForce` $\rightarrow$ `bruteforce` (TA0006, T1110)
* `Bot` $\rightarrow$ `botnet_c2` (TA0011, T1071)
* `DoS` / `DDoS` $\rightarrow$ `dos` / `ddos` (TA0040, T1499 / T1498)

---

## 3. Known Limitations

* **Synthetic Dynamics**: Packet timings and payload volumes are algorithmically generated; they do not exhibit real-world network jitter or complex routing artefacts.
* **Scope**: Strictly intended for measuring forecasting horizon early-warning rates ($K=6$ windows) on reproducible multi-stage attack transitions without needing live infrastructure attacks.
