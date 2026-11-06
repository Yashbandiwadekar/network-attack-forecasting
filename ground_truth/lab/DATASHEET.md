# Dataset Datasheet: Synthetic Lab Campaigns

**Standardized Target Path**: `ground_truth/lab/events.parquet`  
**Dataset Identifier**: `lab`

---

## 1. Source and Licensing

* **Dataset Name**: Synthetic Lab Campaign Recordings.
* **Official Source**: Generated locally using `scripts/record_lab_campaigns.py` (Network Forecast SIH 2026 isolated research).
* **Dataset Authors / Organisation**: Network Forecast Research Team.
* **Licence**: Internal project research artifact.
* **Generation Date**: Generated on demand using fixed random seeds.

---

> [!IMPORTANT]
> **SYNTHETIC PROVENANCE NOTICE**:  
> The lab recordings are synthetic. Packets are generated locally using Scapy (`wrpcap`) and no traffic is transmitted over a real network.

---

## 2. Coverage

* **Duration**: Variable, determined by scripted campaign execution duration (typically 1 to 4 hours per campaign).
* **Hosts**: Configurable synthetic attacker, victim, decoy, and C2 IPs (e.g. `10.0.0.66`, `10.0.0.5`).
* **Attack Families**: `portscan`, `bruteforce`, `web_exploit`, `botnet_c2`, `infiltration`, `dos`, `ddos`.
* **Available Data**: Full synthetic PCAPs and matching sidecar CSV ground-truth files (`labels.csv`).

---

## 3. Event Construction Methodology

* **Sidecar Conversion**: `scripts/build_events.py --dataset lab` parses `labels.csv` into canonical 14-column format.
* **Provenance Labels**: `label_source = "lab_driver_log"`, `label_confidence = "exact"`.
* **Timestamp Handling**: Converted to UTC ISO 8601 ending in `Z`.
* **Campaign Grouping**: Grouped deterministically by `lab_<YYYYMMDD>_<src_ip>_<label>_<index>`.

---

## 4. Label Counts and Statistics

* **Canonical Event Count**: Generated on demand per recorded session (e.g., 20 to 50 realised attack episodes per run).
* **Attack Families**: Exercises all 5 kill-chain stages (Reconnaissance, Initial Access, Lateral Movement, C2, Exfiltration) and Impact.
* **Unknown Label Rate**: 0% (every injected action has an exact ground-truth label).

---

## 5. Known Issues

1. **Synthetic Dynamics**: Local packet generation does not capture WAN latency, TCP retransmission jitter, or hardware dropped packet behaviour.
2. **Evaluation Role**: Intended strictly for controlled horizon testing ($K=6$ rollout evaluation) and pipeline integration tests.

---

## 6. Open Questions

1. **Replay Validation**: Ensure the live replay server accurately reads synthetic PCAP timestamps alongside sidecar events.
