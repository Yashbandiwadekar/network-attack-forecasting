# Dataset Datasheet: CTU-13

**Standardized Target Path**: `ground_truth/ctu13/events.parquet`  
**Dataset Identifier**: `ctu13`

---

## 1. Source and Licensing

* **Dataset Name**: CTU-13 Dataset (A Labeled Dataset with Real Botnet, Normal and Background Traffic).
* **Official Source URL**: https://www.stratosphereips.org/datasets-ctu13
* **Dataset Authors / Organisation**: Sebastian Garcia, Martin Grill, Jan Stiborek, and Pavol Celeda (Czech Technical University in Prague, Stratosphere Laboratory).
* **Citation Requested**:
  > Sebastian Garcia, Martin Grill, Jan Stiborek, and Pavol Celeda, "An empirical comparison of botnet detection methods", Computers & Security journal, Elsevier, 2014.
* **Licence**: Creative Commons Attribution 4.0 International (CC BY 4.0).
* **Download Date**: 13 scenario folders with `.binetflow` files and PCAPs present on drive `V:` (validated 2026-10-10).

---

## 2. Coverage

* **Duration**: 13 distinct capture scenarios recorded in 2011.
* **Scenarios Covered**: Scenarios 1 through 13 covering malware families: Neris, Rbot, Virut, Menti, Sogou, Murlo, and NSIS.ay.
* **Hosts**: Infected botnet hosts in university subnet `147.32.84.0/24` (primary bot host `147.32.84.165`); documented normal hosts (`147.32.84.170`, `147.32.84.134`, `147.32.84.164`).
* **Attack Families**: `botnet_c2`, `ddos`, `web_exploit`, `portscan`, `benign`.
* **Available Data**: Full bidirectional NetFlow (`.binetflow`) files (2.5 GB total) and PCAP captures for all 13 scenarios (87 GB).

---

## 3. Event Construction Methodology

* **Automated Scenario Parser**: `scripts/build_events.py --dataset ctu13` processes scenario BINETFLOW files.
* **Grouping**: Flows are grouped into events per `(infected_host, behaviour)`.
* **Stage & Family Mapping**: Reuses existing `ctu13_label_to_stage` from `pipeline/mitre_mapping.py`.
* **Background Exclusion**: Flows marked `Background` produce **NO events** and remain `unknown`.
* **Normal Traffic Restrictions**: Normal flows produce `benign` events **only** for the 3 explicitly verified normal hosts (`147.32.84.170`, `147.32.84.134`, `147.32.84.164`).

---

## 4. Label Counts and Statistics

* **Total Scenarios**: 13 scenarios.
* **Infected Host Count**: 10 distinct infected bot IPs (dominated by `147.32.84.165`).
* **Attack Families**:
  * `botnet_c2`: IRC, DNS, and HTTP C&C beaconing flows across all scenarios (Tactic TA0011, Technique T1071).
  * `ddos`: ICMP and TCP SYN flooding events in scenarios 4, 10, and 11 (Tactic TA0040, Technique T1498).
  * `web_exploit`: Binary download activities in scenario 6 (Tactic TA0001, Technique T1190).
  * `portscan`: Host and service scanning in scenarios 3, 5, 7, 8, 9, 10.
  * `benign`: Verified traffic for documented normal hosts.
* **Flow Counts**: ~20 million flows across the 13 scenarios; over 440,000 verified botnet flows.
* **Background Traffic Rate**: >85% of total dataset flows are unverified background traffic (excluded from events).

---

## 5. Known Issues

1. **Unverified Background Noise**: Majority of dataset traffic consists of campus background traffic that cannot be proven benign; treating it as benign causes severe evaluation contamination (addressed by Defect D-1).
2. **ICMP Port Representation**: BINETFLOW represents ICMP type/code in port fields (e.g. `0x0303`), normalized to port 0.
3. **Single University Subnet**: All infected hosts originate inside `147.32.84.0/24`.

---

## 6. Open Questions

1. **Full Execution on Drive `V:`**: Yash to execute `scripts/build_events.py --dataset ctu13` across all 13 scenarios on the storage workstation.
2. **PCAP Scenario 6 Timing**: Cross-check timestamp alignment between BINETFLOW and PCAP for scenario 6.
