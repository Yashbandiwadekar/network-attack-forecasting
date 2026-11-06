# CTU-13 Dataset Ground-Truth Events Documentation and Notes

**Dataset**: CTU-13 Botnet Dataset  
**Authors**: Sebastian Garcia, Martin Grill, Jan Stiborek, and Pavol Celeda (Czech Technical University / Stratosphere Laboratory)  
**Official Source URL**: https://www.stratosphereips.org/datasets-ctu13  
**Target Format**: Canonical 14-column events table (`events.parquet` / `events.csv`)  
**Builder Script**: `scripts/build_events.py --dataset ctu13`

---

## 1. Scenario Registry & Metadata (13 Scenarios)

| Scenario | Bot Name | Infected Host IPs | Normal Verified Hosts | Primary Attack Behaviours | Input BINETFLOW |
|---|---|---|---|---|---|
| **1** | Neris | `147.32.84.165` | `147.32.84.170`, `147.32.84.134`, `147.32.84.164` | IRC bot, SPAM, HTTP C&C | `capture20110810.binetflow` |
| **2** | Neris | `147.32.84.165` | `147.32.84.170`, `147.32.84.164` | IRC bot, SPAM, HTTP C&C | `capture20110811.binetflow` |
| **3** | Rbot | `147.32.84.165` | `147.32.84.170`, `147.32.84.134`, `147.32.84.164` | IRC botnet, portscan, USer-to-User | `capture20110812.binetflow` |
| **4** | Rbot | `147.32.84.165` | `147.32.84.170`, `147.32.84.134`, `147.32.84.164` | IRC botnet, ICMP DDoS, TCP SYN flood | `capture20110815.binetflow` |
| **5** | Virut | `147.32.84.165` | `147.32.84.170`, `147.32.84.134`, `147.32.84.164` | HTTP C&C, SPAM, scanning | `capture20110815-2.binetflow` |
| **6** | Menti | `147.32.84.165` | `147.32.84.170`, `147.32.84.134`, `147.32.84.164` | HTTP C&C, custom encryption, binary download | `capture20110816.binetflow` |
| **7** | Sogou | `147.32.84.165` | `147.32.84.170`, `147.32.84.134`, `147.32.84.164` | HTTP C&C, portscan | `capture20110816-2.binetflow` |
| **8** | Murlo | `147.32.84.165` | `147.32.84.170`, `147.32.84.134`, `147.32.84.164` | Custom encryption C&C, scanning | `capture20110816-3.binetflow` |
| **9** | Neris | `147.32.84.165`, `147.32.84.191`, `147.32.84.192`, `147.32.84.193`, `147.32.84.204`, `147.32.84.205`, `147.32.84.206`, `147.32.84.207`, `147.32.84.208`, `147.32.84.209` | `147.32.84.170`, `147.32.84.134`, `147.32.84.164` | 10 infected hosts, IRC botnet, spam, scan | `capture20110817.binetflow` |
| **10** | Rbot | `147.32.84.165`, `147.32.84.191`, `147.32.84.192`, `147.32.84.193`, `147.32.84.204`, `147.32.84.205`, `147.32.84.206`, `147.32.84.207`, `147.32.84.208`, `147.32.84.209` | `147.32.84.170`, `147.32.84.134`, `147.32.84.164` | 10 infected hosts, ICMP DDoS, portscan | `capture20110818.binetflow` |
| **11** | Rbot | `147.32.84.165`, `147.32.84.191`, `147.32.84.192` | `147.32.84.170`, `147.32.84.134`, `147.32.84.164` | 3 infected hosts, ICMP DDoS | `capture20110818-2.binetflow` |
| **12** | NSIS.ay | `147.32.84.165` | `147.32.84.170`, `147.32.84.134`, `147.32.84.164` | P2P and HTTP C&C | `capture20110819.binetflow` |
| **13** | Virut | `147.32.84.165` | `147.32.84.170`, `147.32.84.134`, `147.32.84.164` | HTTP C&C, SPAM, scanning | `capture20110815-3.binetflow` |

---

## 2. Event Generation Logic

Events are generated per `(infected_host, behaviour)` tuple:
* **Start Time (`start_ts`)**: First flow timestamp matching that behaviour, converted to UTC ISO 8601 ending in `Z`.
* **End Time (`end_ts`)**: Last flow timestamp (+ duration) matching that behaviour, in UTC ISO 8601 ending in `Z`.
* **Campaign ID**: `ctu13_scen<N>_<infected_host>_<sanitized_behaviour>`.
* **Attacker IP**: The infected bot host IP.
* **Victim IP**: The primary external C2 peer or target of the attack behaviour.
* **Attack Family & MITRE Mapping**: Looked up via `pipeline/mitre_mapping.py::ctu13_label_to_stage`:
  * `COMMAND_AND_CONTROL` $\rightarrow$ Family `botnet_c2`, Tactic `TA0011`, Technique `T1071`.
  * `INITIAL_ACCESS` (binary downloads) $\rightarrow$ Family `web_exploit`, Tactic `TA0001`, Technique `T1190`.
  * `IMPACT` (ICMP/TCP floods in scenarios 4, 10, 11) $\rightarrow$ Family `ddos`, Tactic `TA0040`, Technique `T1498`.

---

## 3. Background Traffic Handling (Critical Rule)

* **Background Traffic**: Any flow labeled `flow=Background`, `flow=To-Background`, or `flow=From-Background` is **strictly excluded from event generation**.
* **Downstream Behaviour**: When the existing labelling pipeline processes CTU-13 data, unlabelled background traffic remains `unknown`. It is **never** converted into benign events.
* **Normal Traffic**: Flows labelled `Normal` produce `benign` events **only** when they involve the explicitly documented normal hosts (`147.32.84.170`, `147.32.84.134`, `147.32.84.164`). Normal flows from other unverified hosts are excluded to prevent label corruption.

---

## 4. Known Data Limitations & Defect D-1 Context

* **Defect D-1 (Audit 2026-10-10)**: Earlier pipeline versions previously allowed CTU-13 unknown labels to silently fall through to IMPACT or benign. `pipeline/mitre_mapping.py` now maps known normal variants explicitly to `BENIGN` and logs warnings on unmapped labels.
* **ICMP Port Handling**: CTU-13 ICMP flows contain hexadecimal type/code representations in Sport/Dport (e.g. `0x0303`) rather than numeric ports, handled as port `0` in adapter code.
* **Single Subnet**: All infected hosts reside in the Czech Technical University subnet `147.32.84.0/24`.

---

## 5. Open Questions & Coordination for Yash

1. **Full BINETFLOW Run**: Yash will execute `scripts/build_events.py --dataset ctu13` across all 13 scenarios located at `V:\Datasets\CTU-13\`.
2. **PCAP Scenario 6 Cross-Check**: Yash will run `scripts/check_events_in_pcap.py` against `V:\Datasets\CTU-13-pcaps\6\botnet-capture-20110816-menti.pcap` to confirm exact packet alignment for Menti C2 flows.

