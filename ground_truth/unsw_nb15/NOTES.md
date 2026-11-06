# UNSW-NB15 Ground-Truth Event Generation Notes

**Dataset**: UNSW-NB15  
**Source File**: `NUSW-NB15_GT.csv` (86 MB official ground-truth event schedule)  
**Official Reference**: https://research.unsw.edu.au/projects/unsw-nb15-dataset  
**Builder Script**: `scripts/build_events.py --dataset unsw_nb15`  
**Target Output**: `events.parquet` (Canonical 14-column schema)

---

## 1. Schema Mapping & Rules

The builder maps raw `NUSW-NB15_GT.csv` rows to the project's canonical 14-column event schema:

| Canonical Field | Source Column / Transformation | Notes |
|---|---|---|
| `campaign_id` | `unsw_<YYYYMMDD>_<Source IP>` | Groups attacks by source IP and UTC calendar date |
| `attacker_ip` | `Source IP` | Attacker IPv4 address |
| `victim_ip` | `Destination IP` | Target IPv4 address |
| `dst_port` | `Destination Port` | Blank if not an integer port |
| `start_ts` | `Start time` (Unix epoch) | Converted to UTC ISO 8601 ending in `Z` |
| `end_ts` | `Last time` (Unix epoch) | Converted to UTC ISO 8601 ending in `Z` |
| `attack_family` | `Attack category` via `pipeline.label_standard` | Canonical attack family |
| `attack_variant` | `Attack subcategory` (or `Attack Name`) | Tool or variant |
| `mitre_tactic` | `Attack category` via `pipeline.label_standard` | ATT&CK Tactic ID (e.g. TA0043) |
| `mitre_technique` | `Attack category` via `pipeline.label_standard` | ATT&CK Technique ID (e.g. T1595) |
| `label_source` | Literal `dataset_flow_label` | Verified dataset flow label |
| `label_confidence` | Literal `exact` | Per-event verified ground truth |
| `original_label` | `Attack category` verbatim | Kept unchanged for auditability |
| `citation` | `NUSW-NB15_GT.csv: <Attack Reference>` | Preserves official references |

---

## 2. Duplicate Handling

* Exact duplicate rows across the raw ground-truth table are identified and dropped using pandas `drop_duplicates()`.
* Non-identical records that share timestamps or IP endpoints are strictly preserved.

---

## 3. Attack Categories & Status in pipeline.label_standard

### Standard Mapped Categories:
* `Reconnaissance` → `portscan` (TA0043 Reconnaissance / T1595 Active Scanning)
* `Exploits` → `web_exploit` (TA0001 Initial Access / T1190 Exploit Public-Facing Application)
* `DoS` → `dos` (TA0040 Impact / T1499 Endpoint Denial of Service)

### Unmapped Categories (Requires Yash's Review):
The following 6 categories exist in `NUSW-NB15_GT.csv` but have no pre-approved entry in `pipeline.label_standard`:
1. `Fuzzers` (Protocol fuzzing, mixed port/payload sweeps)
2. `Generic` (Block-cipher complexity attacks)
3. `Shellcode` (Payload code execution)
4. `Worms` (Self-propagating lateral spread)
5. `Backdoors` (C2 / persistence mechanisms)
6. `Analysis` (Port scans, spam, HTML file penetration)

**Enforcement in `scripts/build_events.py`**:
* By default, encountering any unmapped category halts generation with a clear diagnostic message and exit code.
* No mappings have been guessed or fabricated independently (Rule 6).
* Once Yash approves the official MITRE tactic/technique and family mappings for these 6 categories, they will be registered in `pipeline/label_standard.py`.

