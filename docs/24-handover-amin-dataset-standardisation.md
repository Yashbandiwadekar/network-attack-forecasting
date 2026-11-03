# 24 - Handover for Amin: dataset standardisation (weeks 1–4)

Written 2026-11-04 for Mohammed Amin Kaifi. Read `docs/23-dataset-standardisation-plan.md` first;
this file turns the "Amin" column of its section 8 into concrete tasks.

## What we are building, in one paragraph

Every public dataset we use (CIC-IDS-2017, CSE-CIC-IDS2018, UNSW-NB15, CTU-13) and our own lab
recordings get rebuilt into one format, where every packet and every flow carries the same labels:
attack family (`ddos`, `dos`, `bruteforce`, `portscan`, `botnet_c2`, ...), MITRE ATT&CK tactic and
technique, and our kill-chain stage. The labels all come from one **events** table per dataset:
"attacker X hit victim Y on port P from time A to time B with attack Z, source: <citation>".
**You build the events tables and get the raw data in order. Yash builds the code that applies
the events to packets and flows.** Your events tables decide what the model learns, so accuracy matters
more than speed in this work.

## Ground rules

1. Work on the `Dev/Amin` branch. When a task is done, open a pull request into `Production`;
   Yash reviews it before it merges.
2. **Never commit data**: no PCAPs, no dataset CSVs, no Parquet. Commit only scripts, tests,
   `ground_truth/<dataset>/events.csv` files you write by hand, and docs.
3. **Never guess a label or a time.** Every events row needs a citation (URL plus the section or
   table it came from). If a source is unclear, or two sources disagree, write it down under
   "Open questions" in that dataset's `ground_truth/<dataset>/NOTES.md` and ask Yash.
4. **Do not add family → MITRE mappings yourself.** They live in `pipeline/label_standard.py`, which
   Yash writes in week 1 (table in docs/23 section 2). If a label has no mapping, list it for Yash.
5. Datasets live on the dataset drive `V:\Datasets\` on Yash's PC. If you work on your own machine,
   use the same folder names, and check the sha256 of every file you copy across.

## Where things stand (checked 2026-11-04)

| Dataset | On V: now | Missing |
|---|---|---|
| CIC-IDS-2017 | 8 flow CSVs in `V:\Datasets\CIC-IDS-2017\` | The 5 day PCAPs (Monday–Friday, ~51 GB). Yash started this download; check with him before starting it again |
| UNSW-NB15 | CSVs, `CSV Files\NUSW-NB15_GT.csv` (official ground truth), 63 PCAPs (67 GB) in `pcap files\` | `pcaps 17-2-2015\18.pcap` to `26.pcap` (9 files). `pcaps 22-1-2015` is complete (1–53) |
| CSE-CIC-IDS2018 | Flow CSVs in `CIC-IDS-2018-flows\`; full PCAPs for `Wednesday-14-02-2018` (449 files, 45 GB) and `Friday-23-02-2018` (446 files, 64 GB) | Nothing for v1. We use Wed 14-02. Fri 23-02 is a test day: never use it for training |
| CTU-13 | binetflow per scenario in `CTU-13\1..13\`; PCAPs for all 13 scenarios in `CTU-13-pcaps\` (87 GB, with `MANIFEST.md` holding sha256s) | Nothing |

V: had 540 GB free on 2026-11-04. Check free space before each download.

## Week 1: finish the raw data, write the inventory tool

### 1.1 Finish the downloads

- **CIC-IDS-2017 PCAPs.** Official page: https://www.unb.ca/cic/datasets/ids-2017.html (the
  download form is at the bottom). Save to `V:\Datasets\CIC-IDS-2017\pcap\`. Ask Yash first:
  he may already have them.
- **UNSW-NB15 PCAPs 18–26 for 17-2-2015.** Official page:
  https://research.unsw.edu.au/projects/unsw-nb15-dataset . Save next to the others in
  `V:\Datasets\UNSW NB15\pcap files\pcaps 17-2-2015\`.
- For every download, record the source URL, the date, and the size the server reported in a
  `SOURCES.md` file in the dataset folder. Re-download any file whose size doesn't match.

### 1.2 Write `scripts/inventory_raw.py`

This is stage 2 of the pipeline. It walks one dataset folder and writes `inventory.csv` in that folder.

```
python -m scripts.inventory_raw "V:\Datasets\UNSW NB15"            # writes V:\Datasets\UNSW NB15\inventory.csv
python -m scripts.inventory_raw "V:\Datasets\CTU-13-pcaps" --no-hash
```

One row per file, with these columns:

| Column | How |
|---|---|
| `rel_path` | path relative to the dataset folder |
| `size_bytes` | file size |
| `sha256` | streamed in 8 MB chunks (skip with `--no-hash`) |
| `kind` | from the **first bytes**, not the extension (CIC-2018 PCAPs have no extension): `a1b2c3d4` / `d4c3b2a1` / `a1b23c4d` / `4d3cb2a1` → `pcap`, `0a0d0d0a` → `pcapng`, `PK\x03\x04` → `zip`; otherwise `csv`, `binetflow`, `pdf`, `other` by extension |
| `packets`, `first_ts_utc`, `last_ts_utc` | captures only, from Wireshark's `capinfos` (installed at `C:\Program Files\Wireshark\capinfos.exe`), e.g. `capinfos -T -S -c -a -e <file>`; check `capinfos -h` for the exact flags |
| `rows` | CSV / binetflow only: number of data lines (excluding the header) |
| `flags` | `;`-separated: `excel_row_cap` when `rows == 1048575` (the CIC-2018 truncation; see docs/16), `empty`, `capinfos_failed`, `truncated_capture` if capinfos reports a cut-short file |

Requirements:
- **Resumable.** Hashing ~330 GB takes about an hour. If `inventory.csv` already has a row with the
  same `rel_path`, `size_bytes` and modified time, keep that row and don't hash the file again.
- Prints a short summary at the end: file count per kind, total GB, and every flagged file.
- Tests in `tests/test_inventory_raw.py`, written in the same style as `tests/test_adapter_*.py`:
  kind detection on tiny files written to `tmp_path` (a 2-packet pcap via scapy `wrpcap`, as in
  `scripts/record_lab_campaigns.py`), CSV row count, the `excel_row_cap` flag (make the threshold a
  module constant so the test can lower it), and the resume behaviour. Skip the capinfos test when
  capinfos is not installed.

**Done when:** an `inventory.csv` exists for CIC-IDS-2017, UNSW NB15, CIC-IDS-2018,
CIC-IDS-2018-flows and CTU-13-pcaps; the CTU-13 sha256s match `CTU-13-pcaps\MANIFEST.md`; in
CIC-IDS-2018-flows, 7 of the 10 official day CSVs show `excel_row_cap` (the 11th file,
`Synthetic-BenignHighVolume...`, is ours, not CIC's); tests pass (`python -m pytest tests/test_inventory_raw.py`).

## Week 2: events for CIC-IDS-2017 and UNSW-NB15

### Events file format (both datasets)

Columns, in this order (docs/23 section 3):

```
campaign_id,attacker_ip,victim_ip,dst_port,start_ts,end_ts,attack_family,attack_variant,
mitre_tactic,mitre_technique,label_source,label_confidence,original_label,citation
```

- `start_ts`, `end_ts`: **UTC**, ISO 8601 with a `Z`, e.g. `2017-07-05T13:43:00Z`.
- `attacker_ip`, `victim_ip`: one IP each. If an attack hits several victims, write one row per
  victim. Leave `victim_ip` blank only for sweeps that hit a whole subnet (port scans).
- `dst_port`: blank when the attack uses many ports.
- `campaign_id`: `<dataset>_<day>_<family>_<nn>`, e.g. `cic2017_wed_dos_01`. Rows that belong to
  the same attack run share the same id.
- `attack_family`, `mitre_*`: from `pipeline/label_standard.py`. Leave blank if it has no mapping
  yet, and list the label for Yash.
- `original_label`: the dataset's own label name, spelled exactly as in its CSVs (e.g. `DoS Hulk`),
  so we can cross-check automatically later.

### 2.1 CIC-IDS-2017: `ground_truth/cic2017/events.csv` (by hand)

- Source: the attack schedule on the official page (attacks per day, with times, attacker and
  victim machines, and the network diagram). `label_source = ground_truth_schedule`,
  `label_confidence = window`.
- **Time zone trap.** The published times are local Canadian time, not UTC. Do not convert with
  an assumed offset. Find the real offset in the PCAP: for one attack per day, look at the first and
  last packets between attacker and victim, e.g.
  `tshark -r Wednesday-workingHours.pcap -Y "ip.src==<attacker> && ip.dst==<victim>" -T fields -e frame.time_epoch`
  and compare with the schedule. Write the offset you measured, and how you measured it, in
  `ground_truth/cic2017/NOTES.md`.
- **NAT trap.** The attackers sit outside a firewall, so inside the capture their traffic can carry
  a different address from the one on the diagram (docs/23 mentions 172.16.0.1). Use the address
  you actually see in the PCAP, and note both addresses.
- For **every** row, confirm that matching traffic exists in the PCAP inside the window. Record
  "found / not found" per row in NOTES.md.
- Cross-check: the counts per `original_label` in the 8 flow CSVs should line up with your rows
  (every label in the CSVs has at least one event; no event without traffic).

### 2.2 UNSW-NB15: `scripts/build_events.py --dataset unsw_nb15` (generated)

The official ground truth `NUSW-NB15_GT.csv` already has one row per attack (Unix epoch start/last
time, category, subcategory, protocol, source/destination IP and port, attack name). It is 86 MB,
too big for git, so commit the **script**, not its output.

```
python -m scripts.build_events --dataset unsw_nb15 --gt "V:\Datasets\UNSW NB15\CSV Files\NUSW-NB15_GT.csv" --out "V:\Datasets\NAF-standard\v1\unsw_nb15\events.parquet"
```

- One event per GT row. Drop exact duplicate rows and print how many you dropped.
- `original_label` = `Attack category` (`Attack subcategory` → `attack_variant`), `label_source =
  dataset_flow_label`, `label_confidence = exact`, `citation` = the GT file name plus the row's
  `Attack Reference` when it has one.
- `campaign_id` = `unsw_<YYYYMMDD>_<source IP>`, so all rows from one attacker on one day group together
  (used later to keep train and test apart).
- Family/MITRE come from `pipeline/label_standard.py`. If a category has no mapping (UNSW has
  Fuzzers, Generic, Shellcode, Worms, Backdoors, Analysis), **the script stops and lists the
  unmapped categories**. Send that list to Yash; don't write the mappings yourself.
- Tests: a 5-row GT fixture → expected events; duplicate dropping; the unmapped-category error.

**Done when:** both events files exist; NOTES.md for CIC-2017 has the measured time offset and a
found/not-found result for every row; the UNSW script's summary (events per category, per day,
duplicates dropped) is pasted into `ground_truth/unsw_nb15/NOTES.md`.

## Week 3: events for CTU-13 and CIC-2018 Wednesday 14-02

### 3.1 CTU-13: `scripts/build_events.py --dataset ctu13`

- Inputs: the binetflow file per scenario (`V:\Datasets\CTU-13\<n>\*.binetflow`) and each scenario's
  page on https://www.stratosphereips.org/datasets-ctu13 (bot name, infected host IPs).
- One event per (infected host, behaviour), with start/end = first/last flow carrying that
  behaviour's label. Map binetflow label strings with the existing
  `pipeline/mitre_mapping.py::ctu13_label_to_stage`; don't write a new mapping.
- `Background` flows produce **no event**; the labelling stage turns them into `unknown`
  (docs/23 section 6). `Normal` flows become benign events for the normal hosts the page lists.
- Record per scenario in `ground_truth/ctu13/NOTES.md`: bot name, infected IPs, citation, event count.

### 3.2 CIC-2018 Wednesday 14-02: `ground_truth/cic2018/events.csv` (by hand)

- Attacks that day: FTP brute force and SSH brute force. Times and attacker IPs from
  https://www.unb.ca/cic/datasets/ids-2018.html .
- The same two traps as CIC-2017 apply: verify the time offset and the attacker address against the
  PCAPs. The PCAPs here are **one folder of files per victim machine** (file names end in the victim's
  internal IP, e.g. `capDESKTOP-AN3U28N-172.31.64.111`), so first find which files contain the attack.
- Do **not** touch `Friday-23-02-2018` for this: it is a held-out test day.

## Week 4: lab recordings and datasheets

### 4.1 Lab recordings

`scripts/record_lab_campaigns.py` already writes a labels sidecar (`labels.csv`:
`src_ip,dst_ip,start,end,label,dst_port`; see `pipeline/adapters/sidecar.py`). Add
`--dataset lab` to `build_events.py` to convert a sidecar into the events format
(`label_source = lab_driver_log`, `label_confidence = exact`). **The current recordings are
synthetic** (generated packets, nothing sent on a network), so the datasheet must say so.

### 4.2 `DATASHEET.md` for each dataset

Write it in `ground_truth/<dataset>/DATASHEET.md` (it gets copied into `NAF-standard\v1\<dataset>\`
at publish time). Sections:

1. Source, licence, the citation the authors ask for, download date
2. What is covered: days, hosts, attack families, packets/flows available
3. How the events were built (hand schedule or generated), time offset, NAT notes
4. Label counts: events per family, unknown rate (Yash's validator fills in packet/flow counts)
5. Known issues: e.g. CIC-2017/2018 published labelling errors, CIC-2018 CSV truncation, CTU-13
   Background, UNSW's missing files if any are still missing
6. Open questions

## What to send back

- One PR per week into `Production` (scripts + tests + `ground_truth/` files + NOTES). Put the
  summary numbers in the PR description.
- Anything blocked or unclear: message Yash with the dataset, the row or file, and what the two
  sources say. A blank cell with a note is better than a guessed value.
