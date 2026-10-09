# Dataset adapter guide

One toolkit to point at a dataset folder and get data that plugs into the training pipeline with a stated,
checked contract: correct 41-feature schema, correct units, correct label -> MITRE stage mapping, and an
explicit report of what is missing, zero-filled or approximated. Nothing here changes an existing adapter,
config, checkpoint or processed dataset; the toolkit wraps `pipeline/flow_features.py`,
`pipeline/adapters/ctu13*.py` and `pipeline/adapters/unsw_nb15.py` and reuses `pipeline/mitre_mapping.py`
as-is.

```text
python -m scripts.validate_dataset <path> [--adapter NAME]          # read-only; PASS / WARN / FAIL (exit 0/1/2)
python -m scripts.prepare_dataset  <path> --out data/processed_adapter/<name> --config configs/default.yaml
python -c "from pipeline.adapters.registry import detect_dataset; print(detect_dataset('<path>'))"
```

Both CLIs are CPU-only (`CUDA_VISIBLE_DEVICES=-1` is set before torch is imported) and stream large files.

## 1. The canonical flow frame (adapter output)

This is exactly what `build_flow_windows`, `graph_features`, `graph_builder` and
`graph_embedding_features` consume (`pipeline/adapters/base.py::CANONICAL_COLUMNS`). An adapter returns one row per
flow, sorted by `adapter.sort_keys`:

| column | dtype | unit / meaning |
|---|---|---|
| `timestamp` | datetime64 | flow **start**, tz-naive |
| `src_ip`, `dst_ip` | str | host keys. If the dataset has no IPs: `src_ip = "NETWORK-<date>"` (pseudo-host per day), `dst_ip = "UNKNOWN"` |
| `src_port`, `dst_port` | float | `src_port` 0 when unavailable; `dst_port` NaN allowed (ignored by `nunique`) |
| `protocol` | float | IANA number: 6 tcp, 17 udp, 1 icmp |
| `duration_s` | float | **seconds**. CIC `Flow Duration` is microseconds and is divided by 1e6 |
| `fwd_pkts`, `bwd_pkts`, `total_pkts` | float | packet **counts** |
| `fwd_bytes`, `bwd_bytes`, `total_bytes` | float | byte **counts** (CIC: payload only; CTU/UNSW: incl. headers) |
| `syn_cnt` ... `urg_cnt` (6) | float | per-flow **counts** of packets with the flag. Not ratios, not a TCP-flags bitmask |
| `iat_mean`, `iat_std`, `iat_max` | float | **microseconds**. (CIC native; UNSW ms x1000; CTU zero-filled) |
| `is_tcp`, `is_udp` | float | 0/1 |
| `bidir_ratio` | float | [0,1]; packet-based for CIC, byte-based proxy for CTU/UNSW |
| `has_ip_data` | float | 1.0 = real IPs, 0.0 = pseudo-host fallback |
| `label` | str | raw label string that `pipeline.mitre_mapping.label_to_stage` already understands (`unsw=<cat>`, `flow=...`, CIC names) |
| `scenario_id` | optional | **only** where the existing builders set it (CTU-13). Adding it elsewhere changes grouping and the `window_graphs.pkl` keys |
| `source_file` | optional | provenance |

`check_canonical_frame(df)` returns the violations (missing columns, non-datetime timestamp, null IPs/labels,
fractional flag counts).

**Window-level contract (the 41 features).** Produced by the existing code from the frame above; the count and order
come from `common.config.feature_columns(config)` = 19 flow + 5 graph + 8 graph-embedding + 9 packet. Every adapter
declares, per canonical field, `native | derived | approximated | zero_filled`
(`adapter.field_coverage`); `adapter.expected_feature_status(ip_fraction)` turns that into a status for each of the
41 features, which the validator compares with what it observes.

Universal limits (not adapter bugs): the 9 packet-level features are zero-filled for every flow-only dataset, and
`graph_embed_*` come from a frozen random-init GraphSAGE.

## 2. Adapters

| name | status | data | units (`prepare`) | default split | notes |
|---|---|---|---|---|---|
| `cicids2018` | stable | CICFlowMeter day CSVs (`data/raw/flows_real`) | one per file/day | `by_day` | 9/10 days have no IPs -> pseudo-host; IAT/duration in us (duration converted); `Label` header rows removed |
| `synthetic` | stable | reduced 21-column CIC-style CSVs (`data/raw/flows`, `flows_real/Synthetic-BenignHighVolume*`) | all | chronological | fabricated; `SYNTH-Exfiltration` is the only exfiltration source |
| `ctu13` | stable | `*.binetflow` (13 scenarios) | one per scenario | `by_unit` (scenarios 1-9 / 10-11 / 12-13, as `build_ctu13_dataset`) | flags + IAT zero-filled, `bidir_ratio` byte proxy, `scenario_id` set |
| `unsw_nb15` | stable | raw `UNSW-NB15_1..4.csv` (no header) | all | chronological | flags approximated (0/1), IAT ms->us, `iat_std/max`, PSH, URG zero |
| `cicids2017` | **experimental** | TrafficLabelling CSVs (`V:\Datasets\CIC-IDS-2017`) | one per file | `by_day` | real IPs; minute-resolution d/m/Y timestamps; labels unmapped (see 6.1) |
| `netflow_v2` | stub | NF-*-v2 | - | - | detection + column map only |
| `ciciot2023` | unsupported | merged CICIoT2023 CSVs | - | - | no IP, no timestamp |
| `unsw_nb15_split_sets` | unsupported | `Training and Testing Sets/*.csv` | - | - | no srcip/dstip/Stime |
| `cicids2017_mlcve` | unsupported | MachineLearningCVE CSVs | - | - | no IP, no Timestamp |

Detection (`detect_dataset(path)`) reads only the first 64 KB of each file (header or first row), asks every adapter
for `detect_file(info) -> (confidence, evidence)`, and for a folder returns the adapter that claims most files
(ties prefer a real-data adapter over `synthetic`). `Detection.mixed` and `.per_file` always expose the other
formats; `adapter.discover_files()` lists what it will read and why other files are skipped.

## 3. Validator

`python -m scripts.validate_dataset <path> [--adapter N] [--sample-rows 300000] [--label-scan full|skip] [--no-embeddings]
[--report-dir data/adapter_reports] [--name STEM]`. Writes `<stem>.json` and `<stem>.md`; exit code 0 PASS, 1 WARN,
2 FAIL, 3 bad path. Every number is tagged **full pass** (every row, label + 1-in-20 timestamp columns only,
streamed in chunks) or **sampled N rows** (a contiguous prefix of each file run through the adapter and then the real
windowing / graph / embedding code; random rows would make windows meaningless).

Reported: row count; label distribution with stage and status (`mapped`, `impact_by_design`, `unknown_fallthrough`,
`ignorable`); stage totals; time range and days; raw-order sortedness; rows dropped by the adapter's cleaning, broken
down by label; NaN/inf rate; duration / bytes-per-packet / IAT unit plausibility; flag counts vs packets; host and IP
availability; per-feature min/max/mean/zero-fraction for all 41 features with the adapter's declared status.

Verdict policy (thresholds are `T_*` constants in `pipeline/adapters/validation.py`, each branch has a test):

| level | triggers |
|---|---|
| FAIL | no adapter / stub / unsupported / adapter exception; missing canonical columns; NaN/inf in canonical or window features; unknown-fall-through labels >= 1% of rows; adapter drops >= 50% of sampled rows; IAT inconsistent with duration x packets by ~1e3 / 1e-3 / 1e-6 (looks like ns, ms, s); `duration_s` p99 above the adapter's plausible maximum; median bytes/packet > 65535, or < 20 for header-inclusive datasets; negative durations/counts >= 5%; flag columns containing 0<x<1 (ratios); a window ratio feature outside [0,1] |
| WARN | any unknown-fall-through label (< 1%); adapter drops >= 1% of rows, or >= 1% of the non-benign rows; synthetic / experimental adapter; folder of mixed formats or skipped files; flows without real IPs; documented non-packet zero-filled or approximated features; a feature that is constant zero although the adapter claims it carries data; flag count > packets in >= 1% of flows; implausible timestamp years; sample yields no sequences |
| INFO | repeated header rows removed; raw rows unsorted (the adapters sort); universal packet zero-fill; embedding caveat |

The IAT unit test is a physical invariant: for flows with >= 2 packets,
`median(iat_mean_us * (pkts - 1) / (duration_s * 1e6))` should be about 1 (CIC: 1.00 on the real data). It is skipped
for adapters that declare IAT zero-filled.

## 4. `prepare_dataset`

`python -m scripts.prepare_dataset <path> --out data/processed_adapter/<name> --config <yaml> [--adapter N]
[--split by_day|by_unit|chronological] [--train-units A,B --val-units C --test-units D] [--only-units A,B]
[--max-rows-per-file N] [--max-files N] [--allow-experimental] [--allow-fallthrough] [--force]`

Steps (a mirror of `build_dataset.py` / `build_unsw_dataset.py` / `build_ctu13_dataset.py`, same functions):
adapter -> `build_flow_windows` -> graph features -> graph embeddings -> packet features (zero-filled) ->
reconnaissance heuristic -> `build_sequences` -> split -> `save_splits`. Each unit (CIC day file, CTU scenario) is
windowed separately to bound memory. Only the config's `windowing`, `features` and `split` sections are used.

Output directory (`--out`):

```text
train.npz val.npz test.npz   # same keys as the existing builders: X, next_state, future_stages, infiltration,
                             # current_stage, current_infiltration, window_end_time, window_times, src_ip [, scenario_id]
window_graphs.pkl            # joint-GNN training input
metadata.json                # adapter name+version, units, unit_assumptions, field_coverage, caveats, label->stage table,
                             # split mode/assignment, positive rates, mitre_mapping sha256+mtime, files used/skipped
config.yaml                  # the input config with paths.* and split.* pointing at this output
```

Train on it without touching any shipped config: `python -m models.train --config <out>/config.yaml` (`scaler.npz`
is written by training, as for the existing datasets). Do not start training while the GPU is busy.

Split policy: explicit `--split`, else the config's `split.mode: by_day`, else the adapter default. IP-less CIC days
default to **day-disjoint** (a per-host chronological split on one pseudo-host per day is the E1 snooping split; the
tool warns if you force it). With no lists given, days/units are auto-assigned greedily in date order by sequence
count and the metadata says so; pass explicit lists (`--train-units 02-14,02-20 ...`, `MM-DD` for `by_day`) for a
curated split. It aborts when a split is empty, warns when a split has zero positives, aborts when >= 1% of rows
carry labels with no explicit stage mapping (`--allow-fallthrough` overrides), and refuses stub / unsupported /
experimental (`--allow-experimental`) adapters.

Safety: `--out` is checked by path components. It is refused if it equals, sits inside, or contains `data/processed*`
(except `data/processed_adapter`), `checkpoints*`, `configs/`, `data/raw`, `data/threat_intel`, `pipeline/`,
`models/`, `docs/`; and if it is a non-empty directory (`--force` only re-uses a directory this tool created).

## 5. Adding a dataset

1. Look at the header and first rows (never load a multi-GB file whole). Decide: does it have a per-flow source IP,
   destination IP and a start timestamp? If not it cannot be windowed per host/time: register it as `unsupported`
   with a how-to (see `pipeline/adapters/stubs.py`).
2. Write `pipeline/adapters/<name>_adapter.py` subclassing `DatasetAdapter` (or `_CICFlowMeterBase` for another
   CICFlowMeter release) and decorate with `@register_adapter`. Required: `name`, `detect_file`, `iter_flows`
   (chunked, yields canonical frames, fills `ReadStats`), `iter_label_chunks` (label + thinned timestamp only).
   Reuse an existing loader rather than rewriting it. Import the module in `pipeline/adapters/registry.py`.
3. Convert units **inside the adapter**: duration to seconds, IAT to microseconds, bytes/packets to counts, TCP flags
   to per-flow packet counts (a bitmask such as NetFlow `TCP_FLAGS` can only give 0/1 -> declare `approximated`).
4. Declare `field_coverage` honestly (`zero_filled` beats a silently invented value), `unit_assumptions`, `caveats`,
   `sort_keys`, `unit_kind`, `default_split`, `intentional_impact` (labels deliberately mapped to IMPACT) and
   `max_plausible_duration_s`.
5. Labels: every label must reach a stage through `mitre_mapping.label_to_stage`. Anything unknown silently becomes
   IMPACT (a positive), which the validator reports as `unknown_fallthrough`. Do not rewrite labels in the adapter;
   add explicit entries to `pipeline/mitre_mapping.py` (owner decision) and a test in `tests/test_mitre_mapping.py`.
6. Do not add `scenario_id` unless the dataset has independent captures that windowing must never cross.
7. Run `python -m scripts.validate_dataset <path>`; fix FAILs; read every WARN. Add fixture tests
   (`tests/adapter_fixtures.py` has builders) for detection, unit conversion, label status and the schema table.

### 5.1 CIC-IDS-2017 (experimental adapter exists)

Verified from a head-read of the files on `V:\Datasets\CIC-IDS-2017`: headers have leading spaces and plural/long
names; timestamps are `d/m/Y H:MM` without seconds or AM/PM (Monday's file has `03/07/2017 08:55:58`); labels contain
a cp1252 en-dash. Remaining owner decision: map `FTP-Patator`, `SSH-Patator` (initial_access, like the 2018
brute-force labels), `PortScan` (reconnaissance), `Web Attack - Brute Force/XSS/Sql Injection` (initial_access, like
the 2018 web labels) and `Heartbleed` in `pipeline/mitre_mapping.py`; until then `validate_dataset` FAILs it (6.2% of
rows fall through) and `prepare_dataset` refuses it.

### 5.2 CICIoT2023

The merged CSVs are feature rows with no IP or timestamp: unusable. Use the PCAPs through CICFlowMeter (keeps the
5-tuple and timestamp) and reuse the `cicids2018` reader, adding a label map for its attack families.

### 5.3 NF-*-v2 NetFlow datasets

Start from `NetFlowV2Stub` / `NF_V2_COLUMN_MAP` in `pipeline/adapters/stubs.py` (unverified against a file: no NF-*
data is on disk). Traps: `FLOW_DURATION_MILLISECONDS` and `*_IAT_*` are **milliseconds**; `FLOW_START_MILLISECONDS`
is epoch milliseconds; `TCP_FLAGS` is a bitmask; `Attack` strings need `mitre_mapping` entries; `Label` is binary.
Copy `unsw_nb15_adapter.py` as the template (headered CSV, chunked, declare approximated flags).

## 6. Findings from the first full run on the data on disk (2026-10-10)

See `data/adapter_reports/*.md|json`. Material surprises, none of which this toolkit changes:

* **CTU-13**: the existing adapter drops every ICMP flow (hex `Dport` such as `0x0303` -> NaN -> `dropna`). That is
  114,997 of 444,699 botnet flows (25.9%) over the 13 scenarios (full pass); all 588,068 dropped rows are 2.9% of the
  data.
* **UNSW-NB15**: only tcp/udp/icmp survive the protocol map; Argus protocols `unas`, `arp`, `ospf`, `sctp`, ... are
  dropped. Full pass: Exploits 36.4%, DoS 76.4%, Analysis 76.8%, Backdoor 82.7%, Backdoors 91.4%, Reconnaissance
  15.2%, Fuzzers 11.3% of each category's rows are lost; Normal 0.7%.
* **CIC-IDS-2018**: 59 repeated `Label` header rows (dropped by numeric coercion); 9 of 10 days have no IPs.
* **Synthetic sample**: 2.4% of flows have a flag count larger than the packet count (window `ack_ratio` reaches 1.33);
  the validator FAILs it on `ratio_range`.
* UNSW's first file starts with a BOM; pandas strips it, so no bogus `src_ip` is produced (checked).

## 7. Status and what remains

**Done and tested** (85 new tests in `tests/test_adapter_registry.py`, `test_adapter_validation.py`,
`test_adapter_prepare.py`, all passing on CPU; the 406 pre-existing tests also passed in the same session):
registry and auto-detection, canonical contract, unit conversion, label status, schema table, every validator
verdict branch, the output-directory guard, split policy, and array-level equality with `pipeline.build_dataset`
for a single-unit chronological run on `data/raw/flows`.

**Validated with real output** (`data/adapter_reports/*.md|json`): synthetic sample FAIL (flag counts exceed packet
counts, `ratio_range`); `flows_real` WARN; Tuesday 20-02 with IPs WARN; CTU-13 (19,976,700 rows, zero unknown-fallthrough
labels) WARN; UNSW-NB15 (2,540,047 rows) WARN; CIC-IDS-2017 FAIL (6.18% of rows on unmapped labels).
`prepare_dataset` was run only on row-capped prefix demos in `data/processed_adapter/` (CTU 5/7/11, UNSW file 1,
CIC 4 days). They are not experiment-grade: val/test splits of two of them have zero positives.

**Untested / not done**
* Multi-unit `by_day` and `by_unit` paths are not proven array-equal to the existing builders (only a single-unit run is).
* The advertised `models.train --config <out>/config.yaml` and `models.dataset.build_datasets` were never run on an output.
* The validator's drop accounting is sample-only. The full-pass numbers in section 6 (CTU ICMP: 25.9% of botnet
  flows; UNSW per-category losses) came from a one-off script, not from the tool.
* `cicids2017._parse_ts_series` lacks the seconds fallback, so Monday's timestamps are missed in the full-pass day list.
* `graph_embed_*` dead units are reported as a WARN rather than INFO.
* Nothing was run on the full 4 GB Tuesday file through `prepare_dataset`.

**Next steps**
1. Add `--drop-scan full` (stream `adapter.iter_flows`, compare kept vs raw label counts) and re-run CTU and UNSW.
2. Add a three-day `by_day` fixture test against `build_dataset` (compare arrays and `window_graphs.pkl` keys).
3. Copy one demo output to a scratch dir and run `build_datasets(load_config(<copy>/config.yaml))` on CPU.
4. Add the seconds fallback in `cicids2017._parse_ts_series`; downgrade dead embedding units to INFO.
5. Owner decisions: CIC-2017 label mapping; the CTU ICMP and UNSW protocol row drops; whether the synthetic sample's FAIL is acceptable.
