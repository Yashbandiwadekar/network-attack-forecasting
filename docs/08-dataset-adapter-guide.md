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

## 2. Adapters and supported datasets

| dataset | adapter | tested on real data? | zero-filled features (of the 41) | caveats |
|---|---|---|---|---|
| CIC-IDS-2018 CICFlowMeter day CSVs | `cicids2018` (stable) | yes, all 10 days (validated, 16.2M rows; prepare on 4 row-capped days) | 9 packet-level; graph (5) + embedding (8) + `unique_dst_ips` on the 9 IP-less days | 9/10 days have no IPs -> one pseudo-host per day; use a day-disjoint split; 59 repeated header rows removed |
| Reduced 21-column fabricated CSVs (`data/raw/flows`, `flows_real/Synthetic-*`) | `synthetic` (stable) | yes (synthetic sample, prepare == `build_dataset` array-for-array) | 9 packet-level | not real traffic; 2.4% of flows have flag counts > packets |
| CTU-13 `.binetflow` | `ctu13` (stable) | yes, 13 scenarios / 19,976,700 rows | 6 flag ratios, 3 IAT, 9 packet-level; `bidir_ratio` is a byte proxy | no flag/IAT data in binetflow; background is unlabelled-as-benign; ICMP rows kept since 2026-10-10 |
| UNSW-NB15 raw `UNSW-NB15_1..4.csv` | `unsw_nb15` (stable) | yes, 2,540,047 rows | `psh_ratio`, `urg_ratio`, `var_iat`, `max_iat`, 9 packet-level; flags/`mean_iat`/`bidir_ratio` approximated | flags are 0/1 derived from state; non-tcp/udp/icmp protocols kept as protocol 255 since 2026-10-10 |
| CIC-IDS-2017 TrafficLabelling CSVs | `cicids2017` (experimental) | yes, validated on all 8 files (2.83M rows); not prepared | 9 packet-level | minute-resolution d/m/Y timestamps, AM/PM heuristic (hours 1-7 -> +12h); labels now mapped, PortScan is real recon |
| NF-*-v2 NetFlow CSVs | `netflow_v2` (experimental) | **no** (no file on disk; synthetic fixtures only) | 9 packet-level; IAT zero if columns absent; flags 0/1 from bitmask | requires `FLOW_START_MILLISECONDS`; keyword-based label map |
| PCAP / PCAPNG captures | `pcap` (stable on fixtures) | **no** real capture was run end-to-end (fixtures only; the underlying `assemble_flows` is tested in `tests/test_fast_flows.py`) | 9 packet-level; `bwd_pkts/bwd_bytes` zero, `fwd_*` = totals | IPv4 TCP/UDP only; no FIN-termination split; labels only via sidecar |
| Any CICFlowMeter-style CSV (snake_case, CICFlowMeter-py, ...) | `cicflowmeter_generic` (experimental) | fixtures only | 9 packet-level; IPs optional | header matching is heuristic; unlabelled -> BENIGN or sidecar |
| CICIoT2023 merged CSVs | `ciciot2023` (unsupported) | header recognised only | - | feature rows with no IP and no timestamp: cannot be windowed per host/time. Use the raw PCAPs through the `pcap` adapter or CICFlowMeter |
| UNSW `Training and Testing Sets`, CIC-2017 MachineLearningCVE | `unsw_nb15_split_sets`, `cicids2017_mlcve` (unsupported) | header recognised only | - | no IPs / timestamps |

Detection (`detect_dataset(path)`) reads only the first 64 KB of each file (header, first row or PCAP magic), asks
every adapter for `detect_file(info) -> (confidence, evidence)`, and for a folder returns the adapter that claims
most files (ties prefer a real-data adapter over `synthetic`). `Detection.mixed` and `.per_file` always expose the
other formats; `adapter.discover_files()` lists what it will read and why other files are skipped. Dedicated adapters
score 0.95-0.99; the generic CICFlowMeter adapter is capped at 0.6 so it only wins when nothing else matches.

### Labels sidecar (unlabelled captures: lab PCAPs, CICFlowMeter-py output)

`--labels-sidecar rules.csv [--default-label BENIGN]` on both CLIs (or `adapter.with_sidecar(path)`). One rule per
row: `src_ip,dst_ip,start,end,label[,dst_port]` (aliases `attacker_ip`, `victim_ip`, `start_time`, `end_time`). Empty IP
= wildcard; times are ISO text or epoch seconds, empty = unbounded; a rule matches a flow whose START time is in
range and whose IPs match in either direction (`bidirectional=False` in code for strict); later rules override
earlier ones; unmatched flows get the default label. Labels must be names `label_to_stage` knows (the CIC names);
the validator reports anything else as `unknown_fallthrough`. Rules with no IP and no time are rejected.

## 3. Validator

`python -m scripts.validate_dataset <path> [--adapter N] [--sample-rows 300000] [--label-scan full|skip] [--no-embeddings]
[--drop-scan auto|full|off] [--labels-sidecar rules.csv] [--default-label L] [--report-dir data/adapter_reports] [--name STEM]`. Writes `<stem>.json` and `<stem>.md`; exit code 0 PASS, 1 WARN,
2 FAIL, 3 bad path. Every number is tagged **full pass** (every row, label + 1-in-20 timestamp columns only,
streamed in chunks) or **sampled N rows** (a contiguous prefix of each file run through the adapter and then the real
windowing / graph / embedding code; random rows would make windows meaningless).

Reported: row count; label distribution with stage and status (`mapped`, `impact_by_design`, `unknown_fallthrough`,
`ignorable`); stage totals; time range and days; raw-order sortedness; rows dropped by the adapter's cleaning, broken
down by label (sampled, plus EXACT full-pass accounting via `--drop-scan`); NaN/inf rate; duration / bytes-per-packet / IAT unit plausibility; flag counts vs packets; host and IP
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
[--max-rows-per-file N] [--max-files N] [--labels-sidecar rules.csv] [--default-label L] [--allow-experimental] [--allow-fallthrough] [--force]`

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

### 5.1 CIC-IDS-2017 (experimental adapter, labels mapped)

Verified from a head-read of the files on `V:\Datasets\CIC-IDS-2017`: headers have leading spaces and plural/long
names; timestamps are `d/m/Y H:MM` without seconds or AM/PM (Monday's file has `03/07/2017 08:55:58`); labels contain
a cp1252 en-dash. Explicit stage mappings were added to `pipeline/mitre_mapping.py::CIC2017_LABEL_TO_STAGE`
(additive; CIC-2018 and UNSW behaviour unchanged):

| 2017 label | stage | reason |
|---|---|---|
| FTP-Patator, SSH-Patator | initial_access | credential brute force, same as the 2018 FTP-/SSH-Bruteforce |
| PortScan | **reconnaissance** | real labelled recon traffic (158,930 rows): the only genuine recon ground truth in the CIC data; it is mapped directly, not through the `port_scan_score` heuristic, and the packet-level score that heuristic needs is zero-filled anyway |
| Web Attack - Brute Force / XSS / Sql Injection | initial_access | same as the 2018 web labels (en-dash, hyphen and U+FFFD spellings accepted) |
| Heartbleed | initial_access | exploitation of a public-facing service (T1190); it is also data theft, but the label does not say what was read, so the exploit-side stage is used (11 rows in the whole dataset) |
| Infiltration, Bot | lateral_movement, command_and_control | as in 2018 |
| DoS Hulk / GoldenEye / slowloris / Slowhttptest, DDoS | impact | as in 2018 |

The adapter stays `experimental` only because the AM/PM heuristic (hours 1-7 -> +12h) is unverified.

### 5.2 CICIoT2023

The merged CSVs are 10-packet feature windows with no IP and no timestamp: there is nothing to window per host/time,
so it is deliberately NOT implemented (a surrogate clock from row order would fabricate time). Use the raw PCAPs with
the `pcap` adapter (plus a labels sidecar from the dataset's attack schedule) or CICFlowMeter output.

### 5.3 NF-*-v2 NetFlow datasets

Implemented in `pipeline/adapters/netflow_v2_adapter.py` from the published column names, `experimental` because no
NF file was on disk. Zero-filled / approximated: TCP flags are 0/1 decoded from the `TCP_FLAGS` bitmask; IAT std/max are
the max of the two directions; IAT is zero if the `*_IAT_*` columns are absent. It requires `FLOW_START_MILLISECONDS`.
Labels become `nf=<Attack>` and go through `mitre_mapping.nf_classify` (keyword rules; unknown names are reported as
fall-through). Run the validator on the first real file and check the IAT ratio and label table before trusting it.

## 6. Behaviour changes (2026-10-10) -- existing adapters, with before/after numbers

Both fixes change dataset numbers. Nothing under `data/processed*`, `checkpoints*` or `docs/04-evaluation*` was
regenerated: those artefacts were built with the OLD behaviour and a rebuild is the owner's call.

**CTU-13: ICMP rows no longer dropped** (`pipeline/adapters/ctu13.py`). ICMP flows carry a hex type/code in
`Sport`/`Dport` (`0x0303`); `to_numeric` gave NaN and `dropna(dst_port)` removed the row. Now ICMP ports are 0 and the
row is kept; non-ICMP rows with an unparsable port are still dropped (as before). Full pass over the 13 scenarios:

| | rows kept | rows dropped | botnet (non-benign) rows dropped |
|---|---:|---:|---:|
| before | 19,388,632 | 588,068 (2.94%) | 115,501 of 444,699 (25.97%; 114,997 of them ICMP) |
| after | 19,884,984 | 91,716 (0.46%) | 504 of 444,699 (0.11%) |

Positive (non-benign) rows reaching windowing: 329,198 before, 444,195 after (+34.9%). Remaining drops are tcp/udp rows
with a blank port (`Background`, `google-pop`, `From-Botnet-V45-UDP-Attempt` 491 rows).

**UNSW-NB15: other protocols no longer dropped** (`pipeline/adapters/unsw_nb15.py`). Argus protocols other than
tcp/udp/icmp (`unas`, `arp`, `ospf`, `sctp`, `gre`, ...) were NaN and dropped. They are now kept as protocol 255 with
`is_tcp = is_udp = 0` (so `tcp_ratio`/`udp_ratio` do not count them), no derived flags, and no schema change.

| category | rows | dropped before | dropped after |
|---|---:|---:|---:|
| Normal | 2,218,764 | 14,665 (0.7%) | 0 |
| Exploits | 44,525 | 16,208 (36.4%) | 0 |
| DoS | 16,353 | 12,490 (76.4%) | 0 |
| Reconnaissance | 13,987 | 2,132 (15.2%) | 0 |
| Fuzzers | 24,246 | 2,729 (11.3%) | 0 |
| Analysis | 2,677 | 2,055 (76.8%) | 0 |
| Backdoor / Backdoors | 1,795 / 534 | 1,484 (82.7%) / 488 (91.4%) | 0 |
| Generic | 215,481 | 1,763 (0.8%) | 0 |
| non-benign total | 321,283 | 39,349 (12.2%) | 0 |

Regression tests: `tests/test_adapter_formats.py::test_ctu_icmp_hex_port_rows_are_kept_with_port_zero_but_bad_tcp_ports_still_dropped`,
`::test_unsw_other_protocols_are_kept_as_255_without_tcp_udp_flags`, and the exact drop-scan tests in
`tests/test_adapter_validation.py`. The validator's drop accounting is now exact: `--drop-scan auto` (default) runs the
adapter's own `iter_flows` over every row when the data is <= 4 GB, compares kept with raw label counts and warns
(listed first) when >= 10% of non-benign rows are lost; `test_exact_drop_scan_catches_what_the_head_sample_misses`
proves it sees a loss the head-of-file sample cannot.

## 7. Real-data validator results (2026-10-10, exact drop scan, CPU)

Reports: `data/adapter_reports/*.md|json`.

| dataset | rows (full pass) | verdict | note |
|---|---:|---|---|
| `data/raw/flows` synthetic sample | 1,682 | FAIL | `ratio_range`: flag counts > packets in 2.4% of flows |
| `data/raw/flows_real` (CIC-2018, 10 days + synthetic skipped) | 16,233,002 | WARN | 90% of sampled flows without IPs; 0 rows dropped |
| Tuesday 20-02 alone (real IPs) | 7,948,748 | WARN | only `fin_ratio` constant zero in the sampled prefix |
| `data/raw/ctu13` | 19,976,700 | WARN | 9 zero-filled features; 0.46% rows dropped (0.11% of botnet) |
| UNSW-NB15 `V:\Datasets\UNSW NB15\CSV Files` | 2,540,047 | WARN | flags approximated, 4 zero-filled; 0 rows dropped |
| CIC-IDS-2017 `V:\Datasets\CIC-IDS-2017` | 2,830,743 | WARN | experimental adapter; 0 unmapped labels; 0 rows dropped |

## 8. Status and what remains

**Done and tested** (tests/test_adapter_registry.py, test_adapter_validation.py, test_adapter_prepare.py,
test_adapter_formats.py; CPU only): registry and detection (incl. PCAP magic, NF-v2, generic CICFlowMeter, unsupported
formats), canonical contract and unit conversion, label status, schema table, every validator verdict branch, exact drop
scan, output-directory guard, split policy, the labels sidecar, both drop-bug regressions, the PCAP adapter on
scapy-written captures, and array-level equality of `prepare_dataset` with `pipeline.build_dataset` for a single
chronological unit AND a three-day `by_day` run (including the `window_graphs.pkl` key set). A prepared output was fed
to `models.dataset.build_datasets` (CPU, scaler fit, `SequenceDataset` of shape (12, 41)) on a copy.

**Not verified**
* NF-*-v2 and PCAP adapters have only seen synthetic fixtures (no such real data on disk); CICFlowMeter-py output likewise.
* `models.train` itself was not run (GPU busy); only the data loader was.
* The CIC-2017 AM/PM timestamp heuristic; `prepare_dataset` on full multi-GB inputs (only row-capped prefixes were prepared).
* The three `data/processed_adapter/*` outputs (CTU 5/7/11, UNSW file 1, CIC-2018 4 days, CIC-2017 4 files) are row-capped
  demos, not experiment-grade; some splits have zero positives (the tool warns).
* Existing `data/processed*` and checkpoints were built before the two drop fixes; their numbers are not comparable
  with a rebuild.

**Next steps**
1. When NF-v2 / new PCAPs land: `validate_dataset <path>` first (add `--labels-sidecar` for PCAPs), read every WARN, then `prepare_dataset`.
2. Decide whether to rebuild CTU-13 / UNSW processed data with the fixed adapters (CTU rebuild is being done by another agent).
3. Add a curated day split for CIC-2017 (`--train-units/--val-units/--test-units`) before any training on it.
