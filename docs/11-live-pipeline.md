# 11 - Live and replay pipeline (docs/09 A3)

Status: built and tested on the dev PC in **replay** mode, including the real server process with the
model bundle. **Live mode against a real `dumpcap` ring on Debian has not been run** (no capture was
allowed or made here); it is covered only by tests that write ring-style files and drive the tail
reader. Everything below says which it is.

Design lineage: docs/07 section 1.4 (the plan), docs/09 A3 (the task), docs/10 (bundle serving), and the
unmerged branch `live-deployment-2026-10-10`, whose `scripts/live_forecast.py` is merged in but not the
engine (see "What came from the live branch").

## 1. What it is

`app/live.py` holds a `LiveEngine` that runs inside the server process. It takes packets from one of two
sources, builds flows and 10-second per-host windows with the same code the upload path uses, scores
every host that has 12 windows, and swaps the result into the dashboard's `STATE`. The existing 5-second
poll then shows live hosts and alerts. Nothing about the dashboard's endpoints changed; some fields were
added.

```
 REPLAY: a .pcap/.pcapng file or folder           LIVE: dumpcap writes closed 10 s files
          (paced by packet timestamps, 1x..Nx)           into /var/spool/naf-ring  (you start dumpcap)
                         \                                  /
                          v                                v
                   ReplaySource (thread)            LiveDirSource (thread)
                          \                                /
                           v   read_all_frames_counted     v    pipeline/fast_packet_windows.py
                         parsed packet arrays (struct, no Scapy dissection)
                                        |
                                        v          LiveEngine.ingest()   [app/live.py, one lock]
        filter: IPv4 TCP/UDP only, lab CIDR (both ends), ignored ports   -> counted, never silent
                                        |
                          rolling packet buffer  (capped, trimmed behind the oldest open window)
                                        |
                  assemble_flows(timeout, anchors)   whole flows, bidirectional 5-tuple, IAT in microseconds
                                        |
             flow -> window of its FIRST packet, keyed by the initiator IP, floor(10 s)
                    /                                         \
     FINAL windows: start + 10 + timeout + grace <= watermark    PROVISIONAL windows: everything newer
     features computed once, appended to the host's history      recomputed each tick, never stored
        (graph + GraphSAGE embedding per window, packet cols = 0)
                    \                                         /
                     per-host history (last 12 non-empty windows) + provisional tail
                                        |
        hosts with >= 12 windows -> latest_sequences_batch (contiguity flag) -> ForecastEngine.rollout_batch
                                        |
                          Snapshot(flow_df, windows, batch, host_meta)
                                        |   STATE.publish()  (one lock, built completely first)
                                        v
         /api/v1/forecast/hosts, /predict, /explain ... (unchanged)      /api/v1/live/status (new)
                                        |  browser polls every 5 s
                                        v
                       dashboard, header badge: LIVE / REPLAY / STALE / NO LIVE FEED
```

### Why a new module and not `live_forecast.py`

`scripts/live_forecast.py` builds flows file by file with the Scapy path. A flow that crosses a file
boundary is split in two, Scapy parsing is slow (about 3,200 packets/s per core in the repo's own
measurement), it has no flow timeout, its `_seen_windows` set grows without bound, and it writes JSONL
instead of feeding the dashboard. Evolving it in place would have kept all of that. It stays as a
standalone JSONL tool, with its default model and threshold brought in line with the server.

## 2. Run it

All commands from the repo root with the venv active (`.\.venv\Scripts\Activate.ps1` on Windows,
`. .venv/bin/activate` on Debian).

### Replay (the insurance mode)

```
python -m scripts.serve --replay data/raw/pcap/synthetic_sample.pcap --speed 20
python -m scripts.serve --bundle ~/models/seed1 --replay /path/to/lab_run.pcapng --speed 1
```

`--speed 1` is real time, `10` is ten times faster, `0` is as fast as possible. A folder replays its
files in time order. The badge shows **REPLAY** (amber), never LIVE. When a replay ends the badge stays
REPLAY with "replay finished" in the details, and the last scores stay on screen until you stop it.

Start, stop and replay from the machine itself while the server is already running:

```
curl -X POST http://127.0.0.1:8000/api/v1/live/replay -H "Content-Type: application/json" \
     -d '{"path": "data/raw/pcap/synthetic_sample.pcap", "speed": 20}'
curl -X POST http://127.0.0.1:8000/api/v1/live/stop
```

Replay paths must be inside `data/raw/pcap`, `demo`, `lab_rec`, `$PHOENIX_REPLAY_DIR` or
`$PHOENIX_LIVE_DIR` (an arbitrary-file-read guard); a path given on the `--replay` command line adds its
own folder. `data/raw/pcap/synthetic_sample.pcap` has 965 packets over 45 minutes from three hosts, so
its windows are sparse (two of the three hosts score with `input_contiguous: false`); use a dense capture
for a convincing demo.

### Live (Debian laptop) - UNVERIFIED end to end

The server never starts `dumpcap` and never opens an interface. You start capture separately (below),
then point the server at the folder it writes:

```
python -m scripts.serve --bundle ~/models/seed1 --host 192.168.50.10 --port 8000 \
       --live-dir /var/spool/naf-ring --lab-cidr 192.168.50.0/24
```

Bind to the lab address, not `0.0.0.0`, on any network that has a route out (docs/07 section 3.4).
`lan_ip()` in `scripts/serve.py` probes 8.8.8.8 and returns `None` offline, so always pass `--host`.

#### The dumpcap command

```
dumpcap -i eth0 -f "ip and (tcp or udp) and not port 8000" -s 128 -n -q \
        -b duration:10 -b files:60 -w /var/spool/naf-ring/ring.pcapng
```

| Piece | Why |
|---|---|
| `-f "ip and (tcp or udp) and not port 8000"` | the parser is IPv4 TCP/UDP only; `not port 8000` keeps the dashboard's own polling out of the traffic being judged. Change 8000 if you serve elsewhere; the engine also drops the server port in LIVE mode (`PHOENIX_LIVE_IGNORE_PORTS` overrides). |
| `-s 128` | headers only; payload is never stored. The parser takes the payload length from the IPv4 total-length field, so truncation does not change byte counts (tested at a 54-byte snaplen). |
| `-b duration:10 -b files:60` | a new file every 10 s, 10 minutes kept, oldest deleted. |
| `-n` | pcapng (the default; stated so a different build cannot surprise you). |

Files are named `ring_00001_20261017120000.pcapng`. The tail reader reads every file **except the newest**
(dumpcap is still writing it) and reads each file exactly once. The newest file is read only after it has
not changed for 20 s, which covers dumpcap being stopped or the link going quiet; this is a deliberate
choice over "modified more than N seconds ago", which would also mark an idle open file as finished. A
file deleted by rotation is forgotten; an unreadable file is counted in `dropped.files_failed` and
skipped.

Offloads (UNVERIFIED, from how Linux capture works, not from a test here): on a Linux NIC that is both
victim and sensor, `AF_PACKET` sees received packets after GRO/LRO has merged them and transmitted packets
as TSO/GSO super-packets. That undercounts packets and distorts the flag-count and IAT features. For the
demo, turn offloads off on the capture interface: `sudo ethtool -K eth0 gro off lro off gso off tso off`
(not persistent; put it in the unit as `ExecStartPre=` if it helps). The parser already tolerates the
resulting IP total length of 0 on offloaded transmit frames by falling back to the captured length.

Debian permissions: do not run dumpcap as root. Either use the unit below (ambient capabilities), or
`sudo dpkg-reconfigure wireshark-common` and add the user to the `wireshark` group.

#### systemd units (example, not installed or run here)

`/etc/systemd/system/naf-capture.service`:

```ini
[Unit]
Description=NAF dumpcap ring buffer (10 s files)
After=network-online.target
Wants=network-online.target

[Service]
User=naf
Group=naf
EnvironmentFile=/etc/naf/capture.env          # IFACE=eth0
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/spool/naf-ring
ExecStart=/usr/bin/dumpcap -i ${IFACE} -f "ip and (tcp or udp) and not port 8000" -s 128 -n -q \
          -b duration:10 -b files:60 -w /var/spool/naf-ring/ring.pcapng
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/naf-web.service`:

```ini
[Unit]
Description=NAF dashboard + live engine
After=naf-capture.service
Wants=naf-capture.service

[Service]
User=naf
Group=naf
WorkingDirectory=/home/naf/naf
Environment=OMP_NUM_THREADS=2 MKL_NUM_THREADS=2
ExecStart=/home/naf/naf/.venv/bin/python -m scripts.serve --bundle /home/naf/models/seed1 \
          --host 192.168.50.10 --port 8000 --live-dir /var/spool/naf-ring --lab-cidr 192.168.50.0/24
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```
sudo useradd --system --create-home naf && sudo mkdir -p /var/spool/naf-ring /etc/naf
echo "IFACE=eth0" | sudo tee /etc/naf/capture.env
sudo chown naf:naf /var/spool/naf-ring
sudo systemctl daemon-reload && sudo systemctl enable --now naf-capture naf-web
```

Run **one** uvicorn worker only (the state is in the process; `scripts.serve` does).

### Settings

| What | Flag / environment variable | Default |
|---|---|---|
| lab CIDR filter: a packet is kept only if **both** endpoints are inside | `--lab-cidr` (repeatable) / `PHOENIX_LAB_CIDR` (comma list) | none (no filter) |
| ports whose packets are dropped | `PHOENIX_LIVE_IGNORE_PORTS` | LIVE: the server port; REPLAY: none |
| flow timeout | `--flow-timeout` / `PHOENIX_LIVE_FLOW_TIMEOUT` | 30 s |
| grace after the timeout before a window is final | `PHOENIX_LIVE_GRACE` | 2 s |
| JSONL score log (one line per host per newly final window) | `PHOENIX_LIVE_SCORE_LOG` | off |
| extra directories replay may read | `PHOENIX_REPLAY_DIR` | none |

Caps (in `LiveSettings`, reported in `/live/status.caps`): 5,000 hosts (least recently active evicted,
counted), 600 s idle host expiry, 2,000,000 buffered packets (oldest dropped, counted), 100,000 retained
flows, 12 windows per host. The status endpoint stops reporting a host the moment it is evicted.

## 3. Window rules, and where this differs from training

* A flow belongs to the window of its **first packet**, keyed by the **initiator's** IP, floor 10 s of
  epoch time. That is `build_flow_windows` unchanged. The attacker is the scored host; the victim appears
  only as a destination.
* A window is **final** when the newest packet time seen is at least `window start + 10 + flow timeout +
  grace`. Every flow that began in it has ended or been cut by the timeout by then, so its record is
  complete. Final windows are computed once and never revised.
* Newer windows are **provisional**: scored from what has been seen, recomputed every tick, shown with
  `provisional: true`. A host's score therefore moves while its newest window fills, then settles.
* Flows are cut every `timeout` seconds from the flow's first packet (CICFlowMeter's cut, not its FIN
  split). The cut grid is anchored at the true first packet across ticks: the engine remembers, per
  5-tuple, the first packet time and the last packet time it has trimmed away, so a long connection is
  never restarted at a buffer edge and the continuation of a flow that began in an already-final window
  is not counted as a new flow in a later one. This is tested with a connection that lives 300 s.
* Silent windows are not synthesised; a host's sequence is its last 12 **non-empty** windows, as in
  training. `input_contiguous` (the QC-1 flag) says whether those 12 were also back-to-back.
* Silent time does not close windows. In LIVE mode, if traffic stops, the newest windows stay
  provisional; the badge goes STALE after 30 s. (docs/07 proposed advancing the watermark from the wall
  clock when idle; not built, because it adds a clock-skew failure mode and the demo does not need it.)

Deviations from the training distribution, all deliberate and all visible in the status endpoint:

| Deviation | Effect |
|---|---|
| flow timeout 30 s, training used CICFlowMeter's 120 s | a flow longer than 30 s becomes several flows; `--flow-timeout 120` removes the skew at the cost of a final delay of about 2 minutes (provisional windows are unaffected) |
| packet-level features zero-filled | correct for the flow-only checkpoints that are served; the engine **refuses** a checkpoint that was trained with packet features |
| a 5-tuple silent for more than about two timeouts starts a fresh timeout grid | only matters for long-idle reused ports |
| 12 windows (120 s) of history before a host is scored | per-host warm-up; `hosts_warming_up` counts them |
| `has_ip_data = 1` always | docs/07 D5: a provenance confound in the training data, unchanged here |
| the observed stage is "Unlabelled" | a capture has no ground truth; this was fixed earlier for uploads and applies here too (`stage_observed=False`) |

## 4. Thresholds (one coherent scheme)

docs/07 found three numbers in play. They now mean three different, documented things, and only one is
an alert threshold.

| Number | Where | Meaning now |
|---|---|---|
| **0.40** | `service.ALERT_THRESHOLD` | **the alert threshold.** A host alerts when its peak forecast probability is at least this. It is exactly the start of the "serious" severity tier, and it is what `/system/status` and the upload response already called high risk. The live engine, `Host.alert`, `live_forecast.py` and the dashboard all use it. |
| 0.15 / 0.70 | `service.WARNING_THRESHOLD` / `CRITICAL_THRESHOLD` | display tiers only (warning, critical) |
| 0.3 | `windowing.alert_threshold` in the model code | gates a stage-**labelling** heuristic inside `models/forecast.py`. Not an alert. Left alone on purpose: changing it would make live outputs differ from batch outputs and would change published evaluation numbers. |
| 0.5 | the old `stream_consumer.py` default | retired; that script is marked deprecated. |

0.40 is **uncalibrated**. Nobody has measured it on any live network (docs/07 T6 is the calibration
tool, not built). The status endpoint and the log say so.

## 5. API

| Endpoint | Access | Notes |
|---|---|---|
| `GET /api/v1/live/status` | like every other read endpoint (bearer token only if `PHOENIX_REQUIRE_AUTH=1`) | below |
| `POST /api/v1/live/replay` `{path, speed, max_gap_s?}` | loopback only, plus the token if auth is on | starts a replay |
| `POST /api/v1/live/start` `{directory?}` | same | tails `PHOENIX_LIVE_DIR` (or an allowed directory); starts no capture |
| `POST /api/v1/live/stop` | same | stops the session and clears the dashboard state |
| `GET /api/v1/forecast/hosts` | unchanged | rows gain `alert`, and while live: `provisional`, `input_contiguous`, `windows_seen`; the response gains `live_state` |

Control is limited to the direct TCP peer being `127.0.0.1` / `::1`; `X-Forwarded-For` is ignored. A
reverse proxy on the same machine makes every request look local, so do not put one in front without its
own access control. There is no unauthenticated control on a routable address.

While a session is active, `POST /analysis/upload` and `POST /datasets/select` return 409 (the engine
owns the state and the loaded model), and report generation still works but the audit ledger is never
appended to by rescoring.

`/live/status` fields: `state` (`LIVE`, `REPLAY`, `STALE`, `OFF`), `mode`, `source` (`LIVE:<dir name>` /
`REPLAY:<file name>`, never a full path), `finished`, `seconds_since_data`, `stale_after_s` (30),
`packets_per_s`, `flows_per_s` (60 s window), `frames_total`, `packets_total`, `packets_kept`,
`flows_total`, `windows_processed`, `windows_provisional`, `hosts_scored`, `hosts_warming_up`,
`last_window_time`, `watermark`, `lag_seconds` (LIVE: now minus newest packet time; REPLAY: seconds behind
schedule), `dropped{unparsed_frames, filtered_non_tcp_udp, filtered_outside_lab_cidr, filtered_ignored_port,
late_packets, buffer_overflow_packets, hosts_evicted, files_failed}`, `caps{...}`, `alert_threshold`,
`alerts_active`, `recent_alerts`, `flow_timeout_s`, `grace_s`, `ingest_seconds_p50/max`,
`packet_to_dashboard_seconds_p50/max`, `window_final_delay_s_p50`, `error`, `disclosure`.

STALE means no data arrived for more than 30 s while the source is running (counted from the last data,
or from session start before any has arrived, so a fresh start is not STALE until 30 s have passed); a
finished replay is not stale. `packets_per_s` / `flows_per_s` are measured between ingest samples over the
last 60 s, because LIVE ingests only once per 10 s ring file; right after a start that has a backlog of
old files the first value is a catch-up burst. The dashboard badge also shows source, packets/s, scored vs warming hosts, last window, lag and
dropped counts, and says "NO LIVE FEED / upload mode" when the engine is off. The old header text
"LIVE POLLING" (which described only the browser's own timer) is gone.

## 6. Parser throughput and the CTU-13 capture (the go/no-go)

Hardware for every number in this section: **AMD Ryzen 9 9950X3D (16 cores, 32 threads), 31.1 GB RAM,
Windows 11, Python 3.11.7, torch CPU**. The pipeline is single-threaded Python/NumPy/pandas, so only
single-core speed matters. An old laptop will be several times slower; **the laptop has not been
measured.** Reproduce on it with `python -m scripts.bench_live_pipeline` (this section's tool).

### The file

`V:\Datasets\CTU-13-pcaps\1\botnet-capture-20110810-neris.pcap`, read only, 55.6 MB, classic pcap,
Ethernet, 323,154 frames over 17,106 s (4.75 h, average 19 packets/s).

| Check | Result |
|---|---|
| frames where captured length < original length | **0** (not snaplen-truncated) |
| frames where IP total length + 14 differs from captured length | **121,141 (37.5 %)**, all Ethernet minimum-frame padding |
| IPv4 TCP / UDP / ICMP / IGMP | 235,622 / 85,865 / 757 / 4 |
| frames the parser skips | 906 ARP. No IPv6, no VLAN in this file. ICMP and IGMP are parsed and then ignored by the flow builder (no ports to key a flow on) |
| parsed TCP/UDP packets | 322,248 of 323,154 frames |

So the premise in docs/09 was half right. The parser did use captured length for byte counts, and that
**was** wrong for this file, but the cause is padding, not truncation: every pure ACK is a 54-byte frame
padded to 60, and the old code counted those 6 bytes as TCP payload. On this file it overstated total L4
payload by **652,553 bytes of 36.09 M (1.8 %)** in aggregate, and by more in ACK-heavy flows. The IPv4
and TCP/UDP only limit does not affect this file beyond ARP and 761 ICMP/IGMP packets.

### The fix

`pipeline/fast_packet_windows.py::_parse_chunk` now computes L4 payload as `IP total length - IP header -
TCP/UDP header`. That is correct for padded frames, correct for snaplen-truncated frames (the IP header
says how long the datagram really was), and falls back to the captured length only when the total length
is 0 (segmentation offload) or nonsense. The same fix is in the Scapy path
(`packet_features.load_pcap`) so the two stay in agreement. The original/wire length from the pcap record
was not used: it would still count padding, and `pay` (the packet-pilot feature) is left on captured
length on purpose, since changing it would put the existing packet-feature pilots out of step with
their training data. Other callers of the changed code: `app/service.py` (upload), `pipeline/adapters/pcap_adapter.py`,
`scripts/extract_flow_records.py` and the packet-pilot builders. Their existing processed data and
checkpoints (`checkpoints_cic_pkt*`, `checkpoints_unsw_pkt*`, `data/processed*`) were built with the old
count and are untouched; rebuilding them will give slightly different byte columns, and serving a pilot
flow-only checkpoint live carries that small skew. The default served model was trained on CICFlowMeter
CSVs, not on this parser's output, so it is unaffected. I did not check whether CICFlowMeter itself counts
Ethernet padding, so this page claims only that the new count is the IP datagram's real payload length.
Tests: `tests/test_parser_bytes.py` (padding, a hand-written 54-byte-snaplen record of
a 1,514-byte frame, offload, nanosecond pcaps, skipped frames, raw-IP link types). Two other small parser
fixes found on the way: nanosecond-timestamp pcaps were read as microseconds in `read_all_frames`, and
raw-IP link types (101, 228, which `data/raw/pcap/synthetic_sample.pcap` uses) were rejected as unsupported.

### Throughput (one run each; the machine was otherwise idle)

Whole-file, stage by stage (`scripts/bench_live_pipeline.py --pcap ...`, JSON in
`dist/bench/live_<host>.json`, which is git-ignored):

| Stage | Time | Rate |
|---|---|---|
| raw pcap read (`RawPcapReader` loop) | 0.39 s | 828,000 frames/s |
| header parse (`_parse_chunk`) | 0.65 s | 501,000 frames/s |
| flow assembly (`assemble_flows`, 322 k packets -> 24,464 flows) | 0.18 s | 1,797,000 packets/s, 136,000 flows/s |
| **read + parse + assemble together** | 1.22 s | **265,000 packets/s** |
| windowing (`build_flow_windows`, 3,133 windows) | 0.03 s | |
| graph features | 0.15 s | |
| GraphSAGE embedding (per window graph) | 2.32 s | the single largest compute stage |
| batched rollout, 11 hosts | 0.33 s | |
| whole file, all stages | 4.05 s | 79,600 packets/s |

(An earlier ad hoc run of the same first stages gave 1.10 M / 0.79 M / 1.64 M per second; expect
roughly 1.4x run-to-run spread.)

The engine itself, replaying the same file at maximum speed in 10 s slices: 164 s wall, 1,959
packets/s, 147 flows/s. That figure looks bad and is the wrong thing to read: this capture is 1,710 ticks
of about 19 packets each, and every tick pays a fixed 0.1 s of pandas feature work (tick p50 0.106 s, p95
0.127 s, max 0.212 s over the last 200 ticks). The cost is per tick, not per packet. Synthetic traffic
(8-packet TCP flows, 30 hosts, 1-second ticks, 30 s flow timeout) shows how it scales:

| Rate | Ticks | Tick p50 | p95 | max | Buffer at end |
|---|---|---|---|---|---|
| 1,000 packets/s, 180 s | 180 | 0.094 s | **0.177 s** | 0.386 s | 40,060 packets |
| 5,000 packets/s, 120 s | 120 | 0.292 s | 0.422 s | 0.800 s | 200,427 packets |

docs/09 A3's success test was "tick p95 < 2 s at 1,000 packets/s": **0.18 s here, 11x margin on this
CPU.** Parsing is not the bottleneck by two orders of magnitude (265,000 packets/s against a 1,000
packets/s requirement). The bottleneck is the pandas feature code, which scales with the number of
flows and windows in the provisional tail, and is why live ticks are per ring file (10 s) rather than
per packet.

**Go/no-go on this evidence:** go for the parser and engine on this PC. For the laptop, the arithmetic
is: a laptop that is 10x slower single-threaded would take about 1.8 s per tick at 1,000 packets/s and
4 s at 5,000, against a tick budget of 10 s (one ring file), so even that case keeps up in LIVE mode; in
REPLAY at 1x the 1-second slices would fall behind, and the replay then batches whatever is due in one
tick (catch-up) instead of lagging further. That is arithmetic from one fast CPU, not a measurement.
Run the benchmark on the laptop before relying on it.

## 7. Latency, measured in replay

`ReplaySource` at 1x over a 240 s dense synthetic capture (6 hosts, scapy-written, same machine), engine
timestamps taken from the injected clock:

| Quantity | Measured |
|---|---|
| ingest compute per tick | p50 0.060 s, max 0.50 s |
| packet due -> published to `STATE` (provisional view) | p50 0.067 s, max 0.50 s |
| window end -> window FINAL (p50 over the run) | 31.6 s (= flow timeout 30 s + grace 2 s, minus slice granularity) |
| first host scored | 110.0 s into the replay (12 windows of 10 s, the 12th provisional) |

Add the dashboard's 5 s poll (up to 5 s, mean 2.5 s) for what a viewer sees: **a new provisional window
appears within about 0.1 s plus 0-5 s**, and a window becomes final about 32 s after it ends.
Caveats: a replay slice (1 s of capture) is released when its *first* packet is due, so replay latency is
optimistic by up to one slice; and the replay run did not include a file-rotation delay. In LIVE mode add
up to 10 s for the ring file to close, up to 1 s for the tail poll, and up to 20 s more if dumpcap goes
quiet and the newest file has to settle. Unmeasured on a real capture.

## 8. Tests

`tests/test_live_engine.py` (21), `tests/test_live_endpoints.py` (8), `tests/test_parser_bytes.py` (6),
`frontend/src/__tests__/liveBadge.test.jsx` (6 cases), plus one edited existing test: `tests/test_fast_packet_windows.py::test_unsupported_link_type_is_rejected`
now uses link type 147 instead of 101, because raw IP (101, 228) is supported.

* **Parity (strict, < 1e-6 on all 41 features):** incremental replay vs the whole file in one batch call,
  for a dense capture and for one with 300 s connections; the result does not depend on slice size
  (1, 7, 40 s). Compared on identical `(src_ip, window_start)` sets with no duplicate rows.
* **Parity against the upload path** (`service.process_uploads`, Scapy flows, no timeout): all features
  agree, IAT columns within 1e-3 relative (Scapy and the fast reader round timestamps about 1 us apart),
  and `mean_iat` is checked to be in microseconds (median above 1e4 for 0.1-0.5 s packet gaps).
  The parity is for flows shorter than the timeout; the engine is not claimed to equal the upload path for
  longer ones, where the timeout deliberately cuts.
* Warm-up gating, provisional flag and its replacement by the final window, `input_contiguous` true/false
  on a capture with a hole, STALE with an injected clock (and a finished replay not going stale), LIVE
  lag, lab-CIDR / ignored-port / late-packet counters, bounded memory (hosts, buffer, flows, windows,
  anchors), buffer trimming over a long replay, score-log uniqueness, refusal of packet-feature
  checkpoints, alert events once per crossing, replay pacing, and the ring-directory tail (closed files
  read once, open file skipped then read after it settles, deleted and corrupt files).
* Endpoints: status OFF, control refused from a non-loopback peer even with a forged `X-Forwarded-For`,
  path allowlist (outside, `..`, system file, missing, bad speed), a full replay populating
  `/forecast/hosts` and `/predict`, upload and dataset switch refused while live, ledger not created,
  token required for control when auth is on, tail endpoint with a ring directory.

Full suite after this work: **595 passed**, 0 failed (`pytest tests`, 125 s; 35 of them new). Frontend: 7 files, 30 tests
passed (`npx vitest run`); `frontend/dist` was rebuilt.

Also run by hand: the real server (`scripts.serve --bundle dist/models/seed1 --replay
data/raw/pcap/synthetic_sample.pcap --speed 50`) on loopback: status went REPLAY -> finished, 3 hosts
scored, `/forecast/hosts` carried `live_state`, the dashboard HTML was served, stop returned OFF.

## 9. What came from the live branch

`git merge --no-commit --no-ff live-deployment-2026-10-10` was clean (it only adds five files) and is
left uncommitted, so committing completes a merge commit that brings in `90bbd1c`. Kept: `scripts/live_forecast.py`
(header, default model and threshold changed), `scripts/demo_dos_forecast.py`, `docs/04-dos-forecast-demo.md`
(marked STALE: its numbers predate the off-by-one fix `90bbd1c` and were not regenerated),
`docs/dos_forecast_demo.json`, `docs/06-live-deployment.md` (pointer to this page added). Its ideas
carried into the engine: event-time windows closed by a watermark, no empty-window synthesis,
`validate_feature_names`-style schema discipline via `service.load_backend`, JSONL output as an option.
`scripts/stream_consumer.py` is marked deprecated in its docstring and otherwise untouched.

## 10. Limitations

* Live `dumpcap` mode is **unverified**: no interface was opened, no dumpcap run, nothing on Debian.
* IPv4 TCP and UDP only. IPv6, 802.1Q-tagged frames and non-IP frames are counted in
  `dropped.unparsed_frames` and ignored. ICMP is ignored.
* Flow-only checkpoints only; the 8 packet-level features are zero-filled (the engine refuses others).
* Replay reads each file whole into memory (about 100 bytes per packet); a multi-gigabyte capture needs
  splitting. The CTU-13 scenario 10 folder (66 GB) was not touched.
* The 30 s flow timeout is a train/serve skew; it is disclosed, not calibrated.
* The 0.40 alert threshold is uncalibrated, and docs/07's honest ceiling still applies: day-disjoint
  F1 0.481, 93.5 % of transitions missed, no advance warning. The pipeline being correct does not make the
  model good on a new network.
* A host's score changes while its newest window is provisional. That is by design, and the UI marks it.
* `STATE` is swapped under a lock, but request handlers read its fields one at a time, so a request that
  lands exactly during a swap can see a new `batch` with the previous `windows` for one poll. The
  mismatches that matter are guarded (a host missing from `windows` gives a 404 or "Unlabelled").
* CORS and the hard-coded fallback token (docs/07 D9) are unchanged; network isolation remains the
  control until T12.
* QC-10: the task named a "QC-10 finding on scripts/stream_consumer.py". That identifier does not appear
  anywhere in the repository (searched `docs`, code, tests and results files), so the deprecation notice
  is based on docs/07 D2/D3 and T16, which describe the same defects.
