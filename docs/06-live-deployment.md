# Running the model on live network traffic

`scripts/live_forecast.py`. This is the deployment path; `scripts/stream_consumer.py` is a
CSV-replay simulation and is superseded for live use (see *What changed* below).

## Before anything else: three constraints that decide whether this is worth deploying

**1. The probabilities are not calibrated for your network.** The model was fitted on the
CIC-IDS-2018 lab capture — a specific host mix, service profile and volume. The published AUROC
(0.794) does not transfer to a different network, and nothing in this repository has measured it
on one. Treat the output as a **triage ranking signal**, not a verdict, until it has been scored
against ground truth on the network it is watching. The script prints this warning at startup.

**2. A single NIC only sees that host's own traffic.** Capturing on `eth0` of one server gives you
that server's conversations, not the network's. Real visibility needs a **SPAN/mirror port** or a
tap feeding the sensor. Without one, this is host-level monitoring, which is a legitimate thing to
run but is not what "network attack forecasting" implies.

**3. It detects; it does not forecast.** Measured on held-out DoS traffic: 0 of 12 genuine
forecast attempts crossed the alert threshold, while detection of an *in-progress* flood fired
56% of the time. See `docs/04-dos-forecast-demo.md`. Deploy it as an early-warning *detector* and
the numbers support you; deploy it as a predictor and they do not.

## Where flows come from

The 19 flow-level features include `mean_iat`, `var_iat` and `max_iat`, which aggregate each
flow's **intra-flow packet inter-arrival** statistics. That rules out some obvious sensors:

| Source | Works? | Why |
|---|---|---|
| Rotated PCAP (`tcpdump`) | **Yes** | `pipeline/packet_features.build_flow_records` derives genuine per-flow IATs from packet timestamps — the project's own CICFlowMeter stand-in |
| CICFlowMeter live mode | Yes | Produces the exact training schema |
| Zeek `conn.log` | **No** | Carries no intra-flow IAT statistics; 3 of 19 flow features would be unfillable |
| NetFlow / IPFIX | **No** | Same gap, plus no TCP flag counts per flow |

A Zeek-based sensor is therefore **not** offered as an option rather than offered with three
features silently zero-filled — zeroing a feature that is never zero in training puts every
forecast off-distribution, which is the exact defect audit H3 found in `stream_consumer.py`.

## Deploying

### 1. Capture (needs root or `CAP_NET_RAW`)

Rotate on the window boundary so each file is roughly one window:

```bash
sudo mkdir -p /var/spool/naf
sudo tcpdump -i eth0 -G 10 -w /var/spool/naf/cap-%Y%m%d-%H%M%S.pcap
```

To avoid running the forecaster as root, grant the capability to the capture process only:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)
```

`/var/spool/naf` fills quickly. Rotate it out of band (`find /var/spool/naf -mmin +10 -delete`,
or `-z gzip` plus an archive job) — the forecaster reads each file once and does not clean up.

### 2. Forecast

```bash
python -m scripts.live_forecast --source pcap-dir --path /var/spool/naf
```

A file is read only once it has been untouched for `--settle-seconds` (default 2), so a PCAP
still being written by `tcpdump` is never parsed half-complete.

**No forecast appears for the first ~2 minutes.** The model needs `sequence_length` (12) windows
of history per host before it can produce anything — 120 seconds of continuous traffic from that
host. Hosts that go quiet keep their buffer; windows with no flows are not synthesised, because
training dropped them too.

Alerts are appended to `logs/live_alerts.jsonl`. `--post-to URL` is opt-in and off by default.

### 3. Replaying a capture instead

Exercises the same windowing, buffering and scoring code as the live path, so the demo cannot
drift from production:

```bash
python -m scripts.live_forecast --source csv-replay --speed 0 \
  --path data/raw/flows_real/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv
```

`--speed 1` paces at real time; `--speed 0` runs as fast as possible.

## What the server needs

- **No `data/processed*` directory.** The model and scaler load through `service.load_backend`,
  the same loader the dashboard uses. Ship `checkpoints_real_v2_converged/` and the config; the
  processed arrays are build artefacts and are not needed at inference.
- `requirements.txt`, plus a libpcap provider for the `pcap-dir` source (`scapy` warns
  `No libpcap provider available` without one; reading saved files still works).
- The config default is `configs/real_data_v2_converged.yaml` — the real converged checkpoint every
  published number refers to, **not** `configs/default.yaml`, which is the synthetic pipeline.

Feature names and order are validated against the checkpoint at startup
(`validate_feature_names`), so a schema mismatch fails loudly instead of producing a
silently-wrong forecast.

## What changed from `stream_consumer.py`

That script remains useful as a replay simulation, but had four defects that made it unsuitable
for live deployment:

1. **It batched every 100 rows.** A 10-second window does not align to a row count, so windows
   were split across batches and scored twice, each time on a partial view of themselves. The new
   engine closes windows on **event time** — a window is emitted only once the watermark passes
   its end, and flows in the still-open window are carried over.
2. **It loaded the scaler from `processed_dir/scaler.npz`**, which does not exist on a deployment
   box. Now via `service.load_backend`.
3. **It defaulted to `configs/default.yaml`** — the synthetic pipeline.
4. **It POSTed to `/api/v1/alerts/ingest`, which does not exist** in `app/server.py` (it was
   written against the older `app/api.py`). Alerts now go to a JSONL file; posting is opt-in.

Packet-level features stay zero-filled even when the source is a PCAP, because the shipped
checkpoint is flow-only (`service.is_flow_only_model`). Feeding it real packet features would be
off-distribution.
