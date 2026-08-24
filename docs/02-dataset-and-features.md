# Dataset and Features

## Synthetic sample (default, no download needed)

`python -m scripts.make_synthetic_sample` writes a hand-built flow CSV + matching PCAP to
`data/raw/flows/synthetic_sample.csv` / `data/raw/pcap/synthetic_sample.pcap`: a repeating
narrative attack chain (benign → reconnaissance → SSH bruteforce → lateral movement → C2 →
exfiltration → benign) across a handful of source IPs. It exists purely to validate every stage of
the pipeline end-to-end — including `exfiltration`, which no real CIC-IDS-2018 label maps to (see
`docs/03-mitre-mapping.md`) — before spending time on the real, much larger download. **It is not
real attack data.** The Streamlit demo labels it clearly when in use.

## Real dataset: CIC-IDS-2018

Hosted on AWS Open Data (`cse-cic-ids2018` bucket) — no registration needed via the AWS CLI with
`--no-sign-request`. (UNB also offers a direct-download mirror that does require registration; use
the AWS route unless direct download is preferred.)

```bash
pip install awscli
# List what's there first — exact per-day filenames/dates should be confirmed against the live
# bucket rather than assumed:
aws s3 ls --no-sign-request "s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/"
```

Two folders matter:

- **`Processed Traffic Data for ML Algorithms/`** — pre-computed CICFlowMeter flow CSVs, one (or a
  few) per attack day, a few hundred MB to a few GB each. This is what `pipeline/flow_features.py`
  consumes directly. **Start here** — it's sufficient on its own (flow-only mode).
- **`Original Network Traffic and Log data/`** — raw PCAPs per day, tens of GB each. Optional: only
  needed for packet-level features (`pipeline/packet_features.py`). Pull a day's PCAP only if GPU
  time and disk allow it.

### Recommended subset (not the full ~10-day, ~220GB set)

Pick 3–4 days covering a spread of attack types rather than everything, to keep training tractable
on a single machine:

1. One early day with **Benign + FTP/SSH-Bruteforce** (Initial Access).
2. The **Infiltration** day (Lateral Movement) — CIC-IDS-2018 labels this `Infilteration` (dataset's
   spelling, handled in `pipeline/mitre_mapping.py`).
3. The **Bot** day (Command & Control).
4. Optionally, one **DoS/DDoS** day — useful for the `impact` bucket even though it's not one of the
   five PS stages (see `docs/03-mitre-mapping.md`).

Download the chosen days' CSVs into `data/raw/flows/` (and PCAPs into `data/raw/pcap/` if used),
then re-run:

```bash
python -m pipeline.build_dataset
python -m models.train
python -m eval.benchmark
```

`pipeline/build_dataset.py` concatenates every `*.csv` in `data/raw/flows/` and every `*.pcap` in
`data/raw/pcap/`, so multiple days just need to sit in those directories together.

## Feature schema

The exact ordered feature vector lives in `configs/default.yaml` under `features:` — this is the
single source of truth `flow_features.py`/`packet_features.py`/`windowing.py`/`world_model.py` all
read from. Summary:

| Group | Features |
|---|---|
| Flow-level | flow_count, unique_dst_ports, unique_dst_ips, total_bytes, total_packets, mean_duration, syn/ack/fin/rst/psh/urg_ratio, mean/var/max_iat, bidir_ratio, tcp_ratio, udp_ratio |
| Packet-level | mean/var_ttl, mean_window_size, frag_ratio, mean/std_payload_size, port_scan_score, retransmit_ratio |

Windowing parameters (window size, sequence length, forecast horizon) are also in
`configs/default.yaml` under `windowing:`.
