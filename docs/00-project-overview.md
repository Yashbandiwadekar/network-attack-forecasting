# Project Overview

## Problem statement summary

Build an AI system that learns the evolving state of a computer network from traffic telemetry
and predicts the likelihood and progression of malicious activity before compromise is complete —
using a "World Model" approach (learned transition dynamics `P(S_t+1 | S_t)`) rather than static
per-flow classification. Required capabilities:

1. Ingest flow-level (NetFlow/IPFIX) and packet-level (PCAP) traffic features.
2. Learn network state-transition dynamics with a sequence model (LSTM/Transformer/GNN).
3. Forecast future network states via K-step forward simulation and estimate infiltration probability.
4. Map predicted behaviour to MITRE ATT&CK stages (Reconnaissance, Initial Access, Lateral Movement,
   Command & Control, Exfiltration).
5. Explain every prediction (attention or SHAP) — black-box outputs are explicitly not acceptable.
6. Ship a working offline demo and benchmark against a static-classifier baseline.

Full original text: `C:\Users\Yash\Documents\Texts\AI based Network Attack Forecasting.md`.

## What this repo delivers

- A dual-level (flow + packet) feature extraction pipeline against CIC-IDS-2018 — `pipeline/`.
- A Transformer world model trained via supervised dynamics learning on labelled attack-timeline
  transitions — `models/world_model.py`, `models/train.py`.
- A K-step autoregressive forecast engine built on that model — `models/forecast.py`.
- Attention-based (temporal) and SHAP-based (feature) explainability, wired into every forecast —
  `models/explain.py`.
- A logistic-regression baseline and benchmark harness — `models/baseline_lr.py`, `eval/`.
- An offline React dashboard — `frontend/`, served by the REST API in `app/server.py`.

## Key design decisions and why

- **Transformer over GNN**: the problem statement accepts either; a Transformer gives native
  attention-based explainability "for free" and fits the timeline far better than the graph
  construction a GNN would need. See `docs/01-architecture.md`.
- **MITRE stage mapping is a documented heuristic, not a dataset fact**: CIC-IDS-2018 labels don't
  map 1:1 onto the five requested stages. The mapping and its limitations are made explicit in
  `docs/03-mitre-mapping.md` rather than silently overclaiming ground truth that doesn't exist.
- **Synthetic sample first, real dataset second**: CIC-IDS-2018 is tens of GB and needs UNB
  registration to download. Every component is built and unit-tested against a small synthetic
  traffic sample (`scripts/make_synthetic_sample.py`) so the pipeline is verifiably correct before
  spending GPU time on the real download. See `docs/02-dataset-and-features.md`.

## Status

Pipeline, world model, baseline, forecast engine, explainability, benchmark, and demo are all
built and validated end-to-end against the synthetic sample (`pytest tests/` green, demo verified
in-browser). Training against the real CIC-IDS-2018 subset is the remaining step — instructions in
`docs/02-dataset-and-features.md`.
