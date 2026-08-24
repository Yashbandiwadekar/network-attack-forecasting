# AI-Based Network Attack Forecasting

A world-model AI system that learns network traffic dynamics from flow and packet telemetry,
forecasts attacker progression K steps ahead, maps predicted behaviour to MITRE ATT&CK stages,
and explains every prediction — built for the SIH problem statement of the same name (full text
in `docs/00-project-overview.md`).

Rather than classifying each flow in isolation (the traditional approach the problem statement
explicitly wants moved beyond), the core model learns `P(S_t+1 | S_t-L..S_t)` over windowed
network-state sequences and rolls that forward K steps to simulate whether the current trajectory
is heading toward compromise — before it completes.

## Quick start

```bash
# 1. Create and activate a Python 3.11 virtual environment, then install dependencies
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt      # Windows
# source .venv/bin/activate && pip install -r requirements.txt   # macOS/Linux

# 2. Generate the synthetic sample (so everything below runs immediately, no dataset download needed)
python -m scripts.make_synthetic_sample

# 3. Build the windowed sequence dataset
python -m pipeline.build_dataset

# 4. Train the world model (GPU used automatically if available)
python -m models.train

# 5. Benchmark against the logistic-regression baseline
python -m eval.benchmark

# 6. Launch the demo
streamlit run app/streamlit_app.py
```

To point the pipeline at real CIC-IDS-2018 data instead of the synthetic sample, see
`docs/02-dataset-and-features.md` — drop CICFlowMeter CSVs in `data/raw/flows/` (and PCAPs in
`data/raw/pcap/`, optional) and re-run steps 3–6.

## Project layout

| Path | Purpose |
|---|---|
| `pipeline/` | Flow + packet feature extraction, MITRE stage mapping, time-windowing, sequence building |
| `models/` | The Transformer world model, the logistic-regression baseline, training, K-step forecast rollout, explainability |
| `eval/` | Metrics and the world-model-vs-baseline benchmark |
| `app/streamlit_app.py` | Offline demo UI |
| `scripts/make_synthetic_sample.py` | Generates a synthetic traffic sample for dev/demo before the real dataset is downloaded |
| `configs/default.yaml` | Single source of truth for windowing, features, and model hyperparameters |
| `docs/` | Submission documents — project overview, architecture, dataset notes, MITRE mapping, evaluation results |

## Tests

```bash
pytest tests/
```

## Deliverables checklist (per problem statement)

- [x] Feature extraction pipeline (flow-level + packet-level) — `pipeline/`
- [x] Trained world model with reproducible training config — `models/world_model.py`, `models/train.py`, `configs/default.yaml`
- [x] K-step infiltration prediction engine with MITRE stage mapping — `models/forecast.py`
- [x] Explainability (attention + SHAP) — `models/explain.py`
- [x] Offline demo interface — `app/streamlit_app.py`
- [x] Benchmark vs logistic-regression baseline — `eval/benchmark.py`, results in `docs/04-evaluation.md`
- [ ] Trained on full CIC-IDS-2018 (currently validated end-to-end on a synthetic sample; see `docs/02-dataset-and-features.md` for the real-data download step)
