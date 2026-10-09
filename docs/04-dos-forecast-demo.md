# Can it forecast a DoS attack? (held-out 02-16)

**Run 2026-10-10.** `scripts/demo_dos_forecast.py`, config `configs/real_data_v2_converged.yaml`.
Raw output: `docs/dos_forecast_demo.json`.

## Short answer

**No. It detects DoS; it does not forecast it.** Every one of the 12 genuine forecast attempts
failed, at both pre-registered thresholds. On windows already under attack it fires 56% of the
time. That is detection with a 60-second-labelled dashboard on top, not prediction.

This is reported because a demo that shows the alert firing *during* a flood and calls it a
60-second forecast would be showing persistence, not foresight.

## Why 02-16

It is a **test** day (`split.test_days`) and its 601,803 non-benign flows are **100% DoS**
(Hulk, SlowHTTPTest, GoldenEye, Slowloris). 02-20 and 02-21 are also DoS days but sit in
`train_days`, so a demo there measures memorisation; 02-15 is the validation day used for model
selection. 02-16 is the only untouched DoS data in the project.

## Method, with the decision rule fixed in advance

Thresholds were taken from values the project already ships — 0.40 (the dashboard's "serious"
band, `app/service.py::SEVERITY_LEVELS`) and 0.50 (`scripts/stream_consumer.py`'s alert line) —
and written into the script before any probability was inspected. Neither was tuned on this day.

Detection and forecasting are scored separately. A high probability on a window that is *already*
under attack proves nothing about forecasting, so a forecast is counted only from a source window
whose own observed state is still benign, reading the rollout step that lands exactly on the onset:

    at window (o − L), read rollout step k = L, which targets onset window o

## Results

| | n | mean p | fires @0.40 | @0.50 |
|---|---|---|---|---|
| Already under attack (**detection**) | 297 | 0.386 | 56.2% | 55.9% |
| Benign quiet windows (**false positives**) | 184 | 0.063 | 1.1% | 0.5% |
| Benign source → DoS onset (**forecast**) | 12 | 0.172 | **0%** | **0%** |

The 12 forecast attempts, with lead time measured from `window_end_time`:

| Onset | k=1 | k=2 | k=3 | k=4 | k=5 | k=6 |
|---|---|---|---|---|---|---|
| 01:45:00 | 0.111 (50s) | 0.300 (70s) | 0.206 (140s) | 0.248 (210s) | 0.162 (310s) | 0.163 (400s) |
| 10:12:00 | 0.025 (30s) | 0.092 (160s) | 0.153 (170s) | 0.130 (200s) | 0.162 (290s) | 0.146 (370s) |

Highest probability reached before any onset: **0.300**, against a 0.40 threshold. There is no
rising trend toward the onset either — the sequences are flat-to-noisy, which is what you would
expect if the model is reading current volume rather than anticipating a change.

The low false-positive rate (1.1%) is genuine and worth keeping: the model is not simply
alarmist. It is quiet when the network is quiet, loud when the flood is already running, and
silent in the gap between — the one place a forecast would have value.

## Two findings this surfaced

### 1. `k=6` is not 60 seconds on this data

The pipeline **drops windows with no flows** rather than zero-filling them, so six rollout steps
span six *non-empty* windows, not 60 seconds. Measured above: k=6 ranged from **370 to 400
seconds** of real elapsed time, and even k=1 was 30–50s rather than 10s. Any claim of a
"60-second forecast horizon" holds only where traffic is continuous enough that windows are
consecutive. On this day it was not. `scripts/live_forecast.py` reports
`peak_horizon_seconds` as `k × window_seconds`, which inherits the same caveat.

### 2. "infiltration" is an any-attack head, and 20% of its test positives are DoS

`infiltration` is built as `0.0 if stage == BENIGN else 1.0` (`pipeline/windowing.py`), so it is
positive for **every** non-benign stage, DoS included. The name is misleading: it does not mean
the `Infilteration` label, which maps to `lateral_movement`.

Of the 1,482 k=1 positives in the test split, **297 (20%) are DoS** windows whose stage is masked
to −1. These are the same 297 windows `docs/04-evaluation-frozen-state-ablation.md` describes as
"no stage label" — they are specifically the DoS windows, and excluding them moves k=1 AUROC from
0.794 to 0.744. **The DoS windows are the easiest positives in the test set**, and they inflate
the published headline by about 0.05 AUROC.

## What it calls a DoS window

Of the 297 windows actively under DoS attack:

| Named | n | Source |
|---|---|---|
| `impact` | 88 (30%) | **heuristic**, not the trained head |
| `initial_access` | 82 (28%) | trained head — wrong |
| `benign` | 127 (43%) | trained head — wrong |

The trained 6-class head has no `impact` class at all (DoS maps to `impact` in
`pipeline/mitre_mapping.py`, which `_stage_idx_or_masked` sends to −1 and the stage loss ignores).
Every correct `impact` label came from `models/forecast.py::_heuristic_stage_override`, a volume
z-score rule, and the project already discloses that through `stage_is_heuristic` rather than
passing it off as a prediction. That disclosure is the right behaviour and is why this table can
be built at all.

**43% of windows under active DoS flood are labelled `benign` by the stage head.** The attack
probability and the stage label disagree on those windows, and the probability is the one to
trust.

## Limitations

- **n = 2 onsets.** The headline "0 of 12" rests on two attack onsets on one day. It is enough to
  refute a claim of forecasting, not enough to quantify how badly it fails.
- **Not per-host.** This CIC CSV has no `Src IP` column, so the entire day is one pseudo-host
  `NETWORK-2018-02-16` (`pipeline/flow_features.py::_fill_missing_ip_columns`). All three test-day
  hosts are pseudo-hosts, so **the test split contains no per-host forecasting at all.**
- Flow-only checkpoint: packet-level features are zero-filled, so the reconnaissance heuristic
  cannot fire here.
- Onsets are defined from the *labels*, which mark when CIC says the attack began — not when it
  first became observable in the flow features.

## Reproduce

```bash
python -m scripts.demo_dos_forecast
```

The same traffic through the live engine, which exercises the deployment code path rather than
the stored arrays:

```bash
python -m scripts.live_forecast --source csv-replay --speed 0 \
  --path data/raw/flows_real/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv
```

That run produced 489 forecasts and 177 alerts at the 0.50 threshold, clustered in the flood
periods — the same detection-not-forecast behaviour, reached independently.
