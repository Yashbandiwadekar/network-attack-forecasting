"""Can the model FORECAST a DoS attack, or only detect one? (held-out 02-16)

Asked directly by the user: "do a demo where there is a dos attack which it can predict or not".
This answers it on real held-out data with the decision rule fixed before the numbers were seen.

Why 02-16: it is a **test** day (configs/real_data_v2_converged.yaml split.test_days), and its
601,803 non-benign flows are 100% DoS (Hulk, SlowHTTPTest, GoldenEye, Slowloris). 02-20 and 02-21
are also DoS days but sit in `train_days`, so running there would measure memorisation; 02-15 is
the validation day used for model selection. 02-16 is the only untouched DoS data.

Two findings this script exists to make measurable, both established by reading the pipeline:

1. **DoS is a positive for the infiltration head but invisible to the stage head.** CIC's DoS
   labels map to `impact` (pipeline/mitre_mapping.py), and `impact` is not in
   STAGE_CLASSIFICATION_LABELS, so `_stage_idx_or_masked` returns -1 and the stage loss ignores
   those windows. But `infiltration` is built as `0.0 if stage == BENIGN else 1.0`
   (pipeline/windowing.py), which makes every DoS window a positive. So the model is trained to
   raise attack probability on DoS while being structurally unable to name it. "infiltration" is
   therefore a misnomer for what that head predicts -- it is an any-attack head.

2. **k=6 is not 60 seconds here.** Windows with no flows are dropped, not zero-filled, so six
   steps span six *non-empty* windows, which on this day is frequently many minutes. Lead time is
   therefore reported in measured wall-clock seconds from `window_times`, never as k x 10s.

Forecast vs detection, kept apart deliberately. A high probability on a window that is ALREADY
under attack is detection and proves nothing about forecasting. A genuine forecast is scored only
from a window whose own observed state is still benign, predicting an onset L steps later:

    at window (o - L), read rollout step k = L, which lands exactly on onset window o

    python -m scripts.demo_dos_forecast
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from app import service
from common.config import resolve_path
from models.forecast import ForecastEngine

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUT_JSON = PROJECT_ROOT / "docs" / "dos_forecast_demo.json"

# --- Pre-registered decision rule. Fixed BEFORE any probability was inspected, and taken from
#     thresholds the project already shipped rather than invented here: 0.40 is the dashboard's
#     "serious" band (app/service.py::SEVERITY_LEVELS) and 0.50 is the streaming alert threshold
#     (scripts/stream_consumer.py). Not tuned on this day's results.
THRESHOLDS = (0.40, 0.50)


def _rate(vals, t):
    return round(float(np.mean([v >= t for v in vals])), 4) if len(vals) else None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/real_data_v2_converged.yaml")
    ap.add_argument("--day", default="02-16")
    ap.add_argument("--split", default="test")
    args = ap.parse_args()

    config, model, scaler, _ = service.load_backend(args.config)
    if model is None:
        raise SystemExit(f"No checkpoint for {args.config}")
    engine = ForecastEngine(model, scaler, config)

    d = np.load(resolve_path(config, "processed_dir") / f"{args.split}.npz", allow_pickle=True)

    ips = np.array([str(x) for x in d["src_ip"]])
    mask = np.char.find(ips, args.day) >= 0
    if not mask.any():
        raise SystemExit(f"No {args.split} windows matching {args.day}")

    X = d["X"][mask]
    infil = d["infiltration"][mask]
    fstage = d["future_stages"][mask]
    wend = d["window_end_time"][mask]
    cur_infil = d["current_infiltration"][mask]
    host = ips[mask][0]

    order = np.argsort(wend, kind="stable")
    X, infil, fstage, wend, cur_infil = (a[order] for a in (X, infil, fstage, wend, cur_infil))
    n = len(X)

    nxt_attack = infil[:, 0].astype(int)
    nxt_is_dos = (fstage[:, 0] == -1).astype(int)

    # --- Real rollout, batched -- the same call the dashboard makes.
    res = engine.rollout_batch([f"w{i}" for i in range(n)], X)
    probs = np.asarray(getattr(res, "infiltration_probs", res), dtype=np.float32)
    if probs.ndim == 1:
        probs = probs.reshape(n, -1)
    horizon = probs.shape[1]

    # --- What does it NAME a DoS window? The trained head has no `impact` class, so anything
    #     reading `impact` came from `_heuristic_stage_override` (a volume z-score rule), not from
    #     the network. `stage_is_heuristic` is what the project uses to disclose that, and it is
    #     reported here rather than letting a heuristic label pass as a prediction.
    stage_pred = res.stage_predictions
    stage_heur = getattr(res, "stage_is_heuristic", None)
    dos_rows = [i for i in range(n) if cur_infil[i] == 1.0]
    import collections
    named = collections.Counter(stage_pred[i][0] for i in dos_rows) if dos_rows else {}
    named_heur = (collections.Counter(
        stage_pred[i][0] for i in dos_rows if stage_heur and stage_heur[i][0]) if dos_rows else {})

    # --- Onsets: next window is DoS, this window is still observed-benign, and we were not
    #     already in an attack run (so each contiguous DoS burst contributes one onset).
    onsets = [i for i in range(1, n)
              if nxt_is_dos[i] == 1 and cur_infil[i] == 0.0 and nxt_attack[i - 1] == 0]

    # --- Genuine forecast attempts: predict onset o from window o-L, reading rollout step k=L.
    #     The source window must itself still be benign, otherwise this is detection.
    attempts = []
    for o in onsets:
        for L in range(1, horizon + 1):
            j = o - L
            if j < 0 or cur_infil[j] != 0.0:
                continue
            lead_s = int(wend[o].astype("datetime64[s]").astype(np.int64)
                         - wend[j].astype("datetime64[s]").astype(np.int64))
            attempts.append({
                "onset_index": int(o),
                "onset_time": str(wend[o]),
                "steps_ahead": L,
                "lead_seconds_measured": lead_s,
                "prob": round(float(probs[j, L - 1]), 4),
            })

    det = np.array([probs[i, 0] for i in range(n) if cur_infil[i] == 1.0], dtype=np.float32)
    quiet = np.array([probs[i, 0] for i in range(n)
                      if cur_infil[i] == 0.0 and nxt_attack[i] == 0], dtype=np.float32)
    att_p = np.array([a["prob"] for a in attempts], dtype=np.float32)

    summary = {
        "_comment": (
            "Does the model forecast DoS or only detect it? Held-out 02-16 (100% DoS among "
            "non-benign flows). Thresholds pre-registered in the script before results were "
            "seen. Lead time is MEASURED wall-clock from window_end_time, not k x 10s, because "
            "the pipeline drops empty windows."
        ),
        "day": args.day,
        "split": args.split,
        "host": host,
        "host_note": ("pseudo-host: this CIC CSV has no Src IP column, so the whole day is one "
                      "network-wide series (pipeline/flow_features.py::_fill_missing_ip_columns). "
                      "This is NOT per-host forecasting."),
        "windows": int(n),
        "windows_next_is_attack": int(nxt_attack.sum()),
        "windows_next_is_dos": int(nxt_is_dos.sum()),
        "dos_visible_to_trained_stage_head": False,
        "dos_counts_as_infiltration_positive": True,
        "stage_named_on_dos_windows": dict(named),
        "stage_named_on_dos_windows_via_heuristic": dict(named_heur),
        "stage_naming_note": (
            "The trained 6-class head has no `impact` class, so any `impact` here came from "
            "models/forecast.py::_heuristic_stage_override -- a volume z-score rule disclosed via "
            "`stage_is_heuristic`, NOT a trained prediction. Without it the trained head calls "
            "DoS `command_and_control` (570/684 on real data, audit S7)."
        ),
        "onsets_found": len(onsets),
        "thresholds_preregistered": list(THRESHOLDS),
        "forecast_attempts": attempts,
        "forecast_hit_rate": {str(t): _rate(att_p, t) for t in THRESHOLDS},
        "detection_already_under_attack": {
            "n": int(det.size),
            "mean_prob": round(float(det.mean()), 4) if det.size else None,
            "fire_rate": {str(t): _rate(det, t) for t in THRESHOLDS},
        },
        "benign_quiet_windows": {
            "n": int(quiet.size),
            "mean_prob": round(float(quiet.mean()), 4) if quiet.size else None,
            "false_positive_rate": {str(t): _rate(quiet, t) for t in THRESHOLDS},
        },
    }
    OUT_JSON.write_text(json.dumps(summary, indent=1), encoding="utf-8")

    print(f"\nDoS forecast demo -- {args.day} ({args.split} split), host {host}")
    print(f"  {n} windows | next-is-DoS {int(nxt_is_dos.sum())} | onsets {len(onsets)}")

    print(f"\n  DETECTION -- window already under attack (n={det.size}):")
    if det.size:
        print(f"    mean p={det.mean():.3f}   fires@0.40={_rate(det,0.40)}   @0.50={_rate(det,0.50)}")

    print(f"\n  FORECAST -- source window still benign ({len(attempts)} attempts):")
    for a in attempts:
        flag = "HIT " if a["prob"] >= 0.40 else "miss"
        print(f"    {flag} onset {a['onset_time']}  k={a['steps_ahead']}  "
              f"lead={a['lead_seconds_measured']:>6}s  p={a['prob']:.3f}")
    if att_p.size:
        print(f"    hit rate @0.40={_rate(att_p,0.40)}  @0.50={_rate(att_p,0.50)}")

    if quiet.size:
        print(f"\n  BENIGN QUIET (n={quiet.size}): mean p={quiet.mean():.3f}  "
              f"FPR@0.40={_rate(quiet,0.40)}  @0.50={_rate(quiet,0.50)}")
    print(f"\nwrote {OUT_JSON.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
