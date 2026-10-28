"""docs/15: turn a checkpoint's output on a processed dataset into a detector table for
`python -m pipeline.stage_events --detections` (the events_from_detections path of docs/14).

One row per sequence (= per host and predicted window): host = src_ip; window_start = start of the window the model
predicts (last input window + window_seconds, i.e. t+1); stage = argmax of the stage head over the NON-benign classes
when the t+1 infiltration probability is >= --threshold, else 'benign'; confidence = that probability.

    python -m eval.joint_v3_detections --config configs/joint_v3_Bplus.yaml --checkpoint <ckpt> \
        --data-dir data/processed_adapter/cic2017_zeroshot_60s_noMon --splits train,val,test --window-seconds 60 --out x.csv

The world model's stage head has no `impact` class and reconnaissance only exists via a heuristic (docs/14), so this
detector can never emit those two stages; that is a property of the model, not of this exporter.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


def detections_table(p_inf: np.ndarray, stage_probs: np.ndarray, src_ip: np.ndarray, last_window_start: np.ndarray,
                     window_s: float, stages: list[str], threshold: float = 0.40) -> pd.DataFrame:
    """stage_probs (N, C) over `stages` (index 0 = benign)."""
    nb = np.argmax(stage_probs[:, 1:], axis=1) + 1
    names = np.asarray(stages)[nb]
    stage = np.where(p_inf >= threshold, names, "benign")
    start = pd.to_datetime(np.asarray(last_window_start).astype("datetime64[ns]")) + pd.to_timedelta(window_s, unit="s")
    return pd.DataFrame({"host": np.asarray(src_ip).astype(str), "window_start": start, "stage": stage,
                         "confidence": p_inf.astype(float), "window_s": float(window_s)})


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", required=True)
    ap.add_argument("--checkpoint", default=None)
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--splits", default="test")
    ap.add_argument("--window-seconds", type=float, required=True)
    ap.add_argument("--threshold", type=float, default=0.40)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    import torch
    from common.config import load_config, resolve_path
    from eval.joint_v3_eval import load_arr
    from models.dataset import FeatureScaler
    from models.forecast import load_world_model

    cfg = load_config(a.config)
    ckpt = Path(a.checkpoint) if a.checkpoint else resolve_path(cfg, "checkpoint_dir") / "world_model_best.pt"
    model, _ = load_world_model(ckpt)
    device = next(model.parameters()).device
    scaler = FeatureScaler.load(resolve_path(cfg, "processed_dir") / "scaler.npz")
    arr = load_arr(f"{a.data_dir}:{a.splits}")
    X = torch.tensor(scaler.transform(arr["X"]), dtype=torch.float32)
    p_all, s_all = [], []
    with torch.no_grad():
        for i in range(0, len(X), 8192):
            _, sl, il = model(X[i:i + 8192].to(device))
            p_all.append(torch.sigmoid(il).cpu().numpy())
            s_all.append(torch.softmax(sl, dim=-1).cpu().numpy())
    df = detections_table(np.concatenate(p_all), np.concatenate(s_all), arr["src_ip"], arr["window_times"][:, -1],
                          a.window_seconds, list(cfg["mitre_stages"]), a.threshold)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(a.out, index=False)
    print(f"wrote {a.out}: {len(df)} rows, alarmed {(df.stage != 'benign').sum()}, by stage {df.stage.value_counts().to_dict()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
