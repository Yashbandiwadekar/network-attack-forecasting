"""W21: does the world model's state rollout earn its keep?

Every headline number this project publishes -- F1 0.481, AUROC 0.794, the LOFO folds -- comes
from `eval/lofo.py::_predict_infiltration`, which runs **one** forward pass and scores it against
`infiltration[:, 0]`. That is a t+1 measurement. The K-step rollout that the demo actually shows,
and that the phrase "60-second forecast" refers to, has never been evaluated.

This script measures it, by scoring two rollouts against the same per-horizon labels:

  genuine  -- the real rollout: feed the predicted next state back in and advance the window,
              exactly as ForecastEngine.rollout_batch does.
  frozen   -- the control: never advance the state. Because the model is deterministic, this
              produces the t+1 prediction repeated K times. It answers "would simply reusing the
              first-step estimate for the whole minute do just as well?"

The two are identical at k=1 by construction -- that is the sanity check, not a result. Any
separation at k>1 is the world model earning its keep; no separation means the rollout is
decoration and should be reported as such.

Design note: this deliberately re-uses the scaled tensors from `build_datasets` and mirrors
`rollout_batch`'s state-advance line rather than calling `ForecastEngine`, because the engine
takes raw per-host sequences while the evaluation splits are already scaled. The advance step
(`torch.cat([seq[:, 1:, :], next_state.unsqueeze(1)], dim=1)`) is copied verbatim so the two
paths cannot silently diverge.

    python -m scripts.ablate_frozen_state
    python -m scripts.ablate_frozen_state --config configs/real_data_v2_converged.yaml --seeds 1 2 3
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import average_precision_score, f1_score, roc_auc_score

from common.config import load_config, resolve_path
from models.dataset import build_datasets
from models.forecast import load_world_model

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUT_JSON = PROJECT_ROOT / "docs" / "frozen_state_ablation.json"


def _rollout_probs(model, X: torch.Tensor, horizon: int, device, frozen: bool,
                   batch_size: int = 4096) -> np.ndarray:
    """(N, K) infiltration probabilities.

    frozen=False advances the window with each predicted state (the real rollout).
    frozen=True never advances it, so every step re-scores the original window.
    """
    out = []
    with torch.no_grad():
        for start in range(0, len(X), batch_size):
            seq = X[start:start + batch_size].to(device)
            steps = []
            for _ in range(horizon):
                next_state, _, infiltration_logit = model(seq)
                steps.append(torch.sigmoid(infiltration_logit).cpu().numpy())
                if not frozen:
                    seq = torch.cat([seq[:, 1:, :], next_state.unsqueeze(1)], dim=1)
            out.append(np.stack(steps, axis=1))
    return np.concatenate(out, axis=0)


def _score(y: np.ndarray, p: np.ndarray) -> dict:
    """AUROC/AUPRC/F1 for one horizon. Returns Nones rather than raising when a horizon has no
    positives or no negatives -- that is a property of the split worth seeing, not an error."""
    if not (0 < y.sum() < len(y)):
        return {"n": int(len(y)), "n_positive": int(y.sum()),
                "auroc": None, "auprc": None, "f1_at_0.5": None}
    return {
        "n": int(len(y)),
        "n_positive": int(y.sum()),
        "auroc": float(roc_auc_score(y, p)),
        "auprc": float(average_precision_score(y, p)),
        "f1_at_0.5": float(f1_score(y, (p >= 0.5).astype(int), zero_division=0)),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/real_data_v2_converged.yaml")
    parser.add_argument("--seeds", type=int, nargs="*", default=[1, 2, 3])
    args = parser.parse_args()

    config = load_config(args.config)
    horizon = int(config["windowing"]["forecast_horizon"])
    window_seconds = int(config["windowing"]["window_seconds"])
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    _, _, test_ds, _ = build_datasets(config)
    X = test_ds.X
    y_all = test_ds.infiltration.numpy()           # (N, K) per-horizon labels
    stages_all = test_ds.future_stages.numpy()     # (N, K); -1 marks "no label at this horizon"
    print(f"test split: {len(X)} sequences, horizon K={horizon} x {window_seconds}s "
          f"= {horizon * window_seconds}s")

    ckpt_dir = resolve_path(config, "checkpoint_dir")
    per_seed: dict[str, dict] = {}

    for seed in args.seeds:
        path = ckpt_dir / f"seed{seed}" / "world_model_best.pt"
        if not path.exists():
            print(f"[!] missing {path}, skipping seed {seed}")
            continue
        model, _ = load_world_model(path, device)
        model.eval()

        genuine = _rollout_probs(model, X, horizon, device, frozen=False)
        frozen = _rollout_probs(model, X, horizon, device, frozen=True)

        # No masking. `infiltration` is defined for every window at every horizon; the -1 in
        # future_stages marks a missing *stage* label only. Scoring all 7,191 rows is also what
        # eval/lofo.py::_predict_infiltration does, so k=1 here reproduces the published headline
        # AUROC exactly (0.794 mean over these three seeds) and the reader has an anchor.
        # Masking on future_stages instead drops 297 rows and moves k=1 to 0.744 -- reported as a
        # sensitivity check rather than as the result.
        seed_out = {"genuine": {}, "frozen": {}, "genuine_stage_labelled_only": {}}
        for k in range(horizon):
            seed_out["genuine"][str(k + 1)] = _score(y_all[:, k], genuine[:, k])
            seed_out["frozen"][str(k + 1)] = _score(y_all[:, k], frozen[:, k])
            mask = stages_all[:, k] != -1
            seed_out["genuine_stage_labelled_only"][str(k + 1)] = _score(y_all[mask, k], genuine[mask, k])
        per_seed[f"seed{seed}"] = seed_out

        g1, f1_ = seed_out["genuine"]["1"]["auroc"], seed_out["frozen"]["1"]["auroc"]
        gk, fk = seed_out["genuine"][str(horizon)]["auroc"], seed_out["frozen"][str(horizon)]["auroc"]
        print(f"  seed{seed}: k=1 genuine {g1:.4f} / frozen {f1_:.4f}   "
              f"k={horizon} genuine {gk:.4f} / frozen {fk:.4f}")

    if not per_seed:
        raise SystemExit("No seed checkpoints found -- nothing measured.")

    # Aggregate across seeds.
    agg: dict[str, dict] = {}
    for mode in ("genuine", "frozen"):
        agg[mode] = {}
        for k in range(1, horizon + 1):
            for metric in ("auroc", "auprc", "f1_at_0.5"):
                vals = [per_seed[s][mode][str(k)][metric] for s in per_seed
                        if per_seed[s][mode][str(k)][metric] is not None]
                agg[mode].setdefault(str(k), {})[metric] = (
                    {"mean": float(np.mean(vals)), "sd": float(np.std(vals, ddof=0)),
                     "per_seed": [float(v) for v in vals]} if vals else None
                )

    result = {
        "_comment": (
            "W21 frozen-state ablation. 'frozen' never advances the world model's state, so it is "
            "the t+1 prediction reused for every horizon. Identical to 'genuine' at k=1 by "
            "construction. Generated by scripts/ablate_frozen_state.py."
        ),
        "config": args.config,
        "horizon_k": horizon,
        "window_seconds": window_seconds,
        "horizon_seconds": horizon * window_seconds,
        "n_test_sequences": int(len(X)),
        "seeds": list(per_seed.keys()),
        "per_seed": per_seed,
        "across_seeds": agg,
    }
    OUT_JSON.write_text(json.dumps(result, indent=1), encoding="utf-8")
    print(f"\nwrote {OUT_JSON.relative_to(PROJECT_ROOT)}")

    print(f"\n{'step':>6}  {'seconds':>8}  {'genuine AUROC':>22}  {'frozen AUROC':>22}  {'delta':>8}")
    for k in range(1, horizon + 1):
        g = agg["genuine"][str(k)]["auroc"]
        f = agg["frozen"][str(k)]["auroc"]
        if g and f:
            print(f"{k:>6}  {k*window_seconds:>7}s  {g['mean']:>10.4f} ± {g['sd']:.4f}      "
                  f"{f['mean']:>10.4f} ± {f['sd']:.4f}  {g['mean']-f['mean']:>+8.4f}")


if __name__ == "__main__":
    main()
