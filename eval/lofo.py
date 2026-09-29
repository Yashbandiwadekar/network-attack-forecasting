"""Leave-one-attack-family-out evaluation (audit S8): train with one attack family's days removed
entirely, then test on those days (plus a benign-only day so false positives are measured too).
This is the measurable version of the PS requirement "generalise to unseen attack patterns".

Families are defined by which days carry which ATT&CK-mapped CIC-IDS-2018 labels (see
configs/real_data_v2.yaml). Everything is written under data/processed_real_v2_lofo/<family>/ and
checkpoints_real_v2_lofo/<family>/; the original v1 and v2 artefacts are never touched.

Usage:
    python -m eval.lofo --families initial_access lateral_movement --epochs 8
"""
from __future__ import annotations

import argparse
import copy
import json

import numpy as np
import torch
import yaml
from sklearn.metrics import average_precision_score, roc_auc_score

from common.config import PROJECT_ROOT, load_config, resolve_path
from eval.metrics import binary_metrics, threshold_at_fpr
from models.dataset import build_datasets, load_split
from models.forecast import load_world_model
from models.train import train
from pipeline.build_dataset import day_disjoint_split, save_splits

BASE_CONFIG = "configs/real_data_v2.yaml"
BENIGN_TEST_DAY = "04-02"
BENIGN_VAL_DAY = "04-01"
FAMILY_DAYS = {
    "initial_access": ["02-14", "02-22", "02-23"],
    "lateral_movement": ["02-28", "03-01"],
    "command_and_control": ["03-02"],
    "impact": ["02-15", "02-16", "02-20", "02-21"],
}


def fold_days(family: str) -> dict[str, list[str]]:
    """Held-out family + a benign day for test; a benign day + the last day of one other family for
    val (so val still has positives for threshold selection); everything else trains."""
    held = FAMILY_DAYS[family]
    other = next(f for f in FAMILY_DAYS if f != family)
    val = [BENIGN_VAL_DAY, FAMILY_DAYS[other][-1]]
    test = held + [BENIGN_TEST_DAY]
    all_days = {d for days in FAMILY_DAYS.values() for d in days} | {BENIGN_VAL_DAY, BENIGN_TEST_DAY}
    return {"train": sorted(all_days - set(val) - set(test)), "val": val, "test": test}


def _fold_config(base: dict, family: str, days: dict[str, list[str]], epochs: int | None) -> dict:
    cfg = copy.deepcopy(base)
    cfg["paths"]["processed_dir"] = f"data/processed_real_v2_lofo/{family}"
    cfg["paths"]["checkpoint_dir"] = f"checkpoints_real_v2_lofo/{family}"
    cfg["split"] = {"mode": "by_day", **{f"{k}_days": v for k, v in days.items()}}
    if epochs:
        cfg["model"]["epochs"] = epochs
    return cfg


def prepare_fold(family: str, epochs: int | None = None) -> str:
    base = load_config(BASE_CONFIG)
    src = resolve_path(base, "processed_dir")
    parts = [load_split(src, s) for s in ("train", "val", "test")]
    seqs = {k: np.concatenate([p[k] for p in parts]) for k in parts[0]}
    days = fold_days(family)
    cfg = _fold_config(base, family, days, epochs)
    out = resolve_path(cfg, "processed_dir")
    save_splits(day_disjoint_split(seqs, cfg["split"], base["windowing"]["window_seconds"],
                                   base["windowing"]["forecast_horizon"]), out)
    cfg_path = out / "config.yaml"
    cfg_path.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    return str(cfg_path.relative_to(PROJECT_ROOT))


def _predict_infiltration(
    model, X: torch.Tensor, device, batch_size: int = 8192, return_stage: bool = False,
):
    """Batched inference -- the `impact` fold's held-out test set is ~1.2M sequences (it's the
    DDoS days, the largest slice of the dataset by far); pushing that through the model in one
    forward pass OOM'd a 16GB GPU (7+ GiB single allocation for the FFN activations alone).

    Audit G10: reused (not re-implemented) by eval/benchmark.py::_world_model_predictions, which
    had the exact same unbatched-forward-pass pattern. `return_stage=True` also returns the
    argmax stage prediction per window, batched the same way."""
    probs, stages = [], []
    with torch.no_grad():
        for start in range(0, len(X), batch_size):
            batch = X[start:start + batch_size].to(device)
            _, stage_logits, infiltration_logit = model(batch)
            probs.append(torch.sigmoid(infiltration_logit).cpu().numpy())
            if return_stage:
                stages.append(torch.softmax(stage_logits, dim=-1).argmax(dim=-1).cpu().numpy())
    probs_out = np.concatenate(probs) if probs else np.zeros(0)
    if not return_stage:
        return probs_out
    stages_out = np.concatenate(stages) if stages else np.zeros(0, dtype=np.int64)
    return probs_out, stages_out


def evaluate_fold(cfg_path: str, family: str, seed: int | None = None) -> dict:
    config = load_config(cfg_path)
    _, val_ds, test_ds, _ = build_datasets(config)
    ckpt_dir = resolve_path(config, "checkpoint_dir")
    if seed is not None:
        # models.train writes to checkpoint_dir/seed<N> when seeded (audit E10), so read it back
        # from the same place rather than silently scoring another seed's checkpoint.
        ckpt_dir = ckpt_dir / f"seed{seed}"
    model, _ = load_world_model(ckpt_dir / "world_model_best.pt")
    device = next(model.parameters()).device
    val_p = _predict_infiltration(model, val_ds.X, device)
    test_p = _predict_infiltration(model, test_ds.X, device)
    yv, yt = val_ds.infiltration[:, 0].numpy(), test_ds.infiltration[:, 0].numpy()
    # A window inside a held-out attack day; benign windows on those days are also negatives.
    result = {
        "family": family, "seed": seed, "held_out_days": fold_days(family)["test"],
        "n_test": int(len(yt)), "n_test_positive": int(yt.sum()),
        "auroc": float(roc_auc_score(yt, test_p)) if 0 < yt.sum() < len(yt) else None,
        "auprc": float(average_precision_score(yt, test_p)) if yt.sum() > 0 else None,
    }
    for tag, thr in [("at_0.5", 0.5), ("at_val_1pct_fpr", threshold_at_fpr(yv, val_p, 0.01)),
                     ("at_val_0.1pct_fpr", threshold_at_fpr(yv, val_p, 0.001))]:
        result[tag] = {"threshold": float(thr), **{k: float(v) for k, v in binary_metrics(yt, test_p, thr).items()}}
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--families", nargs="+", default=list(FAMILY_DAYS), choices=list(FAMILY_DAYS))
    parser.add_argument("--epochs", type=int, default=None, help="override model.epochs for faster folds")
    parser.add_argument("--skip-train", action="store_true", help="evaluate existing fold checkpoints only")
    parser.add_argument("--seed", type=int, default=None,
                        help="Seed the RNGs; checkpoints go to checkpoint_dir/seed<N> and results to "
                             "lofo_results_v2_seed<N>.json (audit E10). Default: unseeded, as before.")
    args = parser.parse_args()
    out_dir = PROJECT_ROOT / "docs"
    results = []
    for family in args.families:
        print(f"\n===== fold: hold out {family} =====")
        cfg_path = prepare_fold(family, args.epochs) if not args.skip_train else \
            f"data/processed_real_v2_lofo/{family}/config.yaml"
        if not args.skip_train:
            train(cfg_path, seed=args.seed)
        results.append(evaluate_fold(cfg_path, family, seed=args.seed))
        print(json.dumps(results[-1], indent=2))
    name = "lofo_results_v2.json" if args.seed is None else f"lofo_results_v2_seed{args.seed}.json"
    (out_dir / name).write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nwrote {out_dir / name}")


if __name__ == "__main__":
    main()
