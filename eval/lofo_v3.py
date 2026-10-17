"""docs/15: leave-one-attack-family-out on the CONTIGUOUS CIC-2018 build (B), the cheap variant of eval/lofo.py.

eval/lofo.py is bound to configs/real_data_v2.yaml / data/processed_real_v2 and to the fabricated benign days
04-01 / 04-02 (not in the contiguous build). This module reuses its fold definition and its evaluation, but takes the
sequences from `data/processed_adapter/cic18c_v3` (all three splits concatenated, then re-split by day), drops the two
fabricated benign days from the fold lists, and writes everything under NEW directories:
  data/processed_adapter/lofo_v3/<family>/   and   checkpoints_joint_v3/lofo/<family>/seed<N>/

    python -m eval.lofo_v3 --seeds 1 2 3 [--families initial_access ...] [--epochs N]
"""
from __future__ import annotations

import argparse
import copy
import json

import numpy as np
import yaml

from common.config import PROJECT_ROOT, load_config, resolve_path
from eval.lofo import BENIGN_TEST_DAY, BENIGN_VAL_DAY, FAMILY_DAYS, evaluate_fold, fold_days
from models.dataset import load_split
from models.train import train
from pipeline.build_dataset import day_disjoint_split, save_splits

BASE_CONFIG = "configs/joint_v3_B.yaml"


def fold_days_v3(family: str) -> dict[str, list[str]]:
    d = fold_days(family)
    drop = {BENIGN_TEST_DAY, BENIGN_VAL_DAY}
    return {k: [x for x in v if x not in drop] for k, v in d.items()}


def prepare_fold_v3(family: str, epochs: int | None = None) -> str:
    base = load_config(BASE_CONFIG)
    src = resolve_path(base, "processed_dir")
    parts = [load_split(src, s) for s in ("train", "val", "test")]
    keys = set(parts[0]).intersection(*[set(p) for p in parts[1:]])
    seqs = {k: np.concatenate([p[k] for p in parts]) for k in keys}
    days = fold_days_v3(family)
    cfg = copy.deepcopy(base)
    cfg["paths"]["processed_dir"] = f"data/processed_adapter/lofo_v3/{family}"
    cfg["paths"]["checkpoint_dir"] = f"checkpoints_joint_v3/lofo/{family}"
    cfg["split"] = {"mode": "by_day", **{f"{k}_days": v for k, v in days.items()}}
    if epochs:
        cfg["model"]["epochs"] = epochs
    out = resolve_path(cfg, "processed_dir")
    save_splits(day_disjoint_split(seqs, cfg["split"], base["windowing"]["window_seconds"],
                                   base["windowing"]["forecast_horizon"]), out)
    cfg_path = out / "config.yaml"
    cfg_path.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    return str(cfg_path.relative_to(PROJECT_ROOT)) if cfg_path.is_relative_to(PROJECT_ROOT) else str(cfg_path)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--families", nargs="+", default=list(FAMILY_DAYS), choices=list(FAMILY_DAYS))
    ap.add_argument("--seeds", nargs="+", type=int, default=[1, 2, 3])
    ap.add_argument("--epochs", type=int, default=None)
    ap.add_argument("--out", default="docs/joint_v3/lofo_v3.json")
    a = ap.parse_args()
    results = []
    for fam in a.families:
        cfg_path = prepare_fold_v3(fam, a.epochs)
        for s in a.seeds:
            train(cfg_path, seed=s)
            r = evaluate_fold(cfg_path, fam, seed=s)
            r["held_out_days"] = fold_days_v3(fam)["test"]
            print(json.dumps(r), flush=True)
            results.append(r)
    out = PROJECT_ROOT / a.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=1), encoding="utf-8")
    print("wrote", out)


if __name__ == "__main__":
    main()
