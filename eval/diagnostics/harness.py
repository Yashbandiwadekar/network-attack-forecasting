"""Shared loading helpers for the docs/16 diagnostics. READ-ONLY with respect to the project: scalers are loaded with
FeatureScaler.load (never re-fit into an existing directory), checkpoints are only loaded, no data/processed* file is
written. Results go to docs/diagnostics16/ (new folder); large caches of the train arrays go to the OS temp dir.

Run any experiment from the project root, e.g.  python -m eval.diagnostics.exp1_perday
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import json
import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from common.config import feature_columns, load_config, resolve_path  # noqa: E402
from eval.lofo import _predict_infiltration  # noqa: E402
from models.dataset import FeatureScaler  # noqa: E402
from models.forecast import load_world_model  # noqa: E402
from eval.diagnostics.core import day_of, load  # noqa: E402,F401  (tested helpers live in core.py)

OUT = ROOT / "docs" / "diagnostics16"
CACHE = Path(os.environ.get("NAF_DIAG_CACHE", Path(tempfile.gettempdir()) / "naf_diag_cache"))
OUT.mkdir(parents=True, exist_ok=True)
CACHE.mkdir(parents=True, exist_ok=True)

CFG = load_config("configs/real_data_v2_converged_seed1.yaml")
NAMES = feature_columns(CFG)
DS = {
    "cic18_test": "data/processed_real_v2_converged:test",
    "cic18_val": "data/processed_real_v2_converged:val",
    "ctu_contig": "data/processed_adapter/ctu13_10s_contig:train,val,test",
    "unsw_contig": "data/processed_adapter/unsw_10s_contig:train,val,test",
    "cic17_60s": "data/processed_adapter/cic2017_zeroshot_60s_noMon:train,val,test",
}
MODELS = {"seed1": ("configs/real_data_v2_converged_seed1.yaml", None)}
for _arm in ["B", "Bplus"]:
    for _s in [1, 2, 3]:
        MODELS[f"{_arm}_s{_s}"] = (f"configs/joint_v3_{_arm}.yaml", f"checkpoints_joint_v3/{_arm}/seed{_s}")


def get_model(name: str, which: str = "best"):
    cfgp, ck = MODELS[name]
    cfg = load_config(cfgp)
    if ck is None:
        ck = resolve_path(cfg, "checkpoint_dir")
    model, _ = load_world_model(Path(ck) / f"world_model_{which}.pt")
    scaler = FeatureScaler.load(resolve_path(cfg, "processed_dir") / "scaler.npz")
    return model, scaler


def score(model, scaler, X: np.ndarray) -> np.ndarray:
    import torch
    dev = next(model.parameters()).device
    return _predict_infiltration(model, torch.tensor(scaler.transform(X), dtype=torch.float32), dev)


def build_train_caches() -> None:
    """Cache the seed-1 train split (2.4 GB of X) as: last windows + labels + day (train_last.npz) and a per-day
    stratified subsample of full sequences (train_sub.npz: all of the 4 pseudo-host days, 30,000 of 02-20)."""
    if (CACHE / "train_last.npz").exists() and (CACHE / "train_sub.npz").exists():
        return
    tr = load("data/processed_real_v2_converged:train")
    d = day_of(tr)
    yt = (tr["infiltration"][:, 0] > 0).astype(float)
    np.savez_compressed(CACHE / "train_last.npz", Xlast=tr["X"][:, -1, :], y=yt, day=d, hasip=tr["X"][:, -1, 3], src=tr["src_ip"])
    rng = np.random.default_rng(0)
    idx = np.concatenate([rng.choice(np.where(d == u)[0], min(30000, int((d == u).sum())), replace=False) for u in np.unique(d)])
    np.savez_compressed(CACHE / "train_sub.npz", **{k: tr[k][idx] for k in
                        ["X", "next_state", "infiltration", "future_stages", "current_infiltration", "window_end_time", "src_ip"]})
