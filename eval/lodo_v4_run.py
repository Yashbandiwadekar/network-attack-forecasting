"""docs/18 driver: leave-one-day-out out-of-fold (OOF) training of the CIC-2018 Transformer recipe and of the tabular
baselines on the SAME folds, then the frozen-selection sealed-test stage.

Stages (each is a separate invocation, so the order "protocol -> OOF -> selection -> sealed test" is enforced by files):

  python -m eval.lodo_v4_run oof     [--seeds 1 2 3 4 5] [--epochs 20] [--folds NAME ...]
        trains per fold x seed, stores per-epoch OOF probabilities + baseline OOF scores under checkpoints_lodo_v4/oof/.
        Reads ONLY data/processed_adapter/lodo_v4 (train+val days). test.npz is not opened.
  python -m eval.lodo_v4_run select
        reads the OOF files, applies the pre-registered rules (eval/lodo_v4.py), writes docs/lodo_v4/selection.json.
  python -m eval.lodo_v4_run final
        refuses to run without selection.json and refuses to run twice (docs/lodo_v4/test_sealed.json); trains the selected
        recipe(s) on all seven days, then opens the sealed test split ONCE.

Nothing existing is modified: checkpoints, data/processed*, configs are only read; scalers are fitted in memory per fold.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common.config import feature_columns, load_config  # noqa: E402
from eval import lodo_v4 as L  # noqa: E402
from eval.baseline_gate import BASELINE_NAMES, baseline_scores, fit_baselines  # noqa: E402
from models.checkpoint_io import with_config_json  # noqa: E402
from models.dataset import FeatureScaler  # noqa: E402
from models.train import _step_loss  # noqa: E402
from models.world_model import WorldModel  # noqa: E402

CONFIG_PATH = "configs/real_data_v2_converged_seed1.yaml"     # architecture / features / lr / batch size: unchanged
CACHE = ROOT / "data" / "processed_adapter" / "lodo_v4"
CKPT = ROOT / "checkpoints_lodo_v4"
OOF = CKPT / "oof"
RES = ROOT / "docs" / "lodo_v4"
N20 = 70_000            # sequences of 02-20 kept for training (B-recipe scale, docs/15); fixed row sample, seed 0
N_GROUPS = 3
KEYS = ["X", "next_state", "future_stages", "infiltration"]
FCOL = None


def _dev() -> torch.device:
    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


def load_pool(n20: int = N20, seed: int = 0) -> dict:
    """All seven LODO days as one training pool (02-20 reduced to a fixed uniform row sample of n20) plus the memory-mapped
    full 02-20 arrays for evaluating its held-out host groups."""
    out: dict = {"days": {}, "mm": {}}
    xs = {k: [] for k in KEYS}
    day, host = [], []
    for d in L.LODO_DAYS:
        a = {k: np.load(CACHE / d / f"{k}.npy", mmap_mode="r") for k in KEYS + ["src_ip", "current_infiltration"]}
        if d == L.HOST_SPLIT_DAY:
            out["mm"] = a
            n = len(a["X"])
            idx = np.sort(np.random.default_rng(seed).choice(n, n20, replace=False))
            sel = {k: np.asarray(a[k][idx]) for k in a}
            out["idx20"] = idx
        else:
            sel = {k: np.asarray(a[k]) for k in a}
        for k in KEYS:
            xs[k].append(sel[k])
        day += [d] * len(sel["X"])
        host += list(sel["src_ip"].astype(str))
    pool = {k: np.concatenate(v) for k, v in xs.items()}
    out.update(pool=pool, day=np.array(day), host=np.array(host))
    # host groups of 02-20 (attacking hosts spread over the groups)
    h20 = np.asarray(out["mm"]["src_ip"]).astype(str)
    y20 = np.asarray(out["mm"]["infiltration"][:, 0]) > 0
    out["host_group"] = L.assign_host_groups(set(h20), set(h20[y20]), N_GROUPS, seed=0)
    for h in set(out["host"]):
        out["host_group"].setdefault(h, 0)             # pseudo-host days: groups are unused
    out["h20"] = h20
    return out


def heldout_data(P: dict, fold: L.Fold) -> dict:
    """Held-out rows of a fold: the whole day for a day fold; ALL sequences of the held-out host group for a host-group fold."""
    if fold.group is None:
        m = P["day"] == fold.day
        return {"X": P["pool"]["X"][m], "y": (P["pool"]["infiltration"][m][:, 0] > 0).astype(np.int8),
                "host": P["host"][m], "idx": np.flatnonzero(m)}
    g = np.array([P["host_group"][h] for h in P["h20"]])
    idx = np.flatnonzero(g == fold.group)
    return {"X": np.asarray(P["mm"]["X"][idx]), "y": (np.asarray(P["mm"]["infiltration"][idx][:, 0]) > 0).astype(np.int8),
            "host": P["h20"][idx], "idx": idx}


def train_rows(P: dict, fold: L.Fold) -> np.ndarray:
    tr, he = L.fold_masks(fold, P["day"], P["host"], P["host_group"])
    L.assert_no_leakage(fold, P["day"], P["host"], tr, he, P["host_group"])
    return tr


def _predict(model, Xs: torch.Tensor, bs: int = 16384) -> np.ndarray:
    out = []
    with torch.no_grad():
        for i in range(0, len(Xs), bs):
            _, _, logit = model(Xs[i:i + bs])
            out.append(torch.sigmoid(logit).float().cpu().numpy())
    return np.concatenate(out)


def fit_transformer(Xtr, ntr, ftr, itr, scaler: FeatureScaler, config: dict, seed: int, epochs: int,
                    eval_X: np.ndarray | None, snapshot_epochs=(), snapshot_dir: Path | None = None):
    """GPU-resident training loop: same model, loss (mse + ce + bce on t+1), optimiser, lr and batch size as models/train.py;
    no DataLoader (data lives on the device). Returns (per-epoch probabilities on eval_X [E, n] or None, seconds)."""
    dev = _dev()
    torch.manual_seed(seed)
    np.random.seed(seed)
    n_features = Xtr.shape[-1]
    model = WorldModel(n_features, len(config["mitre_stages"]), config).to(dev)
    opt = torch.optim.Adam(model.parameters(), lr=config["model"]["lr"])
    bs = config["model"]["batch_size"]
    X = torch.tensor(scaler.transform(Xtr), dtype=torch.float32, device=dev)
    NS = torch.tensor(scaler.transform(ntr), dtype=torch.float32, device=dev)
    FS = torch.tensor(ftr, dtype=torch.long, device=dev)
    IN = torch.tensor(itr, dtype=torch.float32, device=dev)
    EX = None if eval_X is None else torch.tensor(scaler.transform(eval_X), dtype=torch.float32, device=dev)
    probs = []
    t0 = time.time()
    n = len(X)
    for ep in range(epochs):
        model.train()
        perm = torch.randperm(n, device=dev)
        for i in range(0, n, bs):
            j = perm[i:i + bs]
            opt.zero_grad(set_to_none=True)
            loss, _ = _step_loss(model, (X[j], NS[j], FS[j], IN[j]), dev)
            loss.backward()
            opt.step()
        model.eval()
        if EX is not None:
            probs.append(_predict(model, EX))
        if (ep + 1) in snapshot_epochs and snapshot_dir is not None:
            snapshot_dir.mkdir(parents=True, exist_ok=True)
            # same safe format as models/train.py (config as JSON, tensors only), so torch.load(weights_only=True) and the
            # checkpoint-format test accept it; the scaler travels with the weights as tensors
            torch.save(with_config_json({
                "model_state": model.state_dict(), "n_features": n_features, "n_stage_classes": len(config["mitre_stages"]),
                "feature_names": feature_columns(config), "config": config, "epoch": ep + 1, "seed": seed,
                "scaler_mean": torch.tensor(scaler.mean), "scaler_std": torch.tensor(scaler.std),
                "scaler_clip_std": float(scaler.clip_std)}), snapshot_dir / f"ep{ep + 1}.pt")
    if dev.type == "cuda":
        torch.cuda.synchronize()
    return (np.stack(probs) if probs else None), time.time() - t0


# ----------------------------------------------------------------------------- stage: oof

def stage_oof(seeds, epochs, only_folds=None) -> None:
    config = load_config(CONFIG_PATH)
    names = feature_columns(config)
    j_fc = names.index("flow_count")
    OOF.mkdir(parents=True, exist_ok=True)
    P = load_pool()
    folds = L.build_folds(n_groups=N_GROUPS)
    log = []
    for fold in folds:
        if only_folds and fold.name not in only_folds:
            continue
        tr = train_rows(P, fold)
        H = heldout_data(P, fold)
        pool = P["pool"]
        if fold.group is not None:
            assert not (set(H["host"]) & set(P["host"][tr & (P["day"] == fold.day)])), "host leak"
        cov = L.family_coverage(fold, set(P["day"][tr]))
        Xtr, ntr, ftr, itr = (pool[k][tr] for k in KEYS)
        ytr = (itr[:, 0] > 0).astype(int)
        scaler = FeatureScaler().fit(Xtr)
        f_base = OOF / f"{fold.name}__baselines.npz"
        if not f_base.exists():
            t0 = time.time()
            models = fit_baselines(Xtr, ytr, j_fc, max_train_rows=None)
            sc = baseline_scores(models, H["X"])
            np.savez(f_base, y=H["y"], idx=H["idx"], **sc)
            print(f"[{fold.name}] baselines fitted+scored in {time.time() - t0:.0f}s  train={len(ytr)} pos={int(ytr.sum())} "
                  f"held={len(H['y'])} pos={int(H['y'].sum())}", flush=True)
        for seed in seeds:
            f_out = OOF / f"{fold.name}__s{seed}.npz"
            if f_out.exists():
                continue
            probs, secs = fit_transformer(Xtr, ntr, ftr, itr, scaler, config, seed, epochs, H["X"])
            np.savez(f_out, probs=probs.astype(np.float32), y=H["y"], idx=H["idx"])
            auc = [L._auc(H["y"], probs[e]) for e in range(len(probs))]
            log.append({"fold": fold.name, "seed": seed, "gpu_seconds": secs, "n_train": int(len(ytr)), "n_held": int(len(H["y"]))})
            print(f"[{fold.name}] seed {seed}: {secs:.0f}s  within-fold AUROC per epoch "
                  f"{' '.join('nan' if np.isnan(a) else f'{a:.2f}' for a in auc)}   coverage={cov['family_in_train']}", flush=True)
            (RES).mkdir(parents=True, exist_ok=True)
            with open(RES / "oof_timing.jsonl", "a", encoding="utf-8") as fh:
                fh.write(json.dumps(log[-1]) + "\n")
        del scaler


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["oof", "select", "final", "export"])
    ap.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3, 4, 5])
    ap.add_argument("--epochs", type=int, default=20)
    ap.add_argument("--folds", nargs="+", default=None)
    a = ap.parse_args()
    if a.stage == "oof":
        stage_oof(a.seeds, a.epochs, a.folds)
    elif a.stage == "select":
        from eval.lodo_v4_select import stage_select
        stage_select()
    elif a.stage == "export":
        from eval.lodo_v4_select import stage_export
        stage_export()
    else:
        from eval.lodo_v4_select import stage_final
        stage_final()


if __name__ == "__main__":
    main()
