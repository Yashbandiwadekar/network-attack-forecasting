"""Packet-aware vs flow-only, matched, multi-seed, on the held-out day (UNSW-NB15 pilot).

Both variants use the SAME sequences, split and hyper-parameters; the flow-only control just has every
packet-level column zeroed. So any gap is attributable to the packet features and nothing else.
For each seed: score the held-out test day (02-18) with the best-val checkpoint, report AUROC / AUPRC and
precision / recall / FPR at thresholds chosen on val (never on test). Then mean +/- std over seeds and a
bootstrap 95% CI on the paired per-seed AUROC difference. Everything is measured by this script -- nothing
is carried forward from an earlier run.

    python -m eval.pilot_packet_compare --seeds 1 2 3
"""
from __future__ import annotations

import argparse
import json

import numpy as np
import torch

from common.config import load_config, resolve_path
from eval.lofo import _predict_infiltration
from eval.metrics import binary_metrics, threshold_at_fpr, threshold_free_metrics
from models.dataset import FeatureScaler, SequenceDataset, load_split
from models.forecast import load_world_model

VARIANTS = {"packet-aware": "configs/unsw_nb15_pkt.yaml", "flow-only control": "configs/unsw_nb15_pkt_flowonly.yaml"}


def score_one(config_path: str, seed: int) -> dict:
    cfg = load_config(config_path)
    d = resolve_path(cfg, "processed_dir")
    scaler = FeatureScaler.load(d / "scaler.npz")
    val, test = (SequenceDataset(load_split(d, s), scaler) for s in ("val", "test"))
    model, _ = load_world_model(resolve_path(cfg, "checkpoint_dir") / f"seed{seed}" / "world_model_best.pt")
    dev = next(model.parameters()).device
    pv, pt = _predict_infiltration(model, val.X, dev), _predict_infiltration(model, test.X, dev)
    yv, yt = val.infiltration[:, 0].numpy(), test.infiltration[:, 0].numpy()
    out = {"seed": seed, "n_test": int(len(yt)), "n_test_pos": int(yt.sum()), **threshold_free_metrics(yt, pt)}
    for tag, fpr in (("fpr5pct", 0.05), ("fpr1pct", 0.01)):
        thr = threshold_at_fpr(yv, pv, fpr)
        out[tag] = {"threshold": float(thr), **{k: float(v) for k, v in binary_metrics(yt, pt, thr).items()}}
    out["f1_at_0.5"] = float(binary_metrics(yt, pt, 0.5)["f1"])
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3])
    ap.add_argument("--out", default="docs/unsw_pkt_pilot_results.json")
    args = ap.parse_args()
    res = {name: [score_one(path, s) for s in args.seeds] for name, path in VARIANTS.items()}
    summary = {}
    for name, runs in res.items():
        au = np.array([r["auroc"] for r in runs]); ap_ = np.array([r["auprc"] for r in runs])
        summary[name] = {"auroc_mean": float(au.mean()), "auroc_std": float(au.std(ddof=1)) if len(au) > 1 else None,
                         "auprc_mean": float(ap_.mean()), "auprc_std": float(ap_.std(ddof=1)) if len(ap_) > 1 else None}
    diff = np.array([a["auroc"] - b["auroc"] for a, b in zip(res["packet-aware"], res["flow-only control"])])
    rng = np.random.default_rng(0)
    boot = rng.choice(diff, size=(10_000, len(diff)), replace=True).mean(axis=1)
    summary["paired_auroc_diff_packet_minus_flow"] = {
        "per_seed": diff.tolist(), "mean": float(diff.mean()),
        "bootstrap_95ci": [float(np.percentile(boot, 2.5)), float(np.percentile(boot, 97.5))],
        "note": f"only {len(diff)} seeds -- the CI is a rough guide, not a precise interval",
    }
    json.dump({"runs": res, "summary": summary}, open(args.out, "w"), indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
