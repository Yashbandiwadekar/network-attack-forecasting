"""docs/15: single-step (t+1) detection metrics of several checkpoints on several processed datasets.

    python -m eval.joint_v3_eval --models seed1=configs/real_data_v2_converged_seed1.yaml \
        Bplus_s1=configs/joint_v3_Bplus.yaml@checkpoints_joint_v3/Bplus/seed1/world_model_best.pt \
        --datasets cic18_v2_test=data/processed_real_v2_converged:test ... --out docs/joint_v3/t1_metrics.json

A model spec is `name=config[@checkpoint]`; the scaler is always the one in that config's processed_dir (the scaler the
model was trained with). A dataset spec is `name=dir:split1,split2`. Metrics are on the t+1 infiltration probability
(`infiltration[:, 0]`, the same quantity as docs/04-evaluation-real-v2-seeds.md). AUROC/AUPRC get a block-bootstrap
95% interval: sequences are ordered by (host, time) and cut into blocks of `--block` consecutive sequences of one host,
and blocks are resampled (overlapping sliding sequences are not independent; with a handful of pseudo-hosts the
interval is only indicative, which docs/13 explains). Inference only; writes only the JSON.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np


def block_ids(src_ip: np.ndarray, t_end: np.ndarray, block: int) -> tuple[np.ndarray, np.ndarray]:
    """(order, block id per sequence in that order)."""
    order = np.lexsort((np.asarray(t_end).astype("datetime64[ns]").astype(np.int64), np.asarray(src_ip).astype(str)))
    ips = np.asarray(src_ip).astype(str)[order]
    ids = np.zeros(len(order), dtype=np.int64)
    cur, cnt, bid = None, 0, -1
    for i, ip in enumerate(ips):
        if ip != cur or cnt >= block:
            bid += 1
            cur, cnt = ip, 0
        ids[i] = bid
        cnt += 1
    return order, ids


def auc_ap(y: np.ndarray, p: np.ndarray) -> tuple[float | None, float | None]:
    from sklearn.metrics import average_precision_score, roc_auc_score
    if y.sum() == 0 or y.sum() == len(y):
        return None, None
    return float(roc_auc_score(y, p)), float(average_precision_score(y, p))


def t1_metrics(y: np.ndarray, p: np.ndarray, src_ip: np.ndarray, t_end: np.ndarray, B: int = 300, block: int = 50,
               seed: int = 0) -> dict:
    from eval.metrics import binary_metrics
    n, npos = int(len(y)), int(y.sum())
    out: dict = {"n": n, "n_positive": npos, "n_hosts": int(len(np.unique(np.asarray(src_ip).astype(str))))}
    auc, ap = auc_ap(y, p)
    out["auroc"], out["auprc"] = auc, ap
    if auc is not None:
        out["at_0.5"] = {k: float(v) for k, v in binary_metrics(y, p, 0.5).items()}
        out["at_0.4"] = {k: float(v) for k, v in binary_metrics(y, p, 0.4).items()}
        order, ids = block_ids(src_ip, t_end, block)
        ys, ps = y[order], p[order]
        nb = int(ids.max()) + 1
        starts = np.searchsorted(ids, np.arange(nb))
        ends = np.append(starts[1:], len(ids))
        rng = np.random.default_rng(seed)
        a_vals, p_vals = [], []
        for _ in range(B):
            pick = rng.integers(0, nb, nb)
            idx = np.concatenate([np.arange(starts[b], ends[b]) for b in pick])
            a, q = auc_ap(ys[idx], ps[idx])
            if a is not None:
                a_vals.append(a)
                p_vals.append(q)
        if a_vals:
            out["auroc_ci95_block_bootstrap"] = [float(np.percentile(a_vals, 2.5)), float(np.percentile(a_vals, 97.5))]
            out["auprc_ci95_block_bootstrap"] = [float(np.percentile(p_vals, 2.5)), float(np.percentile(p_vals, 97.5))]
            out["n_blocks"] = nb
    return out


def load_arr(spec: str) -> dict[str, np.ndarray]:
    d, _, splits = spec.partition(":")
    parts = []
    for s in splits.split(","):
        z = np.load(Path(d) / f"{s}.npz", allow_pickle=False)
        parts.append({k: z[k] for k in z.files})
    keys = set(parts[0]).intersection(*[set(q) for q in parts[1:]])
    return {k: np.concatenate([q[k] for q in parts]) for k in keys}


def predict_t1(model, scaler, X: np.ndarray, device, batch: int = 8192) -> np.ndarray:
    import torch
    from eval.lofo import _predict_infiltration
    Xs = torch.tensor(scaler.transform(X), dtype=torch.float32)
    return _predict_infiltration(model, Xs, device, batch_size=batch)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--models", nargs="+", required=True)
    ap.add_argument("--datasets", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--bootstrap", type=int, default=300)
    ap.add_argument("--block", type=int, default=50)
    a = ap.parse_args()

    from common.config import load_config, resolve_path
    from models.dataset import FeatureScaler
    from models.forecast import load_world_model

    data = {}
    for s in a.datasets:
        name, _, rest = s.partition("=")
        data[name] = load_arr(rest)
    results: dict = {}
    for m in a.models:
        name, _, rest = m.partition("=")
        cfg_path, _, ckpt = rest.partition("@")
        cfg = load_config(cfg_path)
        ckpt_path = Path(ckpt) if ckpt else resolve_path(cfg, "checkpoint_dir") / "world_model_best.pt"
        model, _ = load_world_model(ckpt_path)
        device = next(model.parameters()).device
        scaler = FeatureScaler.load(resolve_path(cfg, "processed_dir") / "scaler.npz")
        results[name] = {"config": cfg_path, "checkpoint": str(ckpt_path), "datasets": {}}
        for dname, arr in data.items():
            p = predict_t1(model, scaler, arr["X"], device)
            y = (np.asarray(arr["infiltration"])[:, 0] > 0).astype(np.float32)
            results[name]["datasets"][dname] = t1_metrics(y, p, arr["src_ip"], arr["window_end_time"], a.bootstrap, a.block)
            r = results[name]["datasets"][dname]
            print(f"{name:12s} {dname:28s} n={r['n']:7d} pos={r['n_positive']:6d} AUROC={r['auroc']} AUPRC={r['auprc']}", flush=True)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=1), encoding="utf-8")
    print("wrote", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
