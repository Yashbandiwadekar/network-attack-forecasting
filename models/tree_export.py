"""Pickle-free export of a fitted sklearn HistGradientBoostingClassifier (binary) to flat arrays, and a numpy-only predictor.

Why: the model bundle (common/bundle.py) and the checkpoint loader (models/checkpoint_io.py, torch.load(weights_only=True)) are built so that
loading a model can never execute code. A pickled sklearn estimator would break that guarantee. A tree ensemble is just node arrays, so it
can be stored as plain numeric arrays (np.savez, allow_pickle=False) and evaluated without sklearn. `predict_proba_flat` reproduces
`clf.predict_proba(X)[:, 1]` (tested in tests/test_tree_export.py). This module is NOT wired into the server (docs/18, recommendation).

Layout of the .npz: for T trees, nodes are concatenated; `tree_offsets` (T+1) gives each tree's slice; left/right are indices LOCAL to a tree.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

FORMAT = "naf-hgb-flat-v1"


def export_hgb(clf, feature_names: list[str], path: str | Path | None = None, threshold: float | None = None) -> dict[str, np.ndarray]:
    preds = [p for it in clf._predictors for p in it]
    if len(clf._predictors[0]) != 1:
        raise ValueError("only binary classifiers (one tree per iteration) are supported")
    nodes = [p.nodes for p in preds]
    if any(n["is_categorical"].any() for n in nodes):
        raise ValueError("categorical splits are not supported")
    offsets = np.r_[0, np.cumsum([len(n) for n in nodes])].astype(np.int64)
    cat = np.concatenate(nodes)
    arrays = {
        "tree_offsets": offsets,
        "feature_idx": cat["feature_idx"].astype(np.int32),
        "threshold": cat["num_threshold"].astype(np.float64),
        "left": cat["left"].astype(np.int32),
        "right": cat["right"].astype(np.int32),
        "missing_go_to_left": cat["missing_go_to_left"].astype(np.uint8),
        "is_leaf": cat["is_leaf"].astype(np.uint8),
        "value": cat["value"].astype(np.float64),
        "baseline": np.asarray(clf._baseline_prediction, dtype=np.float64).reshape(-1)[:1],
        "meta_json": np.array(json.dumps({"format": FORMAT, "feature_names": list(feature_names), "n_features": int(clf.n_features_in_),
                                          "alert_threshold_oof_1pct_fpr": threshold, "link": "sigmoid"})),
    }
    if path is not None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        np.savez(path, **arrays)
    return arrays


def load_flat(path: str | Path) -> dict[str, np.ndarray]:
    z = np.load(path, allow_pickle=False)
    return {k: z[k] for k in z.files}


def predict_proba_flat(arrays: dict[str, np.ndarray], X: np.ndarray) -> np.ndarray:
    """P(class 1) for rows of X (N, F), numpy only. Missing values (NaN) follow the stored default direction."""
    X = np.asarray(X, dtype=np.float64)
    n = len(X)
    raw = np.full(n, float(arrays["baseline"][0]))
    off = arrays["tree_offsets"]
    rows = np.arange(n)
    for t in range(len(off) - 1):
        s, e = int(off[t]), int(off[t + 1])
        feat, thr = arrays["feature_idx"][s:e], arrays["threshold"][s:e]
        left, right = arrays["left"][s:e], arrays["right"][s:e]
        mgl, leaf, val = arrays["missing_go_to_left"][s:e], arrays["is_leaf"][s:e], arrays["value"][s:e]
        node = np.zeros(n, dtype=np.int64)
        active = ~leaf[node].astype(bool)
        while active.any():
            r = rows[active]
            nd = node[r]
            x = X[r, feat[nd]]
            go_left = np.where(np.isnan(x), mgl[nd].astype(bool), x <= thr[nd])
            node[r] = np.where(go_left, left[nd], right[nd])
            active = ~leaf[node].astype(bool)
        raw += val[node]
    return 1.0 / (1.0 + np.exp(-raw))
