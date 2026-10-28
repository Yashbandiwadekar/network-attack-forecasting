"""Pickle-free export of the docs/19 baseline models (HGB, ExtraTrees / RandomForest, LR) as plain numeric arrays in a .npz
(np.savez, loaded with allow_pickle=False) plus numpy-only predictors, extending models/tree_export.py (HGB) to the other families.

`meta_json` carries the feature recipe: the variant id (models/features_v5.VARIANTS), the exact input column names, the constants the recipe
uses and the alert threshold, so a loader can verify the schema. Nothing here is wired into the server or the model bundle.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from models import features_v5 as F5
from models.tree_export import export_hgb, load_flat, predict_proba_flat  # noqa: F401  (re-exported)

FORMAT_FOREST = "naf-forest-flat-v1"
FORMAT_LR = "naf-lr-flat-v1"


def recipe_meta(variant: str, feature_names: list[str], threshold: float | None, extra: dict | None = None) -> dict:
    v = F5.VARIANTS[variant]
    return {"variant": variant, "variant_doc": v.doc, "feature_names": list(feature_names),
            "constants": {"Z_FLOOR": F5.Z_FLOOR, "CTX_WINDOW": F5.CTX_WINDOW, "CTX_MIN": F5.CTX_MIN, "VOL": F5.VOL, "LEVEL_VOL": F5.LEVEL_VOL,
                          "LOG_COLS": F5.LOG_COLS, "STACK_BLOCKS": list(F5.STACK_BLOCKS)},
            "needs_context": bool(v.ctx), "needs_window_times": bool(v.temporal),
            "alert_threshold_oof_1pct_fpr": threshold, **(extra or {})}


def export_hgb_v5(clf, variant: str, feature_names: list[str], path: str | Path, threshold: float | None = None, extra: dict | None = None) -> dict:
    arrays = export_hgb(clf, feature_names, None, threshold)
    meta = json.loads(str(arrays["meta_json"]))
    meta.update({"recipe": recipe_meta(variant, feature_names, threshold, extra)})
    arrays["meta_json"] = np.array(json.dumps(meta))
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    np.savez(path, **arrays)
    return arrays


# ---------------------------------------------------------------- forests (ExtraTrees / RandomForest)
def export_forest(model, variant: str, feature_names: list[str], path: str | Path | None = None, threshold: float | None = None,
                  extra: dict | None = None) -> dict:
    """`model` is eval.baselines_v5.Model (family ET or RF, fitted): stores the train-median imputation and every tree's node arrays."""
    est, med = model.est, np.asarray(model.med, float)
    trees = [t.tree_ for t in est.estimators_]
    off = np.r_[0, np.cumsum([t.node_count for t in trees])].astype(np.int64)

    def cat(f):
        return np.concatenate([f(t) for t in trees])
    leaf_p = []
    for t in trees:
        v = t.value[:, 0, :]
        leaf_p.append(v[:, 1] / np.maximum(v.sum(1), 1e-300))
    arrays = {
        "tree_offsets": off,
        "feature_idx": cat(lambda t: t.feature).astype(np.int32),
        "threshold": cat(lambda t: t.threshold).astype(np.float64),
        "left": cat(lambda t: t.children_left).astype(np.int32),
        "right": cat(lambda t: t.children_right).astype(np.int32),
        "leaf_p1": np.concatenate(leaf_p).astype(np.float64),
        "impute_median": med,
        "meta_json": np.array(json.dumps({"format": FORMAT_FOREST, "n_features": int(len(med)),
                                          "recipe": recipe_meta(variant, feature_names, threshold, extra)})),
    }
    if path is not None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        np.savez(path, **arrays)
    return arrays


def predict_proba_forest(arrays: dict, X: np.ndarray) -> np.ndarray:
    X = np.asarray(X, dtype=np.float64)
    X = np.where(np.isnan(X), arrays["impute_median"], X)
    off = arrays["tree_offsets"]
    n = len(X)
    rows = np.arange(n)
    acc = np.zeros(n)
    for t in range(len(off) - 1):
        s, e = int(off[t]), int(off[t + 1])
        feat, thr, left, right, p1 = (arrays[k][s:e] for k in ("feature_idx", "threshold", "left", "right", "leaf_p1"))
        node = np.zeros(n, dtype=np.int64)
        active = left[node] != -1
        while active.any():
            r = rows[active]
            nd = node[r]
            node[r] = np.where(X[r, feat[nd]] <= thr[nd], left[nd], right[nd])
            active = left[node] != -1
        acc += p1[node]
    return acc / (len(off) - 1)


# ---------------------------------------------------------------- logistic regression
def export_lr(model, variant: str, feature_names: list[str], path: str | Path | None = None, threshold: float | None = None,
              extra: dict | None = None) -> dict:
    arrays = {"coef": np.asarray(model.est.coef_[0], float), "intercept": np.asarray(model.est.intercept_, float).reshape(-1)[:1],
              "mu": np.asarray(model.mu, float), "sd": np.asarray(model.sd, float), "impute_median": np.asarray(model.med, float),
              "meta_json": np.array(json.dumps({"format": FORMAT_LR, "clip": 6.0, "recipe": recipe_meta(variant, feature_names, threshold, extra)}))}
    if path is not None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        np.savez(path, **arrays)
    return arrays


def predict_proba_lr(arrays: dict, X: np.ndarray) -> np.ndarray:
    X = np.asarray(X, dtype=np.float64)
    X = np.where(np.isnan(X), arrays["impute_median"], X)
    z = np.clip((X - arrays["mu"]) / arrays["sd"], -6, 6) @ arrays["coef"] + arrays["intercept"][0]
    return 1.0 / (1.0 + np.exp(-z))


def predict_any(arrays: dict, X: np.ndarray) -> np.ndarray:
    fmt = json.loads(str(arrays["meta_json"])).get("format")
    if fmt == FORMAT_FOREST:
        return predict_proba_forest(arrays, X)
    if fmt == FORMAT_LR:
        return predict_proba_lr(arrays, X)
    return predict_proba_flat(arrays, X)
