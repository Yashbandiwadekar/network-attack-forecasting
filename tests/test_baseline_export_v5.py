"""docs/19: pickle-free export round trips (numpy predictor == sklearn) for HGB, ExtraTrees, RandomForest and LR with the recipe in meta_json."""
from __future__ import annotations

import json

import numpy as np
import pytest

from eval.baselines_v5 import Model
from models import baseline_export_v5 as E


def _data(seed=0, n=600, f=12):
    rng = np.random.default_rng(seed)
    X = rng.normal(size=(n, f)).astype(np.float32)
    y = ((X[:, 0] + 0.5 * X[:, 3] + rng.normal(0, 0.5, n)) > 0.3).astype(int)
    X[rng.random(X.shape) < 0.03] = np.nan                       # warm-up style NaN
    return X, y


@pytest.mark.parametrize("family,cfg", [("HGB", dict(learning_rate=0.1, max_leaf_nodes=8, min_samples_leaf=20, l2_regularization=1.0, class_weight=None)),
                                        ("ET", dict(min_samples_leaf=5, class_weight=None)), ("RF", dict(min_samples_leaf=5, class_weight="balanced_subsample")),
                                        ("LR", dict(C=0.1, class_weight="balanced"))])
def test_round_trip_and_no_pickle(tmp_path, family, cfg):
    X, y = _data()
    m = Model(family, cfg, 2).fit(X, y)
    names = [f"c{i}" for i in range(X.shape[1])]
    p = tmp_path / "m.npz"
    if family == "HGB":
        E.export_hgb_v5(m.est, "S3_log", names, p, threshold=0.7)
    elif family == "LR":
        E.export_lr(m, "S3_log", names, p, 0.7)
    else:
        E.export_forest(m, "S3_log", names, p, 0.7)
    z = np.load(p, allow_pickle=False)                          # raises if any object array was stored
    arr = {k: z[k] for k in z.files}
    Xt, _ = _data(seed=1, n=300)
    assert np.allclose(E.predict_any(arr, Xt), m.score(Xt), atol=(1e-6 if family == "LR" else 1e-9), rtol=0)
    meta = json.loads(str(arr["meta_json"]))
    rec = meta["recipe"]
    assert rec["variant"] == "S3_log" and rec["feature_names"] == names and rec["alert_threshold_oof_1pct_fpr"] == 0.7
    assert "CTX_WINDOW" in rec["constants"]
