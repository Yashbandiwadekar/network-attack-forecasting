"""docs/19 analysis: per-arm per-day tables, nested arm selection, gates, threshold transfer, calibration (stages 'tables', 'threshold').

Everything is computed from the OOF files written by eval.baselines_v5_run plus the docs/18 reference numbers in docs/lodo_v4/selection.json
(read only). No test day is touched.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval import baselines_v5 as B  # noqa: E402
from eval import lodo_v4 as L  # noqa: E402
from eval.baselines_v5_run import OOF, arm_path, load_arm, per_day_auroc  # noqa: E402
from eval.diagnostics.core import baseline_gate  # noqa: E402

DAYS = list(L.LODO_DAYS)
PSEUDO = [d for d in DAYS if d != L.HOST_SPLIT_DAY]
SEL = json.loads((ROOT / "docs" / "lodo_v4" / "selection.json").read_text(encoding="utf-8"))
REFS = ["flow_count", "LR_last", "HGB_last", "HGB_stacked"]


def ref_per_day() -> dict[str, dict[str, float]]:
    pd_ = SEL["per_day"]
    out = {n: {d: pd_[d][n]["auroc"] for d in DAYS} for n in REFS}
    out["Transformer_single_nested"] = {d: pd_[d]["single"]["auroc_nested"] for d in DAYS}
    out["Transformer_ens5_nested"] = {d: pd_[d]["ens5"]["auroc_nested"] for d in DAYS}
    return out


def registered_arms() -> list[str]:
    """A (8 variants), B (2 tuned), C (3 families) in the registered order that exist on disk."""
    names = sorted(p.name for p in OOF.iterdir() if p.is_dir())
    a = [n for n in names if n.startswith("A_")]
    a.sort(key=lambda n: list(B.F5.VARIANTS).index(n[2:]))
    return a + sorted(n for n in names if n.startswith("B_")) + sorted(n for n in names if n.startswith("C_"))


def mean_over(per_day: dict, days) -> float:
    v = [per_day[d] for d in days if per_day[d] is not None and not np.isnan(per_day[d])]
    return float(np.mean(v)) if v else float("nan")


def boot_ci(per_day: dict, days, n_boot=10000, seed=0) -> tuple[float, float]:
    v = np.array([per_day[d] for d in days], float)
    rng = np.random.default_rng(seed)
    m = v[rng.integers(0, len(v), size=(n_boot, len(v)))].mean(1)
    return float(np.percentile(m, 2.5)), float(np.percentile(m, 97.5))


def nested_selection(arm_auc: dict[str, dict[str, float]], days=DAYS) -> dict:
    """Day d is read from the arm with the highest mean AUROC over the OTHER days (ties: earlier arm in dict order)."""
    arms = list(arm_auc)
    out = {}
    for d in days:
        others = [x for x in days if x != d]
        best = max(arms, key=lambda a: (round(mean_over(arm_auc[a], others), 12), -arms.index(a)))
        out[d] = {"arm": best, "auroc": arm_auc[best][d]}
    return out


def gate_row(model: dict, base: dict, days) -> dict:
    g = baseline_gate({d: model[d] for d in days}, {d: base[d] for d in days})
    return g


def fmt_gate(name: str, g: dict) -> str:
    if g["mean_diff"] is None:
        return f"| {name} | {g['n_units']} | n/a | n/a | n/a | n/a | FAIL |"
    lo, hi = g["ci95_day_bootstrap"]
    return (f"| {name} | {g['n_units']} | {g['mean_diff']:+.3f} | {g['mde']:.3f} | [{lo:+.3f}, {hi:+.3f}] | {g['wins']}/{g['n_units']} | "
            f"**{g['verdict']}** |")


# ------------------------------------------------------------------ threshold transfer
def thresholds_from_inner(arm: str, fold: L.Fold, target: float) -> float:
    z = np.load(arm_path(arm, fold.name), allow_pickle=False)
    return L.day_balanced_threshold(z["inner_y"], z["inner_score"], z["inner_day"], target)


def transfer_summary(fpr_by_day: dict, nneg: dict, target: float = 0.01) -> dict:
    ds = [d for d in fpr_by_day if nneg[d] >= 100 and fpr_by_day[d] is not None]
    f = np.array([fpr_by_day[d] for d in ds])
    fl = np.maximum(f, np.array([0.5 / nneg[d] for d in ds]))
    return {"min": float(f.min()), "max": float(f.max()), "mean_abs_log_ratio": float(np.mean(np.abs(np.log(fl / target)))),
            "n_within_x3": int(np.sum((f >= target / 3) & (f <= target * 3))), "n_days": len(ds)}


def calibrate_fold(arm: str, fold: L.Fold, kind: str):
    """Platt or isotonic calibrator fitted ONLY on the inner OOF scores of the outer-train days (day-balanced weights)."""
    from sklearn.isotonic import IsotonicRegression
    from sklearn.linear_model import LogisticRegression
    z = np.load(arm_path(arm, fold.name), allow_pickle=False)
    s, y, d = z["inner_score"].astype(float), z["inner_y"], z["inner_day"]
    _, inv, cnt = np.unique(d, return_inverse=True, return_counts=True)
    w = 1.0 / cnt[inv]
    w = w / w.sum() * len(w)
    if kind == "isotonic":
        iso = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=1).fit(s, y, sample_weight=w)
        return lambda x: iso.predict(np.asarray(x, float))
    lg = lambda p: np.log(np.clip(p, 1e-6, 1 - 1e-6) / (1 - np.clip(p, 1e-6, 1 - 1e-6)))
    lr = LogisticRegression(C=1e6, max_iter=1000).fit(lg(s)[:, None], y, sample_weight=w)
    return lambda x: lr.predict_proba(lg(np.asarray(x, float))[:, None])[:, 1]


def brier_ece(y, p, bins=10) -> tuple[float, float]:
    y, p = np.asarray(y, float), np.asarray(p, float)
    b = float(np.mean((p - y) ** 2))
    e = 0.0
    edges = np.linspace(0, 1, bins + 1)
    ix = np.clip(np.digitize(p, edges[1:-1]), 0, bins - 1)
    for k in range(bins):
        m = ix == k
        if m.any():
            e += m.mean() * abs(p[m].mean() - y[m].mean())
    return b, float(e)


def adaptive_alarm(score: np.ndarray, window: int = 360, min_periods: int = 60, q: float = 0.99) -> np.ndarray:
    """Label-free causal alarm rule: score_i >= q-quantile of the PREVIOUS `window` scores (needs `min_periods`); no alarm before that."""
    import pandas as pd
    s = pd.Series(np.asarray(score, float))
    thr = s.shift(1).rolling(window, min_periods=min_periods).quantile(q).to_numpy()
    return np.where(np.isnan(thr), False, np.asarray(score) >= thr)


def fold_scores(arm: str, fold: L.Fold):
    z = np.load(arm_path(arm, fold.name), allow_pickle=False)
    return z["y"], z["score"].astype(float), z["idx"]
