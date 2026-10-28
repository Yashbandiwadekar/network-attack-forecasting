"""Tabular baselines and the "beat the tree and the one-liner" gate (docs/16 action 3, docs/18).

Baselines (all fixed hyper-parameters, no tuning, fitted on RAW features - never on the clipped/standardized tensors the
Transformer sees, because the +/-6 clip creates ties that change a flow_count ranking):

  flow_count        last-window flow_count, no training (a volume score)
  LR_last           sklearn LogisticRegression(max_iter=1000) on the standardized last window
  HGB_last          sklearn HistGradientBoostingClassifier(max_iter=200, early_stopping=False, random_state=0), last window
  HGB_stacked       same HGB on [last, mean, std, 1-step delta, 6-step delta, max] over the 12 windows (6 x F columns)

The gate (eval.diagnostics.core.baseline_gate) says PASS only when the model's mean paired per-unit AUROC gain over a
baseline exceeds the paired minimum detectable effect for that number of units. Units are days (or scenarios), never
sequences. Pure functions of arrays plus sklearn; nothing here reads or writes a file.
"""
from __future__ import annotations

import numpy as np

from eval.diagnostics.core import baseline_gate, per_unit_auroc

BASELINE_NAMES = ("flow_count", "LR_last", "HGB_last", "HGB_stacked")


def stack_features(X: np.ndarray) -> np.ndarray:
    """(N, L, F) raw windows -> (N, 6F): last, mean, std, last-minus-previous, last-minus-6-back, max over the L windows."""
    last = X[:, -1, :]
    back = min(6, X.shape[1] - 1)
    return np.concatenate([last, X.mean(1), X.std(1), X[:, -1, :] - X[:, -2, :], X[:, -1, :] - X[:, -1 - back, :], X.max(1)], axis=1)


def per_day_cap_indices(day: np.ndarray, cap: int, seed: int = 0) -> np.ndarray:
    """Row indices keeping at most `cap` rows of every day (all rows of smaller days), days in sorted order, rows in the order drawn
    (rng.choice without replacement). This is the docs/16 exp6 'train A' rule (cap 30,000): a train split that is 99% one day
    would otherwise be dominated by that day and by identity-like features that only exist on it."""
    day = np.asarray(day).astype(str)
    rng = np.random.default_rng(seed)
    return np.concatenate([rng.choice(np.flatnonzero(day == u), min(cap, int((day == u).sum())), replace=False)
                           for u in np.unique(day)])


def fit_baselines(X: np.ndarray, y: np.ndarray, flow_count_index: int, max_train_rows: int | None = 200_000,
                  seed: int = 0, names=BASELINE_NAMES, day: np.ndarray | None = None, per_day_cap: int | None = None) -> dict:
    """Fit the baselines on raw sequences X (N, L, F) and binary labels y. Returns {name: f(X_raw) -> score}.
    Row selection (all arms see the same rows): if `per_day_cap` and `day` are given, at most per_day_cap rows per day
    (per_day_cap_indices); otherwise, if N > max_train_rows, a seeded uniform subsample."""
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    y = (np.asarray(y) > 0).astype(int)
    if per_day_cap is not None and day is not None:
        idx = per_day_cap_indices(day, per_day_cap, seed)
        X, y = X[idx], y[idx]
    elif max_train_rows is not None and len(y) > max_train_rows:
        idx = np.sort(np.random.default_rng(seed).choice(len(y), max_train_rows, replace=False))
        X, y = X[idx], y[idx]
    out: dict = {}
    if "flow_count" in names:
        out["flow_count"] = lambda Xr, j=flow_count_index: np.asarray(Xr[:, -1, j], dtype=float)
    if len(np.unique(y)) < 2:             # nothing to fit: trained arms degrade to the volume score
        for n in names:
            out.setdefault(n, lambda Xr, j=flow_count_index: np.asarray(Xr[:, -1, j], dtype=float))
        return out
    last = X[:, -1, :]
    if "LR_last" in names:
        sc = StandardScaler().fit(last)
        lr = LogisticRegression(max_iter=1000).fit(sc.transform(last), y)
        out["LR_last"] = lambda Xr, lr=lr, sc=sc: lr.predict_proba(sc.transform(Xr[:, -1, :]))[:, 1]
    if "HGB_last" in names:
        h = HistGradientBoostingClassifier(max_iter=200, early_stopping=False, random_state=0).fit(last, y)
        out["HGB_last"] = lambda Xr, h=h: h.predict_proba(Xr[:, -1, :])[:, 1]
        out["HGB_last"].estimator = h                        # kept so the fitted tree can be exported (models/tree_export.py)
    if "HGB_stacked" in names:
        h2 = HistGradientBoostingClassifier(max_iter=200, early_stopping=False, random_state=0).fit(stack_features(X), y)
        out["HGB_stacked"] = lambda Xr, h=h2: h.predict_proba(stack_features(Xr))[:, 1]
        out["HGB_stacked"].estimator = h2
    return out


def baseline_scores(models: dict, X: np.ndarray, batch: int = 200_000) -> dict[str, np.ndarray]:
    """Apply each fitted baseline to X in batches (stacked features of 1.2M x 12 x 41 would not fit in one go)."""
    out = {}
    for n, f in models.items():
        out[n] = np.concatenate([np.asarray(f(X[i:i + batch]), float) for i in range(0, len(X), batch)])
    return out


def gate_unit_ids(split: dict) -> np.ndarray:
    """Independent evaluation units of a split: scenario_id when the split has >1 scenario (CTU-13), else the calendar day of
    the last input window (CIC-2018, UNSW, CIC-2017)."""
    sc = split.get("scenario_id")
    if sc is not None and len(np.asarray(sc)) == len(split["X"]) and len(np.unique(np.asarray(sc))) > 1:
        return np.asarray(sc).astype(str)
    if split.get("window_end_time") is None:                      # old split without timestamps: one unit -> gate says FAIL (<2 units)
        return np.full(len(split["X"]), "all")
    return np.asarray(split["window_end_time"]).astype("datetime64[D]").astype(str)


def run_gate(y: np.ndarray, scores: dict[str, np.ndarray], unit: np.ndarray, model_name: str,
             baselines=BASELINE_NAMES) -> dict:
    """Per-unit within-unit AUROC of every score and the gate verdict of `model_name` against each baseline present."""
    y = (np.asarray(y) > 0).astype(float)
    table = {n: per_unit_auroc(y, s, unit)["within"] for n, s in scores.items()}
    verdicts = {b: baseline_gate(table[model_name], table[b]) for b in baselines if b in table and b != model_name}
    return {"model": model_name, "per_unit_auroc": table, "gates": verdicts,
            "all_pass": bool(verdicts) and all(v["verdict"] == "PASS" for v in verdicts.values()),
            "n_units_with_both_classes": int(sum(v is not None for v in table[model_name].values()))}


def _f(x, nd=3):
    return "n/a" if x is None or (isinstance(x, float) and np.isnan(x)) else f"{x:.{nd}f}"


def gate_markdown(g: dict, title: str = "Baseline gate") -> str:
    """Markdown block: per-unit AUROC table (model + baselines) and the PASS/FAIL line per baseline."""
    units = sorted({u for t in g["per_unit_auroc"].values() for u in t})
    head = "| score | " + " | ".join(units) + " | mean |\n|---|" + "---|" * (len(units) + 1)
    rows = []
    for n, t in g["per_unit_auroc"].items():
        vals = [t.get(u) for u in units]
        d = [v for v in vals if v is not None]
        rows.append(f"| {n} | " + " | ".join(_f(v) for v in vals) + f" | {_f(float(np.mean(d)) if d else None)} |")
    lines = [f"### {title}", "", head, *rows, "",
             "| baseline | units | mean paired gain | MDE (sd used) | day-bootstrap 95% CI | verdict |", "|---|---|---|---|---|---|"]
    for b, v in g["gates"].items():
        if v["mean_diff"] is None:
            lines.append(f"| {b} | {v['n_units']} | n/a | n/a | n/a | **FAIL** ({v['reason']}) |")
        else:
            lo, hi = v["ci95_day_bootstrap"]
            lines.append(f"| {b} | {v['n_units']} | {v['mean_diff']:+.3f} | {v['mde']:.3f} (sd {v['sd_used']:.3f}) | "
                         f"[{lo:+.3f}, {hi:+.3f}] | **{v['verdict']}** |")
    lines += ["", f"Gate rule: PASS iff mean paired per-unit AUROC gain over the baseline > paired MDE "
                  f"(80% power, 5% two-sided, SD = max(0.0245, observed SD of the per-unit differences)). "
                  f"All baselines beaten: **{'YES' if g['all_pass'] else 'NO'}**."]
    return "\n".join(lines)
