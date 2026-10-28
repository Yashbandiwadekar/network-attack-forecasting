"""docs/19 section 0.7: robustness of the best non-anchor candidate and of the incumbent HGB_stacked (S0).

Mean-ablation: the named RAW columns are set to the fold-training mean in all 12 windows of the held-out rows BEFORE feature construction (so
log / ratio / rolling / z-score / delta / context columns are rebuilt from the ablated input); the model is the same one that produced the OOF
scores (refitted here with the stored configuration; the clean re-score is checked against the stored OOF scores). Range / clip rates are
computed on the held-out feature matrices against the fold-training range and SD.
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
from eval import baselines_v5_report as R  # noqa: E402
from eval import lodo_v4 as L  # noqa: E402
from eval.baselines_v5_run import arm_path  # noqa: E402
from eval.baselines_v5_secondary import arm_spec  # noqa: E402
from models import features_v5 as F5  # noqa: E402

ABLATIONS = {"flow_count": ["flow_count"], "volume4": ["flow_count", "unique_dst_ports", "total_bytes", "total_packets"]}


def ablated_features(day: str, rows: np.ndarray, variant: str, cols: list[str], values: np.ndarray, chunk: int = 100_000) -> np.ndarray:
    X = np.load(B.SRC / day / "X.npy", mmap_mode="r")
    T = np.load(B.SRC / day / "window_times.npy", mmap_mode="r")
    unit = np.load(B.SRC / day / "src_ip.npy")
    t = np.load(B.SRC / day / "window_end_time.npy")
    last = np.asarray(X[:, -1, :]).copy()
    for c, v in zip(cols, values):
        last[:, B.NAMES.index(c)] = v
    mu, sd = F5.causal_context(F5.vol_last_log(last, B.NAMES), unit, t)
    out = []
    for i in range(0, len(rows), chunk):
        r = rows[i:i + chunk]
        Xc = F5.ablate_feature(np.asarray(X[r]), B.NAMES, cols, values)
        out.append(F5.build_features(Xc, B.NAMES, variant, T=np.asarray(T[r]), ctx=(mu[r], sd[r]))[0])
    return np.concatenate(out)


def day_rows_of_fold(pool: B.Pool, fold: L.Fold, O: dict) -> np.ndarray:
    """Row numbers WITHIN the day's cache file of the outer held-out rows."""
    if fold.group is not None:
        return O["idx"]                                   # 02-20 groups index the full 02-20 file directly
    first = np.flatnonzero(pool.day == fold.day)[0]
    return O["idx"] - first                               # pseudo-host days: pool rows of a day are the day's file rows in order


def range_rates(Ftr: np.ndarray, Fte: np.ndarray) -> dict:
    lo, hi = np.nanmin(Ftr, axis=0), np.nanmax(Ftr, axis=0)
    mu, sd = np.nanmean(Ftr, axis=0), np.nanstd(Ftr, axis=0) + 1e-6
    ok = ~np.isnan(Fte)
    outside = ((Fte < lo) | (Fte > hi)) & ok
    beyond = (np.abs((Fte - mu) / sd) > 6) & ok
    return {"outside_train_range": float(outside.sum() / ok.sum()), "beyond_6sd": float(beyond.sum() / ok.sum()),
            "rows_with_any_outside": float(outside.any(1).mean())}


def stage_robust() -> None:
    tb = json.loads((B.RES / "tables.json").read_text(encoding="utf-8"))
    best = tb["best_non_anchor"]
    arms = {"HGB_stacked(current)": "A_S0_stacked41", f"best={best}": best}
    pools = {a: B.Pool(arm_spec(a)[0]) for a in arms.values()}
    pool0 = pools["A_S0_stacked41"]
    names0 = json.loads((B.DATA / R.PSEUDO[0] / "S0_stacked41.names.json").read_text())
    last_cols = {c: names0.index(f"last:{c}") for c in B.NAMES if f"last:{c}" in names0}
    out = {"best": best, "ablation": {}, "clean_check": {}, "ranges": {}, "ranges_raw41_transformer_analogue": {}}
    acc: dict = {}
    for fold in pool0.folds():
        O0 = pool0.outer(fold)
        trainmask = O0["train"]
        for label, arm in arms.items():
            pool = pools[arm]
            v, fam = arm_spec(arm)
            O = pool.outer(fold)
            cfg = json.loads(str(np.load(arm_path(arm, fold.name), allow_pickle=False)["cfg"]))
            tr = np.flatnonzero(O["train"])
            m = B.Model(fam, cfg, 32).fit(pool.F[tr], pool.y[tr])
            clean = m.score(O["F"])
            ref = np.load(arm_path(arm, fold.name), allow_pickle=False)["score"]
            acc.setdefault((label, "clean_diff"), []).append(float(np.max(np.abs(clean - ref))))
            acc.setdefault((label, "clean"), {}).setdefault(fold.day, []).append((O["y"], clean))
            rows = day_rows_of_fold(pool, fold, O)
            for an, cols in ABLATIONS.items():
                vals = np.array([pool0.F[trainmask, last_cols[c]].mean() for c in cols])
                Fa = ablated_features(fold.day, rows, v, cols, vals)
                sa = m.score(Fa)
                acc.setdefault((label, an), {}).setdefault(fold.day, []).append((O["y"], sa))
            if label.startswith("best") or True:
                acc.setdefault((label, "ranges"), {}).setdefault(fold.day, []).append((len(O["y"]), range_rates(pool.F[tr], O["F"])))
        # Transformer-scaler analogue on the 41 raw last-window features (S0 columns last:*)
        cols41 = [names0.index(f"last:{c}") for c in B.NAMES]
        acc.setdefault(("raw41", "ranges"), {}).setdefault(fold.day, []).append(
            (len(O0["y"]), range_rates(pool0.F[trainmask][:, cols41], O0["F"][:, cols41])))
        print("done", fold.name, flush=True)

    def pooled(dd):
        return {d: B.auc(np.concatenate([a for a, _ in v]), np.concatenate([b for _, b in v])) for d, v in dd.items()}
    for label in arms:
        base = pooled(acc[(label, "clean")])
        out["clean_check"][label] = {"max_abs_diff_vs_stored_oof": float(max(acc[(label, "clean_diff")])), "auroc_clean": base}
        out["ablation"][label] = {"clean": base}
        for an in ABLATIONS:
            ab = pooled(acc[(label, an)])
            out["ablation"][label][an] = ab
            out["ablation"][label][an + "_drop"] = {d: base[d] - ab[d] for d in base}
    for label, key in [(l, (l, "ranges")) for l in arms] + [("raw41", ("raw41", "ranges"))]:
        res = {}
        for d, v in acc[key].items():
            w = np.array([n for n, _ in v], float)
            res[d] = {k: float(np.average([r[k] for _, r in v], weights=w)) for k in v[0][1]}
        (out["ranges"] if label != "raw41" else out["ranges_raw41_transformer_analogue"]).update({label: res} if label != "raw41" else res)
    (B.RES / "robust.json").write_text(json.dumps(out, indent=1, default=float), encoding="utf-8")
    print(json.dumps({k: {a: {d: round(x, 3) for d, x in v.items()} for a, v in out["ablation"][k].items() if a.endswith("_drop")} for k in arms}, indent=1))
