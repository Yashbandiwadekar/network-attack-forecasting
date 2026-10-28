"""docs/19 section 0.6: secondary label definitions, reported alongside the primary label (pseudo-host LODO days only; 02-20 keeps the primary).

Counts come from the raw CSVs of the six pseudo-host LODO days (never a test day), are verified against the primary label (>= 99% match) and
cached under data/processed_adapter/baselines_v5/<day>/next_counts.npz.
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
from eval import secondary_labels as S  # noqa: E402
from eval.baselines_v5_run import arm_path  # noqa: E402

PSEUDO = R.PSEUDO


def arm_spec(arm: str) -> tuple[str, str]:
    """(variant, family) of a registered arm name."""
    if arm.startswith("A_"):
        return arm[2:], "HGB"
    if arm.startswith("B_"):
        return arm[2:].rsplit("_HGBtuned", 1)[0], "HGB"
    _, rest = arm.split("_", 1)
    v, fam = rest.rsplit("_", 1)
    return v, fam


def counts_for(day: str) -> dict:
    f = B.DATA / day / "next_counts.npz"
    if f.exists():
        z = np.load(f)
        return {k: z[k] for k in z.files}
    c = S.window_counts(day)
    inf = np.load(B.SRC / day / "infiltration.npy")[:, 0]
    t = np.load(B.SRC / day / "window_end_time.npy")
    a = S.align_next_counts(t, inf, c)
    np.savez(f, **a)
    return a


def weighted_quantile(vals_by_day: list[np.ndarray], q: float) -> float:
    v = np.concatenate(vals_by_day)
    w = np.concatenate([np.full(len(x), 1.0 / len(x)) for x in vals_by_day])
    o = np.argsort(v, kind="stable")
    cw = np.cumsum(w[o]) / w.sum()
    return float(v[o][np.searchsorted(cw, q)])


def fold_ks(train_days: list[str], cnt: dict) -> tuple[int, float]:
    na = [cnt[d]["n_attack_next"][cnt[d]["y"] > 0].astype(float) for d in train_days]
    sh = [(cnt[d]["n_attack_next"] / np.maximum(cnt[d]["n_flows_next"], 1))[cnt[d]["y"] > 0] for d in train_days]
    k = max(2, int(np.ceil(weighted_quantile(na, 0.10))))
    s = max(0.01, weighted_quantile(sh, 0.10))
    return k, s


def eval_auc(y_pos, keep, score):
    m = keep
    return B.auc(y_pos[m].astype(int), score[m]) if m.any() and y_pos[m].min() != y_pos[m].max() else float("nan")


def stage_secondary() -> None:
    tb = json.loads((B.RES / "tables.json").read_text(encoding="utf-8"))
    best = tb["best_non_anchor"]
    pool0 = B.Pool("S0_stacked41")
    names0 = json.loads((B.DATA / PSEUDO[0] / "S0_stacked41.names.json").read_text())
    j_fc = names0.index("last:flow_count")
    cnt = {}
    for d in PSEUDO:
        c = counts_for(d)
        c["y"] = pool0.y[pool0.day == d]
        cnt[d] = c
    out = {"best_non_anchor": best, "alignment": {d: {"match_rate": float(cnt[d]["match_rate"]), "primary_pos_recovered": float(cnt[d]["primary_pos_recovered"])} for d in PSEUDO},
           "fold_k_s": {}, "positives": {}, "auroc": {}, "trained_on_S_train": {}}
    v_best, fam_best = arm_spec(best)
    pool_best = B.Pool(v_best)
    for d in PSEUDO:
        others = [x for x in PSEUDO if x != d]
        k, s = fold_ks(others, cnt)
        out["fold_k_s"][d] = {"k": k, "s": s, "train_days": others}
        c = cnt[d]
        prim = c["y"] > 0
        defs = {"primary": (prim, np.ones(len(prim), bool))}
        sf = S.secondary_labels(c["n_attack_next"], c["n_flows_next"], prim, 5, 0.05)
        defs["S_fix(k>=5,s>=5%)"] = (sf["pos"] & prim, sf["keep"])
        st = S.secondary_labels(c["n_attack_next"], c["n_flows_next"], prim, k, s)
        defs[f"S_train(k>={k},s>={s:.3f})"] = (st["pos"] & prim, st["keep"])
        run = S.sustained_mask(prim.astype(int), 6)
        defs["S_run6"] = (run, run | ~prim)
        out["positives"][d] = {n: {"pos": int(p.sum()), "dropped_ambiguous": int((~kp).sum()), "n_kept": int(kp.sum()),
                                   "median_attack_flows_in_primary_pos": float(np.median(c["n_attack_next"][prim])) if prim.any() else None}
                               for n, (p, kp) in defs.items()}
        # scores of the primary-trained arms (outer OOF of the day fold)
        f = L.Fold(d, d)
        scores = {"flow_count": pool0.outer(f)["F"][:, j_fc], "HGB_stacked(current)": R.fold_scores("A_S0_stacked41", f)[1], f"best={best}": R.fold_scores(best, f)[1]}
        out["auroc"][d] = {n: {dn: eval_auc(p, kp, sc) for dn, (p, kp) in defs.items()} for n, sc in scores.items()}
        # arm trained on S_train (ambiguous rows dropped from training); same family/config as the primary-trained arm of this fold
        tr_idx = np.flatnonzero(pool0.day != d)
        lab = pool0.y.astype(int).copy()
        drop = np.zeros(len(lab), bool)
        for dd in others:
            cc = cnt[dd]
            sl = S.secondary_labels(cc["n_attack_next"], cc["n_flows_next"], cc["y"] > 0, k, s)
            rows = np.flatnonzero(pool0.day == dd)
            lab[rows] = (sl["pos"] & (cc["y"] > 0)).astype(int)
            drop[rows] = ~sl["keep"]
        tr_idx = tr_idx[~drop[tr_idx]]
        res = {}
        pst, kst = defs[f"S_train(k>={k},s>={s:.3f})"]
        for nm, arm, pl in (("HGB_stacked(current)", "A_S0_stacked41", pool0), (f"best={best}", best, pool_best)):
            v, fam = arm_spec(arm)
            cfg = json.loads(str(np.load(arm_path(arm, d), allow_pickle=False)["cfg"]))
            m = B.Model(fam, cfg, 32).fit(pl.F[tr_idx], lab[tr_idx])
            sc = m.score(pl.outer(f)["F"])
            res[nm] = {"trained_on_S_train_auc_on_S_train": eval_auc(pst, kst, sc),
                       "trained_on_primary_auc_on_S_train": out["auroc"][d][nm][f"S_train(k>={k},s>={s:.3f})"]}
        out["trained_on_S_train"][d] = res
        print(d, "k,s", k, round(s, 3), json.dumps(out["auroc"][d]), flush=True)
    (B.RES / "secondary.json").write_text(json.dumps(out, indent=1, default=float), encoding="utf-8")
