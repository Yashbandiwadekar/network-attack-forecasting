"""docs/19 stages after the model fits: tables (+nested selection, gates), threshold (+calibration, adaptive), secondary, robust.

  python -m eval.baselines_v5_stages tables
  python -m eval.baselines_v5_stages threshold
  python -m eval.baselines_v5_stages secondary
  python -m eval.baselines_v5_stages robust
Each writes docs/lodo_v5/<stage>.json. Read-only with respect to everything outside checkpoints_baselines_v5/, docs/lodo_v5/ and
data/processed_adapter/baselines_v5/.
"""
from __future__ import annotations

import argparse
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
from eval.baselines_v5_run import arm_path, load_arm, per_day_auroc  # noqa: E402

DAYS, PSEUDO = R.DAYS, R.PSEUDO


def _dump(name: str, obj) -> None:
    B.RES.mkdir(parents=True, exist_ok=True)
    (B.RES / f"{name}.json").write_text(json.dumps(obj, indent=1, default=float), encoding="utf-8")


def _auprc(y, s):
    return L._ap(y, s)


def best_non_anchor(arm_auc: dict) -> str:
    arms = [a for a in arm_auc if a != "A_S0_stacked41"]
    return max(arms, key=lambda a: (round(R.mean_over(arm_auc[a], DAYS), 12), -list(arm_auc).index(a)))


def stage_tables() -> None:
    arms = R.registered_arms()
    arm_auc = {a: per_day_auroc(a) for a in arms}
    arm_ap = {}
    for a in arms:
        r = load_arm(a)
        arm_ap[a] = {d: _auprc(y, s) for d, (y, s) in r["days"].items()}
    refs = R.ref_per_day()
    sets = {"all7": DAYS, "pseudo6": PSEUDO}
    out = {"arms": arms, "per_day_auroc": arm_auc, "per_day_auprc": arm_ap, "refs": refs, "summary": {}, "gates": {}, "chosen_cfg": {}}
    for a in arms:
        out["chosen_cfg"][a] = load_arm(a)["cfg"]
        out["summary"][a] = {}
        for tag, ds in sets.items():
            v = [arm_auc[a][d] for d in ds]
            out["summary"][a][tag] = {"mean": float(np.mean(v)), "sd": float(np.std(v, ddof=1)), "min": float(np.min(v)), "max": float(np.max(v)),
                                      "ci95_boot": R.boot_ci(arm_auc[a], ds)}
    for n, r in refs.items():
        out["summary"][n] = {tag: {"mean": float(np.mean([r[d] for d in ds])), "sd": float(np.std([r[d] for d in ds], ddof=1)),
                                   "min": float(min(r[d] for d in ds)), "max": float(max(r[d] for d in ds)), "ci95_boot": R.boot_ci(r, ds)}
                             for tag, ds in sets.items()}
    # nested arm selection (the claim) over the registered arms
    nested = R.nested_selection(arm_auc, DAYS)
    out["nested_selection"] = nested
    nested_auc = {d: nested[d]["auroc"] for d in DAYS}
    out["nested_auroc"] = nested_auc
    out["nested_summary"] = {tag: {"mean": float(np.mean([nested_auc[d] for d in ds])), "ci95_boot": R.boot_ci(nested_auc, ds)} for tag, ds in sets.items()}
    # nested selection over NON-anchor arms only (does the search find anything the incumbent does not already have?)
    non_anchor = {a: v for a, v in arm_auc.items() if a != "A_S0_stacked41"}
    nested_na = R.nested_selection(non_anchor, DAYS)
    out["nested_selection_non_anchor"] = nested_na
    nested_na_auc = {d: nested_na[d]["auroc"] for d in DAYS}
    out["nested_non_anchor_auroc"] = nested_na_auc
    best = best_non_anchor(arm_auc)
    out["best_non_anchor"] = best
    out["best_unnested"] = max(arm_auc, key=lambda a: R.mean_over(arm_auc[a], DAYS))
    # gates: candidates vs every reference
    cand = {"nested_selection": nested_auc, "nested_selection_non_anchor": nested_na_auc, f"best_non_anchor={best}": arm_auc[best]}
    for a in arms:
        cand.setdefault(a, arm_auc[a])
    for cname, c in cand.items():
        for rn, r in refs.items():
            for tag, ds in sets.items():
                out["gates"][f"{cname}|{rn}|{tag}"] = R.gate_row(c, r, ds)
    # EXPLORATORY (not registered, excluded from the arm count, nested selection and every verdict): probability average of the incumbent and the best non-anchor arm
    ex = {}
    for f in L.build_folds(n_groups=B.N_GROUPS):
        y, s0, _ = R.fold_scores("A_S0_stacked41", f)
        _, s1, _ = R.fold_scores(best, f)
        ex.setdefault(f.day, []).append((y, 0.5 * (s0 + s1)))
    ex_auc = {d: B.auc(np.concatenate([a for a, _ in v]), np.concatenate([b for _, b in v])) for d, v in ex.items()}
    out["exploratory_mean_S0_and_best"] = {"per_day": ex_auc, "mean7": float(np.mean(list(ex_auc.values()))),
                                           "gate_vs_HGB_stacked_all7": R.gate_row(ex_auc, refs["HGB_stacked"], DAYS),
                                           "gate_vs_flow_count_all7": R.gate_row(ex_auc, refs["flow_count"], DAYS)}
    _dump("tables", out)
    print(json.dumps({"best_non_anchor": best, "best_unnested": out["best_unnested"], "nested": out["nested_summary"],
                      "summary7": {a: round(out["summary"][a]["all7"]["mean"], 4) for a in arms}}, indent=1))


def stage_threshold() -> None:
    from eval.baselines_v5_run import VARIANTS  # noqa: F401
    tb = json.loads((B.RES / "tables.json").read_text(encoding="utf-8"))
    best = tb["best_non_anchor"]
    b_arms = [a for a in tb["arms"] if a.startswith("B_")]
    best_b = max(b_arms, key=lambda a: tb["summary"][a]["all7"]["mean"]) if b_arms else best
    # evaluation-only additions (not selection): the normalised / temporal variants S5, S6, S7, so that "does the rolling baseline reduce the operating-point shift" is measured
    arms = ["A_S0_stacked41", best, best_b, "A_S5_temporal", "A_S6_context", "A_S7_relative"]
    arms = list(dict.fromkeys(arms))
    pool0 = B.Pool("S0_stacked41")
    j_fc = B.feature_names("S0_stacked41").index("last:flow_count") if False else None
    names0 = json.loads((B.DATA / PSEUDO[0] / "S0_stacked41.names.json").read_text())
    j_fc = names0.index("last:flow_count")
    folds = pool0.folds()
    targets = (0.01, 0.05)
    out: dict = {"arms": arms, "best_b": best_b, "targets": targets, "rows": {}}

    def day_rows(rule: str, getter):
        """getter(fold) -> (y, alarm bool array) ; pooled per day"""
        per: dict = {}
        for f in folds:
            y, alarm = getter(f)
            per.setdefault(f.day, []).append((y, alarm))
        res = {}
        for d, v in per.items():
            y = np.concatenate([a for a, _ in v]); al = np.concatenate([b for _, b in v])
            neg, pos = y <= 0, y > 0
            res[d] = {"fpr": float(al[neg].mean()) if neg.any() else None, "recall": float(al[pos].mean()) if pos.any() else None,
                      "alarm_rate": float(al.mean()), "n_neg": int(neg.sum()), "n_pos": int(pos.sum())}
        return res

    for tgt in targets:
        key = f"fpr{int(tgt * 100)}pct"
        out["rows"][key] = {}
        # flow_count: threshold from the raw scores of the outer-train rows (no model, so nothing to nest)
        def fc_getter(f, tgt=tgt):
            O = pool0.outer(f)
            tr = O["train"]
            thr = L.day_balanced_threshold(pool0.y[tr], pool0.F[tr, j_fc], pool0.day[tr], tgt)
            return O["y"], O["F"][:, j_fc] >= thr
        out["rows"][key]["flow_count"] = day_rows("flow_count", fc_getter)
        for a in arms:
            def getter(f, a=a, tgt=tgt):
                y, s, _ = R.fold_scores(a, f)
                return y, s >= R.thresholds_from_inner(a, f, tgt)
            out["rows"][key][a] = day_rows(a, getter)
        # calibrated versions of the best stage-B arm: calibrator and threshold both from inner OOF scores of the outer-train days
        for kind in ("platt", "isotonic"):
            def cgetter(f, kind=kind, tgt=tgt):
                z = np.load(arm_path(best_b, f.name), allow_pickle=False)
                cal = R.calibrate_fold(best_b, f, kind)
                thr = L.day_balanced_threshold(z["inner_y"], cal(z["inner_score"]), z["inner_day"], tgt)
                return z["y"], cal(z["score"]) >= thr
            out["rows"][key][f"{best_b}+{kind}"] = day_rows(kind, cgetter)
    # adaptive rolling-quantile rule on pseudo-host days (primary 1% <-> q = 0.99; 5% <-> q = 0.95)
    for tgt in targets:
        key = f"adaptive_q{int((1 - tgt) * 100)}"
        out["rows"][key] = {}
        for a in ["flow_count"] + arms:
            per = {}
            for f in folds:
                if f.day == L.HOST_SPLIT_DAY:
                    continue
                if a == "flow_count":
                    O = pool0.outer(f); y, s = O["y"], O["F"][:, j_fc]
                else:
                    y, s, _ = R.fold_scores(a, f)
                per[f.day] = (y, R.adaptive_alarm(s, q=1 - tgt))
            res = {}
            for d, (y, al) in per.items():
                neg, pos = y <= 0, y > 0
                res[d] = {"fpr": float(al[neg].mean()), "recall": float(al[pos].mean()) if pos.any() else None,
                          "alarm_rate": float(al.mean()), "n_neg": int(neg.sum()), "n_pos": int(pos.sum())}
            out["rows"][key][a] = res
    # calibration quality (Brier, ECE) of raw / Platt / isotonic scores, per day, outer held-out
    cal = {}
    for kind in ("raw", "platt", "isotonic"):
        per = {}
        for f in folds:
            y, s, _ = R.fold_scores(best_b, f)
            p = s if kind == "raw" else R.calibrate_fold(best_b, f, kind)(s)
            per.setdefault(f.day, []).append((y, p))
        cal[kind] = {d: dict(zip(("brier", "ece"), R.brier_ece(np.concatenate([a for a, _ in v]), np.concatenate([b for _, b in v])))) for d, v in per.items()}
        # within-day AUROC after calibration (isotonic can only add ties)
        cal[kind + "_auroc"] = {d: B.auc(np.concatenate([a for a, _ in v]), np.concatenate([b for _, b in v])) for d, v in per.items()}
    out["calibration"] = cal
    # summary
    summ = {}
    for key, d1 in out["rows"].items():
        summ[key] = {}
        for name, rows in d1.items():
            fp = {d: r["fpr"] for d, r in rows.items()}
            nn = {d: r["n_neg"] for d, r in rows.items()}
            tgt = (0.01 if key in ("fpr1pct", "adaptive_q99") else 0.05)
            summ[key][name] = R.transfer_summary(fp, nn, tgt)
    out["summary"] = summ
    _dump("threshold", out)
    print(json.dumps(summ, indent=1))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["tables", "threshold", "secondary", "robust"])
    a = ap.parse_args()
    if a.stage == "tables":
        stage_tables()
    elif a.stage == "threshold":
        stage_threshold()
    elif a.stage == "secondary":
        from eval.baselines_v5_secondary import stage_secondary
        stage_secondary()
    else:
        from eval.baselines_v5_robust import stage_robust
        stage_robust()


if __name__ == "__main__":
    main()
