"""docs/19 driver. Stages (each a separate invocation; section 0 of docs/19 fixes what they do):

  anchor    S0 + default HGB on the 9 outer folds must reproduce the docs/18 HGB_stacked OOF scores (stops otherwise)
  A         the 8 feature variants with the default HGB configuration (9 outer folds, inner OOF scores kept for thresholds)
  B         nested-LODO HGB tuning on the two best non-anchor variants of stage A
  C         ExtraTrees / RandomForest / LR (nested-LODO tuned) on the best non-anchor variant of stage A

Outputs: checkpoints_baselines_v5/oof/<arm>/<fold>.npz  (outer OOF scores + chosen configuration + inner OOF scores of that configuration)
and docs/lodo_v5/stage_*.json (choices). Reads data/processed_adapter/lodo_v4 and baselines_v5 only; the sealed test is never opened.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval import baselines_v5 as B  # noqa: E402
from eval import lodo_v4 as L  # noqa: E402
from models import features_v5 as F5  # noqa: E402

OOF = B.CKPT / "oof"
VARIANTS = list(F5.VARIANTS)
N_JOBS = 8


def arm_path(arm: str, fold: str) -> Path:
    return OOF / arm / f"{fold.replace('#', '_')}.npz"


def run_arm(arm: str, variant: str, family: str, grid: list[dict], pool: B.Pool, tune: bool, n_jobs: int = N_JOBS) -> None:
    """For every outer fold: [inner LODO over the outer-train days for every grid configuration] -> best configuration -> refit on all
    outer-train rows -> score the outer held-out rows. tune=False: grid has one entry; the inner loop still runs once to store inner OOF
    scores of that configuration (needed for thresholds and calibration)."""
    from joblib import Parallel, delayed
    (OOF / arm).mkdir(parents=True, exist_ok=True)
    for fold in pool.folds():
        f_out = arm_path(arm, fold.name)
        if f_out.exists():
            continue
        t0 = time.time()
        O = pool.outer(fold)
        ifs = B.inner_folds(pool, O["train"])
        tasks = [(ci, ii) for ci in range(len(grid)) for ii in range(len(ifs))]
        res = Parallel(n_jobs=n_jobs, backend="loky")(
            delayed(B.inner_task)(pool.F, pool.y, np.flatnonzero(O["train"] & ~ifs[ii][1]), np.flatnonzero(ifs[ii][1]), family, grid[ci], 4)
            for ci, ii in tasks)
        inner_auc = np.full((len(grid), len(ifs)), np.nan)
        scores = {}
        for (ci, ii), s in zip(tasks, res):
            scores[(ci, ii)] = s
            inner_auc[ci, ii] = B.auc(pool.y[ifs[ii][1]], s)
        mean_auc = np.nanmean(inner_auc, axis=1)
        best = int(np.flatnonzero(mean_auc >= np.nanmax(mean_auc) - 1e-12)[0]) if tune else 0
        rows = np.concatenate([np.flatnonzero(ifs[ii][1]) for ii in range(len(ifs))])
        inner_score = np.concatenate([scores[(best, ii)] for ii in range(len(ifs))])
        tr = np.flatnonzero(O["train"])
        m = B.Model(family, grid[best], 32).fit(pool.F[tr], pool.y[tr])
        sc = m.score(O["F"]).astype(np.float32)
        np.savez(f_out, y=O["y"], idx=O["idx"], score=sc, cfg=json.dumps(grid[best]), cfg_index=best, inner_auc=inner_auc,
                 inner_names=np.array([n for n, _ in ifs]), inner_rows=rows, inner_score=inner_score,
                 inner_day=pool.day[rows], inner_y=pool.y[rows])
        print(f"[{arm}] {fold.name}: cfg#{best} inner mean AUROC {mean_auc[best]:.3f}  held-out AUROC {B.auc(O['y'], sc):.3f}  "
              f"({len(tasks)} inner fits, {time.time() - t0:.0f}s)", flush=True)


def load_arm(arm: str) -> dict:
    """{day: (y, score)} pooled per day (02-20 groups concatenated) and the chosen configuration per fold."""
    per: dict = {}
    cfgs = {}
    for fold in L.build_folds(n_groups=B.N_GROUPS):
        z = np.load(arm_path(arm, fold.name), allow_pickle=False)
        per.setdefault(fold.day, []).append((z["y"], z["score"]))
        cfgs[fold.name] = json.loads(str(z["cfg"]))
    out = {d: (np.concatenate([a for a, _ in v]), np.concatenate([b for _, b in v])) for d, v in per.items()}
    return {"days": out, "cfg": cfgs}


def per_day_auroc(arm: str) -> dict[str, float]:
    r = load_arm(arm)
    return {d: B.auc(y, s) for d, (y, s) in r["days"].items()}


def stage_anchor() -> None:
    pool = B.Pool("S0_stacked41")
    run_arm("A_S0_stacked41", "S0_stacked41", "HGB", [B.HGB_DEFAULT], pool, tune=False)
    worst = 0.0
    rows = []
    for fold in pool.folds():
        z = np.load(arm_path("A_S0_stacked41", fold.name))
        ref = np.load(ROOT / "checkpoints_lodo_v4" / "oof" / f"{fold.name}__baselines.npz")
        assert np.array_equal(ref["idx"], z["idx"]) and np.array_equal(ref["y"], z["y"]), f"row mismatch in {fold.name}"
        d = float(np.max(np.abs(ref["HGB_stacked"] - z["score"])))
        worst = max(worst, d)
        rows.append({"fold": fold.name, "max_abs_score_diff": d, "auroc_new": B.auc(z["y"], z["score"]), "auroc_docs18": B.auc(ref["y"], ref["HGB_stacked"])})
        print(rows[-1], flush=True)
    new, old = per_day_auroc("A_S0_stacked41"), {}
    for fold in pool.folds():
        pass
    ref_days: dict = {}
    for fold in pool.folds():
        ref = np.load(ROOT / "checkpoints_lodo_v4" / "oof" / f"{fold.name}__baselines.npz")
        ref_days.setdefault(fold.day, []).append((ref["y"], ref["HGB_stacked"]))
    old = {d: B.auc(np.concatenate([a for a, _ in v]), np.concatenate([b for _, b in v])) for d, v in ref_days.items()}
    ok = all(abs(new[d] - old[d]) < 5e-4 for d in new)
    B.RES.mkdir(parents=True, exist_ok=True)
    (B.RES / "anchor.json").write_text(json.dumps({"ok": ok, "worst_abs_score_diff": worst, "per_fold": rows, "new": new, "docs18": old,
                                                    "mean_new": float(np.mean(list(new.values()))), "mean_docs18": float(np.mean(list(old.values())))},
                                                   indent=1), encoding="utf-8")
    print("ANCHOR", "OK" if ok else "FAILED", "mean new", np.mean(list(new.values())), "docs18", np.mean(list(old.values())), "worst score diff", worst)
    if not ok:
        raise SystemExit("anchor failed: the new HGB_stacked does not reproduce docs/18; stop")


def stage_a() -> None:
    for v in VARIANTS:
        pool = B.Pool(v)
        run_arm(f"A_{v}", v, "HGB", [B.HGB_DEFAULT], pool, tune=False)
    res = {v: per_day_auroc(f"A_{v}") for v in VARIANTS}
    means = {v: float(np.nanmean(list(r.values()))) for v, r in res.items()}
    non_anchor = [v for v in VARIANTS if v != "S0_stacked41"]
    ranked = sorted(non_anchor, key=lambda v: (-round(means[v], 12), VARIANTS.index(v)))
    out = {"means_7day": means, "per_day": res, "best_two_non_anchor": ranked[:2], "best_non_anchor": ranked[0]}
    (B.RES / "stage_A.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(json.dumps({"means": means, "best_two": ranked[:2]}, indent=1))


def stage_b() -> None:
    sa = json.loads((B.RES / "stage_A.json").read_text(encoding="utf-8"))
    for v in sa["best_two_non_anchor"]:
        pool = B.Pool(v)
        run_arm(f"B_{v}_HGBtuned", v, "HGB", B.hgb_grid(), pool, tune=True)
    out = {v: per_day_auroc(f"B_{v}_HGBtuned") for v in sa["best_two_non_anchor"]}
    (B.RES / "stage_B.json").write_text(json.dumps({"per_day": out, "variants": sa["best_two_non_anchor"],
                                                    "mean_7day": {v: float(np.nanmean(list(r.values()))) for v, r in out.items()}}, indent=1))
    print({v: np.nanmean(list(r.values())) for v, r in out.items()})


def stage_c() -> None:
    sa = json.loads((B.RES / "stage_A.json").read_text(encoding="utf-8"))
    v = sa["best_non_anchor"]
    pool = B.Pool(v)
    for fam in ("ET", "RF", "LR"):
        run_arm(f"C_{v}_{fam}", v, fam, B.GRIDS[fam](), pool, tune=True, n_jobs=(4 if fam != "LR" else 8))
    out = {fam: per_day_auroc(f"C_{v}_{fam}") for fam in ("ET", "RF", "LR")}
    (B.RES / "stage_C.json").write_text(json.dumps({"variant": v, "per_day": out, "mean_7day": {f: float(np.nanmean(list(r.values()))) for f, r in out.items()}}, indent=1))
    print({f: np.nanmean(list(r.values())) for f, r in out.items()})


def stage_prep() -> None:
    """Build the per-day causal context and the feature cache of every variant (deterministic; data/processed_adapter/baselines_v5/)."""
    for d in L.LODO_DAYS:
        B.prep_context(d)
        for v in VARIANTS:
            B.prep_variant(d, v)
        print("prepared", d, flush=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["prep", "anchor", "A", "B", "C"])
    a = ap.parse_args()
    B.RES.mkdir(parents=True, exist_ok=True)
    {"prep": stage_prep, "anchor": stage_anchor, "A": stage_a, "B": stage_b, "C": stage_c}[a.stage]()


if __name__ == "__main__":
    main()
