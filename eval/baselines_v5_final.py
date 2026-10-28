"""docs/19 section 0.8 / 0.9: full-7-day tuning of the best non-anchor candidate, pickle-free export into checkpoints_baselines_v5/, and the
secondary zero-shot cross-dataset evaluation (CTU-13, UNSW-NB15, CIC-2017 60 s; never used for selection).

  python -m eval.baselines_v5_final
Writes checkpoints_baselines_v5/final/*.npz (no .pt, no pickle), docs/lodo_v5/final.json. Reads the external sets with read-only np.load
(allow_pickle=False); window_graphs.pkl files and every PCAP folder are not touched.
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
from eval.baselines_v5_secondary import arm_spec  # noqa: E402
from eval.diagnostics.core import unit_balanced_auroc  # noqa: E402
from models import baseline_export_v5 as E  # noqa: E402
from models import features_v5 as F5  # noqa: E402

EXTERNAL = {"CTU-13": "ctu13_10s_contig", "UNSW-NB15": "unsw_10s_contig", "CIC-2017 60s": "cic2017_zeroshot_60s_noMon"}


def full_tune(pool: B.Pool, family: str, grid: list[dict]) -> dict:
    from joblib import Parallel, delayed
    train = np.ones(len(pool.y), bool)
    ifs = B.inner_folds(pool, train)
    tasks = [(ci, ii) for ci in range(len(grid)) for ii in range(len(ifs))]
    res = Parallel(n_jobs=8, backend="loky")(
        delayed(B.inner_task)(pool.F, pool.y, np.flatnonzero(~ifs[ii][1]), np.flatnonzero(ifs[ii][1]), family, grid[ci], 4) for ci, ii in tasks)
    inner = np.full((len(grid), len(ifs)), np.nan)
    sc = {}
    for (ci, ii), s in zip(tasks, res):
        sc[(ci, ii)] = s
        inner[ci, ii] = B.auc(pool.y[ifs[ii][1]], s)
    mean = np.nanmean(inner, axis=1)
    best = int(np.flatnonzero(mean >= np.nanmax(mean) - 1e-12)[0]) if len(grid) > 1 else 0
    rows = np.concatenate([np.flatnonzero(ifs[ii][1]) for ii in range(len(ifs))])
    s_in = np.concatenate([sc[(best, ii)] for ii in range(len(ifs))])
    thr1 = L.day_balanced_threshold(pool.y[rows], s_in, pool.day[rows], 0.01)
    return {"best": best, "cfg": grid[best], "inner_auc": inner.tolist(), "inner_folds": [n for n, _ in ifs], "inner_mean": mean.tolist(),
            "threshold_1pct": thr1}


def load_external(dirname: str) -> dict:
    parts = []
    for s in ("train", "val", "test"):
        z = np.load(ROOT / "data" / "processed_adapter" / dirname / f"{s}.npz", allow_pickle=False)
        keep = [k for k in ("X", "infiltration", "window_end_time", "window_times", "src_ip", "scenario_id") if k in z.files]
        parts.append({k: z[k] for k in keep})
    keys = set(parts[0]).intersection(*[set(p) for p in parts[1:]])
    return {k: np.concatenate([p[k] for p in parts]) for k in keys}


def external_features(d: dict, variant: str, chunk: int = 100_000) -> tuple[np.ndarray, np.ndarray]:
    ip = d["src_ip"].astype(str)
    unit = np.char.add(np.char.add(d["scenario_id"].astype(str), "|"), ip) if "scenario_id" in d else ip
    mu, sd = F5.causal_context(F5.vol_last_log(d["X"][:, -1, :], B.NAMES), unit, d["window_end_time"])
    out = [F5.build_features(d["X"][i:i + chunk], B.NAMES, variant, T=d["window_times"][i:i + chunk], ctx=(mu[i:i + chunk], sd[i:i + chunk]))[0]
           for i in range(0, len(d["X"]), chunk)]
    return np.concatenate(out), unit


def host_mean_auroc(y, s, ip):
    import pandas as pd
    df = pd.DataFrame({"ip": ip, "y": y, "s": s}).groupby("ip").agg(y=("y", "max"), s=("s", "mean"))
    return B.auc(df["y"].values, df["s"].values), int(len(df)), int(df["y"].sum())


def main() -> None:
    tb = json.loads((B.RES / "tables.json").read_text(encoding="utf-8"))
    best = tb["best_non_anchor"]
    v, fam = arm_spec(best)
    pool, pool0 = B.Pool(v), B.Pool("S0_stacked41")
    grid = B.GRIDS[fam]() if best[0] in "BC" else [B.HGB_DEFAULT]
    tuned = full_tune(pool, fam, grid)
    inc = full_tune(pool0, "HGB", [B.HGB_DEFAULT])
    names = B.feature_names(v)
    names0 = B.feature_names("S0_stacked41")
    model = B.Model(fam, tuned["cfg"], 32).fit(pool.F, pool.y)
    model0 = B.Model("HGB", B.HGB_DEFAULT, 32).fit(pool0.F, pool0.y)
    out_dir = B.CKPT / "final"
    out_dir.mkdir(parents=True, exist_ok=True)
    extra = {"trained_on": "7 non-test CIC-2018 days (six pseudo-host days + 70,000-row seed-0 sample of 02-20), 87,058 rows",
             "config": tuned["cfg"], "selected_by": "full 7-day inner LODO (docs/19 0.9)", "arm": best, "protocol": "docs/19"}
    path = out_dir / f"{best}.npz"
    if fam == "HGB":
        E.export_hgb_v5(model.est, v, names, path, tuned["threshold_1pct"], extra)
    elif fam == "LR":
        E.export_lr(model, v, names, path, tuned["threshold_1pct"], extra)
    else:
        E.export_forest(model, v, names, path, tuned["threshold_1pct"], extra)
    arrays = {k: np.load(path, allow_pickle=False)[k] for k in np.load(path, allow_pickle=False).files}
    chk = float(np.max(np.abs(E.predict_any(arrays, pool.F[:5000]) - model.score(pool.F[:5000]))))
    E.export_hgb_v5(model0.est, "S0_stacked41", names0, out_dir / "HGB_stacked_incumbent_refit.npz", inc["threshold_1pct"],
                    {"note": "the incumbent refit by the docs/19 driver (identical recipe to docs/18)", "config": B.HGB_DEFAULT})
    res = {"best": best, "variant": v, "family": fam, "tuned": tuned, "incumbent_threshold_1pct": inc["threshold_1pct"], "export_path": str(path.relative_to(ROOT)),
           "export_roundtrip_max_abs_diff_5000_train_rows": chk, "n_columns": len(names), "external": {}}
    j_fc = B.NAMES.index("flow_count")
    pool3 = B.Pool("S3_log")
    post_hoc = B.Model("HGB", B.HGB_DEFAULT, 32).fit(pool3.F, pool3.y)
    for label, dn in EXTERNAL.items():
        d = load_external(dn)
        y = (d["infiltration"][:, 0] > 0).astype(int)
        ip = d["src_ip"].astype(str)
        Fc, unit = external_features(d, v)
        F0, _ = external_features(d, "S0_stacked41")
        sc = {"flow_count": d["X"][:, -1, j_fc].astype(float), "HGB_stacked(current)": model0.score(F0), f"candidate={best}": model.score(Fc)}
        if post_hoc is not None:        # S3_log default HGB, post-hoc secondary row (docs/19 section 4), not part of any selection
            sc["S3_log default HGB (post-hoc)"] = post_hoc.score(external_features(d, "S3_log")[0])
        rec = {"n_seq": int(len(y)), "pos_seq": int(y.sum())}
        for n, s in sc.items():
            hm, nh, npos = host_mean_auroc(y, s, ip)
            rec[n] = {"pooled_seq": B.auc(y, s), "unit_balanced": unit_balanced_auroc(y, s, unit), "unit_balanced_by_ip": unit_balanced_auroc(y, s, ip),
                      "host_mean": hm, "n_hosts": nh, "n_pos_hosts": npos}
        res["external"][label] = rec
        print(label, json.dumps({n: {k: (round(x, 3) if isinstance(x, float) else x) for k, x in r.items()} for n, r in rec.items() if isinstance(r, dict)}), flush=True)
    (B.RES / "final.json").write_text(json.dumps(res, indent=1, default=float), encoding="utf-8")


if __name__ == "__main__":
    main()
