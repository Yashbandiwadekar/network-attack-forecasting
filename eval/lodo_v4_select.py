"""docs/18 stages `select` and `final` (see eval/lodo_v4_run.py). `select` applies the rules fixed in docs/18 section 0 to the stored
OOF scores; `final` retrains the selected recipe on all seven days and opens the sealed test split exactly once."""
from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np

from common.config import feature_columns, load_config
from eval import lodo_v4 as L
from eval import lodo_v4_run as R
from eval.baseline_gate import BASELINE_NAMES, baseline_scores, fit_baselines
from eval.diagnostics import core as C
from models.checkpoint_io import load_checkpoint

SEEDS5 = (1, 2, 3, 4, 5)
SEEDS3 = (1, 2, 3)


def episode_summary(arr: dict, window_seconds: int = 10) -> dict:
    """Onset episodes (docs/13 convention: eval.onset_eval.structure) of a split, total and per host key."""
    from eval.onset_eval import structure
    S = structure(arr, window_seconds)
    per: dict[str, int] = {}
    for e in S["episodes"]:
        per[e.key] = per.get(e.key, 0) + 1
    y = np.asarray(arr["infiltration"])[:, 0] > 0
    return {"n_episodes": len(S["episodes"]), "n_hosts_with_episode": len(per), "label_mismatch": int(S["mismatch"]),
            "n_hosts": int(len(np.unique(np.asarray(arr["src_ip"]).astype(str)))),
            "n_hosts_with_positive": int(len(np.unique(np.asarray(arr["src_ip"]).astype(str)[y])))}


def day_arrays(day: str) -> dict:
    return {k: np.load(R.CACHE / day / f"{k}.npy", mmap_mode="r") for k in
            ["window_times", "current_stage", "current_infiltration", "future_stages", "infiltration", "src_ip"]}


# ----------------------------------------------------------------------------- OOF assembly

def load_oof(seeds) -> dict:
    """{day: {"y": y, "probs": {seed: (E, n)}, "base": {name: (n,)}, "idx": idx-or-None}} with 02-20 pooled over its host groups."""
    out: dict = {}
    for fold in L.build_folds(n_groups=R.N_GROUPS):
        parts = []
        for s in seeds:
            z = np.load(R.OOF / f"{fold.name}__s{s}.npz")
            parts.append((s, z["probs"], z["y"], z["idx"]))
        b = np.load(R.OOF / f"{fold.name}__baselines.npz")
        d = out.setdefault(fold.day, {"y": [], "probs": {s: [] for s in seeds}, "base": {n: [] for n in BASELINE_NAMES}, "idx": [],
                                      "fold_names": []})
        for s, p, y, idx in parts:
            d["probs"][s].append(p)
        d["y"].append(parts[0][2])
        d["idx"].append(parts[0][3])
        d["fold_names"].append(fold.name)
        for n in BASELINE_NAMES:
            d["base"][n].append(b[n])
    for day, d in out.items():
        d["y"] = np.concatenate(d["y"])
        d["idx"] = np.concatenate(d["idx"])
        d["probs"] = {s: np.concatenate(v, axis=1) for s, v in d["probs"].items()}
        d["base"] = {n: np.concatenate(v) for n, v in d["base"].items()}
    return out


def _curves(oof: dict, seeds, metric) -> tuple[dict, dict, dict]:
    """per-day per-epoch metric: (single = seed mean, ensemble = metric of seed-averaged probability, per_seed array [S, E])."""
    single, ens, per_seed = {}, {}, {}
    for day, d in oof.items():
        E = next(iter(d["probs"].values())).shape[0]
        ps = np.array([[metric(d["y"], d["probs"][s][e]) for e in range(E)] for s in seeds])
        mean_p = np.mean([d["probs"][s] for s in seeds], axis=0)
        en = np.array([metric(d["y"], mean_p[e]) for e in range(E)])
        per_seed[day], single[day], ens[day] = ps, np.nanmean(ps, axis=0), en
    return single, ens, per_seed


def _day_mean(dct: dict) -> float:
    return L.selection_metric({k: v for k, v in dct.items()})


def stage_select() -> None:
    RES = R.RES
    RES.mkdir(parents=True, exist_ok=True)
    oof = load_oof(SEEDS5)
    days = sorted(oof)
    assert set(days) == set(L.LODO_DAYS), days
    E = next(iter(oof[days[0]]["probs"].values())).shape[0]
    res: dict = {"days": days, "epochs": E, "seeds5": list(SEEDS5), "seeds3": list(SEEDS3), "protocol": "docs/18 section 0"}
    # ---- curves
    auc_s5, auc_e5, auc_ps5 = _curves(oof, SEEDS5, L._auc)
    auc_s3, auc_e3, _ = _curves(oof, SEEDS3, L._auc)
    ap_s5, ap_e5, _ = _curves(oof, SEEDS5, L._ap)
    sel = {}
    for name, curves in [("single", auc_s5), ("ens5", auc_e5), ("ens3", auc_e3)]:
        e, mean = L.select_epoch(curves)
        nested = L.nested_epoch_selection(curves)
        sel[name] = {"epoch_index": e, "epoch": e + 1, "oof_mean_auroc_at_epoch": float(mean[e]),
                     "mean_curve": [float(x) for x in mean], "nested": nested,
                     "nested_mean_auroc": float(np.mean([v["auroc"] for v in nested.values()])),
                     "per_day_auroc_at_epoch": {d: float(curves[d][e]) for d in days},
                     "per_day_curves": {d: [float(x) for x in curves[d]] for d in days}}
    res["selection"] = sel
    res["val_loss_not_used"] = True
    # ---- per-day table at the selected epochs: AUROC / AUPRC for model variants and baselines
    def nested_epoch(name, d):
        return sel[name]["nested"][d]["epoch"]            # 0-based, as returned by nested_epoch_selection

    per_day: dict = {}
    for d in days:
        y = oof[d]["y"]
        row = {"n": int(len(y)), "pos": int(y.sum()), "family": L.DAY_FAMILY[d]}
        for name, ap_curve, auc_curve in [("single", ap_s5, auc_s5), ("ens5", ap_e5, auc_e5)]:
            e_g, e_n = sel[name]["epoch_index"], nested_epoch(name, d)
            row[name] = {"auroc_global_epoch": float(auc_curve[d][e_g]), "auroc_nested": float(auc_curve[d][e_n]),
                         "auprc_global_epoch": float(ap_curve[d][e_g]), "auprc_nested": float(ap_curve[d][e_n])}
        row["ens3"] = {"auroc_global_epoch": float(auc_e3[d][sel["ens3"]["epoch_index"]]),
                       "auroc_nested": float(auc_e3[d][nested_epoch("ens3", d)])}
        row["single_seed_sd_global_epoch"] = float(np.std(auc_ps5[d][:, sel["single"]["epoch_index"]], ddof=1))
        for n in BASELINE_NAMES:
            row[n] = {"auroc": L._auc(y, oof[d]["base"][n]), "auprc": L._ap(y, oof[d]["base"][n])}
        per_day[d] = row
    res["per_day"] = per_day
    # ---- persistence oracle and episode counts from the cache (not deployable / structure only)
    for d in days:
        y = oof[d]["y"]
        full = np.load(R.CACHE / d / "current_infiltration.npy", mmap_mode="r")
        # a day fold holds out the whole day in file order; the 02-20 OOF rows are the host-group rows given by idx
        cur = np.asarray(full[oof[d]["idx"]]) if d == L.HOST_SPLIT_DAY else np.asarray(full)
        assert len(cur) == len(y)
        per_day[d]["persistence_oracle"] = {"auroc": L._auc(y, cur + 1e-9 * oof[d]["base"]["flow_count"])}
        t0 = time.time()
        per_day[d]["episodes"] = episode_summary({k: np.asarray(v) for k, v in day_arrays(d).items()})
        print(f"episodes {d}: {per_day[d]['episodes']} ({time.time() - t0:.0f}s)", flush=True)
    # ---- aggregates and the gate
    covered = [d for d in days if L.family_coverage(L.Fold(d, d), [x for x in days if x != d])["family_in_train"]]
    pseudo = [d for d in days if d != L.HOST_SPLIT_DAY]
    res["family_coverage"] = {d: L.family_coverage(L.Fold(d, d), [x for x in days if x != d]) for d in days}
    res["day_sets"] = {"all7": days, "pseudo_host6": pseudo, "family_covered": covered}

    def agg(get):
        out = {}
        for tag, ds in res["day_sets"].items():
            v = [get(d) for d in ds if get(d) is not None and not np.isnan(get(d))]
            out[tag] = {"mean": float(np.mean(v)), "sd": float(np.std(v, ddof=1)) if len(v) > 1 else None, "n": len(v)}
        return out
    res["aggregate_auroc"] = {
        "single_nested": agg(lambda d: per_day[d]["single"]["auroc_nested"]),
        "single_global_epoch": agg(lambda d: per_day[d]["single"]["auroc_global_epoch"]),
        "ens5_nested": agg(lambda d: per_day[d]["ens5"]["auroc_nested"]),
        "ens5_global_epoch": agg(lambda d: per_day[d]["ens5"]["auroc_global_epoch"]),
        "ens3_nested": agg(lambda d: per_day[d]["ens3"]["auroc_nested"]),
        **{n: agg(lambda d, n=n: per_day[d][n]["auroc"]) for n in BASELINE_NAMES},
        "persistence_oracle": agg(lambda d: per_day[d]["persistence_oracle"]["auroc"]),
    }
    gates = {}
    for tag, dset in [("all7", days), ("pseudo_host6", pseudo)]:
        for mname, getter in [("single", lambda d: per_day[d]["single"]["auroc_nested"]),
                              ("ens5", lambda d: per_day[d]["ens5"]["auroc_nested"]),
                              ("ens3", lambda d: per_day[d]["ens3"]["auroc_nested"])]:
            m = {d: getter(d) for d in dset}
            for b in BASELINE_NAMES:
                gates[f"{mname}|{b}|{tag}"] = C.baseline_gate(m, {d: per_day[d][b]["auroc"] for d in dset})
    # HGB vs the other baselines (is the tree itself better than the one-liner?)
    for b in ("HGB_last", "HGB_stacked"):
        gates[f"{b}|flow_count|all7"] = C.baseline_gate({d: per_day[d][b]["auroc"] for d in days},
                                                       {d: per_day[d]["flow_count"]["auroc"] for d in days})
    res["gates"] = gates
    # ---- operating points from OOF at the selected epochs
    ops = {}
    for name, seeds in [("single", SEEDS5), ("ens5", SEEDS5)]:
        e = sel[name]["epoch_index"]
        y_all = np.concatenate([oof[d]["y"] for d in days])
        day_all = np.concatenate([[d] * len(oof[d]["y"]) for d in days])
        if name == "single":     # each seed's OOF score vector is a replicate of the single-model recipe
            ys = np.tile(y_all, len(seeds))
            ds = np.tile(day_all, len(seeds))
            sc = np.concatenate([np.concatenate([oof[d]["probs"][s][e] for d in days]) for s in seeds])
        else:
            ys, ds = y_all, day_all
            sc = np.concatenate([np.mean([oof[d]["probs"][s][e] for s in seeds], axis=0) for d in days])
        for fpr in (0.01, 0.05):
            thr = L.day_balanced_threshold(ys, sc, ds, fpr)
            ops[f"{name}|fpr{int(fpr * 100)}pct"] = {"threshold": thr, "epoch": e + 1,
                                                    "per_day_oof": L.operating_point_by_day(ys, sc, ds, thr)}
    for b in ("HGB_last", "HGB_stacked", "LR_last"):          # same rule for the trees / LR (their scores are probabilities)
        y_all = np.concatenate([oof[d]["y"] for d in days])
        day_all = np.concatenate([[d] * len(oof[d]["y"]) for d in days])
        sc = np.concatenate([oof[d]["base"][b] for d in days])
        for fpr in (0.01, 0.05):
            thr = L.day_balanced_threshold(y_all, sc, day_all, fpr)
            ops[f"{b}|fpr{int(fpr * 100)}pct"] = {"threshold": thr, "epoch": None,
                                                 "per_day_oof": L.operating_point_by_day(y_all, sc, day_all, thr)}
    res["operating_points"] = ops
    res["decisions"] = {"E_single": sel["single"]["epoch"], "E_ens5": sel["ens5"]["epoch"], "E_ens3": sel["ens3"]["epoch"],
                        "threshold_single_1pct": ops["single|fpr1pct"]["threshold"],
                        "threshold_ens5_1pct": ops["ens5|fpr1pct"]["threshold"],
                        "threshold_single_5pct": ops["single|fpr5pct"]["threshold"],
                        "threshold_ens5_5pct": ops["ens5|fpr5pct"]["threshold"],
                        "threshold_HGB_last_1pct": ops["HGB_last|fpr1pct"]["threshold"],
                        "threshold_HGB_stacked_1pct": ops["HGB_stacked|fpr1pct"]["threshold"],
                        "threshold_LR_last_1pct": ops["LR_last|fpr1pct"]["threshold"]}
    # ---- timing
    tf = R.RES / "oof_timing.jsonl"
    if tf.exists():
        rows = [json.loads(x) for x in tf.read_text().splitlines() if x.strip()]
        res["gpu_seconds_oof"] = float(sum(r["gpu_seconds"] for r in rows))
        res["n_oof_runs"] = len(rows)
    (RES / "selection.json").write_text(json.dumps(res, indent=1, default=float), encoding="utf-8")
    print(json.dumps(res["decisions"], indent=1), flush=True)
    print("aggregate AUROC:", {k: {t: round(v["mean"], 3) for t, v in a.items()} for k, a in res["aggregate_auroc"].items()}, flush=True)


# ----------------------------------------------------------------------------- final (sealed test, once)

def stage_final() -> None:
    import torch
    from models.dataset import FeatureScaler
    from models.world_model import WorldModel
    RES = R.RES
    sel_path, out_path = RES / "selection.json", RES / "test_sealed.json"
    if not sel_path.exists():
        raise SystemExit("selection.json missing: run the `select` stage first (protocol docs/18 0.8)")
    if out_path.exists():
        raise SystemExit(f"{out_path.name} exists: the sealed test split has been scored once and must not be re-scored")
    sel = json.loads(sel_path.read_text())
    dec = sel["decisions"]
    config = load_config(R.CONFIG_PATH)
    names = feature_columns(config)
    epochs_needed = sorted({dec["E_single"], dec["E_ens5"], dec["E_ens3"]})
    P = R.load_pool()
    pool = P["pool"]
    Xtr, ntr, ftr, itr = (pool[k] for k in R.KEYS)
    ytr = (itr[:, 0] > 0).astype(int)
    scaler = FeatureScaler().fit(Xtr)
    dev = R._dev()
    print(f"final: training on all 7 days, {len(ytr)} rows, snapshots at epochs {epochs_needed}", flush=True)
    secs_total = 0.0
    for s in SEEDS5:
        _, secs = R.fit_transformer(Xtr, ntr, ftr, itr, scaler, config, s, max(epochs_needed), None,
                                    snapshot_epochs=epochs_needed, snapshot_dir=R.CKPT / "final" / f"seed{s}")
        secs_total += secs
        print(f"  seed {s}: {secs:.0f}s", flush=True)
    t0 = time.time()
    base_models = fit_baselines(Xtr, ytr, names.index("flow_count"), max_train_rows=None)
    hgb_export_path = R.CKPT / "final" / "hgb_last_flat.npz"
    try:
        from models.tree_export import export_hgb
        export_hgb(base_models["HGB_last"].estimator, names, hgb_export_path, threshold=dec["threshold_HGB_last_1pct"])
    except Exception as exc:                 # export is a convenience; the scientific result must not depend on it
        print("  HGB export failed:", repr(exc), flush=True)
    print(f"  baselines fitted {time.time() - t0:.0f}s", flush=True)
    # ---------------- the sealed split is opened here and only here
    z = np.load(R.ROOT / "data" / "processed_real_v2_converged" / "test.npz", allow_pickle=False)
    T = {k: z[k] for k in z.files}
    day = T["window_end_time"].astype("datetime64[D]").astype(str)
    y = (T["infiltration"][:, 0] > 0).astype(int)
    scores: dict[str, np.ndarray] = {}

    def snap_probs(seed, ep):
        ck = load_checkpoint(R.CKPT / "final" / f"seed{seed}" / f"ep{ep}.pt", dev)          # safe loader (weights_only=True)
        m = WorldModel(Xtr.shape[-1], len(config["mitre_stages"]), config).to(dev)
        m.load_state_dict(ck["model_state"])
        m.eval()
        sc = FeatureScaler(mean=ck["scaler_mean"].cpu().numpy(), std=ck["scaler_std"].cpu().numpy(), clip_std=ck["scaler_clip_std"])
        return R._predict(m, torch.tensor(sc.transform(T["X"]), dtype=torch.float32, device=dev))

    single_p = {s: snap_probs(s, dec["E_single"]) for s in SEEDS5}
    ens5 = np.mean([snap_probs(s, dec["E_ens5"]) for s in SEEDS5], axis=0)
    ens3 = np.mean([snap_probs(s, dec["E_ens3"]) for s in SEEDS3], axis=0)
    for s in SEEDS5:
        scores[f"transformer_seed{s}"] = single_p[s]
    scores["transformer_ens5"] = ens5
    scores["transformer_ens3"] = ens3
    scores.update(baseline_scores(base_models, T["X"]))
    scores["persistence_oracle"] = T["current_infiltration"] + 1e-9 * T["X"][:, -1, names.index("flow_count")]
    days = sorted(set(day))
    assert set(days) == set(L.SEALED_TEST_DAYS), days
    per_day = {}
    for d in days:
        m = day == d
        row = {"n": int(m.sum()), "pos": int(y[m].sum()), "family": L.DAY_FAMILY[d],
               "episodes": episode_summary({k: v[m] for k, v in T.items() if len(v) == len(day)})}
        for n, sc in scores.items():
            row[n] = {"auroc": L._auc(y[m], sc[m]), "auprc": L._ap(y[m], sc[m])}
        per_day[d] = row
    # thresholds from OOF (frozen in selection.json), applied unchanged
    ops = {}
    for tag, key, sc in [("single_seed_mean_1pct", "threshold_single_1pct", None), ("ens5_1pct", "threshold_ens5_1pct", ens5),
                         ("single_seed_mean_5pct", "threshold_single_5pct", None), ("ens5_5pct", "threshold_ens5_5pct", ens5)]:
        thr = dec[key]
        if sc is None:
            per_seed = [L.operating_point_by_day(y, single_p[s], day, thr) for s in SEEDS5]
            ops[tag] = {"threshold": thr, "per_day_mean_over_seeds": {
                d: {k: float(np.mean([p[d][k] for p in per_seed])) for k in ("fpr", "tpr", "alarm_rate")} for d in days}}
        else:
            ops[tag] = {"threshold": thr, "per_day": L.operating_point_by_day(y, sc, day, thr)}
    for b in ("HGB_last", "HGB_stacked", "LR_last"):
        thr = dec[f"threshold_{b}_1pct"]
        ops[f"{b}_1pct"] = {"threshold": thr, "per_day": L.operating_point_by_day(y, scores[b], day, thr)}
    # gates on the 3 sealed days
    gates = {}
    for mname in ("transformer_ens5", "transformer_ens3"):
        for b in BASELINE_NAMES:
            gates[f"{mname}|{b}"] = C.baseline_gate({d: per_day[d][mname]["auroc"] for d in days},
                                                    {d: per_day[d][b]["auroc"] for d in days})
    single_mean = {d: float(np.mean([per_day[d][f"transformer_seed{s}"]["auroc"] for s in SEEDS5])) for d in days}
    for b in BASELINE_NAMES:
        gates[f"transformer_single_seedmean|{b}"] = C.baseline_gate(single_mean, {d: per_day[d][b]["auroc"] for d in days})
    pooled = {n: L._auc(y, sc) for n, sc in scores.items()}
    out = {"opened": time.strftime("%Y-%m-%d %H:%M:%S"), "decisions_used": dec, "n_test": int(len(y)), "per_day": per_day,
           "single_seed_mean_auroc": single_mean, "pooled_auroc_secondary": pooled, "operating_points": ops, "gates": gates,
           "gpu_seconds_final_training": secs_total}
    out_path.write_text(json.dumps(out, indent=1, default=float), encoding="utf-8")
    print("sealed test written:", out_path, flush=True)
    for d in days:
        print(d, {n: round(per_day[d][n]["auroc"], 3) for n in ("transformer_ens5", "HGB_last", "HGB_stacked", "LR_last", "flow_count", "persistence_oracle")})


# ----------------------------------------------------------------------------- export (no test data involved)

def stage_export() -> None:
    """Refit HGB_stacked and HGB_last on the same 7-day training pool as `final` (fixed settings, deterministic; checked by fitting twice)
    and write pickle-free flat arrays (models/tree_export.py) with the OOF-derived alert thresholds. Opens no test data."""
    from models.tree_export import export_hgb, load_flat, predict_proba_flat
    from eval.baseline_gate import stack_features
    dec = json.loads((R.RES / "selection.json").read_text())["decisions"]
    names = feature_columns(load_config(R.CONFIG_PATH))
    P = R.load_pool()
    Xtr = P["pool"]["X"]
    ytr = (P["pool"]["infiltration"][:, 0] > 0).astype(int)
    m1 = fit_baselines(Xtr, ytr, names.index("flow_count"), max_train_rows=None)
    m2 = fit_baselines(Xtr, ytr, names.index("flow_count"), max_train_rows=None)
    probe = Xtr[::37]
    for b in ("HGB_last", "HGB_stacked"):
        a, c = m1[b](probe), m2[b](probe)
        assert np.array_equal(a, c), f"{b} is not deterministic"
    out = {}
    for b, feats in (("HGB_last", names), ("HGB_stacked", [f"{st}:{n}" for st in ("last", "mean", "std", "d1", "d6", "max") for n in names])):
        est = m1[b].estimator
        path = R.CKPT / "final" / f"{b.lower()}_flat.npz"
        arrays = export_hgb(est, feats, path, threshold=dec[f"threshold_{b}_1pct"])
        loaded = load_flat(path)
        X_in = Xtr[:, -1, :] if b == "HGB_last" else stack_features(Xtr)
        err = float(np.abs(predict_proba_flat(loaded, X_in[::11]) - est.predict_proba(X_in[::11])[:, 1]).max())
        out[b] = {"file": str(path.relative_to(R.ROOT)), "n_trees": int(len(arrays["tree_offsets"]) - 1), "n_nodes": int(len(arrays["value"])),
                  "bytes": path.stat().st_size, "max_abs_diff_vs_sklearn_on_train_rows": err,
                  "alert_threshold_oof_1pct_fpr": dec[f"threshold_{b}_1pct"]}
        print(b, out[b], flush=True)
    (R.RES / "hgb_export.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
