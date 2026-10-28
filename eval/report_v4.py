"""docs/16 action 1: the per-day / per-unit results report (docs/17-results-per-day.md + docs/results_per_day_v4.json).

Replaces pooled and sequence-weighted cross-dataset AUROC as headlines by
  * a per-day table (n sequences, positives, onset episodes, within-day AUROC/AUPRC) for the CIC-2018 v2 val and test splits,
    with the label oracle, flow_count, LR and HGB baselines beside the 9 trained models, and
  * unit-balanced (every host/series weighs the same) AUROC and the host-mean AUROC for CTU-13, UNSW-NB15 and CIC-2017, with unit counts.
Pooled / sequence-weighted figures are kept as clearly labelled secondary rows.

INFERENCE ONLY. Checkpoints and scalers are loaded (never re-fitted into an existing directory); the tabular baselines are fitted in
memory on the seed-1 train rows (all pseudo-host days + a fixed 30,000-row sample of 02-20, the same subsample as docs/16 exp6).

    python -m eval.report_v4
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TRUNCATED_DAYS = ("2018-02-14", "2018-02-15", "2018-02-16", "2018-02-21", "2018-02-22", "2018-02-23", "2018-03-02")
TRUNCATION_NOTE = ("The processed CIC-2018 CSVs on AWS stop at 1,048,575 rows on 7 of the 10 days (02-14, 02-15, 02-16, 02-21, 02-22, "
                   "02-23, 03-02; local files are byte-identical to the official bucket), so those days are partial prefixes of unknown "
                   "extent. Only 02-20, 02-28 and 03-01 are complete.")
MODEL_ORDER = ["seed1", "seed2", "seed3", "B_s1", "B_s2", "B_s3", "Bplus_s1", "Bplus_s2", "Bplus_s3"]
BASELINE_ORDER = ["persistence_oracle", "flow_count", "HGB_last", "HGB_stacked", "LR_last"]


# ----------------------------------------------------------------------------- pure helpers (tested)

def _auc(y, s):
    from eval.diagnostics.core import _auc as a
    return a(y, s)


def _ap(y, s):
    from sklearn.metrics import average_precision_score
    y = np.asarray(y)
    return None if y.size == 0 or y.max() == 0 else float(average_precision_score(y, s))


def day_table(y: np.ndarray, score: np.ndarray, day: np.ndarray) -> dict:
    """{day: {"auroc","auprc"}} within each day (None when a day has one class) plus the unweighted mean of the defined AUROCs."""
    day = np.asarray(day).astype(str)
    out = {}
    for d in sorted(set(day)):
        m = day == d
        out[d] = {"auroc": _auc(y[m], score[m]), "auprc": _ap(y[m], score[m])}
    v = [r["auroc"] for r in out.values() if r["auroc"] is not None]
    return {"days": out, "mean_within_auroc": float(np.mean(v)) if v else None}


def unit_table(y: np.ndarray, score: np.ndarray, unit: np.ndarray, n_boot: int = 300, seed: int = 0) -> dict:
    """Sequence-weighted AUROC, unit-balanced AUROC (each unit total weight 1), host-mean AUROC (AUROC of the per-unit mean score,
    one point per unit) with a unit bootstrap 95% interval, and the unit counts. A unit is positive if any of its sequences is."""
    from eval.diagnostics.core import unit_balanced_auroc
    y = (np.asarray(y) > 0).astype(int)
    score = np.asarray(score, float)
    unit = np.asarray(unit).astype(str)
    u, inv = np.unique(unit, return_inverse=True)
    cnt = np.bincount(inv)
    pos_any = np.bincount(inv, weights=y) > 0
    mean_score = np.bincount(inv, weights=score) / cnt
    out = {"n_sequences": int(len(y)), "n_units": int(len(u)), "n_pos_units": int(pos_any.sum()),
           "n_neg_units": int((~pos_any).sum()), "seq_weighted": _auc(y, score),
           "unit_balanced": unit_balanced_auroc(y, score, unit), "host_mean": _auc(pos_any.astype(int), mean_score)}
    if out["n_pos_units"] > 0 and out["n_neg_units"] > 0 and n_boot:
        rng = np.random.default_rng(seed)
        pi, ni = np.flatnonzero(pos_any), np.flatnonzero(~pos_any)
        vals = []
        for _ in range(n_boot):
            b = np.r_[rng.choice(pi, len(pi)), rng.choice(ni, len(ni))]
            vals.append(_auc(pos_any[b].astype(int), mean_score[b]))
        out["host_mean_ci95"] = [float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))]
    else:
        out["host_mean_ci95"] = None
    return out


def _f(x, nd=3):
    return "n/a" if x is None or (isinstance(x, float) and np.isnan(x)) else f"{x:.{nd}f}"


def _day_label(d: str) -> str:
    return d[5:] + (" *" if d in TRUNCATED_DAYS else "")


def render_split_table(split: dict, names: list[str], metric: str) -> str:
    days = sorted(split["days"])
    head = "| day | seq | pos (rate) | episodes | " + " | ".join(names) + " |\n|---|---|---|---|" + "---|" * len(names)
    rows = []
    for d in days:
        r = split["days"][d]
        cells = [_f(r["scores"][n][metric]) if n in r["scores"] else "n/a" for n in names]
        rows.append(f"| {_day_label(d)} | {r['n']:,} | {r['pos']:,} ({r['pos'] / r['n']:.1%}) | {r['episodes']} | " + " | ".join(cells) + " |")
    mean_cells = [_f(split["mean_within"][n][metric]) if n in split["mean_within"] else "n/a" for n in names]
    rows.append(f"| **mean of days** | {split['n_sequences']:,} | {split['n_pos']:,} | **{split['n_episodes']}** | " + " | ".join(f"**{c}**" for c in mean_cells) + " |")
    return "\n".join([head, *rows])


def render_unit_table(block: dict, names: list[str]) -> str:
    c = block["counts"]
    lines = [f"{c['n_sequences']:,} sequences, **{c['n_units']} units** ({c['n_pos_units']} positive, {c['n_neg_units']} negative); "
             f"unit = {block['unit_definition']}. Onset episodes: {block['episodes']}.", "",
             "| score | **unit-balanced AUROC** | host-mean AUROC [95% unit bootstrap] (per unit; docs/16 F4 used per IP for CTU: seed 1 0.842) | *secondary:* sequence-weighted AUROC |", "|---|---|---|---|"]
    for n in names:
        if n not in block["scores"]:
            continue
        s = block["scores"][n]
        ci = s["host_mean_ci95"]
        ci_s = f" [{_f(ci[0], 2)}-{_f(ci[1], 2)}]" if ci else ""
        lines.append(f"| {n} | **{_f(s['unit_balanced'])}** | {_f(s['host_mean'])}{ci_s} | *{_f(s['seq_weighted'])}* |")
    return "\n".join(lines)


def render_markdown(res: dict) -> str:
    names = MODEL_ORDER + BASELINE_ORDER
    a = res["anchors"]
    md = [f"""# 17 - Results per day (docs/16 action 1)

Generated by `python -m eval.report_v4` on {res['generated']} (inference only; no model, scaler, config or `data/processed*` file changed; seed 1
stays the served model). Machine-readable copy: `docs/results_per_day_v4.json` (served by `/api/v1/eval/metrics` as `per_day_v4`).

**Truncated source days (`*`).** {TRUNCATION_NOTE} Every per-day figure below describes the available slice, not a full day.

**How to read this.** A CIC-2018 day is ONE network-wide series (9 of 10 days have no IPs), so each day is one independent unit and its
sequences overlap by 11 of 12 windows. The headline is therefore the **within-day AUROC per day**, with the number of onset episodes beside it;
the pooled AUROC (0.800 for seed 1) is a secondary row because it mixes a between-day offset with within-day ranking (docs/16 F1: a score that is
constant within each day already gives 0.715). The paired minimum detectable per-day difference between two models is **0.076 with 3 days, 0.041
with 5, 0.024 with 10** (docs/16 F9): gaps smaller than that are not evidence.

Anchors (this script reproduces the earlier figures before anything new is read): seed 1 pooled test AUROC {_f(a['seed1_test_pooled'], 4)} (docs/15: 0.8003),
per day 02-16/02-23/03-01 = {" / ".join(_f(a['seed1_test_days'][d]) for d in sorted(a['seed1_test_days']))} (docs/16: 0.989 / 0.500 / 0.778); baselines
HGB_last test pooled {_f(a['hgb_last_test_pooled'])} (docs/16: 0.759), LR_last {_f(a['lr_last_test_pooled'])} (0.666; docs/16 dropped the 9 always-zero packet features before fitting, this report keeps all 41), HGB_stacked {_f(a['hgb_stacked_test_pooled'])} (0.764).

Columns. `seed1/2/3` = the three converged runs (`checkpoints_real_v2_converged/seed*`, trained on the v2 split; seed1 is served); `B_s*` / `Bplus_s*`
= the joint_v3 retrains of docs/15 (best-val-loss checkpoints; none replaces seed 1). Baselines: `persistence_oracle` reads the TRUE current label
(not deployable, an upper reference); `flow_count` = last-window flow_count (no training); `HGB_last` / `HGB_stacked` / `LR_last` = scikit-learn
HistGradientBoosting on the last window / on a 6-statistic stack of the 12 windows / logistic regression on the last window, fixed hyper-parameters,
trained on the seed-1 train rows (all pseudo-host days + 30,000 sampled 02-20 sequences), raw features, no tuning.
""", "## 1. CIC-2018 v2 test (the three held-out days): within-day AUROC\n",
          render_split_table(res["cic2018"]["test"], names, "auroc"),
          "\n## 2. CIC-2018 v2 test: within-day AUPRC\n",
          render_split_table(res["cic2018"]["test"], names, "auprc"),
          "\n## 3. CIC-2018 v2 validation (02-15, 02-22): within-day AUROC\n",
          render_split_table(res["cic2018"]["val"], names, "auroc"),
          "\n## 4. CIC-2018 v2 validation: within-day AUPRC\n",
          render_split_table(res["cic2018"]["val"], names, "auprc")]
    md.append("\n## 5. Secondary rows: pooled AUROC (mixes days; do not quote as a headline)\n")
    head = "| split | " + " | ".join(names) + " |\n|---|" + "---|" * len(names)
    rows = [f"| {sp} pooled | " + " | ".join(_f(res["cic2018"][sp]["pooled"].get(n)) for n in names) + " |" for sp in ("test", "val")]
    rows += [f"| {sp} day-constant score | " + " | ".join(_f(res["cic2018"][sp]["day_constant"].get(n)) for n in names) + " |" for sp in ("test",)]
    md.append("\n".join([head, *rows]))
    md.append("\n'day-constant score' = every score replaced by its day's mean: it carries no within-day information, yet gives the pooled-looking number.")
    md.append("\n## 6. Cross-dataset zero-shot: unit-balanced AUROC with unit counts (sequence-weighted AUROC is secondary)\n")
    md.append("The models were trained on CIC-2018 only (the seed-1 scaler is applied; B/B+ use their own). The baselines are trained on the CIC-2018 seed-1 train rows "
              "as well, so this is zero-shot for every column. With 4-10 positive hosts the intervals are wide and the sign of the result depends on the "
              "weighting (docs/16 F4): none of these numbers is a claim of transfer or of inversion.\n")
    for key, title in [("ctu13", "CTU-13 (contiguous 10 s build)"), ("unsw", "UNSW-NB15 (contiguous 10 s build)"),
                       ("cic2017", "CIC-2017 Tue-Fri (60 s windows, scale-mismatched)")]:
        blk = res["cross_dataset"][key]
        md.append(f"### {title}\n")
        md.append(render_unit_table(blk, names))
        md.append("")
    md.append("## 7. Retired headlines\n")
    md.append("Not used as headlines any more (kept only as the secondary rows above): pooled test AUROC 0.800/0.794, sequence-weighted CTU-13 / UNSW / CIC-2017 AUROC "
              "(0.155, 0.454, 0.690 for seed 1; 0.7804 CTU-13 in older reports), and any single cross-dataset AUROC without its host count and weighting.\n")
    md.append("## 8. Reproduce\n\n```text\npython -m eval.report_v4        # writes docs/17-results-per-day.md and docs/results_per_day_v4.json\npython -m pytest tests/test_report_v4.py -q\n```\n")
    return "\n".join(md)


# ----------------------------------------------------------------------------- the script (I/O)

def main() -> None:
    from eval.diagnostics import harness as H
    from eval.baseline_gate import baseline_scores, fit_baselines
    from eval.diagnostics.core import day_of, load
    from eval.onset_eval import structure
    from eval import lodo_v4 as L

    MODELS = dict(H.MODELS)
    for s in (2, 3):
        MODELS[f"seed{s}"] = ("configs/real_data_v2_converged_seed1.yaml", f"checkpoints_real_v2_converged/seed{s}")
    ix = {n: i for i, n in enumerate(H.NAMES)}
    j_fc = ix["flow_count"]

    # ---- baselines: seed-1 train rows rebuilt from the per-day cache (same rows as docs/16 train_sub.npz: rng(0), sorted days)
    cache = ROOT / "data" / "processed_adapter" / "lodo_v4"
    rng = np.random.default_rng(0)
    Xs, ys = [], []
    # docs/16 exp6/build_train_caches: for each train day in sorted order, rng.choice(rows of that day, min(30000, n), replace=False),
    # rows kept in the order drawn. rng.choice(n, k) draws the same positions as rng.choice(arange(n), k), so the row set AND order match.
    for d in ("2018-02-14", "2018-02-20", "2018-02-21", "2018-02-28", "2018-03-02"):
        X = np.load(cache / d / "X.npy", mmap_mode="r")
        y = np.load(cache / d / "infiltration.npy", mmap_mode="r")[:, 0] > 0
        idx = rng.choice(len(X), min(30000, len(X)), replace=False)
        Xs.append(np.asarray(X[idx]))
        ys.append(np.asarray(y[idx]))
    Xtr, ytr = np.concatenate(Xs), np.concatenate(ys).astype(int)
    print("baseline train rows", len(ytr), "pos", int(ytr.sum()), flush=True)
    base_models = fit_baselines(Xtr, ytr, j_fc, max_train_rows=None)

    data = {k: load(H.DS[k]) for k in H.DS}
    res: dict = {"generated": time.strftime("%Y-%m-%d"), "truncation_note": TRUNCATION_NOTE, "truncated_days": list(TRUNCATED_DAYS),
                 "models": MODEL_ORDER, "baselines": BASELINE_ORDER, "baseline_train": {"rows": int(len(ytr)), "positives": int(ytr.sum())}}
    scores: dict[str, dict[str, np.ndarray]] = {k: {} for k in data}
    for name in MODEL_ORDER:
        model, scaler = (H.get_model(name) if name in H.MODELS else _get(H, MODELS, name))
        for k, arr in data.items():
            scores[k][name] = H.score(model, scaler, arr["X"])
        print("scored", name, flush=True)
        del model
    for k, arr in data.items():
        bs = baseline_scores({n: f for n, f in base_models.items() if n in ("flow_count", "HGB_last", "HGB_stacked", "LR_last")}, arr["X"])
        scores[k].update(bs)
        scores[k]["persistence_oracle"] = np.asarray(arr["current_infiltration"], float) + 1e-9 * arr["X"][:, -1, j_fc]

    # ---- CIC-2018 val / test
    res["cic2018"] = {}
    for sp, key in (("test", "cic18_test"), ("val", "cic18_val")):
        arr = data[key]
        y = (arr["infiltration"][:, 0] > 0).astype(int)
        day = day_of(arr)
        S = structure(arr, 10)
        ep_by_host: dict[str, int] = {}
        for e in S["episodes"]:
            ep_by_host[e.key] = ep_by_host.get(e.key, 0) + 1
        ep_by_day = {d: sum(v for k, v in ep_by_host.items() if k.endswith(d)) for d in sorted(set(day))}
        assert sum(ep_by_day.values()) == len(S["episodes"]), "episode keys do not map to days"
        block = {"days": {}, "n_sequences": int(len(y)), "n_pos": int(y.sum()), "n_episodes": len(S["episodes"]),
                 "mean_within": {}, "pooled": {}, "day_constant": {}}
        tabs = {n: day_table(y, sc, day) for n, sc in scores[key].items()}
        for d in sorted(set(day)):
            m = day == d
            block["days"][d] = {"n": int(m.sum()), "pos": int(y[m].sum()), "episodes": ep_by_day[d],
                                "truncated": d in TRUNCATED_DAYS,
                                "scores": {n: tabs[n]["days"][d] for n in tabs}}
        for n, sc in scores[key].items():
            block["mean_within"][n] = {"auroc": tabs[n]["mean_within_auroc"],
                                       "auprc": float(np.mean([tabs[n]["days"][d]["auprc"] for d in tabs[n]["days"] if tabs[n]["days"][d]["auprc"] is not None]))}
            block["pooled"][n] = _auc(y, sc)
            dm = {d: sc[day == d].mean() for d in set(day)}
            block["day_constant"][n] = _auc(y, np.array([dm[d] for d in day]))
        res["cic2018"][sp] = block
        print(sp, "episodes", len(S["episodes"]), ep_by_day, flush=True)
    assert res["cic2018"]["test"]["n_episodes"] == 12 and res["cic2018"]["val"]["n_episodes"] == 14, "episode anchors (docs/13) not reproduced"
    t = res["cic2018"]["test"]
    res["anchors"] = {"seed1_test_pooled": t["pooled"]["seed1"],
                      "seed1_test_days": {d: t["days"][d]["scores"]["seed1"]["auroc"] for d in t["days"]},
                      "hgb_last_test_pooled": t["pooled"]["HGB_last"], "lr_last_test_pooled": t["pooled"]["LR_last"],
                      "hgb_stacked_test_pooled": t["pooled"]["HGB_stacked"]}
    # ---- cross-dataset unit tables
    res["cross_dataset"] = {}
    for key, dk, unit_fn, uname, ws in [
        ("ctu13", "ctu_contig", lambda a: np.char.add(np.char.add(a["scenario_id"].astype(str), "|"), a["src_ip"].astype(str)),
         "(scenario, source IP) series", 10),
        ("unsw", "unsw_contig", lambda a: a["src_ip"].astype(str), "source IP", 10),
        ("cic2017", "cic17_60s", lambda a: a["src_ip"].astype(str), "source IP", 60)]:
        arr = data[dk]
        y = (arr["infiltration"][:, 0] > 0).astype(int)
        unit = unit_fn(arr)
        try:
            eps = int(len(structure(arr, ws)["episodes"]))
            ep_txt = f"{eps}" + (" (labels are constant per host, so no benign-to-attack transitions exist)" if eps == 0
                                 else " (docs/13 definition; counted inside the positive units only)")
        except Exception as exc:                                            # pragma: no cover - diagnostic only
            ep_txt = f"n/a ({type(exc).__name__})"
        blk = {"unit_definition": uname, "episodes": ep_txt, "scores": {}}
        for n, sc in scores[dk].items():
            blk["scores"][n] = unit_table(y, sc, unit)
        c = blk["scores"]["seed1"]
        blk["counts"] = {k: c[k] for k in ("n_sequences", "n_units", "n_pos_units", "n_neg_units")}
        res["cross_dataset"][key] = blk
        print(key, blk["counts"], "episodes", ep_txt, flush=True)
    out_json = ROOT / "docs" / "results_per_day_v4.json"
    out_json.write_text(json.dumps(res, indent=1, default=float), encoding="utf-8")
    (ROOT / "docs" / "17-results-per-day.md").write_text(render_markdown(res), encoding="utf-8")
    print("written docs/17-results-per-day.md and", out_json.name)


def _get(H, MODELS, name):
    from common.config import load_config, resolve_path
    from models.dataset import FeatureScaler
    from models.forecast import load_world_model
    cfgp, ck = MODELS[name]
    cfg = load_config(cfgp)
    model, _ = load_world_model(Path(ck) / "world_model_best.pt")
    return model, FeatureScaler.load(resolve_path(cfg, "processed_dir") / "scaler.npz")


if __name__ == "__main__":
    main()
