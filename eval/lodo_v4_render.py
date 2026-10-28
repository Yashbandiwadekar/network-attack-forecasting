"""Render docs/lodo_v4/selection.json and test_sealed.json as the markdown tables used in docs/18 (so no number is transcribed by hand).

    python -m eval.lodo_v4_render       # writes docs/lodo_v4/tables.md
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "docs" / "lodo_v4"
TRUNC = ("2018-02-14", "2018-02-15", "2018-02-16", "2018-02-21", "2018-02-22", "2018-02-23", "2018-03-02")
BASE = ["flow_count", "LR_last", "HGB_last", "HGB_stacked"]


def f(x, nd=3):
    return "n/a" if x is None or (isinstance(x, float) and np.isnan(x)) else f"{x:.{nd}f}"


def lab(d):
    return d[5:] + (" *" if d in TRUNC else "")


def gate_row(name, g):
    if g["mean_diff"] is None:
        return f"| {name} | {g['n_units']} | n/a | n/a | n/a | n/a | **FAIL** ({g.get('reason')}) |"
    lo, hi = g["ci95_day_bootstrap"]
    return (f"| {name} | {g['n_units']} | {g['mean_diff']:+.3f} | {g['mde']:.3f} | [{lo:+.3f}, {hi:+.3f}] | {g['wins']}/{g['n_units']} | "
            f"**{g['verdict']}** |")


def render_lodo(sel: dict) -> str:
    days = sel["days"]
    pd = sel["per_day"]
    out = []
    dec = sel["decisions"]
    out.append(f"Selected epochs (1-based, by OOF day-mean within-day AUROC, ties to the earlier epoch): single **{dec['E_single']}**, "
               f"ensemble of 5 seeds **{dec['E_ens5']}**, ensemble of 3 seeds **{dec['E_ens3']}**. Validation loss was not used.\n")
    # per-day table
    head = ("| held-out day | family (in train?) | seq | pos | episodes | **single (5-seed mean), nested epoch** | single, global epoch | "
            "**ensemble-5, nested** | ensemble-3, nested | flow_count | LR_last | HGB_last | HGB_stacked | label oracle |\n"
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    rows = []
    for d in days:
        r = pd[d]
        fc = sel["family_coverage"][d]
        cov = "yes" if fc["family_in_train"] else "**NO**"
        rows.append(f"| {lab(d)} | {r['family']} ({cov}) | {r['n']:,} | {r['pos']:,} | {r['episodes']['n_episodes']} | "
                    f"**{f(r['single']['auroc_nested'])}** | {f(r['single']['auroc_global_epoch'])} | **{f(r['ens5']['auroc_nested'])}** | "
                    f"{f(r['ens3']['auroc_nested'])} | {f(r['flow_count']['auroc'])} | {f(r['LR_last']['auroc'])} | {f(r['HGB_last']['auroc'])} | "
                    f"{f(r['HGB_stacked']['auroc'])} | {f(r['persistence_oracle']['auroc'])} |")
    A = sel["aggregate_auroc"]
    cols = ["single_nested", "single_global_epoch", "ens5_nested", "ens3_nested", "flow_count", "LR_last", "HGB_last", "HGB_stacked", "persistence_oracle"]
    for tag, name in [("all7", "**mean, all 7 days**"), ("pseudo_host6", "mean, 6 pseudo-host days (without 02-20)"),
                      ("family_covered", f"mean, {len(sel['day_sets']['family_covered'])} family-covered days")]:
        rows.append(f"| {name} | | | | | " + " | ".join(f"{f(A[c][tag]['mean'])} (sd {f(A[c][tag]['sd'], 2)})" for c in cols) + " |")
    out.append(head + "\n" + "\n".join(rows))
    out.append("\n`*` = partial source day (CSV truncated at 1,048,575 rows). 02-20 = the three host-group folds pooled (host-disjoint, not day-disjoint). "
               "'nested' = each day read at the epoch chosen from the other six days.\n")
    # AUPRC
    head = "| held-out day | single AUPRC (nested) | ensemble-5 AUPRC (nested) | flow_count | LR_last | HGB_last | HGB_stacked | positive rate |\n|---|---|---|---|---|---|---|---|"
    rows = [f"| {lab(d)} | {f(pd[d]['single']['auprc_nested'])} | {f(pd[d]['ens5']['auprc_nested'])} | " +
            " | ".join(f(pd[d][b]['auprc']) for b in BASE) + f" | {pd[d]['pos'] / pd[d]['n']:.3f} |" for d in days]
    out.append("### AUPRC (secondary)\n\n" + head + "\n" + "\n".join(rows))
    # curves
    ep = sel["epochs"]
    head = "| epoch | " + " | ".join(str(i + 1) for i in range(ep)) + " |\n|---|" + "---|" * ep
    rows = [f"| {n} | " + " | ".join(f"{v:.3f}" for v in sel['selection'][k]['mean_curve']) + " |" for n, k in
            [("single (5-seed mean)", "single"), ("ensemble-5", "ens5"), ("ensemble-3", "ens3")]]
    out.append("### OOF day-mean within-day AUROC by epoch (the selection curve)\n\n" + head + "\n" + "\n".join(rows))
    nest = sel["selection"]["single"]["nested"]
    out.append("\nNested epoch per held-out day (single): " + ", ".join(f"{lab(d)} -> {nest[d]['epoch'] + 1}" for d in days) + ".")
    nest = sel["selection"]["ens5"]["nested"]
    out.append("Nested epoch per held-out day (ensemble-5): " + ", ".join(f"{lab(d)} -> {nest[d]['epoch'] + 1}" for d in days) + ".\n")
    # gates
    for tag, title in [("all7", "all 7 LODO days (primary)"), ("pseudo_host6", "6 pseudo-host days only (02-20 removed)")]:
        h = "| comparison (model minus baseline) | days | mean paired gain | MDE | day-bootstrap 95% CI | days won | verdict |\n|---|---|---|---|---|---|---|"
        rows = []
        for m, mn in [("single", "single Transformer"), ("ens5", "ensemble-5"), ("ens3", "ensemble-3")]:
            for b in BASE:
                rows.append(gate_row(f"{mn} vs {b}", sel["gates"][f"{m}|{b}|{tag}"]))
        if tag == "all7":
            for b in ("HGB_last", "HGB_stacked"):
                rows.append(gate_row(f"{b} vs flow_count (is the tree better than the one-liner?)", sel["gates"][f"{b}|flow_count|all7"]))
        out.append(f"### Baseline gate, {title}\n\n" + h + "\n" + "\n".join(rows))
    # operating points
    for key, title in [("ens5|fpr1pct", "ensemble-5, 1% day-balanced FPR budget"), ("single|fpr1pct", "single model, 1% budget"),
                       ("ens5|fpr5pct", "ensemble-5, 5% budget")]:
        op = sel["operating_points"][key]
        h = "| day | OOF FPR | OOF recall | alarm rate |\n|---|---|---|---|"
        rows = [f"| {lab(d)} | {f(v['fpr'], 4)} | {f(v['tpr'])} | {f(v['alarm_rate'], 4)} |" for d, v in op["per_day_oof"].items()]
        fp = [v["fpr"] for v in op["per_day_oof"].values() if v["fpr"] is not None]
        out.append(f"### Operating point from OOF scores: {title}\n\nthreshold = **{op['threshold']:.5f}** (epoch {op['epoch']}); realised per-day FPR "
                   f"range {min(fp):.4f}-{max(fp):.4f}\n\n" + h + "\n" + "\n".join(rows))
    out.append(f"\nGPU time of the 45 OOF runs: {sel.get('gpu_seconds_oof', 0) / 3600:.2f} h over {sel.get('n_oof_runs')} runs (logged in docs/lodo_v4/oof_timing.jsonl).")
    return "\n\n".join(out)


def render_sealed(t: dict) -> str:
    days = sorted(t["per_day"])
    pdy = t["per_day"]
    names = ["transformer_ens5", "transformer_ens3", "flow_count", "LR_last", "HGB_last", "HGB_stacked", "persistence_oracle"]
    head = ("| test day | seq | pos | episodes | **ensemble-5** | ensemble-3 | single (5 seeds: mean [min-max]) | flow_count | LR_last | HGB_last | HGB_stacked | label oracle |\n"
            "|---|---|---|---|---|---|---|---|---|---|---|---|")
    rows = []
    for d in days:
        r = pdy[d]
        sv = [r[f"transformer_seed{s}"]["auroc"] for s in range(1, 6)]
        rows.append(f"| {lab(d)} | {r['n']:,} | {r['pos']:,} | {r['episodes']['n_episodes']} | **{f(r['transformer_ens5']['auroc'])}** | "
                    f"{f(r['transformer_ens3']['auroc'])} | {np.mean(sv):.3f} [{min(sv):.3f}-{max(sv):.3f}] | {f(r['flow_count']['auroc'])} | "
                    f"{f(r['LR_last']['auroc'])} | {f(r['HGB_last']['auroc'])} | {f(r['HGB_stacked']['auroc'])} | {f(r['persistence_oracle']['auroc'])} |")
    mean = lambda n: np.mean([pdy[d][n]["auroc"] for d in days])
    rows.append(f"| **mean of 3 days** | | | {sum(pdy[d]['episodes']['n_episodes'] for d in days)} | **{mean('transformer_ens5'):.3f}** | {mean('transformer_ens3'):.3f} | "
                f"{np.mean(list(t['single_seed_mean_auroc'].values())):.3f} | " + " | ".join(f"{mean(n):.3f}" for n in names[2:]) + " |")
    out = ["### Within-day AUROC on the sealed test days\n\n" + head + "\n" + "\n".join(rows)]
    h = "| comparison (model minus baseline) | days | mean paired gain | MDE | day-bootstrap 95% CI | days won | verdict |\n|---|---|---|---|---|---|---|"
    rows = [gate_row(k.replace("|", " vs "), g) for k, g in t["gates"].items()]
    out.append("### Baseline gate on the 3 sealed test days (informative only as far as 3 days allow)\n\n" + h + "\n" + "\n".join(rows))
    h = "| day | realised FPR | recall | alarm rate |\n|---|---|---|---|"
    for key, title in [("ens5_1pct", "ensemble-5 at the OOF 1% threshold"), ("ens5_5pct", "ensemble-5 at the OOF 5% threshold")]:
        op = t["operating_points"][key]
        rows = [f"| {lab(d)} | {f(v['fpr'], 4)} | {f(v['tpr'])} | {f(v['alarm_rate'], 4)} |" for d, v in op["per_day"].items()]
        out.append(f"### Operating point: {title} (threshold {op['threshold']:.5f}, frozen before the test was opened)\n\n" + h + "\n" + "\n".join(rows))
    out.append("Pooled test AUROC (secondary): " + ", ".join(f"{n} {t['pooled_auroc_secondary'][n]:.3f}" for n in names if n in t["pooled_auroc_secondary"]) + ".")
    out.append(f"Sealed test opened {t['opened']}; final training GPU time {t['gpu_seconds_final_training'] / 60:.1f} min.")
    return "\n\n".join(out)


def main() -> None:
    parts = []
    if (RES / "selection.json").exists():
        parts.append("## LODO\n\n" + render_lodo(json.loads((RES / "selection.json").read_text())))
    if (RES / "test_sealed.json").exists():
        parts.append("## SEALED\n\n" + render_sealed(json.loads((RES / "test_sealed.json").read_text())))
    (RES / "tables.md").write_text("\n\n".join(parts), encoding="utf-8")
    print("written", RES / "tables.md")


if __name__ == "__main__":
    main()
