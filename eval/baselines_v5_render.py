"""docs/19: render docs/lodo_v5/*.json into markdown tables (docs/lodo_v5/tables.md). Pure formatting; no number is computed here that is not in a JSON."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval import baselines_v5 as B  # noqa: E402
from models import features_v5 as F5  # noqa: E402

DAYS = list(B.L.LODO_DAYS)
HDR = "| " + " | ".join(d[5:] for d in DAYS) + " |"


def f3(x):
    return "n/a" if x is None or (isinstance(x, float) and np.isnan(x)) else f"{x:.3f}"


def pct(x):
    return "n/a" if x is None else f"{100 * x:.2f}%"


def J(name):
    p = B.RES / f"{name}.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def features_table() -> str:
    lines = ["| variant | columns | base features / blocks | recipe |", "|---|---|---|---|"]
    for v in F5.VARIANTS:
        try:
            n = len(B.feature_names(v))
        except FileNotFoundError:
            n = "?"
        var = F5.VARIANTS[v]
        base = B.NAMES
        cols = F5.base_columns(base, var)
        extra = []
        if var.ratio:
            extra.append("+6 ratios")
        if var.temporal:
            extra.append("+temporal block")
        if var.ctx:
            extra.append("+context block")
        lines.append(f"| {v} | {n} | {len(cols)} raw/window features x 6 stack blocks {' '.join(extra)}{' (level blocks of volume dropped)' if var.relative_only else ''} | {var.doc} |")
    return "\n".join(lines)


def per_day_table(T: dict) -> str:
    sm = T["summary"]
    lines = ["| arm | " + " | ".join(d[5:] for d in DAYS) + " | mean 7 [95% day-boot CI] | mean 6 pseudo | SD (7) | min | max |", "|---|" + "---|" * (len(DAYS) + 5)]

    def row(name, per, key):
        s7, s6 = sm[key]["all7"], sm[key]["pseudo6"]
        lines.append(f"| {name} | " + " | ".join(f3(per[d]) for d in DAYS) + f" | **{s7['mean']:.3f}** [{s7['ci95_boot'][0]:.3f}, {s7['ci95_boot'][1]:.3f}] | {s6['mean']:.3f} | {s7['sd']:.3f} | {s7['min']:.3f} | {s7['max']:.3f} |")
    for a in T["arms"]:
        row(a, T["per_day_auroc"][a], a)
    lines.append("| *references (docs/18)* |" + " |" * (len(DAYS) + 5))
    for n, per in T["refs"].items():
        row(n, per, n)
    ns = T["nested_summary"]
    lines.append("| **nested arm selection (the claim)** | " + " | ".join(f3(T["nested_auroc"][d]) for d in DAYS) +
                 f" | **{ns['all7']['mean']:.3f}** [{ns['all7']['ci95_boot'][0]:.3f}, {ns['all7']['ci95_boot'][1]:.3f}] | {ns['pseudo6']['mean']:.3f} | | | |")
    nn = np.array([T["nested_non_anchor_auroc"][d] for d in DAYS])
    lines.append("| nested selection, anchor excluded | " + " | ".join(f3(x) for x in nn) + f" | {nn.mean():.3f} | {np.mean([T['nested_non_anchor_auroc'][d] for d in DAYS if d != '2018-02-20']):.3f} | | | |")
    lines.append("| arm chosen per day (nested) | " + " | ".join(T["nested_selection"][d]["arm"].replace("_", " ")[:18] for d in DAYS) + " | | | | | |")
    return "\n".join(lines)


def gate_table(T: dict, cands: list[str], refs: list[str], tag: str) -> str:
    lines = ["| candidate | reference | days | mean paired gain | MDE | day-bootstrap 95% CI | days won | verdict |", "|---|---|---|---|---|---|---|---|"]
    for c in cands:
        for r in refs:
            g = T["gates"].get(f"{c}|{r}|{tag}")
            if g is None:
                continue
            if g["mean_diff"] is None:
                lines.append(f"| {c} | {r} | {g['n_units']} | n/a | n/a | n/a | n/a | FAIL |")
                continue
            lo, hi = g["ci95_day_bootstrap"]
            lines.append(f"| {c} | {r} | {g['n_units']} | {g['mean_diff']:+.3f} | {g['mde']:.3f} | [{lo:+.3f}, {hi:+.3f}] | {g['wins']}/{g['n_units']} | **{g['verdict']}** |")
    return "\n".join(lines)


def tuned_cfg_table(T: dict) -> str:
    lines = ["| arm | fold | chosen configuration |", "|---|---|---|"]
    for a in T["arms"]:
        if a.startswith("A_"):
            continue
        for f, c in T["chosen_cfg"][a].items():
            lines.append(f"| {a} | {f} | {json.dumps(c)} |")
    return "\n".join(lines)


def threshold_tables(Th: dict) -> str:
    out = []
    for key in ("fpr1pct", "fpr5pct"):
        rows = Th["rows"][key]
        out.append(f"#### Realised FPR / recall per day, leave-one-day-out threshold, target {key[3:-3]}% (threshold from inner OOF scores of the other days)\n")
        out.append("| arm | " + " | ".join(d[5:] for d in DAYS) + " | FPR min-max | mean abs log(FPR/target) | days within x3 of target |")
        out.append("|---|" + "---|" * (len(DAYS) + 3))
        for a, r in rows.items():
            s = Th["summary"][key][a]
            out.append(f"| {a} | " + " | ".join(f"{pct(r[d]['fpr'])} / {pct(r[d]['recall'])}" for d in DAYS) + f" | {pct(s['min'])}-{pct(s['max'])} | {s['mean_abs_log_ratio']:.2f} | {s['n_within_x3']}/{s['n_days']} |")
        out.append("")
    for key in [k for k in Th["rows"] if k.startswith("adaptive")]:
        rows = Th["rows"][key]
        out.append(f"#### Label-free adaptive rule ({key}): realised FPR / recall per pseudo-host day\n")
        out.append("| arm | " + " | ".join(d[5:] for d in DAYS if d != "2018-02-20") + " | FPR min-max | mean abs log ratio | within x3 |")
        out.append("|---|" + "---|" * (len(DAYS) + 2))
        for a, r in rows.items():
            s = Th["summary"][key][a]
            out.append(f"| {a} | " + " | ".join(f"{pct(r[d]['fpr'])} / {pct(r[d]['recall'])}" for d in DAYS if d != "2018-02-20") + f" | {pct(s['min'])}-{pct(s['max'])} | {s['mean_abs_log_ratio']:.2f} | {s['n_within_x3']}/{s['n_days']} |")
        out.append("")
    cal = Th["calibration"]
    out.append(f"#### Calibration of {Th['best_b']} (outer held-out; Brier / ECE-10 per day; calibrators fitted on inner OOF scores of the other days only)\n")
    out.append("| score | " + " | ".join(d[5:] for d in DAYS) + " | mean Brier | mean AUROC |")
    out.append("|---|" + "---|" * (len(DAYS) + 2))
    for k in ("raw", "platt", "isotonic"):
        out.append(f"| {k} | " + " | ".join(f"{cal[k][d]['brier']:.3f} / {cal[k][d]['ece']:.3f}" for d in DAYS) +
                   f" | {np.mean([cal[k][d]['brier'] for d in DAYS]):.4f} | {np.mean([cal[k + '_auroc'][d] for d in DAYS]):.4f} |")
    return "\n".join(out)


def secondary_tables(S: dict) -> str:
    out = ["| day | k, s (train-derived) | definition | positives kept | dropped as ambiguous | median attack flows in primary-positive windows |", "|---|---|---|---|---|---|"]
    for d, v in S["positives"].items():
        ks = S["fold_k_s"][d]
        for dn, r in v.items():
            out.append(f"| {d[5:]} | {ks['k']}, {ks['s']:.3f} | {dn} | {r['pos']} | {r['dropped_ambiguous']} | {r['median_attack_flows_in_primary_pos']} |")
    out += ["", "AUROC on each label definition (scores from the primary-trained arms; ambiguous windows dropped from scoring):", "",
            "| day | score | " + " | ".join(next(iter(next(iter(S["auroc"].values())).values())).keys()) + " |", "|---|---|" + "---|" * len(next(iter(next(iter(S["auroc"].values())).values())))]
    for d, v in S["auroc"].items():
        for n, r in v.items():
            out.append(f"| {d[5:]} | {n} | " + " | ".join(f3(x) for x in r.values()) + " |")
    out += ["", "Trained on S_train (ambiguous dropped from training), evaluated on S_train, against the primary-trained arm on the same rows:", "",
            "| day | arm | primary-trained | S_train-trained |", "|---|---|---|---|"]
    for d, v in S["trained_on_S_train"].items():
        for n, r in v.items():
            out.append(f"| {d[5:]} | {n} | {f3(r['trained_on_primary_auc_on_S_train'])} | {f3(r['trained_on_S_train_auc_on_S_train'])} |")
    out += ["", "Alignment check (raw-CSV rebuilt label vs primary): " + ", ".join(f"{d[5:]} {100 * v['match_rate']:.2f}% match, {100 * v['primary_pos_recovered']:.1f}% of primary positives recovered" for d, v in S["alignment"].items())]
    return "\n".join(out)


def robust_tables(Rb: dict) -> str:
    out = ["| arm | ablation | " + " | ".join(d[5:] for d in DAYS) + " | max drop (volumetric days 02-14, 02-15, 02-21) |", "|---|---|" + "---|" * (len(DAYS) + 1)]
    for arm, v in Rb["ablation"].items():
        out.append(f"| {arm} | none | " + " | ".join(f3(v["clean"][d]) for d in DAYS) + " | |")
        for an in ("flow_count", "volume4"):
            vol = max(v[an + "_drop"][d] for d in ("2018-02-14", "2018-02-15", "2018-02-21"))
            out.append(f"| {arm} | {an} | " + " | ".join(f"{f3(v[an][d])} ({v[an + '_drop'][d]:+.3f})" for d in DAYS) + f" | {vol:+.3f} |")
    out += ["", "Share of held-out feature values outside the fold-training range / beyond 6 training SD (per day):", "",
            "| features | " + " | ".join(d[5:] for d in DAYS) + " |", "|---|" + "---|" * len(DAYS)]
    for arm, v in Rb["ranges"].items():
        out.append(f"| {arm} (outside range) | " + " | ".join(pct(v[d]["outside_train_range"]) for d in DAYS) + " |")
        out.append(f"| {arm} (> 6 SD) | " + " | ".join(pct(v[d]["beyond_6sd"]) for d in DAYS) + " |")
    v = Rb["ranges_raw41_transformer_analogue"]
    out.append("| raw 41 last-window features, Transformer-scaler analogue (> 6 SD) | " + " | ".join(pct(v[d]["beyond_6sd"]) for d in DAYS) + " |")
    out += ["", "Clean re-score check (max abs difference to the stored OOF score): " + ", ".join(f"{a} {x['max_abs_diff_vs_stored_oof']:.1e}" for a, x in Rb["clean_check"].items())]
    return "\n".join(out)


def final_tables(Fn: dict) -> str:
    out = [f"Best non-anchor arm **{Fn['best']}** (variant {Fn['variant']}, family {Fn['family']}), configuration chosen by the full 7-day inner LODO: `{json.dumps(Fn['tuned']['cfg'])}`; "
           f"1% day-balanced FPR threshold from the inner OOF scores {Fn['tuned']['threshold_1pct']:.4f}; export `{Fn['export_path']}`; numpy-vs-sklearn max abs difference on 5,000 rows {Fn['export_roundtrip_max_abs_diff_5000_train_rows']:.1e}.", "",
           "| dataset (sequences / positive) | score | pooled sequence AUROC | unit-balanced (scenario,ip) | unit-balanced (ip) | host-mean AUROC (hosts / positive hosts) |", "|---|---|---|---|---|---|"]
    for ds, r in Fn["external"].items():
        for n, v in r.items():
            if isinstance(v, dict):
                out.append(f"| {ds} ({r['n_seq']} / {r['pos_seq']}) | {n} | {f3(v['pooled_seq'])} | {f3(v['unit_balanced'])} | {f3(v['unit_balanced_by_ip'])} | {f3(v['host_mean'])} ({v['n_hosts']} / {v['n_pos_hosts']}) |")
    return "\n".join(out)


def main() -> None:
    T, Th, S, Rb, Fn, A = J("tables"), J("threshold"), J("secondary"), J("robust"), J("final"), J("anchor")
    parts = ["## Generated tables (eval/baselines_v5_render.py from docs/lodo_v5/*.json)", "", "### Feature variants", "", features_table(), ""]
    if A:
        parts += ["### Anchor", "", f"S0 + default HGB reproduces docs/18 `HGB_stacked`: ok={A['ok']}, max abs score difference {A['worst_abs_score_diff']:.1e}, mean AUROC {A['mean_new']:.4f} vs {A['mean_docs18']:.4f}.", ""]
    if T:
        best = T["best_non_anchor"]
        parts += ["### Per-day OOF within-day AUROC of every registered arm", "", HDR.replace("| 02", "| arm | 02", 1) if False else "", per_day_table(T), "",
                  f"Best non-anchor arm (un-nested): **{best}**; best arm overall (un-nested): {T['best_unnested']}. Chosen configuration per fold: see the tuning table.", ""]
        cands = ["nested_selection", "nested_selection_non_anchor", f"best_non_anchor={best}"]
        refs = ["HGB_stacked", "flow_count", "HGB_last", "LR_last", "Transformer_single_nested", "Transformer_ens5_nested"]
        parts += ["### Gate, 7 days", "", gate_table(T, cands, refs, "all7"), "", "### Gate, 6 pseudo-host days", "", gate_table(T, cands, refs, "pseudo6"), "",
                  "### Gate of every registered arm against the incumbent and against flow_count (7 days / 6 days)", "",
                  gate_table(T, [a for a in T["arms"] if a != "A_S0_stacked41"], ["HGB_stacked", "flow_count"], "all7"), "",
                  gate_table(T, [a for a in T["arms"] if a != "A_S0_stacked41"], ["HGB_stacked", "flow_count"], "pseudo6"), "",
                  "### Tuned configurations per fold", "", tuned_cfg_table(T), ""]
        ex = T.get("exploratory_mean_S0_and_best")
        if ex:
            g = ex["gate_vs_HGB_stacked_all7"]
            parts += ["### Exploratory (not registered, excluded from every verdict): mean probability of the incumbent and the best non-anchor arm", "",
                      f"7-day mean {ex['mean7']:.3f}; per day " + ", ".join(f"{d[5:]} {x:.3f}" for d, x in ex["per_day"].items()) +
                      f"; vs HGB_stacked gain {g['mean_diff']:+.3f}, MDE {g['mde']:.3f}, verdict {g['verdict']}.", ""]
    if Th:
        parts += ["### Threshold transfer", "", threshold_tables(Th), ""]
    if S:
        parts += ["### Secondary labels", "", secondary_tables(S), ""]
    if Rb:
        parts += ["### Robustness", "", robust_tables(Rb), ""]
    if Fn:
        parts += ["### Export and secondary cross-dataset (zero-shot, not used for selection)", "", final_tables(Fn), ""]
    (B.RES / "tables.md").write_text("\n".join(parts), encoding="utf-8")
    print("wrote", B.RES / "tables.md")


if __name__ == "__main__":
    main()
