"""Held-out evaluation of the stage forecaster (docs/14-stage-forecasting.md section 4).

Unit of analysis: an EVENT of a held-out chain (usually: each reconnaissance event).  Training never sees the
chain (fold_by='chain'), the entity (fold_by='entity') or the calendar day (fold_by='day') it is scored on.

Scored item, for event i of a held-out chain
    issue time   t_i = start_i + confirm_s         the earliest the event is known to be happening
    T0           start of the next event of the chain (None if the chain ends / is still open)
    forecast     p_any = P(some next stage begins within H of t_i)  from the model fitted WITHOUT this chain
    alarm        p_any >= threshold                 (fixed in advance; never tuned on the scored data)
Outcomes use the vocabulary of eval/onset_eval.py (docs/13) with exact Clopper-Pearson CIs:
    early            T0 - t_i in (0, H]  and alarm       lead = T0 - t_i (real seconds); `stage_correct` records
                                                         whether the model's top stage was the actual next stage
    missed           T0 - t_i in (0, H]  and no alarm
    already_started  T0 <= t_i (the next stage began before this event was confirmed: nothing to forecast)
    beyond_horizon   T0 - t_i > H        (negative at this horizon)
    no_followup      the chain terminated after this event (negative)
    unresolved       the chain was still open when the data ended (excluded)
Negatives = beyond_horizon + no_followup; `false_alarm` = alarmed negatives / negatives.  The same scoring is
done for the order-0 marginal-frequency baseline and for the trivial always-alarm rule, so "early" can be read
against what a state-blind rule gets.  Log-loss of the next-outcome distribution (next stage or END) is paired
against the baseline.

    python -m eval.stage_forecast_eval --events-dir data/processed_adapter/stage_events_cic2017 --view attacker
    python -m eval.stage_forecast_eval --synthetic --view host            # SYNTHETIC correctness check only
"""
from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from eval.onset_eval import _prop, clopper_pearson
from models.stage_forecaster import END, StageForecaster
from pipeline.stage_events import (
    DEFAULT_MAX_CHAIN_GAP_S, STAGES, Chain, events_from_flows, link_chains, load_events,
)
from pipeline.stage_events import RECONNAISSANCE as RECON


# ---------------------------------------------------------------------------------------------
# folds
# ---------------------------------------------------------------------------------------------

def _fold_key(c: Chain, fold_by: str) -> str:
    return {"chain": c.chain_id, "entity": f"{c.view}|{c.entity}", "day": c.day}[fold_by]


def _train_mask(c: Chain, held: Chain, fold_by: str) -> bool:
    """True when chain c may be used to train a model that is tested on `held`."""
    if fold_by == "chain":
        return c.chain_id != held.chain_id
    if fold_by == "entity":
        return (c.view, c.entity) != (held.view, held.entity)
    if fold_by == "day":
        return c.day != held.day
    raise ValueError(fold_by)


def _make_model(order: int, **kw) -> StageForecaster:
    return StageForecaster(order=order, **kw)


# ---------------------------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------------------------

def _outcome(item: dict[str, Any], alarm: bool, H: float) -> str:
    if item["resolution"] == "censored":
        return "unresolved"
    if item["T0"] is None:
        return "no_followup"
    d = item["T0"] - item["t_issue"]
    if d <= 0:
        return "already_started"
    if d > H:
        return "beyond_horizon"
    return "early" if alarm else "missed"


def score_items(chains: list[Chain], observed_until: float, *, fold_by: str = "chain", horizon_s: float = 3600.0,
                thresholds: tuple[float, ...] = (0.25, 0.5), confirm_s: float = 0.0, orders: tuple[int, ...] = (1, 0),
                model_kw: dict[str, Any] | None = None, stages_filter: set[str] | None = None) -> list[dict[str, Any]]:
    """One record per scored event, with the forecasts of every order in `orders`."""
    model_kw = dict(model_kw or {})
    items: list[dict[str, Any]] = []
    full = {o: _make_model(o, **model_kw).fit(chains, observed_until) for o in orders}
    groups: dict[str, list[Chain]] = defaultdict(list)
    for c in chains:
        groups[_fold_key(c, fold_by)].append(c)
    cache: dict[tuple[int, str], StageForecaster] = {}
    for held in chains:
        fk = _fold_key(held, fold_by)
        n_train = len(chains) - len(groups[fk])
        models = {}
        for o in orders:
            key = (o, fk)
            if key not in cache:
                cache[key] = full[o].copy().fit(groups[fk], observed_until, sign=-1)
            models[o] = cache[key]
        evs = held.events
        for i, e in enumerate(evs):
            if stages_filter is not None and e["stage"] not in stages_filter:
                continue
            nxt = evs[i + 1] if i + 1 < len(evs) else None
            rec: dict[str, Any] = {
                "chain": held.chain_id, "view": held.view, "entity": held.entity, "day": held.day, "idx": i,
                "stage": e["stage"], "event_id": e.get("event_id"), "t_issue": e["start_s"] + confirm_s,
                "T0": None if nxt is None else nxt["start_s"],
                "next_stage": None if nxt is None else nxt["stage"],
                "resolution": "followed" if nxt else ("terminated" if held.terminated else "censored"),
                "n_train_chains": n_train, "fold": fk,
                # the next stage already happened earlier in this chain: a re-onset inside an ongoing campaign
                "reonset": bool(nxt is not None and any(p["stage"] == nxt["stage"] for p in evs[:i])),
            }
            truth = rec["next_stage"] if nxt else (END if held.terminated else None)
            for o in orders:
                f = models[o].predict(evs[: i + 1], horizon_s, now=rec["t_issue"], entity=held.entity, view=held.view)
                rec[f"o{o}"] = {
                    "p_any": f.p_any_stage_within_horizon, "top": f.top_stage, "p_next": f.p_next,
                    "p_truth": None if truth is None else f.p_next.get(truth, None),
                    "expected_time_to_next_s": f.expected_time_to_next_s,
                    "ranked_victims": [v["ip"] for v in f.ranked_victims],
                }
            items.append(rec)
    return items


def _group_report(items: list[dict[str, Any]], order_key: str, horizon_s: float, thresholds: tuple[float, ...]) -> dict[str, Any]:
    out: dict[str, Any] = {"n_items": len(items)}
    out["resolution"] = {r: sum(i["resolution"] == r for i in items) for r in ("followed", "terminated", "censored")}
    for thr in thresholds:
        cnt: dict[str, int] = defaultdict(int)
        leads, correct = [], 0
        for it in items:
            m = it[order_key]
            alarm = m["p_any"] >= thr
            oc = _outcome(it, alarm, horizon_s)
            cnt[oc] += 1
            if oc == "early":
                leads.append(it["T0"] - it["t_issue"])
                correct += int(m["top"] == it["next_stage"])
        pos = cnt["early"] + cnt["missed"]
        neg = cnt["beyond_horizon"] + cnt["no_followup"]
        fa = sum(1 for it in items if _outcome(it, it[order_key]["p_any"] >= thr, horizon_s) in ("beyond_horizon", "no_followup")
                 and it[order_key]["p_any"] >= thr)
        out[f"thr_{thr:g}"] = {
            "outcomes": dict(cnt), "positives_next_stage_within_H": pos,
            "early": _prop(cnt["early"], pos), "missed": _prop(cnt["missed"], pos),
            "lead_s": {"n": len(leads), "median": float(np.median(leads)) if leads else None,
                       "min": float(min(leads)) if leads else None, "max": float(max(leads)) if leads else None},
            "early_and_top_stage_correct": _prop(correct, cnt["early"]),
            "negatives": neg, "false_alarm": _prop(fa, neg),
            "always_alarm_rule": {"early": _prop(pos, pos), "false_alarm": _prop(neg, neg)},
        }
    # log-loss of the next-outcome distribution, over items whose outcome is known
    ll = [-math.log(it[order_key]["p_truth"]) for it in items if it[order_key]["p_truth"] is not None]
    out["next_outcome_log_loss"] = {"n": len(ll), "mean_nats": float(np.mean(ll)) if ll else None}
    br = []
    for it in items:
        oc = _outcome(it, False, horizon_s)
        if oc == "missed":
            br.append((it[order_key]["p_any"] - 1.0) ** 2)
        elif oc in ("beyond_horizon", "no_followup"):
            br.append(it[order_key]["p_any"] ** 2)
    out["brier_p_any_within_H"] = {"n": len(br), "mean": float(np.mean(br)) if br else None}
    fol = [it for it in items if it["resolution"] == "followed"]
    out["next_stage_top1"] = _prop(sum(1 for it in fol if max(
        (k for k in it[order_key]["p_next"] if k != END), key=it[order_key]["p_next"].get) == it["next_stage"]), len(fol))
    return out


def evaluate(chains: list[Chain], observed_until: float, *, fold_by: str = "chain", horizon_s: float = 3600.0,
             thresholds: tuple[float, ...] = (0.25, 0.5), confirm_s: float = 0.0, model_kw: dict[str, Any] | None = None,
             orders: tuple[int, ...] = (1, 0, 2), focus_stage: str = RECON) -> dict[str, Any]:
    items = score_items(chains, observed_until, fold_by=fold_by, horizon_s=horizon_s, thresholds=thresholds,
                        confirm_s=confirm_s, orders=orders, model_kw=model_kw)
    res: dict[str, Any] = {
        "setup": {"fold_by": fold_by, "horizon_s": horizon_s, "thresholds": list(thresholds), "confirm_s": confirm_s,
                  "model_kw": model_kw or {}, "n_chains": len(chains), "n_events": sum(len(c.events) for c in chains),
                  "n_entities": len({(c.view, c.entity) for c in chains}), "focus_stage": focus_stage,
                  "n_chains_terminated": sum(c.terminated for c in chains),
                  "chain_length_histogram": dict(sorted(pd.Series([len(c.events) for c in chains]).value_counts().items()))
                  if chains else {}},
    }
    foc = [i for i in items if i["stage"] == focus_stage]
    groups = {"focus_events": foc,
              "focus_events_first_onset": [i for i in foc if not i["reonset"]],
              "focus_events_reonset": [i for i in foc if i["reonset"]],
              "all_events": items,
              "all_events_first_onset": [i for i in items if not i["reonset"]],
              "all_events_reonset": [i for i in items if i["reonset"]]}
    for g, its in groups.items():
        res[g] = {f"order{o}": _group_report(its, f"o{o}", horizon_s, thresholds) for o in orders}
    # paired log-loss difference vs the marginal baseline (negative = state helps)
    for g, its in list(groups.items()):
        if not (1 in orders and 0 in orders):
            break
        both = [i for i in its if i["o1"]["p_truth"] is not None and i["o0"]["p_truth"] is not None]
        d = np.array([-math.log(i["o1"]["p_truth"]) + math.log(i["o0"]["p_truth"]) for i in both])
        res[g]["paired_logloss_order1_minus_order0"] = {
            "n": len(d), "mean": float(d.mean()) if len(d) else None,
            "n_entities_or_chains_independent": len({i["chain"] for i in both})}
    # likely-victim ranking for recon events whose successor is another stage
    rk = [i for i in groups["focus_events"] if i["resolution"] == "followed" and i["next_stage"] != RECON and i["view"] in ("attacker", "pair")]
    res["victim_ranking"] = {"n_recon_events_with_successor": len(rk)}
    return res, items  # type: ignore[return-value]


def victim_hit_at_k(chains: list[Chain], items: list[dict[str, Any]], ks=(1, 3)) -> dict[str, Any]:
    by_chain = {c.chain_id: c for c in chains}
    n = 0
    hits = {k: 0 for k in ks}
    nonempty = 0
    for it in items:
        if it["stage"] != RECON or it["resolution"] != "followed" or it["view"] not in ("attacker", "pair"):
            continue
        ch = by_chain[it["chain"]]
        succ = ch.events[it["idx"] + 1]
        if not succ["dsts"]:
            continue
        n += 1
        truth = max(succ["dsts"], key=succ["dsts"].get)
        rank = it["o1"]["ranked_victims"]
        nonempty += int(bool(rank))
        for k in ks:
            hits[k] += int(truth in rank[:k])
    return {"n": n, "n_with_nonempty_ranking": nonempty, **{f"hit@{k}": _prop(hits[k], n) for k in ks}}


# ---------------------------------------------------------------------------------------------
# correctness check on synthetic data
# ---------------------------------------------------------------------------------------------

def recovery_check(n_campaigns: int = 1500, seed: int = 0, view: str = "host", n_decoys: int | None = None,
                   max_chain_gap_s: float = 7200.0, merge_gap_s: float = 300.0, **gen_kw) -> dict[str, Any]:
    """Generate synthetic campaigns, run them through event building -> chains -> forecaster and compare the
    fitted transition probabilities and mean times with the generator's truth.  SYNTHETIC: a check of the
    machinery, not evidence about real traffic."""
    from eval.synthetic_campaigns import synthetic_campaigns
    if n_decoys is None:
        n_decoys = 0 if view == "host" else 3
    flows, truth = synthetic_campaigns(n_campaigns, n_decoys=n_decoys, seed=seed, **gen_kw)
    ev, rep = events_from_flows(flows, view, merge_gap_s)
    chains = link_chains(ev, max_chain_gap_s)
    m = StageForecaster(1, max_chain_gap_s=max_chain_gap_s).fit(chains)
    rows = []
    pairs = [("reconnaissance", "initial_access"), ("initial_access", "command_and_control"),
             ("command_and_control", "exfiltration")]
    for a, b in pairs:
        key = f"{a}->{b}"
        row = m.counts1.get(a, {})
        n = sum(row.values())
        k = row.get(b, 0)
        lo, hi = clopper_pearson(k, n)
        p_true = truth["p"][key]
        p_est = m._p1(a)[b]
        mu = m.rate(a)
        rows.append({"transition": key, "n_from_state": n, "k": k, "p_true": p_true, "p_mle": k / n if n else None,
                     "p_smoothed": p_est, "ci95_exact": [lo, hi], "truth_inside_ci": bool(lo is not None and lo <= p_true <= hi),
                     "mean_gap_true_s": truth["mean_gap_s"][key], "mean_gap_est_s": 1.0 / mu})
    return {"SYNTHETIC": True, "view": view, "n_decoys": n_decoys, "n_campaigns": n_campaigns, "seed": seed,
            "events": rep.n_events, "chains": len(chains), "rows": rows,
            "all_truth_inside_ci": all(r["truth_inside_ci"] for r in rows)}


# ---------------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------------

def _fmt(p: dict) -> str:
    if p["n"] == 0:
        return "n/a (0)"
    lo, hi = p["ci95_exact"]
    return f"{p['k']}/{p['n']} = {p['rate']:.0%} [{lo:.0%}-{hi:.0%}]"


def print_report(label: str, res: dict[str, Any]) -> None:
    s = res["setup"]
    print(f"\n=== {label} ===\nchains {s['n_chains']} ({s['n_chains_terminated']} terminated), events {s['n_events']}, "
          f"entities {s['n_entities']}; fold_by={s['fold_by']} H={s['horizon_s']:g}s confirm={s['confirm_s']:g}s")
    for g in ("focus_events", "focus_events_first_onset", "focus_events_reonset", "all_events",
              "all_events_first_onset", "all_events_reonset"):
        for o in ("order1", "order0", "order2"):
            if o not in res[g]:
                continue
            r = res[g][o]
            print(f"-- {g} / {o}: items {r['n_items']} {r['resolution']}; log-loss {r['next_outcome_log_loss']}; brier {r['brier_p_any_within_H']}; "
                  f"top-1 next stage {_fmt(r['next_stage_top1'])}")
            for k, v in r.items():
                if k.startswith("thr_"):
                    print(f"   {k}: outcomes {v['outcomes']}; early {_fmt(v['early'])} lead median {v['lead_s']['median']}; "
                          f"stage-correct {_fmt(v['early_and_top_stage_correct'])}; false alarm {_fmt(v['false_alarm'])}")
        print(f"   paired log-loss (order1 - order0): {res[g]['paired_logloss_order1_minus_order0']}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--events-dir", default=None, help="folder written by `python -m pipeline.stage_events`")
    ap.add_argument("--view", default="attacker")
    ap.add_argument("--fold", default="chain", choices=("chain", "entity", "day"))
    ap.add_argument("--horizon", type=float, default=3600.0)
    ap.add_argument("--thresholds", default="0.25,0.5")
    ap.add_argument("--focus-stage", default=RECON, help="stage whose events form the headline group")
    ap.add_argument("--confirm", type=float, default=0.0, help="seconds after an event starts until it is confirmed")
    ap.add_argument("--max-chain-gap", type=float, default=DEFAULT_MAX_CHAIN_GAP_S)
    ap.add_argument("--synthetic", action="store_true", help="SYNTHETIC campaigns instead of --events-dir")
    ap.add_argument("--n-campaigns", type=int, default=1500)
    ap.add_argument("--label", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--save-model", default=None, help="fit order 1 on ALL chains and write the JSON model")
    a = ap.parse_args(argv)
    thr = tuple(float(x) for x in a.thresholds.split(","))
    out: dict[str, Any] = {}
    if a.synthetic:
        from eval.synthetic_campaigns import synthetic_campaigns
        flows, truth = synthetic_campaigns(a.n_campaigns, n_decoys=0 if a.view == "host" else 3)
        ev, rep = events_from_flows(flows, a.view)
        observed = float(pd.to_datetime(flows["timestamp"]).astype("datetime64[ns]").astype(np.int64).max() / 1e9)
        out["SYNTHETIC"] = True
        out["recovery"] = recovery_check(a.n_campaigns, view=a.view)
        for r in out["recovery"]["rows"]:
            print(r)
        label = a.label or f"synthetic_{a.view}"
    else:
        d = Path(a.events_dir)
        ev = load_events(d / f"events_{a.view}.csv")
        rep_json = json.loads((d / "report.json").read_text(encoding="utf-8"))["views"][a.view]
        observed = pd.Timestamp(rep_json["observed_until"]).timestamp() if rep_json.get("observed_until") else float(ev["end_s"].max())
        label = a.label or f"{d.name}_{a.view}"
    chains = link_chains(ev, a.max_chain_gap, observed, collapse_same_stage=True)
    res, items = evaluate(chains, observed, fold_by=a.fold, horizon_s=a.horizon, thresholds=thr, confirm_s=a.confirm,
                          model_kw={"max_chain_gap_s": a.max_chain_gap}, focus_stage=a.focus_stage)
    res["victim_ranking"].update(victim_hit_at_k(chains, items))
    full = StageForecaster(1, max_chain_gap_s=a.max_chain_gap).fit(chains, observed)
    res["full_data_transition_table_DESCRIPTIVE_ONLY_in_sample"] = full.transition_table()
    res["chains"] = [{"chain": c.chain_id, "view": c.view, "entity": c.entity, "day": c.day, "terminated": c.terminated,
                      "stages": c.stages, "start": pd.Timestamp(c.events[0]["start_s"], unit="s").isoformat(),
                      "gaps_s": [round(c.events[i + 1]["start_s"] - c.events[i]["start_s"], 1) for i in range(len(c.events) - 1)]}
                     for c in chains] if len(chains) <= 400 else "omitted (>400 chains)"
    out.update(res)
    if len(items) <= 3000:
        out["items_compact"] = [{"chain": i["chain"], "fold": i["fold"], "entity": i["entity"], "stage": i["stage"],
                                 "next_stage": i["next_stage"], "resolution": i["resolution"], "reonset": i["reonset"], "t_issue": i["t_issue"],
                                 "T0": i["T0"], **{f"p_any_o{o}": i[f"o{o}"]["p_any"] for o in (0, 1, 2) if f"o{o}" in i},
                                 **{f"top_o{o}": i[f"o{o}"]["top"] for o in (0, 1, 2) if f"o{o}" in i}} for i in items]
    print_report(label, res)
    print("victim ranking:", res["victim_ranking"])
    if a.save_model:
        full.save(a.save_model)
        print("wrote", a.save_model)
    p = Path(a.out) if a.out else Path(__file__).resolve().parents[1] / "docs" / "stage_forecast" / f"{label}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    print("wrote", p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
