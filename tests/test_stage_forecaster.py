"""Markov stage forecaster (models/stage_forecaster.py), its JSON round trip, the leave-out evaluation and the
SYNTHETIC recovery check.  The synthetic tests verify the machinery against a known generator; they say nothing
about real attackers."""
from __future__ import annotations

import json
import math

import pytest

from eval.stage_forecast_eval import evaluate, recovery_check, score_items, victim_hit_at_k
from models.stage_forecaster import END, SCHEMA, StageForecaster
from pipeline.stage_events import Chain

REC, IA, LAT, C2, EXF, IMP = ("reconnaissance", "initial_access", "lateral_movement", "command_and_control",
                              "exfiltration", "impact")
BASE = 1_800_000_000.0


def ev(stage, start, dur=60.0, dsts=None, eid=None):
    return {"event_id": eid or f"{stage[:3]}{int(start)}", "view": "attacker", "entity": "E", "stage": stage,
            "start_s": BASE + start, "end_s": BASE + start + dur, "duration_s": dur, "n_flows": 10, "n_src": 1,
            "n_dst": len(dsts or {"V": 1}), "srcs": {"A": 10}, "dsts": dsts or {"V": 10}, "source": "label",
            "confidence": 1.0, "labels": {}, "unit": "u"}


def chain(i, spec, terminated=True, entity=None, day="2026-01-01", view="attacker"):
    """spec: [(stage, start_offset_s), ...]"""
    evs = [ev(s, t) for s, t in spec]
    return Chain(f"c{i}", view, entity or f"E{i}", evs, terminated, day)


# ------------------------------------------------------------------ smoothing
def test_laplace_smoothing_exact_numbers():
    chains = [chain(i, [(REC, 0), (IA, 100)]) for i in range(3)] + [chain(10, [(REC, 0)])]
    m = StageForecaster(1, alpha=1.0).fit(chains)
    row = m.counts1[REC]
    assert row == {IA: 3, END: 1}
    p = m._p1(REC)
    # outcomes after recon: 5 other stages + END = 6 -> (n_ab + 1) / (4 + 6)
    assert math.isclose(p[IA], 4 / 10) and math.isclose(p[END], 2 / 10) and math.isclose(p[IMP], 1 / 10)
    assert math.isclose(sum(p.values()), 1.0) and REC not in p            # same-stage repeat is structurally impossible


def test_unseen_state_gets_uniform_not_zero():
    m = StageForecaster(1).fit([chain(0, [(REC, 0), (IA, 100)])])
    p = m._p1(EXF)
    assert len(set(round(v, 12) for v in p.values())) == 1 and min(p.values()) > 0


def test_alpha_must_be_positive():
    with pytest.raises(ValueError):
        StageForecaster(1, alpha=0)


def test_order0_is_state_blind_marginal():
    chains = [chain(0, [(REC, 0), (IA, 100), (C2, 200)]), chain(1, [(REC, 0), (IA, 100)])]
    m = StageForecaster(0).fit(chains)
    f_rec = m.predict(chains[0].events[:1], 3600)
    f_ia = m.predict(chains[0].events[:2], 3600)
    assert f_rec.p_next == f_ia.p_next and m.next_distribution(REC)[1] == 0


# ------------------------------------------------------------------ time to next stage / censoring / END
def test_time_to_next_is_the_onset_to_onset_mean():
    chains = [chain(i, [(REC, 0), (IA, 200)]) for i in range(40)]
    m = StageForecaster(1, rate_prior_events=1.0, max_chain_gap_s=7200).fit(chains)
    f = m.predict(chains[0].events[:1], 3600)
    assert abs(f.expected_time_to_next_s - 200) < 10              # prior shrinks 1 of 41 pseudo-observations
    # P(IA within H) = P(IA) * (1 - exp(-H / 200)); horizon monotone
    f_short = m.predict(chains[0].events[:1], 100)
    f_long = m.predict(chains[0].events[:1], 3600)
    assert f_short.p_next_within_horizon[IA] < f_long.p_next_within_horizon[IA]
    assert math.isclose(f_long.p_next_within_horizon[IA], f_long.p_next[IA] * (1 - math.exp(-3600 * f_long.rate_per_s)))
    assert f_long.p_any_stage_within_horizon + f_long.p_no_further_stage_within_horizon == pytest.approx(1.0)


def test_chains_that_end_set_probability_but_do_not_distort_the_rate():
    """Half the chains end after recon. P(IA) must be ~0.5 and the mean gap must stay 200 s."""
    chains = [chain(i, [(REC, 0), (IA, 200)]) for i in range(100)] + [chain(1000 + i, [(REC, 0)]) for i in range(100)]
    m = StageForecaster(1, alpha=1.0, max_chain_gap_s=7200).fit(chains)
    f = m.predict(chains[0].events[:1], 3600)
    assert abs(f.p_next[IA] - 0.5) < 0.03 and abs(f.p_next[END] - 0.5) < 0.03
    assert abs(f.expected_time_to_next_s - 200) < 10
    assert f.evidence["p_chain_ends"] == f.p_next[END]
    assert f.p_any_stage_within_horizon < 0.51                     # the END mass is never promised as a stage


def test_right_censored_events_add_exposure_but_not_transitions():
    done = [chain(i, [(REC, 0), (IA, 100)]) for i in range(20)]
    open_ = chain(99, [(REC, 0)], terminated=False)
    base = StageForecaster(1).fit(done, observed_until=BASE + 1000)
    m = StageForecaster(1).fit(done + [open_], observed_until=BASE + 10_000)
    assert m.counts1[REC] == base.counts1[REC]                     # no END / transition counted for the open chain
    assert m.fit_info["n_censored"] == 1
    assert m.rate(REC) < base.rate(REC)                            # 10 000 s of silence lowers the estimated rate


# ------------------------------------------------------------------ second order with backoff
def test_second_order_uses_context_when_supported_and_backs_off_otherwise():
    # X -> REC -> IA   but   Y -> REC -> END
    chains = [chain(i, [(LAT, 0), (REC, 100), (IA, 200)]) for i in range(10)] + \
             [chain(100 + i, [(C2, 0), (REC, 100)]) for i in range(10)]
    m1, m2 = StageForecaster(1).fit(chains), StageForecaster(2, beta=2.0, min_support2=2).fit(chains)
    after_x = chains[0].events[:2]
    after_y = chains[10].events[:2]
    f1 = m1.predict(after_x, 3600)
    f2x, f2y = m2.predict(after_x, 3600), m2.predict(after_y, 3600)
    assert f2x.evidence["order_used"] == 2 and f2y.evidence["order_used"] == 2
    assert f2x.p_next[IA] > f1.p_next[IA] > f2y.p_next[IA]
    # an unseen context (prev = exfiltration) has no support -> falls back to the first-order estimate exactly
    unseen = [ev(EXF, -200), ev(REC, 0)]
    fb = m2.predict(unseen, 3600)
    assert fb.evidence["order_used"] == 1 and fb.p_next == pytest.approx(m1.predict(unseen, 3600).p_next)


# ------------------------------------------------------------------ ranking and evidence
def test_likely_victims_ranked_from_recon_targets_and_evidence_names_the_events():
    recon = ev(REC, 0, dsts={"V1": 90, "V2": 8, "V3": 2}, eid="R1")
    m = StageForecaster(1).fit([chain(0, [(REC, 0), (IA, 100)])])
    f = m.predict([recon], 3600, entity="A", view="attacker")
    assert [v["ip"] for v in f.ranked_victims] == ["V1", "V2", "V3"] and f.ranked_victims[0]["score"] == pytest.approx(0.9)
    assert f.evidence["recon_events_used"] == ["R1"] and f.evidence["current_event"]["event_id"] == "R1"
    assert f.evidence["support"]["counts"] == {IA: 1}
    assert m.predict([recon], 3600, view="host").ranked_victims == []        # the entity IS the target there
    f2 = m.predict([recon, ev(IA, 100, dsts={"V1": 5})], 3600, view="attacker")
    assert {v["ip"]: v["already_targeted_after_recon"] for v in f2.ranked_victims} == {"V1": True, "V2": False, "V3": False}


def test_predict_collapses_adjacent_same_stage_events_and_needs_an_event():
    m = StageForecaster(1).fit([chain(0, [(REC, 0), (IA, 100)])])
    f = m.predict([ev(REC, 0), ev(REC, 500), ev(REC, 900)], 600)
    assert f.state["stage"] == REC and f.state["start_s"] == BASE
    with pytest.raises(ValueError):
        m.predict([], 600)


# ------------------------------------------------------------------ JSON
def test_json_round_trip_is_exact_and_not_pickle(tmp_path):
    chains = [chain(i, [(REC, 0), (IA, 100), (C2, 250)]) for i in range(7)] + [chain(50, [(REC, 0)], terminated=False)]
    m = StageForecaster(2, alpha=0.5, beta=3.0, min_support2=3).fit(chains, observed_until=BASE + 5000)
    p = tmp_path / "m.json"
    m.save(p)
    doc = json.loads(p.read_text(encoding="utf-8"))
    assert doc["schema"] == SCHEMA
    m2 = StageForecaster.load(p)
    assert m2.to_dict() == m.to_dict()
    for k in (1, 2, 3):
        a = m.predict(chains[0].events[:k], 1800).as_dict()
        b = m2.predict(chains[0].events[:k], 1800).as_dict()
        assert a == b
    json.dumps(a)                                                # the forecast itself is JSON-serialisable


def test_loader_rejects_foreign_documents():
    with pytest.raises(ValueError):
        StageForecaster.from_dict({"schema": "something.else"})


def test_leave_out_is_exact_inverse_of_fit():
    chains = [chain(i, [(REC, 0), (IA, 100 + i), (C2, 300 + i)]) for i in range(6)] + [chain(9, [(REC, 0)], terminated=False)]
    full = StageForecaster(2).fit(chains, BASE + 9000)
    loo = full.copy().fit([chains[2]], BASE + 9000, sign=-1)
    ref = StageForecaster(2).fit(chains[:2] + chains[3:], BASE + 9000)
    for s in (REC, IA):
        assert {k: v for k, v in loo.counts1.get(s, {}).items() if v} == ref.counts1.get(s, {})
    assert loo.exposure[REC] == pytest.approx(ref.exposure[REC])
    assert loo.fit_info["n_chains"] == ref.fit_info["n_chains"]


# ------------------------------------------------------------------ held-out evaluation
def test_heldout_chain_never_sees_itself():
    """A transition that exists in exactly ONE chain must get only the smoothed prior when that chain is held out."""
    common = [chain(i, [(REC, 0), (IA, 100)]) for i in range(10)]
    odd = chain(99, [(REC, 0), (EXF, 100)])
    items = score_items(common + [odd], BASE + 10_000, fold_by="chain", horizon_s=3600, orders=(1,))
    it = [i for i in items if i["chain"] == "c99" and i["stage"] == REC][0]
    assert it["o1"]["p_next"][EXF] == pytest.approx(1 / 16)         # (0 + 1) / (10 + 6): 6 outcomes, 10 recon->IA seen
    assert it["n_train_chains"] == 10
    other = [i for i in items if i["chain"] == "c0" and i["stage"] == REC][0]
    assert other["o1"]["p_next"][EXF] == pytest.approx(2 / 16)     # the odd chain is in ITS training set: (1 + 1) / (9 + 1 + 6)


def test_entity_and_day_folds_hold_out_every_chain_of_the_group():
    cs = [chain(i, [(REC, 0), (IA, 100)], entity="same", day=f"2026-01-0{1 + i % 2}") for i in range(6)]
    by_entity = score_items(cs, BASE + 9000, fold_by="entity", orders=(1,))
    assert all(i["n_train_chains"] == 0 for i in by_entity)
    by_day = score_items(cs, BASE + 9000, fold_by="day", orders=(1,))
    assert all(i["n_train_chains"] == 3 for i in by_day)


def test_outcome_taxonomy_and_exact_counts():
    cs = [chain(0, [(REC, 0), (IA, 600)]),                   # followed within H
          chain(1, [(REC, 0), (IA, 9000)]),                  # followed beyond H
          chain(2, [(REC, 0)], terminated=True),             # no follow-up
          chain(3, [(REC, 0)], terminated=False)]            # still open -> unresolved
    res, items = evaluate(cs, BASE + 20_000, horizon_s=3600, thresholds=(0.0,), orders=(1,))
    o = res["focus_events"]["order1"]["thr_0"]["outcomes"]
    assert {k: v for k, v in o.items() if v} == {"early": 1, "beyond_horizon": 1, "no_followup": 1, "unresolved": 1}
    assert res["focus_events"]["order1"]["thr_0"]["early"]["n"] == 1
    assert res["setup"]["n_chains"] == 4


def test_victim_hit_at_k():
    cs = [chain(i, [(REC, 0), (IA, 100)]) for i in range(4)]
    for c in cs:
        c.events[0]["dsts"] = {"V1": 50, "V2": 5}
        c.events[1]["dsts"] = {"V1": 9}
    cs[3].events[1]["dsts"] = {"V2": 9}
    _, items = evaluate(cs, BASE + 9000, horizon_s=3600, orders=(1,))
    r = victim_hit_at_k(cs, items)
    assert r["n"] == 4 and r["hit@1"]["k"] == 3 and r["hit@3"]["k"] == 4


# ------------------------------------------------------------------ SYNTHETIC recovery (machinery check only)
def test_synthetic_recovery_in_the_host_view_recovers_known_probabilities_and_gaps():
    r = recovery_check(n_campaigns=700, seed=3, view="host")
    assert r["SYNTHETIC"] is True and r["chains"] == 700
    for row in r["rows"]:
        assert row["truth_inside_ci"], row
        assert abs(row["p_mle"] - row["p_true"]) < 0.07, row
        assert abs(row["mean_gap_est_s"] / row["mean_gap_true_s"] - 1) < 0.2, row


def test_synthetic_attacker_view_cannot_link_across_the_direction_flip():
    """After compromise the victim is the SOURCE; the attacker-keyed view therefore never sees initial_access ->
    command_and_control. This is the reason the host view exists."""
    r = recovery_check(n_campaigns=500, seed=4, view="attacker")
    rows = {x["transition"]: x for x in r["rows"]}
    assert rows["reconnaissance->initial_access"]["truth_inside_ci"]
    assert rows["initial_access->command_and_control"]["k"] == 0
    assert not rows["initial_access->command_and_control"]["truth_inside_ci"]


def test_synthetic_decoy_targets_dilute_the_host_view_but_not_the_attacker_view():
    host = recovery_check(n_campaigns=300, seed=5, view="host", n_decoys=3)
    p_host = host["rows"][0]["p_mle"]
    assert p_host < 0.7 / 2.5                                        # ~0.7 / 4: three of four recon targets are never attacked
    att = recovery_check(n_campaigns=300, seed=5, view="attacker", n_decoys=3)
    assert abs(att["rows"][0]["p_mle"] - 0.7) < 0.1


def test_synthetic_generator_is_deterministic_and_labels_the_data_synthetic():
    from eval.synthetic_campaigns import synthetic_campaigns
    a, ta = synthetic_campaigns(20, seed=1)
    b, tb = synthetic_campaigns(20, seed=1)
    assert a.equals(b) and ta["SYNTHETIC"] is True
    assert set(a.label) >= {"PortScan", "SSH-Bruteforce", "Bot", "SYNTH-Exfiltration", "BENIGN"}


def test_reonsets_are_flagged_and_reported_separately_from_first_onsets():
    """c2 -> impact -> c2 -> impact: only the first c2 -> impact is a first onset; the second repeats a stage that
    already happened in the chain (the pattern docs/13 section 5 discounts)."""
    cs = [chain(i, [(C2, 0), (IMP, 600), (C2, 1200), (IMP, 1800)]) for i in range(5)] + [chain(50, [(C2, 0)])]
    res, items = evaluate(cs, BASE + 50_000, horizon_s=3600, thresholds=(0.0,), orders=(1, 0, 2), focus_stage=C2)
    flags = sorted((i["idx"], i["reonset"]) for i in items if i["chain"] == "c0")
    assert flags == [(0, False), (1, True), (2, True), (3, False)]        # idx 3 = last impact, no successor
    assert res["focus_events_first_onset"]["order1"]["n_items"] == 6        # 5 first c2 -> impact + the chain that ends
    assert res["focus_events_reonset"]["order1"]["n_items"] == 5
    assert res["focus_events_reonset"]["order1"]["thr_0"]["positives_next_stage_within_H"] == 5
