"""eval/onset_eval.py: episode grouping, early / on-time / late / missed, real-timestamp lead time and gap
handling, on small synthetic hosts. The arrays come from the REAL pipeline.windowing.build_sequences, so the
tests also pin the sequence layout the evaluator reconstructs timelines from."""
import copy

import numpy as np
import pandas as pd
import pytest

from eval.onset_eval import (
    analyse, build_chains, clopper_pearson, episode_outcome, find_episodes, sequence_categories, structure,
    threshold_for_false_alarm_rate,
)
from pipeline.mitre_mapping import BENIGN, INITIAL_ACCESS
from pipeline.windowing import build_sequences

L, K, WS = 3, 3, 10
CFG = {"windowing": {"sequence_length": L, "forecast_horizon": K, "window_seconds": WS}}
T0 = pd.Timestamp("2026-01-01")
B, A = 0, 1


def windows(labels, times_s=None, ip="h", scenario=None):
    times_s = list(range(0, len(labels) * WS, WS)) if times_s is None else times_s
    rows = []
    for lab, t in zip(labels, times_s):
        r = {"src_ip": ip, "window_start": T0 + pd.Timedelta(seconds=t), "flow_count": float(t),
             "stage": INITIAL_ACCESS if lab == A else BENIGN}
        if scenario is not None:
            r["scenario_id"] = scenario
        rows.append(r)
    return pd.DataFrame(rows)


def arrays(frames, cfg=CFG):
    df = pd.concat(frames, ignore_index=True)
    return build_sequences(df, ["flow_count"], cfg)


def alarm_at(S, **kw):
    """alarm vector with True at the given chain-order sequence indices (single chain)."""
    a = np.zeros(S["n"], bool)
    a[list(kw["idx"])] = True
    return a


def one_episode_labels():
    # 10 benign, 5 attack, 5 benign: onset window p=10
    return [B] * 10 + [A] * 5 + [B] * 5


def outcome_for(idx, labels=None, times_s=None):
    arr = arrays([windows(labels or one_episode_labels(), times_s)])
    S = structure(arr, WS)
    assert len(S["episodes"]) == 1
    # sequences are in time order for a single host: sequence i has current window L-1+i
    return episode_outcome(S["episodes"][0], alarm_at(S, idx=idx), WS, K), S


# ------------------------------------------------------------------ populations, layout, timeline
def test_categories_and_timeline_consistent():
    arr = arrays([windows(one_episode_labels())])
    cat = sequence_categories(arr)
    # current window c = L-1+i: benign-throughout needs c..c+K all benign
    n = len(cat)
    assert n == 20 - L - K + 1
    chains, mism = build_chains(arr, L, K)
    assert mism == 0 and len(chains) == 1 and chains[0].n == n
    # onset sequences: c in {7,8,9} -> i in {5,6,7}
    assert list(np.flatnonzero(cat == 1)) == [5, 6, 7]
    assert list(np.flatnonzero(cat == 2)) == [8, 9, 10, 11, 12]  # c = 10..14 attack
    assert (cat[:5] == 0).all()


def test_future_timestamps_reconstructed_from_overlap():
    arr = arrays([windows(one_episode_labels())])
    chains, _ = build_chains(arr, L, K)
    ch = chains[0]
    assert len(ch.t) == ch.last + 1
    assert ch.y[3 * 0 + L - 1] == 0 and ch.y[10] == 1 and ch.y[15] == 0
    assert ch.t[10] == np.datetime64(T0 + pd.Timedelta(seconds=100), "ns").astype(np.int64)


# ------------------------------------------------------------------ outcomes
def test_early_alarm_has_real_lead_time():
    # onset p=10 (T0=100 s). Sequence 5 has current window c=7, issued at 70+10=80 s -> lead 20 s.
    o, _ = outcome_for([5])
    assert o["outcome"] == "early" and o["lead_s"] == pytest.approx(20.0)
    assert o["contiguous"] is True


def test_earliest_alarm_gives_the_lead():
    o, _ = outcome_for([5, 6, 7])
    assert o["outcome"] == "early" and o["lead_s"] == pytest.approx(20.0)  # first (earliest) alarm


def test_alarm_issued_exactly_at_onset_is_on_time_not_early():
    # sequence 7: current window c=9 (benign), issued at 90+10=100 s = T0 -> no warning
    o, _ = outcome_for([7])
    assert o["outcome"] == "on_time" and o["lead_s"] is None and o["delay_s"] == pytest.approx(0.0)


def test_alarm_from_onset_window_itself_is_on_time():
    # sequence 8: current window c=10 is the onset window, issued at 110 s = T0 + WS
    o, _ = outcome_for([8])
    assert o["outcome"] == "on_time" and o["delay_s"] == pytest.approx(10.0)


def test_alarm_after_onset_is_late():
    o, _ = outcome_for([9])   # c=11, issued 120 s
    assert o["outcome"] == "late" and o["delay_s"] == pytest.approx(20.0)
    o, _ = outcome_for([12])  # c=14, last attack window
    assert o["outcome"] == "late" and o["delay_s"] == pytest.approx(50.0)


def test_no_alarm_is_missed_and_alarms_outside_the_episode_do_not_count():
    # sequences 0..4 (c<=6) are benign-throughout: their alarms are false alarms, not early warning
    o, _ = outcome_for([0, 1, 2, 3, 4])
    assert o["outcome"] == "missed"
    o, _ = outcome_for([])
    assert o["outcome"] == "missed" and o["n_early_origins"] == 3


def test_early_origins_alarmed_counted():
    o, _ = outcome_for([5, 6])
    assert o["n_early_origins"] == 3 and o["n_early_origins_alarmed"] == 2


# ------------------------------------------------------------------ real timestamps and gaps
def test_lead_time_uses_real_timestamps_not_k_times_window():
    # 10 benign windows 10 s apart (0..90 s), then the attack starts 300 s later. The origin whose current
    # window is the last benign one (90 s) is issued at 100 s; the onset is at 300 s.
    times = list(range(0, 100, 10)) + [300, 310, 320, 330, 340, 350, 360]
    labels = [B] * 10 + [A] * 3 + [B] * 4
    arr = arrays([windows(labels, times)])
    S = structure(arr, WS)
    ep = S["episodes"][0]
    assert ep.T0_ns == np.datetime64(T0 + pd.Timedelta(seconds=300), "ns").astype(np.int64)
    n = S["n"]
    alarm = np.zeros(n, bool)
    last_benign_origin = ep.early[-1][0]
    alarm[last_benign_origin] = True
    o = episode_outcome(ep, alarm, WS, K)
    assert o["outcome"] == "early"
    assert o["lead_s"] == pytest.approx(200.0)       # real: 300 - (90 + 10), not 1 * 10 s
    alarm[:] = False
    alarm[ep.early[0][0]] = True                     # earliest origin: current window at 70 s -> 300 - 80
    assert episode_outcome(ep, alarm, WS, K)["lead_s"] == pytest.approx(220.0)
    assert o["lead_s"] != 1 * WS
    assert o["contiguous"] is False                  # a 210 s step sits between origin and onset
    assert o["lead_within_nominal_horizon"] is False  # 200 s > K * WS = 30 s


def test_gap_before_inputs_makes_episode_gapped_but_not_clean_timeline_break():
    # a 460 s step into window 5 lies inside the input history of the earliest eligible origin (c=6)
    times = [0, 10, 20, 30, 40, 500, 510, 520, 530, 540, 550, 560, 570]
    labels = [B] * 9 + [A] * 3 + [B]
    arr = arrays([windows(labels, times)])
    S = structure(arr, WS)
    assert S["mismatch"] == 0 and len(S["chains"]) == 1
    ep = S["episodes"][0]
    assert ep.contiguous is False


def test_contiguous_episode_is_flagged_contiguous():
    _, S = outcome_for([])
    assert S["episodes"][0].contiguous is True
    assert S["seq_contig"][5:8].all()


def test_sequence_contiguity_flags_unverifiable_tail_as_gapped():
    arr = arrays([windows([B] * 12)])
    S = structure(arr, WS)
    # every sequence's K target windows are inside the stored timeline only for the early part
    assert S["seq_contig"].dtype == bool
    assert S["seq_contig"][0]
    assert not S["seq_contig"][-1]   # its targets lie beyond the last stored timestamp


def test_onset_in_unverifiable_tail_is_unresolved():
    # attack begins in the last two windows of the host's data: its real start time is not stored
    labels = [B] * 10 + [A] * 2
    arr = arrays([windows(labels)])
    S = structure(arr, WS)
    assert len(S["episodes"]) == 1 and S["episodes"][0].T0_ns is None
    o = episode_outcome(S["episodes"][0], np.ones(S["n"], bool), WS, K)
    assert o["outcome"] == "unresolved"
    res = analyse(arr, np.ones(S["n"]), {"t": 0.5}, WS, S=S)
    assert res["thresholds"]["t"]["episodes_all"]["n_unresolved_time"] == 1
    assert res["thresholds"]["t"]["episodes_all"]["n_scored"] == 0


# ------------------------------------------------------------------ episode grouping
def test_flicker_inside_an_attack_is_one_episode_but_two_raw_events():
    labels = [B] * 8 + [A, A] + [B] + [A, A] + [B] * 8   # one benign window between two bursts (< K)
    arr = arrays([windows(labels)])
    S = structure(arr, WS)
    assert len(S["episodes"]) == 1 and S["episodes"][0].n_raw == 2
    assert len(S["raw_episodes"]) == 2
    # every onset sequence (benign now, attack within K) belongs to exactly one episode
    assert set(S["seq_to_ep"]) == set(np.flatnonzero(sequence_categories(arr) == 1))


def test_long_benign_gap_separates_episodes():
    labels = [B] * 8 + [A, A] + [B] * 5 + [A, A] + [B] * 8   # 5 benign windows >= K
    arr = arrays([windows(labels)])
    S = structure(arr, WS)
    assert len(S["episodes"]) == 2
    assert [e.n_raw for e in S["episodes"]] == [1, 1]


def test_merge_gap_zero_gives_raw_events():
    labels = [B] * 8 + [A, A] + [B] + [A, A] + [B] * 8
    arr = arrays([windows(labels)])
    chains, _ = build_chains(arr, L, K)
    eps, _ = find_episodes(chains, WS, merge_gap=0)
    assert len(eps) == 2


def test_different_onset_stage_is_a_different_episode():
    df = windows([B] * 8 + [A, A] + [B] + [A, A] + [B] * 8)
    df.loc[11:12, "stage"] = "lateral_movement"   # second burst has another stage
    arr = arrays([df])
    S = structure(arr, WS)
    assert len(S["episodes"]) == 2


def test_hosts_are_kept_apart_and_scenarios_too():
    f1 = windows(one_episode_labels(), ip="h1")
    f2 = windows([B] * 20, ip="h2")                   # benign-throughout host
    f3 = windows(one_episode_labels(), ip="h1", scenario=7)
    f4 = windows(one_episode_labels(), ip="h1", scenario=8)
    arr = arrays([f1, f2])
    S = structure(arr, WS)
    assert len(S["chains"]) == 2 and len(S["episodes"]) == 1
    res = analyse(arr, np.zeros(S["n"]), {"t": 0.5}, WS, S=S)
    assert res["hosts"]["n_hosts"] == 2 and res["hosts"]["n_hosts_benign_throughout_only"] == 1
    arr2 = arrays([f3, f4])
    S2 = structure(arr2, WS)
    assert len(S2["chains"]) == 2 and len(S2["episodes"]) == 2   # same src_ip, different scenario


def test_dropped_sequences_break_the_chain_instead_of_inventing_adjacency():
    cfg = copy.deepcopy(CFG)
    cfg["windowing"]["require_contiguous_windows"] = True
    times = list(range(0, 130, 10)) + list(range(600, 730, 10))
    arr = arrays([windows([B] * 13 + [B] * 9 + [A] * 4, times)], cfg)
    S = structure(arr, WS)
    assert S["mismatch"] == 0 and len(S["chains"]) >= 2


def test_host_attacking_from_first_window_has_no_onset():
    arr = arrays([windows([A] * 16)])
    S = structure(arr, WS)
    assert len(S["episodes"]) == 0
    res = analyse(arr, np.ones(S["n"]), {"t": 0.5}, WS, S=S)
    assert res["hosts"]["n_hosts_whose_first_observed_window_is_already_attacking"] == 1
    assert res["sequences"]["onset"] == 0 and res["sequences"]["already_attacking"] == S["n"]
    assert res["already_attacking_runs"]["n_runs"] == 1


# ------------------------------------------------------------------ analyse + stats helpers
def test_analyse_reports_counts_and_false_alarms_on_benign_throughout():
    arr = arrays([windows(one_episode_labels())])
    S = structure(arr, WS)
    score = np.zeros(S["n"])
    score[[0, 1]] = 0.9            # 2 false alarms on benign-throughout origins
    score[5] = 0.9                 # early warning, 20 s
    res = analyse(arr, score, {"t": 0.4}, WS, S=S, B=50)
    t = res["thresholds"]["t"]
    assert res["episodes"]["n_episodes_merged"] == 1 and res["episodes"]["n_hosts"] == 1
    assert t["episodes_all"]["early"]["k"] == 1 and t["episodes_all"]["early"]["n"] == 1
    assert t["episodes_all"]["lead_s"]["median"] == pytest.approx(20.0)
    fa = t["false_alarm_benign_throughout_sequences"]["all"]
    assert fa["k"] == 2 and fa["n"] == 7   # c = 2..6 (before the onset horizon) and c = 15, 16 (after the attack)
    assert t["episodes_contiguous"]["n_episodes"] == 1
    assert t["episodes_gapped_or_unverifiable"]["n_episodes"] == 0


def test_clopper_pearson_exact_values():
    lo, hi = clopper_pearson(0, 10)
    assert lo == 0.0 and hi == pytest.approx(0.3085, abs=1e-3)
    lo, hi = clopper_pearson(10, 10)
    assert hi == 1.0 and lo == pytest.approx(0.6915, abs=1e-3)
    assert clopper_pearson(0, 0) == (None, None)


def test_threshold_for_false_alarm_rate_never_exceeds_budget():
    rng = np.random.default_rng(0)
    s = rng.random(1000)
    mask = np.ones(1000, bool)
    for r in (0.0, 0.01, 0.05, 0.5):
        thr = threshold_for_false_alarm_rate(s, mask, r)
        assert (s >= thr).mean() <= r + 1e-12
    assert (s >= threshold_for_false_alarm_rate(s, mask, 0.05)).mean() > 0.04
