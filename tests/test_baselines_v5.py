"""docs/19: grids, nested selection, secondary-label rules, adaptive alarm causality, raw-CSV alignment guard."""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from eval import baselines_v5 as B
from eval import baselines_v5_report as R
from eval import secondary_labels as S


def test_hgb_grid_is_registered_size_default_first_and_deterministic():
    g1, g2 = B.hgb_grid(), B.hgb_grid()
    assert g1 == g2 and len(g1) == 13 and g1[0] == B.HGB_DEFAULT
    assert len({tuple(sorted(map(str, c.items()))) for c in g1}) == 13
    assert len(B.tree_grid()) == 4 and len(B.lr_grid()) == 6


def test_nested_arm_selection_never_reads_the_held_out_day():
    days = ["a", "b", "c", "d"]
    arms = {"x": {"a": 0.9, "b": 0.5, "c": 0.5, "d": 0.5}, "y": {"a": 0.1, "b": 0.6, "c": 0.6, "d": 0.6}}
    n = R.nested_selection(arms, days)
    assert n["a"]["arm"] == "y" and n["a"]["auroc"] == 0.1          # arm chosen WITHOUT day a, although x is best on a itself
    assert n["b"]["arm"] == "x"                                      # without b, x wins on {a, c, d}
    # changing the held-out day's own scores cannot change which arm is chosen for it
    arms2 = {"x": {**arms["x"], "a": 0.0}, "y": {**arms["y"], "a": 1.0}}
    assert R.nested_selection(arms2, days)["a"]["arm"] == "y"
    arms3 = {"x": {**arms["x"], "a": 1.0}, "y": {**arms["y"], "a": 0.0}}
    assert R.nested_selection(arms3, days)["a"]["arm"] == "y"


def test_adaptive_alarm_is_causal_and_label_free():
    rng = np.random.default_rng(0)
    s = rng.random(600)
    a = R.adaptive_alarm(s, window=100, min_periods=20)
    assert not a[:20].any()
    s2 = s.copy()
    s2[300:] = rng.random(300) * 10                                  # change the future
    a2 = R.adaptive_alarm(s2, window=100, min_periods=20)
    assert np.array_equal(a[:300], a2[:300])


def test_secondary_label_rules_and_ambiguous_handling():
    n_att = np.array([0, 1, 4, 5, 50, 0])
    n_all = np.array([100, 100, 100, 100, 100, 100])
    prim = n_att > 0
    r = S.secondary_labels(n_att, n_all, prim, k=5, s=0.05)
    assert r["pos"].tolist() == [False, False, False, True, True, False]
    assert r["keep"].tolist() == [True, False, False, True, True, True]       # primary-positive but failing the rule -> dropped
    run = S.sustained_mask(np.array([0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0]), run=6)
    assert run.tolist() == [False] + [True] * 6 + [False] * 4


def test_align_next_counts_enforces_the_primary_label_match():
    t0 = np.datetime64("2018-02-14T08:00:00")
    ends = t0 + np.arange(5) * np.timedelta64(10, "s")
    idx = pd.DatetimeIndex(ends + np.timedelta64(10, "s"))
    counts = pd.DataFrame({"n_flows": [10, 10, 10, 10, 10], "n_attack": [0, 2, 0, 7, 0]}, index=idx)
    prim = np.array([0, 1, 0, 1, 0])
    a = S.align_next_counts(ends, prim, counts)
    assert a["match_rate"] == 1.0 and a["n_attack_next"].tolist() == [0, 2, 0, 7, 0]
    with pytest.raises(ValueError):
        S.align_next_counts(ends, np.array([1, 0, 1, 0, 1]), counts)           # misaligned labels are refused


def test_sealed_days_are_refused_by_the_raw_reader():
    for d in ("2018-02-16", "2018-02-23", "2018-03-01"):
        with pytest.raises(ValueError):
            S.window_counts(d)


def test_transfer_summary_and_threshold_from_other_days_only():
    s = R.transfer_summary({"a": 0.01, "b": 0.03, "c": 0.0}, {"a": 1000, "b": 1000, "c": 1000}, 0.01)
    assert s["n_within_x3"] == 2 and s["max"] == 0.03 and s["min"] == 0.0
