import numpy as np
import pytest

from eval import lodo_v4 as L
from eval.diagnostics import core as c


def _toy():
    rng = np.random.default_rng(0)
    days = ["2018-02-14", "2018-02-15", "2018-02-20", "2018-02-21", "2018-02-22", "2018-02-28", "2018-03-02"]
    day, host = [], []
    for d in days:
        if d == "2018-02-20":
            for h in range(60):
                day += [d] * 5
                host += [f"ip{h}"] * 5
        else:
            day += [d] * 20
            host += [f"NETWORK-{d}"] * 20
    return np.array(day), np.array(host), rng


def test_host_groups_partition_and_spread_attackers():
    hosts = [f"h{i}" for i in range(100)]
    pos = ["h3", "h10", "h50", "h51", "h99", "h7", "h8", "h9", "h20", "h21"]
    g = L.assign_host_groups(hosts, pos, 3, seed=0)
    assert set(g) == set(hosts) and set(g.values()) == {0, 1, 2}
    counts = np.bincount([g[p] for p in pos], minlength=3)
    assert counts.min() >= 3 and counts.max() <= 4          # 10 attackers over 3 groups: 4/3/3
    sizes = np.bincount(list(g.values()))
    assert sizes.max() - sizes.min() <= 1
    assert g == L.assign_host_groups(hosts[::-1], pos[::-1], 3, seed=0)   # independent of input order
    with pytest.raises(ValueError):
        L.assign_host_groups(hosts, ["nope"], 3)


def test_build_folds_never_contains_sealed_days_and_splits_0220():
    folds = L.build_folds()
    assert [f.name for f in folds].count("2018-02-20#g0") == 1
    assert len(folds) == 6 + 3
    assert all(f.day not in L.SEALED_TEST_DAYS for f in folds)
    with pytest.raises(ValueError):
        L.build_folds(days=list(L.LODO_DAYS) + ["2018-02-23"])


def test_fold_masks_no_day_or_host_leakage():
    day, host, _ = _toy()
    pos_hosts = [f"ip{i}" for i in range(6)]
    hg = L.assign_host_groups(set(host[day == "2018-02-20"]), pos_hosts, 3)
    hg.update({h: 0 for h in set(host) if h.startswith("NETWORK")})
    folds = L.build_folds()
    seen_heldout = np.zeros(len(day), int)
    for f in folds:
        tr, he = L.fold_masks(f, day, host, hg)
        L.assert_no_leakage(f, day, host, tr, he, hg)
        seen_heldout += he
        if f.kind == "day":
            assert set(day[he]) == {f.day} and f.day not in set(day[tr])
        else:
            assert set(host[he]).isdisjoint(set(host[tr & (day == f.day)]))
    assert (seen_heldout == 1).all()                      # every row is held out in exactly one fold (no host in two folds)


def test_assert_no_leakage_catches_leaks():
    day, host, _ = _toy()
    f = L.Fold("2018-02-15", "2018-02-15")
    tr, he = L.fold_masks(f, day, host, None)
    tr_bad = tr.copy()
    tr_bad[np.flatnonzero(he)[0]] = True
    with pytest.raises(AssertionError):
        L.assert_no_leakage(f, day, host, tr_bad, he)
    # a sealed day anywhere is refused
    day2 = day.copy()
    day2[0] = "2018-02-23"
    with pytest.raises(ValueError):
        L.assert_no_leakage(f, day2, host, *L.fold_masks(f, day2, host, None))


def test_family_coverage():
    cov = L.family_coverage(L.Fold("2018-03-02", "2018-03-02"), [d for d in L.LODO_DAYS if d != "2018-03-02"])
    assert cov["family"] == "command_and_control" and not cov["family_in_train"]
    cov = L.family_coverage(L.Fold("2018-02-28", "2018-02-28"), [d for d in L.LODO_DAYS if d != "2018-02-28"])
    assert not cov["family_in_train"]                      # 03-01 (the other lateral-movement day) is sealed
    cov = L.family_coverage(L.Fold("2018-02-22", "2018-02-22"), [d for d in L.LODO_DAYS if d != "2018-02-22"])
    assert cov["family_in_train"] and cov["other_days_same_family"] == ["2018-02-14"]
    cov = L.family_coverage(L.Fold("2018-02-20#g1", "2018-02-20", 1), L.LODO_DAYS)
    assert cov["same_day_other_hosts_in_train"] and not cov["day_disjoint"]


def test_oof_day_metrics_and_selection_metric_ignore_between_day_offset():
    rng = np.random.default_rng(1)
    day = np.array(["a"] * 400 + ["b"] * 400)
    y = np.r_[rng.random(400) < 0.8, rng.random(400) < 0.1].astype(int)
    s = np.r_[10 + rng.normal(size=400), rng.normal(size=400)]       # only a between-day offset
    m = L.oof_day_metrics(y, s, day)
    assert abs(m["a"]["auroc"] - 0.5) < 0.15 and abs(m["b"]["auroc"] - 0.5) < 0.15
    assert c._auc(y, s) > 0.75                                        # pooled would have looked good
    assert abs(L.selection_metric({d: v["auroc"] for d, v in m.items()}) - 0.5) < 0.1
    assert np.isnan(L.oof_day_metrics(np.zeros(5), np.arange(5.0), np.array(list("aaaaa")))["a"]["auroc"])
    assert L.selection_metric({"a": float("nan"), "b": 0.7}) == 0.7


def test_select_epoch_and_nested_selection():
    curves = {"a": np.array([0.6, 0.9, 0.7, 0.9]), "b": np.array([0.5, 0.8, 0.6, 0.8]), "c": np.array([0.9, 0.5, 0.9, 0.5])}
    e, mean = L.select_epoch(curves)
    assert np.allclose(mean, [2.0 / 3, 2.2 / 3, 2.2 / 3, 2.2 / 3])
    assert e == 1                                          # ties go to the earliest epoch
    nested = L.nested_epoch_selection(curves)
    # day c is read at the epoch chosen from a and b only (epoch 1: first of the tied maxima 0.9/0.8)
    assert nested["c"] == {"epoch": 1, "auroc": 0.5}
    # day a is read at the epoch chosen from b and c: means (0.7, 0.65, 0.75, 0.65) -> epoch 2
    assert nested["a"] == {"epoch": 2, "auroc": 0.7}
    # nested value never exceeds the in-sample (argmax) optimum on average
    in_sample = np.mean([curves[d][e] for d in curves])
    assert np.mean([v["auroc"] for v in nested.values()]) <= in_sample + 1e-12


def test_day_balanced_threshold_is_not_decided_by_the_biggest_day():
    rng = np.random.default_rng(0)
    # day big: 100k benign with low scores; day small: 100 benign with high scores
    y = np.zeros(100_100, int)
    day = np.array(["big"] * 100_000 + ["small"] * 100)
    s = np.r_[rng.random(100_000) * 0.1, 0.5 + rng.random(100) * 0.5]
    thr_bal = L.day_balanced_threshold(y, s, day, 0.01)
    thr_pooled = L.day_balanced_threshold(y, s, np.array(["x"] * len(y)), 0.01)
    assert thr_pooled < 0.1 <= thr_bal                   # pooled FPR would ignore the small day entirely
    op = L.operating_point_by_day(y, s, day, thr_bal)
    # each day's negatives weigh 1/2 -> balanced FPR <= 1% means small-day FPR ~ 2% at most
    assert op["small"]["fpr"] <= 0.02 + 1e-9 and op["big"]["fpr"] <= 0.001
    assert 0.5 * op["small"]["fpr"] + 0.5 * op["big"]["fpr"] <= 0.01 + 1e-9


def test_day_balanced_threshold_handles_ties_and_budget_zero():
    y = np.zeros(10, int)
    s = np.array([1.0] * 5 + [0.0] * 5)
    day = np.array(["a"] * 10)
    t = L.day_balanced_threshold(y, s, day, 0.5)
    assert t == 1.0 and (s >= t).mean() == 0.5            # ties alarm together
    t0 = L.day_balanced_threshold(y, s, day, 0.0)
    assert (s >= t0).sum() == 0


def test_paired_mde_matches_docs16_and_gate_verdicts():
    for n, ref in [(3, 0.076), (5, 0.041), (10, 0.024), (20, 0.016)]:
        assert abs(c.paired_mde(c.PAIRED_SD_FLOOR, n) - ref) < 0.001
    days = [f"d{i}" for i in range(7)]
    base = {d: 0.70 for d in days}
    win = {d: 0.70 + 0.10 + 0.01 * (i % 2) for i, d in enumerate(days)}
    g = c.baseline_gate(win, base)
    assert g["verdict"] == "PASS" and g["ci_excludes_zero"] and g["n_units"] == 7 and g["wins"] == 7
    small = {d: 0.70 + 0.01 for d in days}               # +0.01 is below the 7-day MDE (~0.03)
    assert c.baseline_gate(small, base)["verdict"] == "FAIL"
    worse = {d: 0.60 for d in days}
    assert c.baseline_gate(worse, base)["verdict"] == "FAIL"
    # a noisy comparison cannot shrink its own bar: sd_used is max(floor, observed)
    noisy = {d: 0.70 + (0.2 if i % 2 else -0.1) + 0.2 for i, d in enumerate(days)}
    gn = c.baseline_gate(noisy, base)
    assert gn["sd_used"] == gn["sd_diff_observed"] > c.PAIRED_SD_FLOOR and gn["mde"] > gn["mde_at_floor_sd"]
    # None units are dropped; fewer than 2 comparable units fails
    assert c.baseline_gate({"a": 0.9, "b": None}, {"a": 0.5, "b": 0.5})["verdict"] == "FAIL"
