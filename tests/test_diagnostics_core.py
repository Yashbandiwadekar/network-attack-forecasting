import numpy as np
import pytest

from eval.diagnostics import core as c


def test_per_unit_auroc_separates_between_and_within_unit_signal():
    rng = np.random.default_rng(0)
    # unit A: base rate 0.8, scores offset high but uninformative inside; unit B: base rate 0.1, offset low
    ya = (rng.random(400) < 0.8).astype(int)
    yb = (rng.random(400) < 0.1).astype(int)
    sa = 10 + rng.normal(size=400)
    sb = rng.normal(size=400)
    y = np.r_[ya, yb]
    s = np.r_[sa, sb]
    u = np.array(["A"] * 400 + ["B"] * 400)
    r = c.per_unit_auroc(y, s, u)
    assert r["pooled"] > 0.75           # pooled looks good...
    assert r["unit_mean"] > 0.7         # ...because of the between-unit offset
    assert abs(r["within"]["A"] - 0.5) < 0.1 and abs(r["within"]["B"] - 0.5) < 0.15
    assert r["unit_rate"]["A"] > 0.7


def test_per_unit_single_class_is_none():
    r = c.per_unit_auroc(np.zeros(5), np.arange(5.0), np.array(list("aaaaa")))
    assert r["pooled"] is None and r["within"]["a"] is None and r["mean_within"] is None


def test_univariate_auroc_sign_and_constant():
    y = np.r_[np.zeros(50), np.ones(50)]
    X = np.c_[np.r_[np.arange(50), np.arange(50) + 100], -np.r_[np.arange(50), np.arange(50) + 100], np.ones(100)]
    r = c.univariate_auroc(X, y, ["up", "down", "const"])
    assert r["up"] == 1.0 and r["down"] == 0.0 and r["const"] == 0.5


def test_clip_rates():
    X = np.zeros((10, 3, 2))
    X[0, 0, 0] = 100.0
    rates = c.clip_rates(X, mean=np.zeros(2), std=np.ones(2), clip_std=6.0)
    assert rates[0] == pytest.approx(1 / 30) and rates[1] == 0.0


def test_smd_and_ks_detect_shift():
    rng = np.random.default_rng(1)
    ref = rng.normal(size=(2000, 2))
    oth = np.c_[rng.normal(3, 1, 2000), rng.normal(size=2000)]
    r = c.smd_and_ks(ref, oth)
    assert r["smd"][0] == pytest.approx(3, abs=0.2) and abs(r["smd"][1]) < 0.15
    assert r["ks"][0] > 0.8 and r["ks"][1] < 0.1


def test_constant_features_and_corr_pairs():
    rng = np.random.default_rng(2)
    a = rng.normal(size=500)
    X = np.c_[a, 2 * a + 1, rng.normal(size=500), np.zeros(500)]
    assert list(c.constant_features(X)) == [False, False, False, True]
    pairs = c.high_corr_pairs(X, ["a", "b", "c", "z"])
    assert len(pairs) == 1 and {pairs[0][0], pairs[0][1]} == {"a", "b"}


def test_noisy_auroc_perfect_ranker_degrades_with_noise():
    rng = np.random.default_rng(3)
    y = (rng.random(4000) < 0.2).astype(int)
    clean = c.noisy_auroc(y, y.astype(float), 0.0, 0.0)
    noisy = c.noisy_auroc(y, y.astype(float), 0.07, 0.07)
    assert clean["mean"] == pytest.approx(1.0)
    assert 0.8 < noisy["mean"] < 0.97


def test_clopper_pearson_and_rule_of_three():
    lo, hi = c.clopper_pearson(0, 12)
    assert lo == 0.0 and hi == pytest.approx(0.2646, abs=0.002)   # docs/13: 0/12 -> 26%
    assert c.clopper_pearson(12, 12)[1] == 1.0
    assert c.n_for_rate_zero_events(0.25) == 11 and c.n_for_rate_zero_events(0.30) == 9


def test_hanley_mcneil_and_mde():
    se = c.hanley_mcneil_se(0.8, 100, 100)
    assert 0.03 < se < 0.05
    assert c.min_detectable_auroc(0.5, 12, 12) > c.min_detectable_auroc(0.5, 120, 120)


def test_unit_balanced_auroc_removes_dominance_of_a_long_unit():
    rng = np.random.default_rng(4)
    # one long positive unit that the score misses, nine short positive units that it ranks perfectly
    y = np.r_[np.ones(900), np.ones(90), np.zeros(1000)]
    s = np.r_[rng.normal(-5, 0.1, 900), rng.normal(5, 0.1, 90), rng.normal(0, 1, 1000)]
    u = np.array(["big"] * 900 + [f"s{i}" for i in range(9) for _ in range(10)] + [f"n{i}" for i in range(10) for _ in range(100)])
    seq = c._auc(y, s)
    bal = c.unit_balanced_auroc(y, s, u)
    assert seq < 0.1 + 0.1 and bal > 0.4
    assert c.unit_balanced_auroc(np.zeros(4), np.arange(4.0), np.array(list("abcd"))) is None


def test_load_concatenates_splits_and_keeps_common_keys(tmp_path):
    for name, n in [("train", 3), ("val", 2)]:
        np.savez(tmp_path / f"{name}.npz", X=np.ones((n, 4, 2)) * n, window_end_time=np.array(["2018-02-16T10:00:00"] * n, dtype="datetime64[us]"),
                 only_in_train=np.arange(n) if name == "train" else np.zeros(0))
    # key present in only one split (shape differs) must be dropped rather than crash the concatenation
    for name in ["train", "val"]:
        z = dict(np.load(tmp_path / f"{name}.npz"))
        if name == "val":
            z.pop("only_in_train")
        np.savez(tmp_path / f"{name}.npz", **z)
    a = c.load(f"{tmp_path}:train,val")
    assert a["X"].shape == (5, 4, 2) and "only_in_train" not in a
    single = c.load(f"{tmp_path}:val")
    assert single["X"].shape == (2, 4, 2)
    assert list(c.day_of(a)) == ["2018-02-16"] * 5
