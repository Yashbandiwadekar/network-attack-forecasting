import numpy as np

from eval import baseline_gate as bg
from eval.benchmark import baseline_gate_section

CFG = {"features": {"flow_level": ["flow_count", "other"], "packet_level": ["pk"]}}


def _split(n_days=5, n=300, signal=True, seed=0):
    rng = np.random.default_rng(seed)
    X, y, t = [], [], []
    for d in range(n_days):
        yy = (rng.random(n) < 0.3).astype(float)
        base = rng.normal(size=(n, 12, 3))
        if signal:
            base[:, -1, 1] += 2.0 * yy                      # 'other' carries the signal, flow_count does not
        base[:, :, 0] = np.abs(base[:, :, 0]) * 10
        X.append(base)
        y.append(yy)
        t += [np.datetime64(f"2018-02-{10 + d:02d}T01:00:00")] * n
    X = np.concatenate(X).astype(np.float32)
    y = np.concatenate(y)
    inf = np.repeat(y[:, None], 6, axis=1)
    return {"X": X, "infiltration": inf, "window_end_time": np.array(t, dtype="datetime64[us]")}


def test_stack_features_shape_and_content():
    X = np.random.default_rng(0).normal(size=(4, 12, 5))
    S = bg.stack_features(X)
    assert S.shape == (4, 30)
    assert np.allclose(S[:, :5], X[:, -1, :]) and np.allclose(S[:, 20:25], X[:, -1, :] - X[:, -7, :])


def test_fit_baselines_uses_raw_features_and_ranks_signal():
    tr, te = _split(seed=0), _split(seed=1)
    m = bg.fit_baselines(tr["X"], tr["infiltration"][:, 0], flow_count_index=0)
    assert set(m) == set(bg.BASELINE_NAMES)
    sc = bg.baseline_scores(m, te["X"], batch=250)             # batching must not change the result
    y = te["infiltration"][:, 0]
    from sklearn.metrics import roc_auc_score
    assert roc_auc_score(y, sc["HGB_last"]) > 0.85 and roc_auc_score(y, sc["LR_last"]) > 0.85
    assert abs(roc_auc_score(y, sc["flow_count"]) - 0.5) < 0.06     # raw flow_count, uninformative here
    assert np.array_equal(sc["flow_count"], te["X"][:, -1, 0].astype(float))


def test_fit_baselines_single_class_does_not_crash():
    tr = _split()
    m = bg.fit_baselines(tr["X"], np.zeros(len(tr["X"])), 0)
    assert set(m) == set(bg.BASELINE_NAMES)


def test_gate_unit_ids_prefers_scenarios_then_days():
    s = _split(n_days=3)
    assert len(set(bg.gate_unit_ids(s))) == 3
    s["scenario_id"] = np.array(["a", "b"] * (len(s["X"]) // 2))
    assert set(bg.gate_unit_ids(s)) == {"a", "b"}


def test_gate_fails_for_a_model_equal_to_a_baseline_and_passes_for_an_oracle():
    ev = _split(n_days=7, seed=3)
    y = ev["infiltration"][:, 0]
    unit = bg.gate_unit_ids(ev)
    tr = _split(seed=0)
    m = bg.fit_baselines(tr["X"], tr["infiltration"][:, 0], 0)
    sc = bg.baseline_scores(m, ev["X"])
    g_same = bg.run_gate(y, {"model": sc["HGB_last"], **sc}, unit, "model")
    assert g_same["gates"]["HGB_last"]["verdict"] == "FAIL" and not g_same["all_pass"]
    g_or = bg.run_gate(y, {"model": y + 1e-6 * np.random.default_rng(0).normal(size=len(y)), **sc}, unit, "model")
    assert g_or["all_pass"] and all(v["verdict"] == "PASS" for v in g_or["gates"].values())
    md = bg.gate_markdown(g_or)
    assert "PASS" in md and "HGB_stacked" in md and "MDE" in md


def test_benchmark_section_is_markdown_with_all_baselines_and_one_unit_fails():
    tr, ev = _split(seed=0), _split(n_days=1, seed=2)
    y = ev["infiltration"][:, 0]
    sec = baseline_gate_section(CFG, tr, ev, "World Model (Transformer)", y * 0.9 + 0.05, scope="unit-test")
    for name in bg.BASELINE_NAMES:
        assert name in sec
    assert "Baseline gate (unit-test)" in sec and "FAIL" in sec and "fewer than 2 comparable units" in sec


def test_per_day_cap_keeps_small_days_whole_and_caps_the_big_one_deterministically():
    day = np.array(["a"] * 1000 + ["b"] * 50 + ["c"] * 20)
    idx = bg.per_day_cap_indices(day, 100, seed=0)
    assert len(idx) == 100 + 50 + 20 and len(set(idx)) == len(idx)
    assert (day[idx] == "a").sum() == 100 and (day[idx] == "b").sum() == 50 and (day[idx] == "c").sum() == 20
    assert np.array_equal(idx, bg.per_day_cap_indices(day, 100, seed=0))
    assert not np.array_equal(idx, bg.per_day_cap_indices(day, 100, seed=1))


def test_fit_baselines_with_per_day_cap_uses_only_the_capped_rows():
    tr = _split(n_days=3, n=400, seed=0)
    day = tr["window_end_time"].astype("datetime64[D]").astype(str)
    m = bg.fit_baselines(tr["X"], tr["infiltration"][:, 0], 0, day=day, per_day_cap=100)
    assert set(m) == set(bg.BASELINE_NAMES)


def test_benchmark_section_survives_splits_without_timestamps():
    tr, ev = _split(seed=0), _split(n_days=2, seed=2)
    del tr["window_end_time"], ev["window_end_time"]
    sec = baseline_gate_section(CFG, tr, ev, "World Model (Transformer)", ev["infiltration"][:, 0] * 0.9 + 0.05, scope="no-timestamps")
    assert "Baseline gate (no-timestamps)" in sec and "FAIL" in sec and "fewer than 2 comparable units" in sec
