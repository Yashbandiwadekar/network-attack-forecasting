"""docs/19: the engineered baseline features must be strictly causal (no future window, no label) and order-invariant."""
from __future__ import annotations

import inspect

import numpy as np
import pytest

from common.config import feature_columns, load_config
from models import features_v5 as F5

NAMES = feature_columns(load_config("configs/real_data_v2_converged_seed1.yaml"))


def _series(n_units=3, n=60, L=12, seed=0, gaps=True):
    """Synthetic multi-unit data in the cache layout: per unit a window series, sequences of L consecutive (active) windows."""
    rng = np.random.default_rng(seed)
    Xs, Ts, Us = [], [], []
    for u in range(n_units):
        m = n + L
        w = np.abs(rng.normal(50, 30, (m, len(NAMES)))).astype(np.float32)
        w[:, NAMES.index("syn_ratio")] = rng.random(m)
        step = rng.choice([10, 10, 20, 50], m) if gaps else np.full(m, 10)
        t = np.datetime64("2018-02-14T08:00:00") + np.cumsum(step).astype("timedelta64[s]")
        for i in range(L - 1, m):
            Xs.append(w[i - L + 1:i + 1]); Ts.append(t[i - L + 1:i + 1]); Us.append(f"u{u}")
    X, T, U = np.stack(Xs), np.stack(Ts), np.array(Us)
    return X, T, U


def _feats(X, T, U, variant):
    last_t = T[:, -1]
    ctx = F5.causal_context(F5.vol_last_log(X[:, -1], NAMES), U, last_t, window=20, min_periods=4)
    return F5.build_features(X, NAMES, variant, T=T, ctx=ctx)[0]


def test_context_matches_bruteforce_with_ties():
    rng = np.random.default_rng(1)
    N = 200
    unit = rng.integers(0, 3, N).astype(str)
    time = np.datetime64("2018-01-01T00:00:00") + rng.integers(0, 60, N).astype("timedelta64[s]")   # many ties
    vals = rng.normal(size=(N, 2))
    m, s = F5.causal_context(vals, unit, time, window=7, min_periods=3)
    for i in range(N):
        prev = [j for j in range(N) if unit[j] == unit[i] and time[j] < time[i]]
        prev = sorted(prev, key=lambda j: (time[j], j))[-7:]
        if len(prev) < 3:
            assert np.isnan(m[i]).all()
        else:
            assert np.allclose(m[i], vals[prev].mean(0), atol=1e-9)
            assert np.allclose(s[i], vals[prev].std(0), atol=1e-6)


@pytest.mark.parametrize("variant", ["S5_temporal", "S6_context", "S7_relative"])
def test_no_future_leakage_perturb_and_delete(variant):
    X, T, U = _series()
    full = _feats(X, T, U, variant)
    tcut = np.datetime64("2018-02-14T08:20:00")
    late = T[:, -1] > tcut
    assert late.any() and (~late).sum() > 30 and late.sum() > 10
    # (a) replace EVERY row after the cut by garbage (X and times move later but stay > cut): earlier rows must be bit-identical
    X2, T2 = X.copy(), T.copy()
    rng = np.random.default_rng(5)
    X2[late] = rng.normal(1e6, 1e3, X2[late].shape).astype(np.float32)
    T2[late] = T[late] + np.timedelta64(7, "s")
    pert = _feats(X2, T2, U, variant)
    assert np.array_equal(full[~late], pert[~late], equal_nan=True)
    # (b) deleting all later rows changes nothing for the earlier ones
    kept = _feats(X[~late], T[~late], U[~late], variant)
    assert np.array_equal(full[~late], kept, equal_nan=True)
    # (c) sanity that the test can fail: later rows' features DO change when their own inputs change
    assert not np.array_equal(full[late], pert[late], equal_nan=True)


def test_future_row_change_does_not_move_past_rows_one_by_one():
    X, T, U = _series(n_units=2, n=40)
    base = _feats(X, T, U, "S6_context")
    order = np.argsort(T[:, -1], kind="stable")
    for j in order[-5:]:                              # perturb the 5 latest rows individually
        X2 = X.copy(); X2[j] = X2[j] * 100 + 3
        f = _feats(X2, T, U, "S6_context")
        same = np.all((base == f) | (np.isnan(base) & np.isnan(f)), axis=1)
        earlier = T[:, -1] < T[j, -1]
        assert same[earlier & (U == U[j])].all() and same[U != U[j]].all()


@pytest.mark.parametrize("variant", list(F5.VARIANTS))
def test_row_order_invariance(variant):
    X, T, U = _series(n_units=2, n=30)
    if variant == "S0_stacked41":
        pass
    a = _feats(X, T, U, variant)
    p = np.random.default_rng(3).permutation(len(X))
    b = _feats(X[p], T[p], U[p], variant)
    inv = np.empty_like(p); inv[p] = np.arange(len(p))
    assert np.array_equal(a, b[inv], equal_nan=True)


def test_no_label_argument_anywhere():
    for fn in (F5.build_features, F5.causal_context, F5.temporal_block, F5.context_block, F5.window_matrix, F5.stack_blocks):
        assert not any(("label" in p or "infiltration" in p or "stage" in p) for p in inspect.signature(fn).parameters)


def test_variant_column_counts_and_dropped_groups():
    X, T, U = _series(n_units=1, n=20)
    f0, n0 = F5.build_features(X, NAMES, "S0_stacked41")
    assert f0.shape[1] == 41 * 6
    f1, n1 = F5.build_features(X, NAMES, "S1_no_zero9")
    assert f1.shape[1] == 32 * 6 and not any(z in n for n in n1 for z in F5.ZERO9)
    f2, n2 = F5.build_features(X, NAMES, "S2_no_ident")
    assert f2.shape[1] == 17 * 6
    assert not any(c in n for n in n2 for c in F5.IDENT)
    f7, n7 = F5.build_features(X, NAMES, "S7_relative", T=T, ctx=F5.causal_context(F5.vol_last_log(X[:, -1], NAMES), U, T[:, -1]))
    assert "last:flow_count" not in n7 and "max:flow_count" not in n7 and "std:flow_count" in n7 and "cz:flow_count" in n7
    with pytest.raises(ValueError):
        F5.build_features(X, NAMES, "S6_context", T=T)       # context required


def test_ablation_removes_flow_count_everywhere():
    X, T, U = _series(n_units=1, n=25)
    Xa = F5.ablate_feature(X, NAMES, ["flow_count"], np.array([10.0]))
    ctx = F5.causal_context(F5.vol_last_log(Xa[:, -1], NAMES), U, T[:, -1], window=20, min_periods=4)
    f, n = F5.build_features(Xa, NAMES, "S6_context", T=T, ctx=ctx)
    for name in ("last:flow_count", "mean:flow_count", "tz:flow_count", "tslope:flow_count", "spike_count"):
        j = n.index(name)
        assert np.nanstd(f[:, j]) < 1e-5, name
    j = n.index("cz:flow_count")
    assert np.nanmax(np.abs(f[:, j])) < 1e-4
