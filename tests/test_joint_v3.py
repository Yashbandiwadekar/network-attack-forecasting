"""docs/15 helpers: B+ dataset merge, t+1 metrics with block bootstrap, CIC-2017 adapter caveat text."""
from __future__ import annotations

import numpy as np
import pytest

from eval.joint_v3_eval import auc_ap, block_ids, t1_metrics
from pipeline.adapters.cicids2017_adapter import CICIDS2017Adapter


def test_block_ids_cut_by_host_and_size():
    ips = np.array(["a"] * 5 + ["b"] * 3)
    t = np.arange(8).astype("datetime64[s]").astype("datetime64[ns]")
    order, ids = block_ids(ips, t, block=2)
    assert list(ids) == [0, 0, 1, 1, 2, 3, 3, 4]
    # shuffled input is re-ordered by (host, time)
    perm = np.array([7, 0, 3, 1, 6, 2, 5, 4])
    order2, ids2 = block_ids(ips[perm], t[perm], block=2)
    assert list(ips[perm][order2]) == list(ips)
    assert list(ids2) == list(ids)


def test_auc_ap_degenerate_returns_none():
    assert auc_ap(np.zeros(4), np.random.rand(4)) == (None, None)
    assert auc_ap(np.ones(4), np.random.rand(4)) == (None, None)


def test_t1_metrics_perfect_and_ci_contains_point():
    rng = np.random.default_rng(0)
    n = 400
    y = (rng.random(n) < 0.3).astype(np.float32)
    p = np.where(y > 0, 0.9, 0.1) + rng.normal(0, 0.01, n)
    ips = np.array(["h%d" % (i // 100) for i in range(n)])
    t = (np.arange(n) % 100).astype("datetime64[s]").astype("datetime64[ns]")
    r = t1_metrics(y, p, ips, t, B=50, block=20)
    assert r["auroc"] == pytest.approx(1.0)
    assert r["n"] == n and r["n_positive"] == int(y.sum()) and r["n_hosts"] == 4
    lo, hi = r["auroc_ci95_block_bootstrap"]
    assert lo <= r["auroc"] <= hi
    assert r["at_0.5"]["recall"] == pytest.approx(1.0)


def test_cic2017_caveats_not_stale():
    text = " ".join(CICIDS2017Adapter.caveats)
    assert "Owner must decide the mapping" not in text
    assert "no entry in mitre_mapping" not in text
    assert "Monday" in text and "ZERO sequences" in text


def test_build_joint_v3_appends_monday_to_train_only(tmp_path, monkeypatch):
    import scripts.build_joint_v3 as bj
    from common.config import load_config

    cfg_path = "configs/joint_v3_Bplus.yaml"
    cfg = load_config(cfg_path)
    L, K, F = 12, 6, len(bj.feature_columns(cfg))

    def seqs(n, day, ip):
        t0 = np.datetime64(day + "T10:00:00", "ns")
        wt = t0 + (np.arange(n)[:, None] + np.arange(L)[None, :]) * np.timedelta64(10, "s")
        return {"X": np.ones((n, L, F), np.float32), "next_state": np.ones((n, F), np.float32),
                "future_stages": np.zeros((n, K), np.int64), "infiltration": np.zeros((n, K), np.float32),
                "current_stage": np.zeros(n, np.int64), "current_infiltration": np.zeros(n, np.float32),
                "window_end_time": wt[:, -1], "window_times": wt, "src_ip": np.array([ip] * n)}

    base = tmp_path / "base"
    base.mkdir()
    for name, n, day in (("train", 5, "2018-02-14"), ("val", 3, "2018-02-15"), ("test", 4, "2018-02-16")):
        np.savez(base / f"{name}.npz", **seqs(n, day, "NETWORK"))
    (base / "metadata.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(bj, "_unit_windows", lambda *a, **k: (seqs(7, "2017-07-03", "10.0.0.1"), {}, {"BENIGN": 7}, {"flows": 7}))
    monkeypatch.setattr(bj, "check_out_dir", lambda out, force=False: out)
    out = tmp_path / "out"
    meta = bj.build(base, out, cfg_path, tmp_path / "Monday.csv", log=lambda *_: None)
    assert meta["splits"] == {"train": 12, "val": 3, "test": 4}
    tr = np.load(out / "train.npz")
    assert tr["X"].shape[0] == 12 and set(np.unique(tr["src_ip"])) == {"NETWORK", "10.0.0.1"}
    assert list(tr["window_end_time"]) == sorted(tr["window_end_time"])
    assert np.load(out / "test.npz")["X"].shape[0] == 4


def test_build_joint_v3_refuses_non_benign_monday(tmp_path, monkeypatch):
    import scripts.build_joint_v3 as bj
    from pipeline.adapters.prepare import PrepareError
    monkeypatch.setattr(bj, "check_out_dir", lambda out, force=False: out)
    monkeypatch.setattr(bj, "_unit_windows", lambda *a, **k: ({}, {}, {"BENIGN": 1, "Bot": 1}, {}))
    with pytest.raises(PrepareError):
        bj.build(tmp_path, tmp_path / "o", "configs/joint_v3_Bplus.yaml", tmp_path / "m.csv", log=lambda *_: None)


def test_detections_table_shifts_window_and_thresholds():
    from eval.joint_v3_detections import detections_table
    stages = ["benign", "reconnaissance", "initial_access", "lateral_movement", "command_and_control", "exfiltration"]
    sp = np.array([[0.9, 0.0, 0.05, 0.0, 0.05, 0.0], [0.1, 0.0, 0.1, 0.0, 0.8, 0.0]])
    p = np.array([0.2, 0.7])
    last = np.array(["2017-07-07T10:00:00", "2017-07-07T10:01:00"], dtype="datetime64[ns]")
    df = detections_table(p, sp, np.array(["1.1.1.1", "2.2.2.2"]), last, 60, stages, 0.4)
    assert list(df.stage) == ["benign", "command_and_control"]
    assert str(df.window_start.iloc[0]) == "2017-07-07 10:01:00"
    # benign column never chosen even when it has the highest probability and p is above threshold
    df2 = detections_table(np.array([0.9]), np.array([[0.9, 0, 0.05, 0.03, 0.02, 0]]), np.array(["h"]), last[:1], 10, stages, 0.4)
    assert df2.stage.iloc[0] == "initial_access"


def test_lofo_v3_fold_days_drop_fabricated_benign_days_and_stay_disjoint():
    from eval.lofo import FAMILY_DAYS
    from eval.lofo_v3 import fold_days_v3
    for fam in FAMILY_DAYS:
        d = fold_days_v3(fam)
        every = sum(d.values(), [])
        assert not {"04-01", "04-02"} & set(every)
        assert len(every) == len(set(every))
        assert d["test"] == FAMILY_DAYS[fam]
        assert d["train"] and d["val"]
