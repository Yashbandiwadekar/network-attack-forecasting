"""prepare_dataset: output guard, split policy, layout, and equivalence with pipeline.build_dataset."""
from __future__ import annotations

import os

os.environ.setdefault("CUDA_VISIBLE_DEVICES", "-1")

import json

import numpy as np
import pandas as pd
import pytest
import yaml

from common.config import PROJECT_ROOT, feature_columns, load_config
from models.dataset import load_metadata, load_split
from pipeline.adapters import prepare as P
from scripts import prepare_dataset as cli
from tests.adapter_fixtures import write_cic, write_ctu

CFG = "configs/default.yaml"


def _quiet(*_a, **_k):
    return None


# ---- output-directory guard -------------------------------------------------------------------
@pytest.mark.parametrize("rel", [
    "data/processed", "data/processed/ctu13/final_splits", "data/processed_real_v2", "data/processed_real_v2/x",
    "data/processed_unsw_v2", "checkpoints", "checkpoints_real_v2_converged/sub", "configs", "data/raw",
    "data/raw/flows_real/x", "data", ".",
])
def test_out_dir_guard_refuses_protected_paths(rel):
    with pytest.raises(P.PrepareError, match="overlaps"):
        P.check_out_dir(PROJECT_ROOT / rel)


def test_out_dir_guard_allows_processed_adapter_and_tmp(tmp_path):
    target = PROJECT_ROOT / "data" / "processed_adapter" / "brand_new_xyz"
    assert P.check_out_dir(target) == target.resolve()
    assert not target.exists()                                   # the guard alone creates nothing
    assert P.check_out_dir(tmp_path / "new") == (tmp_path / "new").resolve()


def test_out_dir_guard_refuses_non_empty_and_force_only_for_own_dirs(tmp_path):
    d = tmp_path / "o"
    d.mkdir()
    (d / "f.txt").write_text("x")
    with pytest.raises(P.PrepareError, match="not empty"):
        P.check_out_dir(d)
    with pytest.raises(P.PrepareError, match="not empty"):
        P.check_out_dir(d, force=True)                           # not created by this tool
    (d / "metadata.json").write_text(json.dumps({"tool": "scripts.prepare_dataset"}))
    assert P.check_out_dir(d, force=True) == d.resolve()


def test_auto_assign_fills_all_three_and_is_chronological():
    a = P.auto_assign({"a": 50, "b": 30, "c": 10, "d": 10}, 0.7, 0.15)
    assert a["train"] and a["val"] and a["test"]
    assert sum(a.values(), []) == ["a", "b", "c", "d"]
    with pytest.raises(P.PrepareError):
        P.auto_assign({"a": 1, "b": 1}, 0.7, 0.15)


# ---- end to end -------------------------------------------------------------------------------
def test_prepare_single_file_layout_loads_with_real_loader(tmp_path):
    src = write_cic(tmp_path / "raw" / "sample.csv", n=500, reduced=True, step_s=7)
    out = tmp_path / "out"
    meta = P.prepare_dataset(src.parent, out, CFG, log=_quiet)
    cfg = load_config(CFG)
    assert meta["feature_columns"] == feature_columns(cfg) and len(meta["feature_columns"]) == 41
    for s in ("train", "val", "test"):
        d = load_split(out, s)                                   # allow_pickle=False loader
        assert d["X"].shape[1:] == (12, 41) and d["next_state"].shape[1] == 41
        assert np.isfinite(d["X"]).all()
    assert load_metadata(out)["splits"] == meta["splits"]
    assert (out / "window_graphs.pkl").exists() and (out / "config.yaml").exists()
    assert meta["split_mode"] == "chronological" and meta["adapter"]["name"] == "synthetic"
    assert meta["mitre_mapping"]["sha256"] and meta["label_mapping"]["Benign"]["stage"] == "benign"
    derived = yaml.safe_load((out / "config.yaml").read_text())
    assert derived["paths"]["processed_dir"] == str(out.resolve())
    assert derived["windowing"] == cfg["windowing"] and derived["features"] == cfg["features"]
    assert "unit_assumptions" in meta and "caveat" in meta and meta["packet_features_available"] is False


def _three_days(raw):
    for i, d in enumerate(["2018-02-14", "2018-02-15", "2018-02-16"]):
        write_cic(raw / f"day{i}.csv", n=900, ip=False, step_s=4, start=f"{d} 08:00:00", attack_block=(300, 500), seed=i)


def test_prepare_no_ip_days_default_to_day_disjoint_split(tmp_path):
    raw = tmp_path / "raw"
    _three_days(raw)
    out = tmp_path / "out"
    meta = P.prepare_dataset(raw, out, CFG, log=_quiet)
    assert meta["split_mode"] == "by_day" and meta["split_mode_source"].startswith("adapter default")
    a = meta["split_assignment"]
    assert set(a) == {"train", "val", "test"}
    days = {}
    for s in ("train", "val", "test"):
        d = load_split(out, s)
        days[s] = set(pd.to_datetime(d["window_end_time"]).strftime("%m-%d"))
    assert not (days["train"] & days["val"]) and not (days["train"] & days["test"]) and not (days["val"] & days["test"])
    assert any("AUTO-assigned" in w for w in meta["warnings"])
    assert all(v for v in meta["positive_rate_next_step"].values())


def test_prepare_explicit_split_lists_and_chronological_warning(tmp_path):
    raw = tmp_path / "raw"
    _three_days(raw)
    meta = P.prepare_dataset(raw, tmp_path / "o1", CFG, train_units=["02-14"], val_units=["02-15"],
                             test_units=["02-16"], log=_quiet)
    assert meta["split_assignment"] == {"train": ["02-14"], "val": ["02-15"], "test": ["02-16"]}
    meta2 = P.prepare_dataset(raw, tmp_path / "o2", CFG, split="chronological", log=_quiet)
    assert any("E1" in w for w in meta2["warnings"])             # per-host chronological on pseudo-hosts is flagged


def test_prepare_ctu_scenarios_split_by_unit(tmp_path):
    raw = tmp_path / "ctu"
    for sc in (1, 2, 3):
        write_ctu(raw / str(sc) / f"capture{sc}.binetflow", n=700, seed=sc)
    meta = P.prepare_dataset(raw, tmp_path / "o", CFG, log=_quiet)
    assert meta["split_mode"] == "by_unit"
    d = {s: load_split(tmp_path / "o", s) for s in ("train", "val", "test")}
    sets = {s: set(np.unique(d[s]["scenario_id"]).tolist()) for s in d}
    assert sets["train"].isdisjoint(sets["val"]) and sets["train"].isdisjoint(sets["test"])
    assert sets["val"].isdisjoint(sets["test"]) and all(sets[s] for s in sets)


def test_prepare_refuses_fallthrough_stub_and_experimental(tmp_path):
    raw = tmp_path / "ctu"
    write_ctu(raw / "1" / "c.binetflow", n=800, with_unknown=100)
    with pytest.raises(P.PrepareError, match="NO explicit stage mapping"):
        P.prepare_dataset(raw, tmp_path / "o", CFG, log=_quiet)
    nf = tmp_path / "nf"
    nf.mkdir()
    (nf / "a.csv").write_text("IPV4_SRC_ADDR,L4_SRC_PORT,IPV4_DST_ADDR,L4_DST_PORT,PROTOCOL,IN_BYTES,IN_PKTS,Label,Attack\n"
                              "a,1,b,2,6,1,1,0,Benign\n")
    with pytest.raises(P.PrepareError, match="stub"):
        P.prepare_dataset(nf, tmp_path / "o2", CFG, log=_quiet)
    with pytest.raises(P.PrepareError, match="experimental"):
        P.prepare_dataset(raw, tmp_path / "o3", CFG, adapter_name="cicids2017", log=_quiet)


def test_cli_returns_2_on_protected_out_dir(tmp_path, capsys):
    rc = cli.main([str(tmp_path), "--out", str(PROJECT_ROOT / "data" / "processed_real_v2"), "--config", CFG])
    assert rc == 2
    assert "overlaps" in capsys.readouterr().err


def test_max_rows_per_file_caps_input(tmp_path):
    src = write_cic(tmp_path / "raw" / "s.csv", n=1500, reduced=True, step_s=5)
    meta = P.prepare_dataset(src.parent, tmp_path / "o", CFG, max_rows_per_file=600, log=_quiet)
    assert meta["units"]["all"]["flows"] <= 600 and meta["max_rows_per_file"] == 600


# ---- the wrapping proof ---------------------------------------------------------------------------
RAW = PROJECT_ROOT / "data" / "raw" / "flows"


@pytest.mark.skipif(not (RAW / "synthetic_sample.csv").exists(), reason="synthetic sample not on disk")
def test_prepare_equals_pipeline_build_dataset_on_synthetic_sample(tmp_path, monkeypatch):
    from pipeline.build_dataset import build_dataset
    ref = tmp_path / "ref"
    monkeypatch.setenv("PHOENIX_PROCESSED_DIR", str(ref))
    monkeypatch.setenv("PHOENIX_RAW_FLOW_DIR", str(RAW))
    monkeypatch.delenv("PHOENIX_DATA_DIR", raising=False)
    build_dataset(CFG)
    out = tmp_path / "mine"
    P.prepare_dataset(RAW, out, CFG, log=_quiet)
    for s in ("train", "val", "test"):
        a, b = load_split(ref, s), load_split(out, s)
        assert a.keys() == b.keys()
        for k in a:
            assert np.array_equal(a[k], b[k]), (s, k)
