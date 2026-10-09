"""Docs/07 prerequisites T1 and T2.

T1: the day-disjoint v2 checkpoint is the default served model, v1 stays selectable, a missing
checkpoint/scaler fails loudly, and the active model is reported by the API.

T2: input with no ground-truth labels (CSV without a Label column, PCAP) must report its observed
stage as unknown ("Unlabelled", current_stage_observed=False), not the BENIGN placeholder that the
windowing code needs in order to run.
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest
from fastapi.testclient import TestClient

import app.server as server
from app import service
from app.server import (
    DEFAULT_CONFIG, STATE, ModelUnavailableError, _State, app, check_model_artifacts,
    resolve_config_choice,
)
from common.config import load_config
from pipeline.flow_features import csv_has_label_column

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_CSV = PROJECT_ROOT / "data" / "raw" / "flows" / "synthetic_sample.csv"
SAMPLE_PCAP = PROJECT_ROOT / "data" / "raw" / "pcap" / "synthetic_sample.pcap"
V1 = "configs/real_data.yaml"
V2 = "configs/real_data_v2_converged.yaml"

needs_sample = pytest.mark.skipif(not SAMPLE_CSV.exists(), reason="synthetic sample not present")


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("PHOENIX_REQUIRE_AUTH", "0")
    return TestClient(app)


@pytest.fixture
def restore_state():
    saved = (STATE.config_path, STATE.dataset_id)
    yield
    STATE.config_path, STATE.dataset_id = saved
    STATE.reset_data()


# ------------------------------------------------------------------ T1: model selection

def test_default_model_is_the_v2_day_disjoint_checkpoint(monkeypatch):
    monkeypatch.delenv("PHOENIX_CONFIG", raising=False)
    assert DEFAULT_CONFIG == V2
    assert resolve_config_choice() == V2
    fresh = _State()
    assert fresh.config_path == V2
    assert fresh.dataset_id == "CIC-IDS-2018-v2"


@pytest.mark.parametrize("choice, expected", [
    ("v1", V1), ("V2", V2), (V1, V1), ("configs/real_data_v2_converged.yaml", V2),
])
def test_env_var_selects_model(monkeypatch, choice, expected):
    monkeypatch.setenv("PHOENIX_CONFIG", choice)
    assert resolve_config_choice() == expected
    assert _State().config_path == expected


def test_explicit_choice_beats_env(monkeypatch):
    monkeypatch.setenv("PHOENIX_CONFIG", "v1")
    assert resolve_config_choice("v2") == V2


def test_unknown_config_fails_loudly(monkeypatch):
    monkeypatch.setenv("PHOENIX_CONFIG", "configs/does_not_exist.yaml")
    with pytest.raises(ModelUnavailableError, match="does_not_exist"):
        _State()


def _config_with_paths(tmp_path: Path, make_ckpt: bool, make_scaler: bool) -> str:
    cfg = tmp_path / "cfg.yaml"
    ckpt_dir, proc_dir = tmp_path / "ckpt", tmp_path / "proc"
    ckpt_dir.mkdir()
    proc_dir.mkdir()
    if make_ckpt:
        (ckpt_dir / "world_model_best.pt").write_bytes(b"x")
    if make_scaler:
        (proc_dir / "scaler.npz").write_bytes(b"x")
    cfg.write_text(
        f"paths:\n  checkpoint_dir: {ckpt_dir.as_posix()}\n  processed_dir: {proc_dir.as_posix()}\n",
        encoding="utf-8",
    )
    return str(cfg)


def test_missing_checkpoint_and_scaler_are_named_in_the_error(tmp_path):
    with pytest.raises(ModelUnavailableError) as exc:
        check_model_artifacts(_config_with_paths(tmp_path, make_ckpt=False, make_scaler=False))
    assert "checkpoint" in str(exc.value) and "scaler" in str(exc.value)


def test_missing_scaler_only_is_reported(tmp_path):
    with pytest.raises(ModelUnavailableError, match="scaler") as exc:
        check_model_artifacts(_config_with_paths(tmp_path, make_ckpt=True, make_scaler=False))
    assert "checkpoint" not in str(exc.value).split("missing", 1)[1].split("Train", 1)[0]


def test_present_artifacts_pass_for_v1_and_v2():
    check_model_artifacts(V1)
    check_model_artifacts(V2)


def test_startup_refuses_a_model_with_no_checkpoint(restore_state, tmp_path):
    STATE.config_path = _config_with_paths(tmp_path, make_ckpt=False, make_scaler=True)
    with pytest.raises(ModelUnavailableError):
        with TestClient(app):  # entering the context runs the lifespan startup
            pass


def test_health_and_status_report_the_active_model(client, restore_state):
    STATE.config_path = V2
    health = client.get("/api/v1/health").json()
    assert health["config_path"] == V2
    assert health["model_name"] == "real_data_v2_converged"
    assert health["checkpoint_dir"] == "checkpoints_real_v2_converged"
    status = client.get("/api/v1/system/status").json()
    assert status["model_name"] == "real_data_v2_converged"

    STATE.config_path = V1
    assert client.get("/api/v1/health").json()["model_name"] == "real_data"


def test_both_cic_models_are_selectable_through_the_registry(client, restore_state):
    ids = {d["id"]: d for d in client.get("/api/v1/datasets").json()["datasets"]}
    assert ids["CIC-IDS-2018"]["config"] == V1 and ids["CIC-IDS-2018-v2"]["config"] == V2
    assert ids["CIC-IDS-2018-v2"]["can_forecast"] is True
    assert ids["CIC-IDS-2018-v2"]["features"] == 41
    res = client.post("/api/v1/datasets/select", json={"dataset_id": "CIC-IDS-2018-v2"})
    assert res.status_code == 200 and STATE.config_path == V2
    res = client.post("/api/v1/datasets/select", json={"dataset_id": "CIC-IDS-2018"})
    assert res.status_code == 200 and STATE.config_path == V1


def test_v2_scaler_width_matches_the_checkpoint_features():
    config, model, scaler, _ = service.load_backend(V2)
    assert model is not None and scaler is not None
    assert len(service.feature_cols_for(config)) == 41


# ------------------------------------------------------------------ T2: unlabelled observed stage

def _unlabelled_csv(tmp_path: Path) -> Path:
    df = pd.read_csv(SAMPLE_CSV)
    out = tmp_path / "unlabelled.csv"
    df.drop(columns=["Label"]).to_csv(out, index=False)
    return out


@needs_sample
def test_csv_label_column_detection(tmp_path):
    assert csv_has_label_column(SAMPLE_CSV) is True
    assert csv_has_label_column(_unlabelled_csv(tmp_path)) is False


@needs_sample
def test_process_uploads_marks_stage_observed(tmp_path):
    config = load_config(V2)
    _, labelled = service.process_uploads(SAMPLE_CSV, None, config)
    assert labelled["stage_observed"].all()
    _, unlabelled = service.process_uploads(_unlabelled_csv(tmp_path), None, config)
    assert not unlabelled["stage_observed"].any()


def _upload(client: TestClient, path: Path) -> None:
    with path.open("rb") as fh:
        resp = client.post("/api/v1/analysis/upload",
                           files={"file": (path.name, fh, "application/octet-stream")})
    assert resp.status_code == 200, resp.text


def _assert_unlabelled_everywhere(client: TestClient) -> None:
    hosts = client.get("/api/v1/forecast/hosts").json()["hosts"]
    assert hosts, "upload produced no scored hosts"
    for h in hosts:
        assert h["current_stage_observed"] is False
        assert h["current_stage"] == "Unlabelled"
        assert h["current_stage_id"] is None
        assert h["current_stage"] != "Benign"
    ip = hosts[0]["host_ip"]
    pred = client.post("/api/v1/forecast/predict", json={"host_ip": ip}).json()
    assert pred["current_stage_observed"] is False
    assert pred["current_stage"] == "Unlabelled"
    narrative = client.get("/api/v1/attacks/narrative", params={"host_ip": ip}).json()["narrative"]
    assert "currently classified as" not in narrative


@needs_sample
def test_unlabelled_csv_reports_observed_stage_unknown(client, tmp_path, restore_state):
    STATE.config_path, STATE.dataset_id = V2, "CIC-IDS-2018-v2"
    _upload(client, _unlabelled_csv(tmp_path))
    _assert_unlabelled_everywhere(client)


@pytest.mark.skipif(not SAMPLE_PCAP.exists(), reason="sample pcap not present")
def test_pcap_reports_observed_stage_unknown(client, restore_state):
    STATE.config_path, STATE.dataset_id = V2, "CIC-IDS-2018-v2"
    _upload(client, SAMPLE_PCAP)
    _assert_unlabelled_everywhere(client)


@needs_sample
def test_labelled_csv_still_reports_observed_stage(client, restore_state):
    STATE.config_path, STATE.dataset_id = V2, "CIC-IDS-2018-v2"
    _upload(client, SAMPLE_CSV)
    hosts = client.get("/api/v1/forecast/hosts").json()["hosts"]
    assert hosts
    for h in hosts:
        assert h["current_stage_observed"] is True
        assert h["current_stage_id"] is not None
        assert h["current_stage"] != "Unlabelled"


def test_observed_stage_unit_without_marker_keeps_old_behaviour(restore_state):
    """Windows frames built elsewhere (no stage_observed column) are treated as labelled."""
    STATE.windows = pd.DataFrame({"src_ip": ["a"], "stage": ["command_and_control"]})
    assert server._observed_stage("a") == "command_and_control"
    STATE.windows = pd.DataFrame({"src_ip": ["a"], "stage": ["benign"], "stage_observed": [False]})
    assert server._observed_stage("a") is None
