"""Contract tests for two additive API surfaces.

1. `observed_history` on POST /api/v1/forecast/predict: the host's input windows with the stage
   observed in each (or "Unlabelled" -- never an invented stage), plus runs of equal stages.
2. GET /api/v1/demo/scenarios and POST /api/v1/demo/load: manifest-listed server-side demo files,
   loaded through the upload ingest path. Fixtures only: the real demo CSVs are gitignored and are
   not needed here.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pandas as pd
import pytest
from fastapi.testclient import TestClient

import app.server as server
from app.server import STATE, app
from pipeline.mitre_mapping import STAGE_CLASSIFICATION_LABELS

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_CSV = PROJECT_ROOT / "data" / "raw" / "flows" / "synthetic_sample.csv"
V2 = "configs/real_data_v2_converged_seed1.yaml"
needs_sample = pytest.mark.skipif(not SAMPLE_CSV.exists(), reason="synthetic sample not present")


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("PHOENIX_REQUIRE_AUTH", "0")
    return TestClient(app)


@pytest.fixture
def restore_state():
    saved = (STATE.config_path, STATE.dataset_id)
    STATE.config_path, STATE.dataset_id = V2, "CIC-IDS-2018-v2"
    yield
    STATE.config_path, STATE.dataset_id = saved
    STATE.reset_data()


def _upload(client: TestClient, path: Path) -> dict:
    with path.open("rb") as fh:
        resp = client.post("/api/v1/analysis/upload", files={"file": (path.name, fh, "text/csv")})
    assert resp.status_code == 200, resp.text
    return resp.json()


def _predict(client: TestClient) -> dict:
    ip = client.get("/api/v1/forecast/hosts").json()["hosts"][0]["host_ip"]
    resp = client.post("/api/v1/forecast/predict", json={"host_ip": ip})
    assert resp.status_code == 200, resp.text
    return resp.json()


def _assert_runs_consistent(hist: dict) -> None:
    wins, runs = hist["windows"], hist["runs"]
    assert len(wins) == 12                                   # sequence_length of the served model
    assert sum(r["n_windows"] for r in runs) == len(wins)
    assert sum(r["flow_count"] for r in runs) == sum(w["flow_count"] for w in wins)
    for a, b in zip(runs, runs[1:]):                         # consecutive runs differ: really collapsed
        assert (a["stage_id"], a["may_be_heuristic"]) != (b["stage_id"], b["may_be_heuristic"])
    assert runs[0]["from"] == wins[0]["window_start"] and runs[-1]["to"] == wins[-1]["window_end"]
    assert [w["window_start"] for w in wins] == sorted(w["window_start"] for w in wins)


# ---------------------------------------------------------------- observed_history

@needs_sample
def test_observed_history_labelled_upload(client, restore_state):
    _upload(client, SAMPLE_CSV)
    pred = _predict(client)
    hist = pred["observed_history"]
    assert hist["observed"] is True and pred["current_stage_observed"] is True
    _assert_runs_consistent(hist)
    project_stages = set(STAGE_CLASSIFICATION_LABELS)
    for w in hist["windows"]:
        assert w["stage_observed"] is True and w["stage_id"] in project_stages
    assert "Execution" not in {r["stage"] for r in hist["runs"]}
    # the last run is the host's current observed stage, same semantics as current_stage
    assert hist["runs"][-1]["stage"] == pred["current_stage"]


@needs_sample
def test_observed_history_unlabelled_upload(client, restore_state, tmp_path):
    unl = tmp_path / "unlabelled.csv"
    pd.read_csv(SAMPLE_CSV).drop(columns=["Label"]).to_csv(unl, index=False)
    _upload(client, unl)
    pred = _predict(client)
    hist = pred["observed_history"]
    assert pred["current_stage_observed"] is False
    assert hist["observed"] is False
    _assert_runs_consistent(hist)
    assert [r["stage"] for r in hist["runs"]] == ["Unlabelled"]      # one run, nothing invented
    assert all(w["stage_id"] is None and w["stage_observed"] is False for w in hist["windows"])
    assert all(w["stage"] != "Benign" for w in hist["windows"])


def test_observed_history_collapses_runs_and_flags_recon(restore_state):
    t0 = pd.Timestamp("2018-03-02 10:00:00")
    stages = ["benign", "benign", "reconnaissance", "command_and_control", "command_and_control", "impact"]
    STATE.windows = pd.DataFrame({
        "src_ip": ["h"] * 6, "window_start": [t0 + pd.Timedelta(seconds=10 * i) for i in range(6)],
        "stage": stages, "stage_observed": True, "flow_count": [1, 2, 3, 4, 5, 6],
    })
    cfg = {"windowing": {"sequence_length": 5, "window_seconds": 10}}
    hist = server._observed_history("h", cfg)
    assert len(hist["windows"]) == 5                       # only the last `sequence_length` windows
    assert [(r["stage_id"], r["n_windows"], r["flow_count"]) for r in hist["runs"]] == [
        ("benign", 1, 2), ("reconnaissance", 1, 3), ("command_and_control", 2, 9), ("impact", 1, 6)]
    assert [r["may_be_heuristic"] for r in hist["runs"]] == [False, True, False, False]
    assert hist["runs"][0]["from"] == "2018-03-02T10:00:10" and hist["runs"][-1]["to"] == "2018-03-02T10:01:00"


def test_observed_history_empty_without_data(restore_state):
    STATE.windows = None
    hist = server._observed_history("h", {"windowing": {"sequence_length": 12, "window_seconds": 10}})
    assert hist == {"observed": False, "window_seconds": 10, "windows": [], "runs": []}


# ---------------------------------------------------------------- demo scenarios

def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


@pytest.fixture
def demo_dir(tmp_path, monkeypatch):
    d = tmp_path / "demo"
    d.mkdir()
    monkeypatch.setattr(server, "DEMO_DIR", d)
    monkeypatch.setattr(server, "DEMO_MANIFEST", d / "demo_manifest.json")
    return d


def _write_manifest(demo_dir: Path, scenarios: list[dict]) -> None:
    (demo_dir / "demo_manifest.json").write_text(json.dumps({"scenarios": scenarios}), encoding="utf-8")


def _entry(demo_dir: Path, sid: str = "tiny", **over) -> dict:
    f = demo_dir / f"{sid}.csv"
    if not f.exists():
        shutil.copy(SAMPLE_CSV, f)
    e = {"id": sid, "title": "Tiny", "description": "fixture", "scenario": "benign", "file": f.name,
         "format": "csv", "size_bytes": f.stat().st_size, "size_mb": 0.1, "sha256": _sha(f),
         "source": {"dataset": "fixture", "day": "n/a", "file": "source-day.csv"},
         "split_tag": "n/a", "label_mix": {}, "expected_behaviour": {"verdict": "n/a", "text": "x"},
         "measured": {"peak_prob": 0.5}}
    e.update(over)
    return e


def test_demo_scenarios_empty_when_no_manifest(client, demo_dir):
    body = client.get("/api/v1/demo/scenarios").json()
    assert body["scenarios"] == [] and body["message"]


@needs_sample
def test_demo_scenarios_listing_has_no_paths(client, demo_dir):
    _write_manifest(demo_dir, [_entry(demo_dir), _entry(demo_dir, "gone", file="gone.csv", size_bytes=5)])
    body = client.get("/api/v1/demo/scenarios").json()
    by_id = {s["id"]: s for s in body["scenarios"]}
    assert by_id["tiny"]["available"] is True and by_id["gone"]["available"] is False
    assert "file" not in by_id["tiny"] and "sha256" not in by_id["tiny"] and "size_bytes" not in by_id["tiny"]
    assert str(demo_dir) not in json.dumps(body) and "tiny.csv" not in json.dumps(body)


@needs_sample
def test_demo_load_works_like_an_upload(client, demo_dir, restore_state):
    _write_manifest(demo_dir, [_entry(demo_dir)])
    resp = client.post("/api/v1/demo/load", json={"id": "tiny"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "success" and body["scenario_id"] == "tiny" and body["hosts_scored"] >= 1
    assert body["filename"] == "tiny.csv"
    hosts = client.get("/api/v1/forecast/hosts").json()
    assert hosts["data_source"] == "tiny.csv" and hosts["hosts"]
    assert _predict(client)["observed_history"]["runs"]
    # identical to uploading the same bytes
    up = _upload(client, demo_dir / "tiny.csv")
    for k in ("extracted_flows", "windows", "hosts_scored", "new_host_ip"):
        assert up[k] == body[k]
    assert (demo_dir / "tiny.csv").read_bytes() == SAMPLE_CSV.read_bytes()   # read in place, untouched


def test_demo_load_unknown_id_is_404(client, demo_dir):
    _write_manifest(demo_dir, [])
    assert client.post("/api/v1/demo/load", json={"id": "nope"}).status_code == 404
    assert client.post("/api/v1/demo/load", json={"id": "../../etc/passwd"}).status_code == 404
    assert client.post("/api/v1/demo/load", json={}).status_code == 422


@needs_sample
def test_demo_load_sha_mismatch_is_refused(client, demo_dir, restore_state):
    _write_manifest(demo_dir, [_entry(demo_dir, sha256="0" * 64)])
    resp = client.post("/api/v1/demo/load", json={"id": "tiny"})
    assert resp.status_code == 422 and "checksum" in resp.json()["detail"]
    assert STATE.batch is None                                  # nothing was ingested


@needs_sample
def test_demo_load_tampered_file_is_refused(client, demo_dir, restore_state):
    _write_manifest(demo_dir, [_entry(demo_dir)])
    with (demo_dir / "tiny.csv").open("ab") as fh:
        fh.write(b"\n")
    assert client.post("/api/v1/demo/load", json={"id": "tiny"}).status_code == 422


@needs_sample
def test_demo_load_rejects_traversal_and_missing_file(client, demo_dir, tmp_path, restore_state):
    outside = tmp_path / "outside.csv"
    shutil.copy(SAMPLE_CSV, outside)
    _write_manifest(demo_dir, [
        _entry(demo_dir, "t1", file="../outside.csv", sha256=_sha(outside)),
        _entry(demo_dir, "t2", file=str(outside), sha256=_sha(outside)),
        _entry(demo_dir, "t3", file="missing.csv"),
    ])
    for sid in ("t1", "t2", "t3"):
        assert client.post("/api/v1/demo/load", json={"id": sid}).status_code == 404, sid


@needs_sample
def test_demo_load_refused_while_live_is_active(client, demo_dir, monkeypatch):
    _write_manifest(demo_dir, [_entry(demo_dir)])
    monkeypatch.setattr(server.LIVE, "active", lambda: True)
    resp = client.post("/api/v1/demo/load", json={"id": "tiny"})
    assert resp.status_code == 409 and "live" in resp.json()["detail"].lower()
