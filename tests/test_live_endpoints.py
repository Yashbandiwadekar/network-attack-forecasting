"""docs/09 A3: /api/v1/live/* endpoints, control-endpoint protection, state ownership while live."""
import os
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.server as server
from app.server import LIVE, STATE, app
from tests.live_fixtures import dense_pcap

LOCAL = ("127.0.0.1", 50001)
REMOTE = ("192.168.50.77", 50002)


@pytest.fixture(scope="module")
def pcap_dir(tmp_path_factory):
    d = tmp_path_factory.mktemp("replaydir")
    dense_pcap(d / "dense.pcap", seconds=200)
    return d


@pytest.fixture(autouse=True)
def _clean(monkeypatch, pcap_dir, tmp_path):
    for v in ("PHOENIX_REQUIRE_AUTH", "PHOENIX_API_TOKEN", "PHOENIX_LAB_CIDR", "PHOENIX_LIVE_IGNORE_PORTS"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("PHOENIX_REPLAY_DIR", str(pcap_dir))
    ledger = tmp_path / "ledger.jsonl"
    monkeypatch.setattr(server, "_ledger_path", lambda: ledger)
    LIVE.stop()
    STATE.reset_data()
    yield ledger
    LIVE.stop()
    STATE.reset_data()


def local():
    return TestClient(app, client=LOCAL)


def remote():
    return TestClient(app, client=REMOTE)


def wait_finished(c, timeout=90):
    t0 = time.time()
    while time.time() - t0 < timeout:
        st = c.get("/api/v1/live/status").json()
        if st.get("finished") or st.get("error"):
            return st
        time.sleep(0.2)
    raise AssertionError("replay did not finish")


def test_status_is_off_before_anything_runs():
    st = local().get("/api/v1/live/status").json()
    assert st["state"] == "OFF" and st["mode"] == "OFF"


def test_status_readable_from_remote_but_control_is_not(pcap_dir):
    r = remote()
    assert r.get("/api/v1/live/status").status_code == 200
    body = {"path": str(pcap_dir / "dense.pcap"), "speed": 0}
    assert r.post("/api/v1/live/replay", json=body).status_code == 403
    assert r.post("/api/v1/live/start", json={}).status_code == 403
    assert r.post("/api/v1/live/stop").status_code == 403
    assert not LIVE.active()
    # the client-controlled header must not be believed
    forged = TestClient(app, client=REMOTE, headers={"X-Forwarded-For": "127.0.0.1"})
    assert forged.post("/api/v1/live/replay", json=body).status_code == 403


def test_replay_path_must_be_inside_an_allowed_directory(pcap_dir, tmp_path):
    c = local()
    outside = tmp_path / "secret.pcap"
    outside.write_bytes(b"x")
    assert c.post("/api/v1/live/replay", json={"path": str(outside)}).status_code == 403
    assert c.post("/api/v1/live/replay", json={"path": str(pcap_dir / ".." / "x.pcap")}).status_code == 403
    assert c.post("/api/v1/live/replay", json={"path": "C:/Windows/System32/drivers/etc/hosts"}).status_code == 403
    assert c.post("/api/v1/live/replay", json={"path": str(pcap_dir / "missing.pcap")}).status_code == 404
    assert c.post("/api/v1/live/replay", json={"path": str(pcap_dir / "dense.pcap"), "speed": -1}).status_code == 422
    assert not LIVE.active()


def test_replay_populates_the_dashboard_state_and_owns_it(pcap_dir, _clean):
    c = local()
    r = c.post("/api/v1/live/replay", json={"path": str(pcap_dir / "dense.pcap"), "speed": 0})
    assert r.status_code == 200 and r.json()["status"] == "started"
    assert c.post("/api/v1/live/replay", json={"path": str(pcap_dir / "dense.pcap"), "speed": 0}).status_code == 409
    st = wait_finished(c)
    assert st["error"] is None and st["state"] == "REPLAY" and st["finished"]
    for key in ("source", "packets_per_s", "flows_per_s", "windows_processed", "hosts_warming_up", "hosts_scored",
                "last_window_time", "lag_seconds", "dropped", "alert_threshold", "stale_after_s"):
        assert key in st
    assert st["source"] == "REPLAY:dense.pcap" and st["hosts_scored"] >= 5 and st["windows_processed"] > 100

    hosts = c.get("/api/v1/forecast/hosts").json()
    assert hosts["data_source"] == "REPLAY:dense.pcap" and hosts["live_state"] == "REPLAY"
    row = hosts["hosts"][0]
    assert row["current_stage"] == "Unlabelled" and row["current_stage_observed"] is False
    assert row["input_contiguous"] in (True, False) and "provisional" in row and "alert" in row
    # host-scoped endpoints work on live state
    assert c.post("/api/v1/forecast/predict", json={"host_ip": row["host_ip"]}).status_code == 200

    # state is owned: uploads and model switches are refused, nothing is written to the ledger
    assert c.post("/api/v1/analysis/upload", files={"file": ("x.csv", b"a,b\n1,2\n", "text/csv")}).status_code == 409
    assert c.post("/api/v1/datasets/select", json={"dataset_id": "CIC-IDS-2018"}).status_code == 409
    assert not _clean.exists()

    stopped = c.post("/api/v1/live/stop").json()
    assert stopped["status"] == "stopped" and stopped["state"] == "OFF"
    assert c.get("/api/v1/forecast/hosts").json()["hosts"] == []
    assert c.post("/api/v1/live/stop").json()["status"] == "not_running"


def test_control_requires_the_bearer_token_when_auth_is_on(monkeypatch, pcap_dir):
    monkeypatch.setenv("PHOENIX_REQUIRE_AUTH", "1")
    monkeypatch.setenv("PHOENIX_API_TOKEN", "s3cret")
    c = local()
    body = {"path": str(pcap_dir / "dense.pcap"), "speed": 0}
    assert c.post("/api/v1/live/replay", json=body).status_code == 401
    assert c.post("/api/v1/live/replay", json=body, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.get("/api/v1/live/status").status_code == 401
    ok = c.post("/api/v1/live/replay", json=body, headers={"Authorization": "Bearer s3cret"})
    assert ok.status_code == 200


def test_live_tail_endpoint_reads_a_ring_directory(monkeypatch, tmp_path):
    ring = tmp_path / "ring"
    ring.mkdir()
    dense_pcap(ring / "ring_00001.pcap", seconds=60)
    old = time.time() - 600
    os.utime(ring / "ring_00001.pcap", (old, old))
    monkeypatch.setenv("PHOENIX_LIVE_DIR", str(ring))
    c = local()
    assert c.post("/api/v1/live/start", json={}).status_code == 200
    t0 = time.time()
    st = {}
    while time.time() - t0 < 30:
        st = c.get("/api/v1/live/status").json()
        if st.get("packets_total", 0) > 0:
            break
        time.sleep(0.2)
    assert st["mode"] == "LIVE" and st["source"] == "LIVE:ring" and st["packets_total"] > 0
    assert st["ignored_ports"] == [8000]      # the dashboard's own port is never scored in LIVE mode
    assert c.post("/api/v1/live/stop").status_code == 200


def test_live_start_without_a_directory_is_a_clear_409(monkeypatch):
    monkeypatch.delenv("PHOENIX_LIVE_DIR", raising=False)
    assert local().post("/api/v1/live/start", json={}).status_code == 409


def test_a_stopped_session_cannot_write_into_state_afterwards(pcap_dir):
    """stop() joins for a limited time; a thread stuck in a long read must not publish old data later."""
    import numpy as np
    from pipeline.fast_packet_windows import read_all_frames
    c = local()
    assert c.post("/api/v1/live/replay", json={"path": str(pcap_dir / "dense.pcap"), "speed": 1}).status_code == 200
    old = LIVE.live
    time.sleep(1.0)
    assert c.post("/api/v1/live/stop").status_code == 200
    assert not LIVE.active() and STATE.batch is None
    cols = read_all_frames(pcap_dir / "dense.pcap")
    m = cols["ts"] < cols["ts"].min() + 130
    old.ingest({k: v[m] for k, v in cols.items()})        # the zombie thread's next tick
    assert STATE.batch is None and STATE.windows is None and STATE.source_name is None
