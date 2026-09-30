"""Competitive-parity item 5 (2026-09-30): simulated (not real) device-isolation action.

Three things must hold:
1. The literal word "SIMULATED" appears in the LEDGER entry itself, not just the API response --
   so reading the ledger alone is enough to know this was never real.
2. The API response also says plainly that no real network/firewall change was made.
3. No function reachable from this endpoint touches real network state (no subprocess, no
   firewall/iptables call, no socket-level action) -- grep-based, same pattern as
   tests/test_api_hardening.py's SSRF checks.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.server import app

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_CSV = PROJECT_ROOT / "data" / "raw" / "flows" / "synthetic_sample.csv"

needs_sample = pytest.mark.skipif(not SAMPLE_CSV.exists(), reason="synthetic sample not present")


@pytest.fixture()
def isolated_ledger(tmp_path):
    import app.server as server
    ledger_file = tmp_path / "audit_ledger.jsonl"
    original = server._ledger_path
    server._ledger_path = lambda: ledger_file
    yield ledger_file
    server._ledger_path = original


@pytest.fixture()
def loaded(isolated_ledger) -> TestClient:
    client = TestClient(app)
    with SAMPLE_CSV.open("rb") as fh:
        resp = client.post("/api/v1/analysis/upload",
                           files={"file": (SAMPLE_CSV.name, fh, "text/csv")})
    assert resp.status_code == 200, resp.text
    return client


def _first_host(client: TestClient) -> str:
    hosts = client.get("/api/v1/forecast/hosts").json()["hosts"]
    assert hosts, "upload produced no scored hosts"
    return hosts[0]["host_ip"]


@needs_sample
def test_response_says_simulated_not_real(loaded: TestClient):
    ip = _first_host(loaded)
    body = loaded.post("/api/v1/response/simulate-isolation", json={"host_ip": ip}).json()
    assert body["status"] == "simulated"
    assert "no real" in body["note"].lower()
    assert "audit_hash" in body


@needs_sample
def test_ledger_entry_contains_the_literal_word_simulated(loaded: TestClient, isolated_ledger):
    ip = _first_host(loaded)
    loaded.post("/api/v1/response/simulate-isolation", json={"host_ip": ip})
    lines = isolated_ledger.read_text(encoding="utf-8").strip().splitlines()
    assert lines, "ledger file must have gained an entry"
    last = json.loads(lines[-1])
    assert "SIMULATED" in last["recommended_action"]


def test_refuses_without_data():
    from app.server import STATE
    STATE.reset_data()
    fresh = TestClient(app)
    resp = fresh.post("/api/v1/response/simulate-isolation", json={"host_ip": "10.0.4.5"})
    assert resp.status_code == 409


def test_no_real_network_or_process_action_in_the_endpoint():
    """Grep-based: the endpoint's own function body must not call subprocess, os.system, socket,
    or any firewall/iptables-shaped name -- a real network action here would contradict its own
    'simulated' claim."""
    source = Path(PROJECT_ROOT / "app" / "server.py").read_text(encoding="utf-8")
    fn_start = source.index("def simulate_isolation")
    next_def = source.index("\n@app.", fn_start)
    fn_body = source[fn_start:next_def]
    forbidden = ["subprocess", "os.system", "socket.", "iptables", "firewall_cmd", "netsh", "ufw "]
    hits = [f for f in forbidden if f in fn_body]
    assert hits == [], f"simulate_isolation must not touch real network/process state, found: {hits}"
