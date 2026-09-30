"""Competitive-parity item 4 (2026-09-30): counterfactual what-if rollout.

Same fixtures/pattern as tests/test_server_contract.py.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.server import app

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_CSV = PROJECT_ROOT / "data" / "raw" / "flows" / "synthetic_sample.csv"

needs_sample = pytest.mark.skipif(not SAMPLE_CSV.exists(), reason="synthetic sample not present")


@pytest.fixture(scope="module", autouse=True)
def isolated_ledger(tmp_path_factory):
    import app.server as server
    ledger_file = tmp_path_factory.mktemp("ledger") / "audit_ledger.jsonl"
    original = server._ledger_path
    server._ledger_path = lambda: ledger_file
    yield
    server._ledger_path = original


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture(scope="module")
def loaded(client: TestClient) -> TestClient:
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
def test_what_if_features_lists_curated_and_all(loaded: TestClient):
    body = loaded.get("/api/v1/forecast/what-if/features").json()
    assert body["curated_features"], "at least one curated feature must survive against the real config"
    assert all({"feature", "label"} <= set(f) for f in body["curated_features"])
    assert set(f["feature"] for f in body["curated_features"]) <= set(body["all_features"])


@needs_sample
def test_what_if_zeroing_a_feature_changes_the_forecast(loaded: TestClient):
    ip = _first_host(loaded)
    feature = loaded.get("/api/v1/forecast/what-if/features").json()["curated_features"][0]["feature"]
    body = loaded.post("/api/v1/forecast/what-if",
                       json={"host_ip": ip, "feature": feature, "scale": 0.0}).json()
    assert body["feature"] == feature
    assert len(body["baseline_infiltration_probs"]) == len(body["counterfactual_infiltration_probs"])
    assert body["probability_delta"] == [
        round(c - b, 4) for b, c in zip(body["baseline_infiltration_probs"], body["counterfactual_infiltration_probs"])
    ]
    assert "caveat" in body and "not" in body["caveat"].lower()


@needs_sample
def test_what_if_unknown_feature_rejected(loaded: TestClient):
    ip = _first_host(loaded)
    resp = loaded.post("/api/v1/forecast/what-if",
                       json={"host_ip": ip, "feature": "not_a_real_feature", "scale": 0.0})
    assert resp.status_code == 400


def test_what_if_refuses_without_data():
    from app.server import STATE
    STATE.reset_data()
    fresh = TestClient(app)
    resp = fresh.post("/api/v1/forecast/what-if",
                      json={"host_ip": "10.0.4.5", "feature": "flow_count", "scale": 0.0})
    assert resp.status_code == 409


def test_what_if_indexes_columns_via_feature_columns_not_by_hand():
    """Grep-based, same pattern as tests/test_feature_schema_guard.py: the what-if endpoint must
    look up its column index from feature_cols_for(config)/feature_columns(config), never a
    hand-picked integer, or it becomes a fifth instance of the audit W19 schema-drift bug class."""
    result = subprocess.run(
        ["git", "grep", "-n", "-A3", "def what_if_forecast", "--", "app/server.py"],
        cwd=PROJECT_ROOT, capture_output=True, text=True,
    )
    source = Path(PROJECT_ROOT / "app" / "server.py").read_text(encoding="utf-8")
    fn_start = source.index("def what_if_forecast")
    fn_body = source[fn_start:fn_start + 1500]
    assert "feature_cols_for(config)" in fn_body or "feature_columns(config)" in fn_body
    assert "feature_cols.index(req.feature)" in fn_body
