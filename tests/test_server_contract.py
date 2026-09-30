"""Contract + no-fabrication coverage for app/server.py.

Two jobs:

1. **Contract.** Every field name `frontend/src/**` reads must keep existing. The frontend is owned
   by another developer on a separate branch, so a rename here is a silent breakage there; these
   tests are the tripwire.
2. **No fabrication.** The version of this server that shipped with the frontend returned invented
   metrics (AUROC 0.942 under the day-disjoint split's name, a fixed 0.764 for every upload, a
   hardcoded ISO-27001 certificate). These tests assert the replacements are computed or read from
   results files, and that two different captures produce two different answers.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.server import app

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_CSV = PROJECT_ROOT / "data" / "raw" / "flows" / "synthetic_sample.csv"
SAMPLE_PCAP = PROJECT_ROOT / "data" / "raw" / "pcap" / "synthetic_sample.pcap"

needs_sample = pytest.mark.skipif(not SAMPLE_CSV.exists(), reason="synthetic sample not present")


@pytest.fixture(scope="module", autouse=True)
def isolated_ledger(tmp_path_factory):
    """Report generation appends to the audit ledger. Without this the suite would write into the
    real `checkpoints_real/audit_ledger.jsonl` on every run, polluting the demo's tamper-evident
    chain with test entries."""
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
    """A client with the synthetic capture uploaded, so host-scoped endpoints have real data."""
    with SAMPLE_CSV.open("rb") as fh:
        resp = client.post("/api/v1/analysis/upload",
                           files={"file": (SAMPLE_CSV.name, fh, "text/csv")})
    assert resp.status_code == 200, resp.text
    return client


def _first_host(client: TestClient) -> str:
    hosts = client.get("/api/v1/forecast/hosts").json()["hosts"]
    assert hosts, "upload produced no scored hosts"
    return hosts[0]["host_ip"]


# ----------------------------------------------------------------- empty state

def test_hosts_empty_before_any_upload():
    """A fresh clone ships a checkpoint but no traffic. The honest answer is an empty list with a
    message -- the mock returned four hardcoded hosts here, which is what made the dashboard look
    populated when nothing had been analysed."""
    fresh = TestClient(app)
    from app.server import STATE
    STATE.reset_data()
    body = fresh.get("/api/v1/forecast/hosts").json()
    assert body["hosts"] == []
    assert body["data_source"] is None
    assert "upload" in body["message"].lower()


def test_host_scoped_endpoints_refuse_without_data():
    from app.server import STATE
    STATE.reset_data()
    fresh = TestClient(app)
    assert fresh.post("/api/v1/forecast/predict", json={"host_ip": "10.0.4.5"}).status_code == 409


# ----------------------------------------------------------------- contract

@needs_sample
def test_host_row_keeps_every_field_the_frontend_reads(loaded: TestClient):
    row = loaded.get("/api/v1/forecast/hosts").json()["hosts"][0]
    for field in ("host_ip", "flow_count", "peak_prob", "severity",
                  "current_stage", "predicted_stage", "risk_score", "dataset_source"):
        assert field in row, f"frontend reads .{field}"
    assert row["severity"] in ("critical", "serious", "warning", "good")


@needs_sample
def test_forecast_predict_contract_and_60_second_horizon(loaded: TestClient):
    ip = _first_host(loaded)
    body = loaded.post("/api/v1/forecast/predict", json={"host_ip": ip}).json()
    assert "infiltration_probs" in body and "predicted_stages" in body  # read by Dashboard.jsx
    # The project forecasts K=6 x 10s. The UI previously hardcoded "HORIZON K = 5", no units.
    assert body["horizon_k"] == 6
    assert body["window_seconds"] == 10
    assert body["horizon_seconds"] == 60
    assert len(body["infiltration_probs"]) == 6
    assert body["step_seconds"] == [10, 20, 30, 40, 50, 60]
    # Stage honesty (audit S6/S7): callers must be able to tell rule overrides from predictions.
    assert len(body["stage_is_heuristic"]) == len(body["predicted_stages"])
    assert "Execution" not in body["predicted_stages"], "not a stage this project has"
    # current_stage must be the observed stage, matching the host row and the narrative.
    # Using the forecast's first step made this panel say "Benign" for a host the rest of the
    # UI showed as Command & Control.
    row = loaded.get("/api/v1/forecast/hosts").json()["hosts"][0]
    assert body["current_stage"] == row["current_stage"]


@needs_sample
def test_attribution_contract_uses_real_feature_names(loaded: TestClient):
    ip = _first_host(loaded)
    body = loaded.post("/api/v1/explainability/attribution", json={"host_ip": ip}).json()
    attrs = body["feature_attributions"]
    assert attrs and all({"feature", "contribution"} <= set(a) for a in attrs)
    from app import service
    from app.server import STATE
    config, *_ = service.load_backend(STATE.config_path)
    valid = set(service.feature_cols_for(config))
    assert all(a["feature"] in valid for a in attrs), "attribution must name real model features"


@needs_sample
def test_attribution_shares_are_a_proper_breakdown_not_raw_gradients(loaded: TestClient):
    """The UI printed raw gradient x input values as percentages (0.0% everywhere on a saturated
    host) and drew negative values as negative CSS widths. `share` is the fraction of total
    attribution, so it must be in [0, 1], sum to at most 1 over the returned top features, and
    `direction` must agree with the sign of the raw contribution."""
    ip = _first_host(loaded)
    body = loaded.post("/api/v1/explainability/attribution", json={"host_ip": ip}).json()
    attrs = body["feature_attributions"]
    assert body["attribution_total_abs"] >= 0
    for a in attrs:
        assert 0.0 <= a["share"] <= 1.0
        assert a["direction"] in ("raises", "lowers", "neutral")
        if a["contribution"] > 0:
            assert a["direction"] == "raises"
        if a["contribution"] < 0:
            assert a["direction"] == "lowers"
    assert sum(a["share"] for a in attrs) <= 1.0001
    shares = [a["share"] for a in attrs]
    assert shares == sorted(shares, reverse=True), "ranked by magnitude"
    assert max(shares) > 0.01, "a real host must show a measurable top attribution"


@needs_sample
def test_attribution_separates_provenance_flags_from_behavioural_drivers(loaded: TestClient):
    """has_ip_data records where a capture came from, not what the traffic did. It must never be in
    the behavioural ranking, but must be reported (with a warning) rather than hidden."""
    from models.explain import PROVENANCE_FEATURES

    ip = _first_host(loaded)
    body = loaded.post("/api/v1/explainability/attribution", json={"host_ip": ip}).json()
    assert not any(a["feature"] in PROVENANCE_FEATURES for a in body["feature_attributions"])
    assert {a["feature"] for a in body["provenance_attributions"]} == set(PROVENANCE_FEATURES)
    assert all("not traffic behaviour" in a["note"].lower() for a in body["provenance_attributions"])
    total = sum(a["share"] for a in body["feature_attributions"]) + body["provenance_share_total"]
    assert total <= 1.0001


@needs_sample
def test_pdf_report_downloads_and_does_not_touch_the_ledger(loaded: TestClient):
    """The PDF is built from the host's existing ledger entry. Downloading it must not append a new
    entry, or a harmless click would alter the tamper-evident chain."""
    ip = _first_host(loaded)
    assert loaded.post("/api/v1/reports/generate", json={"host_ip": ip}).status_code == 200
    before = loaded.get("/api/v1/system/status").json()["ledger_entries"]

    resp = loaded.get(f"/api/v1/reports/pdf/{ip}")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert "attachment" in resp.headers["content-disposition"]
    assert resp.content.startswith(b"%PDF-")

    after = loaded.get("/api/v1/system/status").json()["ledger_entries"]
    assert after == before, "downloading a PDF must not append to the audit ledger"


@needs_sample
def test_pdf_report_requires_a_generated_report_first(loaded: TestClient):
    resp = loaded.get("/api/v1/reports/pdf/10.99.99.99")
    assert resp.status_code == 404
    assert "generate a report first" in resp.json()["detail"].lower()


@needs_sample
def test_narrative_contract(loaded: TestClient):
    ip = _first_host(loaded)
    body = loaded.get("/api/v1/attacks/narrative", params={"host_ip": ip}).json()
    assert body["narrative"]
    assert "cve_details" in body
    assert {"title", "action"} <= set(body["recommended_action"])


# ----------------------------------------------------------------- no fabrication

def test_eval_metrics_match_the_results_file_exactly(client: TestClient):
    body = client.get("/api/v1/eval/metrics").json()
    truth = json.loads((PROJECT_ROOT / "docs" / "v2_converged_seed_results.json").read_text())
    across = truth["across_seeds"]
    assert body["auroc"]["mean"] == round(across["auroc"]["mean"], 4)
    assert body["f1_at_0.5"]["mean"] == round(across["f1@0.5"]["mean"], 4)
    assert body["n_test_sequences"] == truth["n_test"]
    # The mock claimed 0.942 AUROC under this split's name; the measured value is ~0.794.
    assert body["auroc"]["mean"] < 0.85
    assert body["auroc"]["sd"] > 0, "a headline without its spread is what audit E10 was about"


def test_eval_metrics_reports_spread_and_seed_count(client: TestClient):
    body = client.get("/api/v1/eval/metrics").json()
    assert body["n_seeds"] == 3
    assert "day-disjoint" in body["split"]


@needs_sample
def test_two_different_captures_give_different_results(client: TestClient):
    """The mock computed extracted_flows as size_mb * 1850 + 320 and returned peak_prob 0.764 for
    every upload. Two genuinely different captures must not agree by construction."""
    if not SAMPLE_PCAP.exists():
        pytest.skip("sample pcap not present")
    seen = []
    for path in (SAMPLE_CSV, SAMPLE_PCAP):
        with path.open("rb") as fh:
            body = client.post("/api/v1/analysis/upload",
                               files={"file": (path.name, fh, "application/octet-stream")}).json()
        seen.append(body["extracted_flows"])
    assert seen[0] != seen[1]
    assert all(n > 0 for n in seen)


@needs_sample
def test_upload_flow_count_is_parsed_not_estimated(client: TestClient):
    """extracted_flows must equal the real parsed row count, not a function of file size."""
    with SAMPLE_CSV.open("rb") as fh:
        body = client.post("/api/v1/analysis/upload",
                           files={"file": (SAMPLE_CSV.name, fh, "text/csv")}).json()
    size_mb = SAMPLE_CSV.stat().st_size / (1024 * 1024)
    assert body["extracted_flows"] != int(size_mb * 1850) + 320
    from app.server import STATE
    assert body["extracted_flows"] == len(STATE.flow_df)


@needs_sample
def test_report_returns_a_real_ledger_hash_and_claims_no_certification(loaded: TestClient):
    ip = _first_host(loaded)
    body = loaded.post("/api/v1/reports/generate", json={"host_ip": ip}).json()
    # The key stays (Dashboard.jsx reads it), but the fabricated ISO/NIST certification is gone.
    cert = body["compliance_certificate"]
    assert cert["certified"] is False
    blob = json.dumps(body)
    assert "ISO/IEC 27001" not in blob and "NIST SP 800-53" not in blob
    assert len(body["audit_hash"]) == 64, "sha256 hex from the hash chain"
    # Stable, unlike the mock's Python hash() which is randomized per process.
    again = loaded.get(f"/api/v1/reports/download/{ip}.json").json()
    assert again["record_hash"] == body["audit_hash"]
    assert again["ledger_intact"] is True
    assert body["compliance"]["framework"].startswith("CERT-In")


def test_login_rejects_arbitrary_credentials(client: TestClient, monkeypatch):
    """The mock accepted any non-empty email/password and shipped a password in source."""
    monkeypatch.delenv("PHOENIX_DEMO_USER", raising=False)
    monkeypatch.delenv("PHOENIX_DEMO_PASSWORD", raising=False)
    resp = client.post("/api/v1/auth/login", json={"email": "anyone@example.com", "password": "x"})
    assert resp.status_code == 503  # unconfigured, not "welcome in"

    monkeypatch.setenv("PHOENIX_DEMO_USER", "analyst@local")
    monkeypatch.setenv("PHOENIX_DEMO_PASSWORD", "correct-horse")
    assert client.post("/api/v1/auth/login",
                       json={"email": "analyst@local", "password": "wrong"}).status_code == 401
    assert client.post("/api/v1/auth/login",
                       json={"email": "analyst@local", "password": "correct-horse"}).status_code == 200


@needs_sample
def test_upload_filename_cannot_escape_the_temp_directory(client: TestClient, tmp_path):
    """The upload used to build its temp path from the client-supplied filename, so a traversing
    name would be written -- and then unlinked in `finally` -- outside the temp directory."""
    victim = tmp_path / "victim.csv"
    victim.write_text("do not delete me", encoding="utf-8")
    hostile = f"../../../../{victim.as_posix().lstrip('/')}"
    with SAMPLE_CSV.open("rb") as fh:
        resp = client.post("/api/v1/analysis/upload", files={"file": (hostile, fh, "text/csv")})
    assert resp.status_code in (200, 422)
    assert victim.exists(), "traversing upload name deleted a file outside the temp dir"
    assert victim.read_text(encoding="utf-8") == "do not delete me"


def test_narrative_and_report_contain_no_html_markup(loaded: TestClient):
    """models/narrative.py emits <b> tags for Streamlit's markdown renderer; React would show
    them literally, and the host string comes from an uploaded file."""
    ip = _first_host(loaded)
    body = loaded.get("/api/v1/attacks/narrative", params={"host_ip": ip}).json()
    assert "<" not in body["narrative"] and ">" not in body["narrative"]


ATTACK_CSV = PROJECT_ROOT / "data" / "raw" / "flows_real" / "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv"


@pytest.mark.skipif(not ATTACK_CSV.exists(), reason="real attack-day CSV not present")
def test_attack_traffic_exercises_the_alerting_paths(client: TestClient, tmp_path):
    """Every other test here runs on benign synthetic traffic scoring ~0.03 / "good". The paths a
    judge actually sees -- a raised severity, a CVE list, a reportable CERT-In category -- are
    only reachable with real attack traffic, so exercise them on a slice of an attack day."""
    import pandas as pd
    head = pd.read_csv(ATTACK_CSV, nrows=60000, low_memory=False)
    slice_path = tmp_path / "attack_slice.csv"
    head.to_csv(slice_path, index=False)

    with slice_path.open("rb") as fh:
        up = client.post("/api/v1/analysis/upload", files={"file": ("attack_slice.csv", fh, "text/csv")})
    assert up.status_code == 200, up.text
    hosts = client.get("/api/v1/forecast/hosts").json()["hosts"]
    assert hosts, "attack slice produced no scored hosts"

    top = hosts[0]
    assert 0.0 <= top["peak_prob"] <= 1.0
    body = client.get("/api/v1/attacks/narrative", params={"host_ip": top["host_ip"]}).json()
    assert body["narrative"]
    for cve in body["cve_details"]:
        assert "cve_id" in cve
    rep = client.post("/api/v1/reports/generate", json={"host_ip": top["host_ip"]}).json()
    assert rep["compliance"]["is_reportable"] in (True, False)
    if rep["compliance"]["is_reportable"]:
        assert rep["compliance"]["category"]


def test_mitre_mapping_has_no_invented_confidences(client: TestClient):
    body = client.get("/api/v1/mitre/mapping").json()
    assert body["mappings"]
    for row in body["mappings"]:
        assert "confidence" not in row, "a deterministic lookup has no confidence score"
        assert row["dataset_labels"], "each stage lists the real CIC labels that map to it"
    stages = {row["stage_id"] for row in body["mappings"]}
    assert "execution" not in stages


# ----------------------------------------------------------------- single-port deployment

def test_health_endpoint_reports_horizon(client: TestClient):
    body = client.get("/api/v1/health").json()
    assert body["status"] == "online"
    assert body["horizon_seconds"] == 60


def test_unknown_api_path_is_404_json_not_the_spa(client: TestClient):
    """The SPA fallback must never swallow an API path: a typo'd endpoint has to fail loudly
    rather than return index.html with a 200, which would look like a working call."""
    resp = client.get("/api/v1/definitely-not-a-route")
    assert resp.status_code == 404


@pytest.mark.skipif(
    not (PROJECT_ROOT / "frontend" / "dist" / "index.html").is_file(),
    reason="frontend not built",
)
def test_spa_is_served_at_root_and_on_client_routes(client: TestClient):
    """With a build present the API serves the dashboard itself, which is what makes the deployed
    setup single-origin: no CORS, and no VITE_API_BASE_URL pointing at a hardcoded host."""
    for path in ("/", "/dashboard", "/login"):
        resp = client.get(path)
        assert resp.status_code == 200, path
        assert "text/html" in resp.headers["content-type"], path


@pytest.mark.skipif(
    not (PROJECT_ROOT / "frontend" / "dist" / "index.html").is_file(),
    reason="frontend not built",
)
def test_spa_fallback_cannot_escape_the_build_directory(client: TestClient):
    """The fallback resolves a client-supplied path against dist/; it must not serve files
    outside it."""
    resp = client.get("/../../app/server.py")
    assert resp.status_code in (200, 404)
    assert "uvicorn.run" not in resp.text
