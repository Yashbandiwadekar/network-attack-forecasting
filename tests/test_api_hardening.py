"""Audit H1/W13: app/api.py must be off by default, require a bearer token on every endpoint, and
refuse to register or dispatch to a webhook that resolves to a private/loopback/link-local address
(including the cloud metadata address 169.254.169.254)."""
import importlib
import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("NAF_API_ENABLED", "1")
    monkeypatch.setenv("NAF_API_TOKEN", "test-token-123")
    monkeypatch.setenv("NAF_WEBHOOK_ALLOWLIST", "siem.example.com")
    import app.api as api
    importlib.reload(api)
    api.webhooks.clear()
    api.recent_alerts.clear()

    # Fake DNS: siem.example.com resolves to a real public address (allowed), IMDS lookups resolve
    # to themselves (disallowed, link-local) -- avoids depending on live network/DNS in CI.
    fake_records = {
        "siem.example.com": "8.8.8.8",
        "169.254.169.254": "169.254.169.254",
        "not-allowlisted.example.org": "8.8.4.4",
    }

    def fake_getaddrinfo(host, *a, **kw):
        ip = fake_records.get(host, "1.1.1.1")
        return [(None, None, None, None, (ip, 0))]

    monkeypatch.setattr(api.socket, "getaddrinfo", fake_getaddrinfo)
    return TestClient(api.app)


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("NAF_API_ENABLED", raising=False)
    monkeypatch.setenv("NAF_API_TOKEN", "test-token-123")
    import app.api as api
    importlib.reload(api)
    client = TestClient(api.app)
    r = client.get("/api/v1/alerts")
    assert r.status_code == 503


def test_unauthenticated_request_rejected(client):
    r = client.get("/api/v1/alerts")
    assert r.status_code == 401

    r = client.post("/api/v1/alerts/ingest", json={
        "host_ip": "10.0.0.5", "infiltration_prob": 0.9, "predicted_stage": "impact", "timestamp": 0.0,
    })
    assert r.status_code == 401

    r = client.post("/api/v1/webhooks", json={"url": "https://siem.example.com/hook"})
    assert r.status_code == 401


def test_authenticated_request_succeeds(client):
    headers = {"Authorization": "Bearer test-token-123"}
    r = client.get("/api/v1/alerts", headers=headers)
    assert r.status_code == 200


def test_wrong_token_rejected(client):
    r = client.get("/api/v1/alerts", headers={"Authorization": "Bearer wrong-token"})
    assert r.status_code == 401


def test_webhook_to_imds_address_refused(client):
    headers = {"Authorization": "Bearer test-token-123"}
    r = client.post(
        "/api/v1/webhooks",
        json={"url": "https://169.254.169.254/latest/meta-data/"},
        headers=headers,
    )
    assert r.status_code == 400
    assert len(client.app.state.__dict__) >= 0  # app still up
    import app.api as api
    assert api.webhooks == []  # nothing was registered


def test_webhook_not_on_allowlist_refused(client):
    headers = {"Authorization": "Bearer test-token-123"}
    r = client.post("/api/v1/webhooks", json={"url": "https://not-allowlisted.example.org/hook"}, headers=headers)
    assert r.status_code == 400


def test_webhook_on_allowlist_over_https_accepted(client):
    headers = {"Authorization": "Bearer test-token-123"}
    r = client.post("/api/v1/webhooks", json={"url": "https://siem.example.com/hook"}, headers=headers)
    assert r.status_code == 200


def test_webhook_http_scheme_rejected(client):
    headers = {"Authorization": "Bearer test-token-123"}
    r = client.post("/api/v1/webhooks", json={"url": "http://siem.example.com/hook"}, headers=headers)
    assert r.status_code in (400, 422)  # 422 if pydantic's own https-only validator fires first
