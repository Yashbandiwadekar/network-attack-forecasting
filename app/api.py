"""Optional, ONLINE SIEM/SOAR webhook integration (audit H1/W13).

This is not part of the offline demo. The project's core claim ("everything runs offline, no
network calls at inference time" -- README) is about `models/`, `pipeline/`, `app/service.py`
and `app/server.py`; this module is a separate, opt-in component that a deployer can run
alongside the offline system to relay alerts to an external SIEM/SOAR, and it never starts by
accident:

  - Off by default: `uvicorn app.api:app` refuses to boot unless the environment variable
    `NAF_API_ENABLED=1` is set (see `_require_enabled` below), so importing this module or running
    it under the test suite never opens a socket.
  - Every endpoint requires a bearer token, read from `NAF_API_TOKEN` (env, never a module
    global or a request field) and compared with `hmac.compare_digest`.
  - Webhook URLs are validated against `NAF_WEBHOOK_ALLOWLIST` (comma-separated host[:port]
    entries, env) before being registered AND again before every dispatch (defends a
    TOCTOU/DNS-rebinding change between registration and send). Anything that resolves to a
    private, loopback, link-local, or multicast address -- including the IMDS address
    169.254.169.254 -- is refused, closing the SSRF path H1 described.

Original functionality (register a webhook, ingest an alert, poll recent alerts) is unchanged;
only the trust boundary changed.
"""
from __future__ import annotations

import hmac
import ipaddress
import os
import socket
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, field_validator

app = FastAPI(
    title="SIEM/SOAR Integration API",
    description="Optional online webhook relay for forecast alerts. Disabled unless NAF_API_ENABLED=1.",
    version="1.1.0",
)

_api_key_header = APIKeyHeader(name="Authorization", auto_error=False)


def _require_enabled() -> None:
    if os.environ.get("NAF_API_ENABLED") != "1":
        raise HTTPException(
            status_code=503,
            detail="This API is disabled by default (audit H1). Set NAF_API_ENABLED=1 to run it.",
        )


def _require_token(authorization: str | None = Security(_api_key_header)) -> None:
    _require_enabled()
    expected = os.environ.get("NAF_API_TOKEN")
    if not expected:
        raise HTTPException(status_code=503, detail="NAF_API_TOKEN is not configured; refusing all requests.")
    presented = (authorization or "").removeprefix("Bearer ").strip()
    if not presented or not hmac.compare_digest(presented, expected):
        raise HTTPException(status_code=401, detail="Missing or invalid bearer token.")


def _allowlisted_hosts() -> set[str]:
    raw = os.environ.get("NAF_WEBHOOK_ALLOWLIST", "")
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def _is_disallowed_address(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable -- refuse rather than guess
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
        or ip.is_reserved or ip.is_unspecified
    )


def _validate_webhook_url(url: str) -> None:
    """Audit H1: reject anything but https to an explicitly allowlisted host, and reject a host
    that resolves to a private/loopback/link-local/multicast/reserved address -- including the
    cloud metadata address 169.254.169.254, which is link-local and so already covered."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise HTTPException(status_code=400, detail="Webhook URL must use https.")
    host = parsed.hostname
    if not host:
        raise HTTPException(status_code=400, detail="Webhook URL has no host.")
    allowlist = _allowlisted_hosts()
    if not allowlist:
        raise HTTPException(status_code=503, detail="NAF_WEBHOOK_ALLOWLIST is not configured; refusing all webhooks.")
    if host.lower() not in allowlist:
        raise HTTPException(status_code=400, detail=f"Host {host!r} is not in NAF_WEBHOOK_ALLOWLIST.")
    try:
        resolved = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except socket.gaierror as e:
        raise HTTPException(status_code=400, detail=f"Could not resolve webhook host: {e}") from e
    if not resolved or any(_is_disallowed_address(ip) for ip in resolved):
        raise HTTPException(status_code=400, detail=f"Host {host!r} resolves to a disallowed (private/internal) address.")


# In-memory alert store (for demo purposes) -- process-local, cleared on restart.
recent_alerts = []


class ForecastAlert(BaseModel):
    host_ip: str
    infiltration_prob: float
    predicted_stage: str
    timestamp: float


class WebhookConfig(BaseModel):
    url: str
    auth_token: Optional[str] = None

    @field_validator("url")
    @classmethod
    def _https_only(cls, v: str) -> str:
        if not v.lower().startswith("https://"):
            raise ValueError("webhook url must start with https://")
        return v


# Configured webhooks (re-validated at dispatch time too, not just at registration).
webhooks: List[WebhookConfig] = []


def dispatch_webhook(alert: dict, webhook: WebhookConfig) -> None:
    import requests  # imported lazily so `NAF_API_ENABLED=0` environments need not have it installed

    try:
        _validate_webhook_url(webhook.url)
    except HTTPException as e:
        print(f"Refusing to dispatch to {webhook.url}: {e.detail}")
        return
    headers = {"Content-Type": "application/json"}
    if webhook.auth_token:
        headers["Authorization"] = f"Bearer {webhook.auth_token}"
    try:
        requests.post(webhook.url, json=alert, headers=headers, timeout=5)
    except Exception as e:
        print(f"Failed to dispatch to {webhook.url}: {e}")


@app.post("/api/v1/alerts/ingest", dependencies=[Depends(_require_token)])
async def ingest_alert(alert: ForecastAlert, background_tasks: BackgroundTasks):
    """Ingest a new forecast alert from the forecasting engine and dispatch to registered webhooks."""
    alert_data = alert.dict()
    recent_alerts.append(alert_data)

    if len(recent_alerts) > 1000:
        recent_alerts.pop(0)

    for webhook in webhooks:
        background_tasks.add_task(dispatch_webhook, alert_data, webhook)

    return {"status": "success", "message": "Alert ingested and dispatched"}


@app.get("/api/v1/alerts", dependencies=[Depends(_require_token)])
async def get_alerts(limit: int = 100):
    """Poll for recent alerts (useful for SIEMs that prefer polling over webhooks)."""
    return {"alerts": recent_alerts[-limit:]}


@app.post("/api/v1/webhooks", dependencies=[Depends(_require_token)])
async def register_webhook(webhook: WebhookConfig):
    """Register a new SIEM/SOAR webhook endpoint. Validated against NAF_WEBHOOK_ALLOWLIST before
    being stored, and re-validated again at dispatch time (see dispatch_webhook)."""
    _validate_webhook_url(webhook.url)
    webhooks.append(webhook)
    return {"status": "success", "message": f"Webhook {webhook.url} registered"}
