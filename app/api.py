from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import requests
import time

app = FastAPI(
    title="SIEM/SOAR Integration API",
    description="Webhook and REST API for Network Attack Forecasting Alerts",
    version="1.0.0"
)

# In-memory alert store (for demo purposes)
recent_alerts = []

class ForecastAlert(BaseModel):
    host_ip: str
    infiltration_prob: float
    predicted_stage: str
    timestamp: float

class WebhookConfig(BaseModel):
    url: str
    auth_token: Optional[str] = None

# Configured webhooks
webhooks: List[WebhookConfig] = []

def dispatch_webhook(alert: dict, webhook: WebhookConfig):
    headers = {"Content-Type": "application/json"}
    if webhook.auth_token:
        headers["Authorization"] = f"Bearer {webhook.auth_token}"
    try:
        requests.post(webhook.url, json=alert, headers=headers, timeout=5)
    except Exception as e:
        print(f"Failed to dispatch to {webhook.url}: {e}")

@app.post("/api/v1/alerts/ingest")
async def ingest_alert(alert: ForecastAlert, background_tasks: BackgroundTasks):
    """
    Ingest a new forecast alert from the forecasting engine and dispatch to SIEM/SOAR webhooks.
    """
    alert_data = alert.dict()
    recent_alerts.append(alert_data)
    
    # Keep only the last 1000 alerts in memory
    if len(recent_alerts) > 1000:
        recent_alerts.pop(0)

    for webhook in webhooks:
        background_tasks.add_task(dispatch_webhook, alert_data, webhook)
        
    return {"status": "success", "message": "Alert ingested and dispatched"}

@app.get("/api/v1/alerts")
async def get_alerts(limit: int = 100):
    """
    Poll for recent alerts (useful for SIEMs that prefer polling over webhooks).
    """
    return {"alerts": recent_alerts[-limit:]}

@app.post("/api/v1/webhooks")
async def register_webhook(webhook: WebhookConfig):
    """
    Register a new SIEM/SOAR webhook endpoint.
    """
    webhooks.append(webhook)
    return {"status": "success", "message": f"Webhook {webhook.url} registered"}
