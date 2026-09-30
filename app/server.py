"""Phoenix IDPS REST API — the backend the React frontend talks to.

Endpoint paths and field names are unchanged from the mock version this replaces, so
`frontend/src/api/index.js` keeps working; the bodies now call the real pipeline. New fields are
additive.

Design rule, from audit findings E1/G1 and the 0.917 retraction: **this module contains no
numeric literals standing in for measurements.** Every figure is computed from the model, read
from a results file, or absent. Where an artifact is missing the response says so (`data_source`,
or HTTP 503) rather than substituting a plausible-looking value. The previous version's
"analytical evaluation engine" fallback is deliberately gone -- that fallback was the mechanism by
which fabricated metrics reached the dashboard.
"""
from __future__ import annotations

import os
import json
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import numpy as np
from fastapi import Depends, FastAPI, File, HTTPException, Security, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app import service
from common.config import resolve_path
from models.audit_ledger import AuditLedger
from models.compliance import generate_cert_in_report
from models.cve_lookup import related_capec, related_cves, snapshot_metadata
from models.explain import gradient_input_attribution, summarize_attention
from models.forecast import ForecastEngine
from models.narrative import generate_attack_narrative
from models.response import recommended_action
from pipeline.mitre_mapping import CIC_LABEL_TO_STAGE, STAGE_CLASSIFICATION_LABELS

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_PATH = PROJECT_ROOT / "docs" / "v2_converged_seed_results.json"
LOFO_PATH = PROJECT_ROOT / "docs" / "lofo_seed_summary.json"

MAX_UPLOAD_MB = service.MAX_PCAP_UPLOAD_MB

# The frontend renders stages as display strings. Responses carry both: `stage` for display and
# `stage_id` (snake_case) as the stable machine value. "Execution" -- in the mock's stage list --
# is not a stage this project has ever had; the real vocabulary is below.
STAGE_DISPLAY = {
    "benign": "Benign",
    "reconnaissance": "Reconnaissance",
    "initial_access": "Initial Access",
    "lateral_movement": "Lateral Movement",
    "command_and_control": "Command & Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def _display(stage: str) -> str:
    return STAGE_DISPLAY.get(stage, stage.replace("_", " ").title())


# Curated subset of feature_columns(config) offered to the what-if UI (audit competitive-parity
# item 4, 2026-09-30): features with an obvious plain-language story. The endpoint itself accepts
# any real feature name, validated against common.config.feature_columns(config) -- this list is
# only a UI convenience, not an allowlist enforced server-side.
WHAT_IF_FEATURE_LABELS = {
    "flow_count": "Number of flows",
    "total_packets": "Total packets",
    "syn_ratio": "SYN-flag ratio",
    "port_scan_score": "Port-scan signature",
}


# ---------------------------------------------------------------- app + auth

def _cors_origins() -> list[str]:
    """Explicit allowlist. The mock used allow_origins=["*"] together with allow_credentials=True,
    which browsers reject anyway and which would expose an authenticated API to any origin."""
    raw = os.environ.get("PHOENIX_CORS_ORIGINS")
    if raw:
        return [o.strip() for o in raw.split(",") if o.strip()]
    return ["http://localhost:5173", "http://127.0.0.1:5173",
            "http://localhost:5174", "http://127.0.0.1:5174"]


app = FastAPI(
    title="Phoenix IDPS Backend API",
    description="REST interface to the Transformer world model, explainability and compliance stack.",
    version="2.0.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

_api_key_header = APIKeyHeader(name="Authorization", auto_error=False)


def _require_token(authorization: str | None = Security(_api_key_header)) -> None:
    """Bearer check, opt-in via PHOENIX_REQUIRE_AUTH=1.

    Off by default *for now* only because the frontend's client.js still sends a hardcoded
    fallback token and Login.jsx never calls /auth/login -- both are frontend-owned files, and
    turning this on mid-flight would break the UI. Flip the env var once those land.
    """
    if os.environ.get("PHOENIX_REQUIRE_AUTH") != "1":
        return
    expected = os.environ.get("PHOENIX_API_TOKEN")
    if not expected:
        raise HTTPException(status_code=503, detail="PHOENIX_REQUIRE_AUTH=1 but PHOENIX_API_TOKEN is unset")
    if authorization != f"Bearer {expected}":
        raise HTTPException(status_code=401, detail="Invalid or missing bearer token")


# ---------------------------------------------------------------- server state

class _State:
    """What the server currently knows. Populated by /analysis/upload -- nothing is preloaded,
    because the repo ships a checkpoint but no traffic. Empty here means empty in the UI."""

    def __init__(self) -> None:
        self.config_path: str = "configs/real_data.yaml"
        self.dataset_id: str = "CIC-IDS-2018"
        self.flow_df = None
        self.windows = None
        self.batch = None          # BatchForecastResult
        self.source_name: str | None = None
        self.ingested_flows: int = 0

    def reset_data(self) -> None:
        self.flow_df = None
        self.windows = None
        self.batch = None
        self.source_name = None
        self.ingested_flows = 0


STATE = _State()


def _backend():
    config, model, scaler, background = service.load_backend(STATE.config_path)
    if model is None:
        raise HTTPException(
            status_code=503,
            detail=f"No trained checkpoint found for {STATE.config_path}. "
                   "Train one or point PHOENIX_CONFIG at a config whose checkpoint_dir is populated.",
        )
    return config, model, scaler, background


def _engine() -> tuple[ForecastEngine, dict[str, Any]]:
    config, model, scaler, _ = _backend()
    return ForecastEngine(model, scaler, config), config


def _ledger_path() -> Path:
    config, _, _, _ = service.load_backend(STATE.config_path)
    return resolve_path(config, "checkpoint_dir") / "audit_ledger.jsonl"


def _require_data() -> None:
    if STATE.batch is None:
        raise HTTPException(
            status_code=409,
            detail="No capture loaded. POST a PCAP or flow CSV to /api/v1/analysis/upload first.",
        )


def _observed_stage(host_ip: str) -> str | None:
    """The most recently *observed* stage label for a host, matching what the Streamlit UI showed
    as "current" (`host_windows.loc[cursor_idx, "stage"]`). This is not the same thing as the
    forecast's first step, which is already t+1. Unlabelled captures have no stage column, in
    which case there is no observed stage and callers must not invent one."""
    if STATE.windows is None or "stage" not in STATE.windows.columns:
        return None
    rows = STATE.windows[STATE.windows["src_ip"] == host_ip]
    if rows.empty:
        return None
    return str(rows.iloc[-1]["stage"])


def _strip_markup(text: str) -> str:
    """models/narrative.py emits light HTML (<b>...</b>) because it was written for Streamlit's
    markdown renderer. React renders a string literally, and the host IP inside it comes from a
    capture file, so returning markup would be both wrong-looking and an injection foothold the
    day someone reaches for dangerouslySetInnerHTML."""
    import re
    return re.sub(r"<[^>]+>", "", text)


def _host_row(idx: int) -> dict[str, Any]:
    """One dashboard row, from the real batched rollout. Field names match what Dashboard.jsx
    already reads; stage_is_heuristic and the disclosure note are additive."""
    b = STATE.batch
    probs = np.asarray(b.infiltration_probs[idx], dtype=float)
    peak_step = int(np.argmax(probs))
    peak = float(probs[peak_step])
    stages = b.stage_predictions[idx]
    heur = b.stage_is_heuristic[idx] if b.stage_is_heuristic else [False] * len(stages)
    peak_stage = stages[peak_step]
    observed = _observed_stage(b.host_ids[idx])
    flows = 0
    if STATE.flow_df is not None and "src_ip" in STATE.flow_df.columns:
        flows = int((STATE.flow_df["src_ip"] == b.host_ids[idx]).sum())
    return {
        "host_ip": b.host_ids[idx],
        "flow_count": flows,
        "peak_prob": round(peak, 4),
        "risk_score": round(peak, 4),
        "severity": service.severity_for(peak),
        # Observed, not forecast: stages[0] is already t+1. Falls back to the first forecast step
        # only when the capture carries no labels, and says so via current_stage_observed.
        "current_stage": _display(observed or stages[0]),
        "current_stage_id": observed or stages[0],
        "current_stage_observed": observed is not None,
        "predicted_stage": _display(peak_stage),
        "predicted_stage_id": peak_stage,
        "stage_is_heuristic": bool(heur[peak_step]),
        "stage_disclosure_note": service.stage_disclosure_note(peak_stage, bool(heur[peak_step])),
        "dataset_source": STATE.source_name or STATE.dataset_id,
    }


# ---------------------------------------------------------------- schemas

class LoginRequest(BaseModel):
    email: str
    password: str


class PredictRequest(BaseModel):
    host_ip: str
    horizon: Optional[int] = None  # ignored; K comes from the config (see /forecast/predict)


class WhatIfRequest(BaseModel):
    host_ip: str
    feature: str
    scale: float  # multiplies the feature's value in the most recent observed window only


class SimulateIsolationRequest(BaseModel):
    host_ip: str


class ReportRequest(BaseModel):
    host_ip: str
    format: Optional[str] = "json"


class SelectDatasetRequest(BaseModel):
    dataset_id: str


# ---------------------------------------------------------------- endpoints

@app.get("/api/v1/health")
def read_root():
    config, model, _, _ = service.load_backend(STATE.config_path)
    return {
        "system": "PHOENIX IDPS Backend Engine",
        "status": "online",
        "active_dataset": STATE.dataset_id,
        "checkpoint_loaded": model is not None,
        "config_path": STATE.config_path,
        **service.horizon_info(config),
    }


def _dataset_registry() -> list[dict[str, Any]]:
    """Only configs that actually exist on disk, with sizes read from each processed
    metadata.json. Datasets without a built dataset are listed as unavailable rather than
    given invented sequence counts."""
    out: list[dict[str, Any]] = []
    for ds_id, cfg_name in (("CIC-IDS-2018", "real_data.yaml"),
                            ("UNSW-NB15", "unsw_nb15.yaml"),
                            ("CTU-13", "ctu13.yaml")):
        cfg_path = PROJECT_ROOT / "configs" / cfg_name
        if not cfg_path.exists():
            continue
        entry: dict[str, Any] = {
            "id": ds_id,
            "name": ds_id,
            "config": f"configs/{cfg_name}",
            "status": "Unavailable",
            "total_sequences": None,
            "features": None,
        }
        try:
            config, model, _, _ = service.load_backend(f"configs/{cfg_name}")
            meta_path = resolve_path(config, "processed_dir") / "metadata.json"
            if meta_path.exists():
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                entry["total_sequences"] = meta.get("num_sequences")
                entry["features"] = len(meta.get("feature_columns", [])) or None
                entry["status"] = "Available" if model is not None else "No checkpoint"
            entry["checkpoint_loaded"] = model is not None
        except Exception as exc:
            entry["status"] = f"Unreadable: {type(exc).__name__}"
        out.append(entry)
    return out


@app.get("/api/v1/datasets", dependencies=[Depends(_require_token)])
def get_datasets():
    config, _, _, _ = service.load_backend(STATE.config_path)
    meta_path = resolve_path(config, "processed_dir") / "metadata.json"
    real_metadata = {}
    if meta_path.exists():
        real_metadata = json.loads(meta_path.read_text(encoding="utf-8"))
    return {
        "active_dataset": STATE.dataset_id,
        "datasets": _dataset_registry(),
        "real_metadata": real_metadata,
    }


@app.post("/api/v1/datasets/select", dependencies=[Depends(_require_token)])
def select_dataset(req: SelectDatasetRequest):
    ds = next((d for d in _dataset_registry() if d["id"] == req.dataset_id), None)
    if not ds:
        raise HTTPException(status_code=404, detail="Dataset not found")
    if not ds.get("checkpoint_loaded"):
        raise HTTPException(
            status_code=409,
            detail=f"{req.dataset_id} has no trained checkpoint, so it cannot be made active.",
        )
    STATE.config_path = ds["config"]
    STATE.dataset_id = ds["id"]
    STATE.reset_data()  # scores from another model/dataset must not survive the switch
    return {
        "status": "success",
        "active_dataset": STATE.dataset_id,
        "message": f"Active config is now {ds['config']}. Loaded capture cleared; re-upload to score.",
    }


@app.post("/api/v1/auth/login")
def login(credentials: LoginRequest):
    """Credentials come from the environment. The previous version accepted *any* non-empty
    email/password and also carried a hardcoded password in source."""
    expected_user = os.environ.get("PHOENIX_DEMO_USER")
    expected_pass = os.environ.get("PHOENIX_DEMO_PASSWORD")
    if not expected_user or not expected_pass:
        raise HTTPException(
            status_code=503,
            detail="Login is not configured. Set PHOENIX_DEMO_USER and PHOENIX_DEMO_PASSWORD.",
        )
    if credentials.email != expected_user or credentials.password != expected_pass:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = os.environ.get("PHOENIX_API_TOKEN", "")
    return {
        "status": "success",
        "access_token": token,
        "token_type": "bearer",
        "user": {"email": credentials.email, "role": "SOC Analyst"},
    }


@app.get("/api/v1/system/status", dependencies=[Depends(_require_token)])
def get_system_status():
    config, model, _, _ = service.load_backend(STATE.config_path)
    ledger = AuditLedger.load_or_create(_ledger_path())
    intact, first_bad = ledger.verify_integrity()
    hosts_n = len(STATE.batch.host_ids) if STATE.batch else 0
    high_risk = 0
    if STATE.batch:
        high_risk = sum(
            1 for i in range(hosts_n)
            if service.severity_for(float(np.max(STATE.batch.infiltration_probs[i]))) in ("critical", "serious")
        )
    return {
        "status": "online",
        "api_connected": True,
        "active_dataset": STATE.dataset_id,
        "model_loaded": model is not None,
        "data_source": STATE.source_name,
        "active_monitored_hosts": hosts_n,
        "total_active_flows": STATE.ingested_flows,
        "high_risk_hosts": high_risk,
        "ledger_entries": len(ledger.entries),
        "ledger_intact": intact,
        "ledger_first_bad_index": first_bad,
        **service.horizon_info(config),
        "last_updated_timestamp": time.time(),
    }


@app.get("/api/v1/forecast/hosts", dependencies=[Depends(_require_token)])
def get_hosts():
    """Empty until a capture is uploaded. The repo ships a checkpoint but no traffic, so a fresh
    clone legitimately has zero hosts -- the UI should show an empty state, not placeholders."""
    if STATE.batch is None:
        return {"active_dataset": STATE.dataset_id, "hosts": [], "data_source": None,
                "message": "No capture loaded. Upload a PCAP or flow CSV to populate hosts.",
                "timestamp": time.time()}
    rows = [_host_row(i) for i in range(len(STATE.batch.host_ids))]
    rows.sort(key=lambda r: r["peak_prob"], reverse=True)
    return {"active_dataset": STATE.dataset_id, "hosts": rows,
            "data_source": STATE.source_name, "timestamp": time.time()}


def _sequence_for(host_ip: str, config: dict[str, Any]) -> np.ndarray:
    from models.forecast import latest_sequence
    feature_cols = service.feature_cols_for(config)
    seq_len = int(config["windowing"]["sequence_length"])
    seq = latest_sequence(STATE.windows, feature_cols, host_ip, seq_len)
    if seq is None:
        raise HTTPException(
            status_code=404,
            detail=f"Host {host_ip} has no complete {seq_len}-window sequence in the loaded capture.",
        )
    return seq


@app.post("/api/v1/forecast/predict", dependencies=[Depends(_require_token)])
def predict_forecast(req: PredictRequest):
    """K-step rollout for one host. K is fixed by the trained model's config (6 steps x 10s =
    60 seconds); a caller-supplied `horizon` is accepted for compatibility but ignored, because
    the model cannot roll out to an arbitrary depth it was not trained for."""
    _require_data()
    engine, config = _engine()
    seq = _sequence_for(req.host_ip, config)
    result = engine.rollout(seq)
    horizon = service.horizon_info(config)
    stages = list(result.stage_predictions)
    heur = list(result.stage_is_heuristic) or [False] * len(stages)
    return {
        "host_ip": req.host_ip,
        **horizon,
        "step_seconds": [(i + 1) * horizon["window_seconds"] for i in range(len(stages))],
        "infiltration_probs": [round(float(p), 4) for p in result.infiltration_probs],
        "predicted_stages": [_display(s) for s in stages],
        "predicted_stage_ids": stages,
        "stage_is_heuristic": [bool(h) for h in heur],
        "stage_disclosure_notes": [service.stage_disclosure_note(s, bool(h)) for s, h in zip(stages, heur)],
        "stage_probs": [[round(float(p), 4) for p in row] for row in result.stage_probs],
        "stage_labels": list(STAGE_CLASSIFICATION_LABELS),
        "transition_magnitude": [round(float(v), 5) for v in result.transition_magnitude],
        # Observed, like _host_row -- stages[0] is already t+1, so using it here made the
        # forecast panel report "Benign" for a host the table and narrative both showed as
        # Command & Control.
        "current_stage": _display(_observed_stage(req.host_ip) or stages[0]),
        "current_stage_observed": _observed_stage(req.host_ip) is not None,
        "horizon_note": (
            f"Forecast covers {horizon['horizon_seconds']} seconds "
            f"({horizon['horizon_k']} steps x {horizon['window_seconds']}s)."
        ),
    }


@app.get("/api/v1/forecast/what-if/features", dependencies=[Depends(_require_token)])
def get_what_if_features():
    """The curated feature list the what-if UI offers, plus the model's real feature order so the
    frontend never has to hardcode column names independently of what the loaded checkpoint
    actually uses (audit W19 -- this endpoint reads common.config.feature_columns(config), the one
    supported way to know the model's feature list, rather than the frontend guessing)."""
    _, config = _engine()
    all_features = service.feature_cols_for(config)
    curated = [
        {"feature": f, "label": WHAT_IF_FEATURE_LABELS[f]}
        for f in WHAT_IF_FEATURE_LABELS if f in all_features
    ]
    return {"curated_features": curated, "all_features": all_features}


@app.post("/api/v1/forecast/what-if", dependencies=[Depends(_require_token)])
def what_if_forecast(req: WhatIfRequest):
    """Counterfactual rollout (audit competitive-parity item 4, 2026-09-30): reruns the same
    K-step rollout as /forecast/predict, but with one named feature in the most recent observed
    window scaled by `req.scale` before the model sees it -- e.g. scale=0.0 asks "what would the
    model forecast if this host's port-scan signature had been zero?"

    This is the model's own learned dynamics responding to a perturbed input, not a causal
    simulation of network behaviour -- the response says so via `caveat` and callers/UI must not
    present it as a guaranteed outcome.

    Column indexing goes through common.config.feature_columns(config), never a hand-picked
    index, so this cannot become a fifth instance of the schema-drift bug class (audit W19,
    models/checkpoint_io.py::validate_feature_names)."""
    _require_data()
    engine, config = _engine()
    feature_cols = service.feature_cols_for(config)
    if req.feature not in feature_cols:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown feature {req.feature!r}. Must be one of the model's trained "
                   f"features (see GET /api/v1/forecast/what-if/features).",
        )
    idx = feature_cols.index(req.feature)

    baseline_seq = _sequence_for(req.host_ip, config)
    perturbed_seq = baseline_seq.copy()
    perturbed_seq[-1, idx] = perturbed_seq[-1, idx] * req.scale

    baseline = engine.rollout(baseline_seq)
    counterfactual = engine.rollout(perturbed_seq)

    horizon = service.horizon_info(config)
    baseline_probs = [round(float(p), 4) for p in baseline.infiltration_probs]
    cf_probs = [round(float(p), 4) for p in counterfactual.infiltration_probs]
    return {
        "host_ip": req.host_ip,
        "feature": req.feature,
        "feature_label": WHAT_IF_FEATURE_LABELS.get(req.feature, req.feature),
        "scale": req.scale,
        **horizon,
        "step_seconds": [(i + 1) * horizon["window_seconds"] for i in range(len(baseline_probs))],
        "baseline_infiltration_probs": baseline_probs,
        "counterfactual_infiltration_probs": cf_probs,
        "probability_delta": [round(c - b, 4) for b, c in zip(baseline_probs, cf_probs)],
        "baseline_predicted_stages": [_display(s) for s in baseline.stage_predictions],
        "counterfactual_predicted_stages": [_display(s) for s in counterfactual.stage_predictions],
        "caveat": (
            "This shows what the trained model's own learned dynamics predict in response to a "
            "perturbed input -- not a causal simulation of real network behaviour, and not a "
            "guarantee of what would actually happen."
        ),
    }


@app.post("/api/v1/explainability/attribution", dependencies=[Depends(_require_token)])
def get_attribution(req: PredictRequest):
    """Gradient x input attribution over the real feature vector, plus the model's own attention
    over the input window history. Both are computed, not listed."""
    _require_data()
    engine, config = _engine()
    _, model, scaler, _ = _backend()
    seq = _sequence_for(req.host_ip, config)
    feature_cols = service.feature_cols_for(config)
    scaled = scaler.transform(seq[None, ...])[0]
    attribution = gradient_input_attribution(model, scaled, feature_cols)
    result = engine.rollout(seq)
    attn_pairs = summarize_attention(np.asarray(result.attentions)[0], int(config["windowing"]["sequence_length"]))
    values = np.asarray(attribution["attribution"], dtype=float)
    names = list(attribution["feature_names"])
    order = np.argsort(-np.abs(values))[:10]
    ranked = [(names[i], float(values[i])) for i in order]
    return {
        "host_ip": req.host_ip,
        "method": "gradient x input",
        "feature_attributions": [
            {"feature": name, "contribution": round(float(value), 6)} for name, value in ranked
        ],
        "attention_weights": [round(float(w), 4) for _, w in attn_pairs],
        "attention_windows": [label for label, _ in attn_pairs],
    }


@app.get("/api/v1/attacks/narrative", dependencies=[Depends(_require_token)])
def get_narrative(host_ip: str):
    """Template-filled prose from models/narrative.py -- deterministic, every claim traced to a
    ForecastResult field. No LLM call; the project makes zero cloud API calls by design."""
    _require_data()
    engine, config = _engine()
    seq = _sequence_for(host_ip, config)
    result = engine.rollout(seq)
    window_seconds = int(config["windowing"]["window_seconds"])
    peak_step = int(np.argmax(result.infiltration_probs))
    peak_stage = result.stage_predictions[peak_step]
    narrative = _strip_markup(generate_attack_narrative(
        host_ip, result, service.feature_cols_for(config), window_seconds,
        current_stage=_observed_stage(host_ip),
    ))
    action = recommended_action(peak_stage)
    cves = related_cves(peak_stage)
    capec = related_capec(peak_stage)
    return {
        "host_ip": host_ip,
        "narrative": narrative,
        "predicted_stage": _display(peak_stage),
        "predicted_stage_id": peak_stage,
        "peak_prob": round(float(result.infiltration_probs[peak_step]), 4),
        "recommended_action": {
            "title": action["action"],
            "action": action["detail"],
            "severity": service.severity_for(float(result.infiltration_probs[peak_step])).upper(),
        },
        "related_cves": [c.get("cve_id") for c in cves],
        "cve_details": cves,
        "related_capec": [c.get("capec_id") for c in capec],
        "capec_details": capec,
        "intel_snapshot": snapshot_metadata(),
    }


@app.get("/api/v1/mitre/mapping", dependencies=[Depends(_require_token)])
def get_mitre():
    """The mapping the system actually uses (pipeline/mitre_mapping.py), not a display table.
    No confidence scores: the label->stage map is a deterministic lookup, so a "confidence"
    figure would be meaningless. `impact` is intentionally absent from the classifier's label
    set -- it is excluded from the 5-way task -- and that is reported rather than hidden.
    """
    by_stage: dict[str, list[str]] = {}
    for label, stage in CIC_LABEL_TO_STAGE.items():
        by_stage.setdefault(stage, []).append(label)
    return {
        "source": "pipeline/mitre_mapping.py::CIC_LABEL_TO_STAGE",
        "classifier_labels": list(STAGE_CLASSIFICATION_LABELS),
        "mappings": [
            {
                "stage": _display(stage),
                "stage_id": stage,
                "dataset_labels": sorted(labels),
                "in_classifier": stage in STAGE_CLASSIFICATION_LABELS,
            }
            for stage, labels in sorted(by_stage.items())
        ],
    }


@app.post("/api/v1/analysis/upload", dependencies=[Depends(_require_token)])
def upload_file(file: UploadFile = File(...)):
    """Actually parses the capture: PCAP/PCAPNG via Scapy, or a flow CSV, then builds windows,
    graph and packet features and scores every host with one batched rollout.

    Deliberately a sync `def`: parsing and inference are seconds of blocking CPU work in Scapy,
    pandas and torch. As `async def` that would run *on the event loop* and stall every other
    request -- including the dashboard's 5-second poll -- for the whole parse. FastAPI runs a
    sync endpoint in a threadpool instead.
    """
    client_name = file.filename or "capture.pcap"
    ext = Path(client_name).suffix.lower()
    if ext not in (".pcap", ".pcapng", ".csv"):
        raise HTTPException(status_code=422, detail=f"Unsupported format '{ext}'. Expected .pcap, .pcapng or .csv")

    contents = file.file.read()
    size_mb = len(contents) / (1024 * 1024)
    if size_mb > MAX_UPLOAD_MB:
        raise HTTPException(status_code=413, detail=f"{size_mb:.1f} MB exceeds the {MAX_UPLOAD_MB} MB limit")

    config, model, scaler, _ = _backend()
    tmp_dir = Path(tempfile.mkdtemp(prefix="phoenix_upload_"))
    # Never build a path from the client-supplied name: "../../x.csv" or an absolute path would
    # escape the temp directory, and the unlink in `finally` would then delete the victim file.
    # Only the extension is taken from the upload; the display name is reported separately.
    filename = Path(client_name).name
    tmp_path = tmp_dir / f"upload{ext}"
    tmp_path.write_bytes(contents)

    try:
        if ext == ".csv":
            flow_df, windows = service.process_uploads(tmp_path, None, config)
        else:
            flow_df, windows = service.process_uploads(None, tmp_path, config)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Could not parse {filename}: {exc}") from exc
    finally:
        try:
            tmp_path.unlink()
            tmp_dir.rmdir()
        except OSError:
            pass

    engine = ForecastEngine(model, scaler, config)
    feature_cols = service.feature_cols_for(config)
    seq_len = int(config["windowing"]["sequence_length"])
    batch = service.score_all_hosts(engine, windows, feature_cols, seq_len)

    STATE.flow_df = flow_df
    STATE.windows = windows
    STATE.batch = batch
    STATE.source_name = filename
    STATE.ingested_flows = int(len(flow_df))

    if batch is None:
        return {
            "status": "partial",
            "filename": filename,
            "size_mb": round(size_mb, 2),
            "extracted_flows": int(len(flow_df)),
            "windows": int(len(windows)),
            "hosts_scored": 0,
            "new_host_ip": None,
            "message": (
                f"Parsed {filename}: {len(flow_df):,} flows, {len(windows):,} windows. No host has "
                f"{seq_len} consecutive windows yet, so nothing could be scored — a longer capture is needed."
            ),
        }

    rows = sorted(
        (_host_row(i) for i in range(len(batch.host_ids))),
        key=lambda r: r["peak_prob"], reverse=True,
    )
    return {
        "status": "success",
        "filename": filename,
        "size_mb": round(size_mb, 2),
        "extracted_flows": int(len(flow_df)),
        "windows": int(len(windows)),
        "hosts_scored": len(rows),
        "new_host_ip": rows[0]["host_ip"],
        "high_risk_hosts": [r["host_ip"] for r in rows if r["severity"] in ("critical", "serious")],
        "message": (
            f"Ingested {filename} ({size_mb:.2f} MB): {len(flow_df):,} flow records, "
            f"{len(windows):,} windows, {len(rows)} hosts scored."
        ),
    }


@app.post("/api/v1/reports/generate", dependencies=[Depends(_require_token)])
def generate_report(req: ReportRequest):
    """A real CERT-In-aligned incident report, appended to the hash-chained audit ledger.

    The mock returned a `compliance_certificate` asserting ISO/IEC 27001 and NIST SP 800-53
    certification. That claim was fabricated and is removed: nothing in this project certifies
    anything. What it can honestly produce is a drafted CERT-In report plus a tamper-evident
    ledger record, which is what this now returns.
    """
    _require_data()
    engine, config = _engine()
    seq = _sequence_for(req.host_ip, config)
    result = engine.rollout(seq)
    peak_step = int(np.argmax(result.infiltration_probs))
    peak_prob = float(result.infiltration_probs[peak_step])
    peak_stage = result.stage_predictions[peak_step]
    action = recommended_action(peak_stage)
    narrative = _strip_markup(generate_attack_narrative(
        req.host_ip, result, service.feature_cols_for(config),
        int(config["windowing"]["window_seconds"]), current_stage=_observed_stage(req.host_ip),
    ))

    ledger_path = _ledger_path()
    ledger = AuditLedger.load_or_create(ledger_path)
    entry = ledger.append(req.host_ip, peak_prob, peak_stage, action["action"])
    ledger.save(ledger_path)

    report = generate_cert_in_report(
        host=req.host_ip,
        detected_at=datetime.now(timezone.utc),
        peak_stage=peak_stage,
        peak_infiltration_prob=peak_prob,
        recommended_action=action["action"],
        narrative=narrative,
        ledger_hash=entry.record_hash,
    )
    return {
        "status": "success",
        "host_ip": req.host_ip,
        "audit_hash": entry.record_hash,
        "ledger_index": entry.index,
        "prev_hash": entry.prev_hash,
        "compliance_certificate": {
            "certified": False,
            "framework": "CERT-In (India) 6-hour incident reporting — drafted, not certified",
            "issuer": "Phoenix IDPS — draft generator; this project certifies nothing",
        },
        "compliance": {
            "framework": "CERT-In (India) directions, 6-hour reporting window",
            "is_reportable": report.is_reportable,
            "category": report.category,
            "detected_at": report.detected_at.isoformat(),
            "reporting_deadline": report.reporting_deadline.isoformat(),
            "hours_remaining": report.hours_remaining,
            "text": report.text,
        },
        "timestamp": time.time(),
        "download_url": f"/api/v1/reports/download/{req.host_ip}.json",
    }


@app.post("/api/v1/response/simulate-isolation", dependencies=[Depends(_require_token)])
def simulate_isolation(req: SimulateIsolationRequest):
    """Competitive-parity item 5 (2026-09-30): a UI-only simulated device-isolation action.

    Deliberately NOT real automation -- models/response.py's own docstring states "nothing here
    is executed automatically" and that guarantee is kept here. This endpoint makes no firewall,
    network, or process-control call of any kind; it only records, on the existing tamper-evident
    ledger, that a demo isolation action was simulated for this host. The literal word "SIMULATED"
    is required to appear in the ledger entry itself (not just the API response or the UI), so
    reading the ledger export alone -- without this endpoint's code -- is enough to tell this was
    never a real action.
    """
    _require_data()
    engine, config = _engine()
    seq = _sequence_for(req.host_ip, config)
    result = engine.rollout(seq)
    peak_step = int(np.argmax(result.infiltration_probs))
    peak_prob = float(result.infiltration_probs[peak_step])
    peak_stage = result.stage_predictions[peak_step]

    ledger_path = _ledger_path()
    ledger = AuditLedger.load_or_create(ledger_path)
    entry = ledger.append(
        req.host_ip, peak_prob, peak_stage,
        "SIMULATED: host isolated (demo action, no real network change)",
    )
    ledger.save(ledger_path)

    return {
        "status": "simulated",
        "host_ip": req.host_ip,
        "audit_hash": entry.record_hash,
        "ledger_index": entry.index,
        "note": "This is a UI simulation. No real network or firewall change was made.",
        "timestamp": time.time(),
    }


@app.get("/api/v1/reports/download/{filename}", dependencies=[Depends(_require_token)])
def download_report(filename: str):
    """Serves the ledger record for a host as a downloadable JSON document."""
    host = filename.replace(".json", "")
    ledger = AuditLedger.load_or_create(_ledger_path())
    entries = [e for e in ledger.entries if e.host == host]
    if not entries:
        raise HTTPException(status_code=404, detail=f"No ledger entry for {host}. Generate a report first.")
    entry = entries[-1]
    intact, first_bad = ledger.verify_integrity()
    return JSONResponse(
        content={
            "report_id": host,
            "generated_at": entry.timestamp,
            "dataset_source": STATE.source_name or STATE.dataset_id,
            "host": entry.host,
            "peak_infiltration_prob": entry.peak_infiltration_prob,
            "peak_stage": entry.peak_stage,
            "recommended_action": entry.recommended_action,
            "ledger_index": entry.index,
            "prev_hash": entry.prev_hash,
            "record_hash": entry.record_hash,
            "ledger_intact": intact,
            "ledger_first_bad_index": first_bad,
        },
        headers={"Content-Disposition": f"attachment; filename={host}.json"},
    )


@app.get("/api/v1/eval/metrics")
def get_eval_metrics():
    """The project's measured results, read from the seed-summary files -- never literals.

    The mock returned AUROC 0.942 labelled as the day-disjoint split. The measured value on that
    split is 0.794 +/- 0.043 across three seeds. Reporting the real figure, with its spread and
    the leave-one-family-out results, is the point of the whole evaluation audit.
    """
    if not RESULTS_PATH.exists():
        raise HTTPException(status_code=503, detail=f"Results file missing: {RESULTS_PATH.name}")
    data = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
    across = data.get("across_seeds", {})

    def stat(key: str) -> dict[str, Any] | None:
        s = across.get(key)
        if not s:
            return None
        return {"mean": round(s["mean"], 4), "sd": round(s["std"], 4),
                "min": round(s["min"], 4), "max": round(s["max"], 4)}

    payload: dict[str, Any] = {
        "split": "day-disjoint (no attack session shared between train and test)",
        "n_seeds": len(across.get("auroc", {}).get("per_seed", [])) or None,
        "n_test_sequences": data.get("n_test"),
        "n_test_positive": data.get("n_test_pos"),
        "auroc": stat("auroc"),
        "auprc": stat("auprc"),
        "f1_at_0.5": stat("f1@0.5"),
        "precision_at_0.5": stat("precision@0.5"),
        "recall_at_0.5": stat("recall@0.5"),
        "source": "docs/v2_converged_seed_results.json",
        "note": (
            "Conservative model: precision ~0.93, recall ~0.32. An earlier 0.917 F1 came from a "
            "split that shared attack sessions between train and test and was withdrawn (audit E1)."
        ),
    }
    if LOFO_PATH.exists():
        lofo = json.loads(LOFO_PATH.read_text(encoding="utf-8"))
        payload["generalisation_lofo"] = {
            family: {
                "auroc_mean": round(v["auroc_mean"], 4),
                "auroc_sd": round(v["auroc_sd"], 4),
                "n_test": v.get("n_test"),
                "distinguishable_from_chance": abs(v.get("t_vs_chance_df2", 0.0)) > 4.303,
            }
            for family, v in lofo.items()
        }
        payload["generalisation_note"] = (
            "Leave-one-attack-family-out, 3 seeds, df=2. Only `impact` clears significance, and "
            "only marginally: no statistically supported evidence of transfer to held-out families."
        )
    return payload


# ---------------------------------------------------------------- single-port deployment
#
# When `frontend/dist` exists (after `npm run build --prefix frontend`), the API also serves the
# built dashboard. That makes the whole system one process on one port, which removes the two
# things that silently broke a LAN demo: the browser and the API are now the same origin, so CORS
# never applies, and the frontend calls relative URLs, so VITE_API_BASE_URL does not need to know
# the host's LAN address. Binding 0.0.0.0 is then the only thing a LAN demo needs.
#
# Mounted last on purpose: every /api/v1 route above is matched first, so the SPA fallback can
# never shadow the API.

DIST_DIR = PROJECT_ROOT / "frontend" / "dist"


def _mount_frontend() -> bool:
    if not (DIST_DIR / "index.html").is_file():
        return False

    assets = DIST_DIR / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        """Serve a built file when it exists, else index.html so client-side routes
        (/dashboard, /login) survive a page reload."""
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail=f"No such endpoint: /{full_path}")
        candidate = (DIST_DIR / full_path).resolve()
        if full_path and candidate.is_file() and candidate.is_relative_to(DIST_DIR.resolve()):
            return FileResponse(candidate)
        return FileResponse(DIST_DIR / "index.html")

    return True


FRONTEND_MOUNTED = _mount_frontend()


if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("PHOENIX_HOST", "127.0.0.1")
    port = int(os.environ.get("PHOENIX_PORT", "8000"))
    uvicorn.run(app, host=host, port=port)
