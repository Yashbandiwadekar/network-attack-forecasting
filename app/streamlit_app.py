"""Offline demo: upload a CICFlowMeter CSV (+ optional PCAP), pick a source IP, and see the world
model's K-step infiltration forecast — probability timeline, predicted MITRE ATT&CK stage per
step, and both explainability views (attention over past windows, SHAP over current features).

No network calls anywhere in this file — everything runs against the locally trained checkpoint.

Usage:
    streamlit run app/streamlit_app.py
"""
from __future__ import annotations

import sys
import tempfile
from datetime import timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import altair as alt
import numpy as np
import pandas as pd
import streamlit as st

from common.config import feature_columns, load_config, resolve_path
from models.dataset import FeatureScaler, load_split
from models.explain import ShapExplainer, gradient_input_attribution, summarize_attention
from models.forecast import (
    ForecastEngine, latest_sequences_batch, load_world_model,
    one_step_reconstruction_error, previous_sequence_and_actual,
)
from models.audit_ledger import AuditLedger
from models.compliance import generate_cert_in_report
from models.cve_lookup import related_cves, snapshot_metadata
from models.narrative import generate_attack_narrative
from models.response import recommended_action
from pipeline.flow_features import clean_and_normalize, load_flow_csv, load_flow_dir
from pipeline.graph_embedding_features import build_graph_embedding_window_features
from pipeline.graph_features import build_graph_window_features
from pipeline.mitre_mapping import BENIGN
from pipeline.packet_features import compute_packet_window_features, load_pcap
from pipeline.windowing import (
    apply_reconnaissance_heuristic, build_flow_windows, merge_graph_embedding_features,
    merge_graph_features, merge_packet_features,
)

st.set_page_config(page_title="Network Attack Forecasting", layout="wide", page_icon="🛡️")

DATA_SOURCES = {
    "Synthetic sample (fast demo)": "configs/default.yaml",
    "Real CIC-IDS-2018 (trained model)": "configs/real_data.yaml",
}

# Status palette (fixed roles — not themed, not reused for series identity). Severity thresholds
# on the world model's own peak K-step infiltration probability. A host below WARNING never
# appears in the alert feed at all — only counted in "hosts monitored" — so the feed doesn't drown
# in near-zero noise.
SEVERITY_LEVELS = [
    (0.70, "critical", "#d03b3b", "#ffffff"),
    (0.40, "serious", "#ec835a", "#0d0d0d"),
    (0.15, "warning", "#fab219", "#0d0d0d"),
]
GOOD_COLOR = "#0ca30c"

DASHBOARD_CSS = """
<style>
.live-pill {
    display:inline-flex; align-items:center; gap:6px; background:rgba(12,163,12,0.12);
    color:#0ca30c; border:1px solid rgba(12,163,12,0.35); padding:3px 12px; border-radius:999px;
    font-size:12px; font-weight:600; letter-spacing:0.03em; text-transform:uppercase;
}
.live-dot { width:7px; height:7px; border-radius:50%; background:#0ca30c; animation: pulse 1.6s ease-in-out infinite; }
@keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:0.3; } }

.stat-tile {
    background:#1a1a19; border:1px solid rgba(255,255,255,0.10); border-radius:10px;
    padding:14px 18px; height:100%;
}
.stat-tile-label { color:#898781; font-size:12px; text-transform:uppercase; letter-spacing:0.05em; margin-bottom:6px; }
.stat-tile-value { color:#ffffff; font-size:30px; font-weight:700; font-variant-numeric: tabular-nums; line-height:1.1; }

.alert-card {
    background:#1a1a19; border:1px solid rgba(255,255,255,0.10); border-left:4px solid;
    border-radius:10px; padding:12px 16px; margin-bottom:8px;
    transition: transform 0.12s ease, box-shadow 0.12s ease;
}
.alert-card:hover { transform: translateX(2px); box-shadow: 0 4px 16px rgba(0,0,0,0.35); }
.stat-tile { transition: transform 0.12s ease; }
.stat-tile:hover { transform: translateY(-2px); }
.alert-card-top { display:flex; align-items:center; gap:10px; margin-bottom:10px; }
.severity-badge {
    font-size:10.5px; font-weight:700; letter-spacing:0.05em; padding:3px 9px; border-radius:999px;
    text-transform:uppercase;
}
.alert-host { color:#ffffff; font-weight:600; font-size:14px; font-family: ui-monospace, "SF Mono", Consolas, monospace; }
.alert-card-body { display:flex; align-items:center; justify-content:space-between; gap:14px; }
.alert-stat-value { font-size:26px; font-weight:700; font-variant-numeric: tabular-nums; line-height:1; }
.alert-stat-label { color:#c3c2b7; font-size:12px; margin-top:4px; }

.empty-state {
    color:#898781; text-align:center; padding:28px; border:1px dashed rgba(255,255,255,0.15);
    border-radius:10px; font-size:14px;
}

.stage-stepper { display:flex; align-items:stretch; gap:3px; margin: 4px 0 14px 0; }
.stage-pill {
    flex:1; text-align:center; padding:9px 4px; font-size:11px; font-weight:700;
    text-transform:uppercase; letter-spacing:0.03em; color:#898781; background:#1a1a19;
    border:1px solid rgba(255,255,255,0.10); border-radius:8px; white-space:nowrap;
    transition: all 0.15s ease;
}
.stage-pill.active { border-color:transparent; transform: scale(1.04); }

.gauge-wrap { display:flex; flex-direction:column; align-items:center; justify-content:center; height:100%; }
.gauge-caption { color:#898781; font-size:12px; margin-top:2px; text-align:center; }

.narrative-card {
    background:#1a1a19; border:1px solid rgba(255,255,255,0.10); border-radius:10px;
    padding:16px 20px; line-height:1.6; color:#e6e5df; font-size:14.5px;
}
.response-card {
    background:#1a1a19; border:1px solid rgba(255,255,255,0.10); border-left:4px solid;
    border-radius:10px; padding:12px 16px; margin-top:10px;
}
.response-label {
    font-size:10.5px; font-weight:700; letter-spacing:0.05em; text-transform:uppercase;
    color:#898781; margin-bottom:4px;
}
.response-action { color:#ffffff; font-size:14.5px; font-weight:600; }
.response-detail { color:#c3c2b7; font-size:12.5px; margin-top:4px; }

.ledger-status {
    display:inline-flex; align-items:center; gap:8px; padding:8px 14px; border-radius:8px;
    font-size:13.5px; font-weight:700; margin-bottom:10px;
}
.ledger-hash {
    font-family: ui-monospace, "SF Mono", Consolas, monospace; font-size:11.5px; color:#898781;
}
</style>
"""


def _severity_for(peak_prob: float) -> tuple[str, str, str] | None:
    """(label, background color, text color) for the given peak probability, or None if it's
    below every threshold — such hosts don't get an alert card at all."""
    for threshold, label, bg, fg in SEVERITY_LEVELS:
        if peak_prob >= threshold:
            return label, bg, fg
    return None


def _sparkline_svg(values: np.ndarray, color: str, width: int = 110, height: int = 30) -> str:
    """A bare inline-SVG sparkline (Tier 2 component) — no axes, no legend, just the shape of the
    K-step trajectory. Two points minimum; degenerates to a flat centered line otherwise."""
    if len(values) < 2:
        return ""
    vmin, vmax = float(np.min(values)), float(np.max(values))
    span = vmax - vmin if vmax > vmin else 1.0
    pad = 3
    xs = np.linspace(pad, width - pad, len(values))
    ys = [height - pad - (v - vmin) / span * (height - 2 * pad) for v in values]
    points = " ".join(f"{x:.1f},{y:.1f}" for x, y in zip(xs, ys))
    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
        f'role="img" aria-label="infiltration probability trend">'
        f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="2" '
        f'stroke-linecap="round" stroke-linejoin="round"/></svg>'
    )


def _alert_card_html(
    host: str, severity_label: str, severity_bg: str, severity_fg: str,
    peak_prob: float, peak_step_seconds: int, stage: str, probs_curve: np.ndarray,
) -> str:
    spark = _sparkline_svg(probs_curve, severity_bg)
    stage_readable = stage.replace("_", " ")
    return f"""
    <div class="alert-card" style="border-left-color:{severity_bg};">
      <div class="alert-card-top">
        <span class="severity-badge" style="background:{severity_bg}; color:{severity_fg};">{severity_label}</span>
        <span class="alert-host">{host}</span>
      </div>
      <div class="alert-card-body">
        <div>
          <div class="alert-stat-value" style="color:{severity_bg};">{peak_prob:.0%}</div>
          <div class="alert-stat-label">peaks in {peak_step_seconds}s &middot; predicted {stage_readable}</div>
        </div>
        <div>{spark}</div>
      </div>
    </div>
    """


@st.cache_resource
def _load_backend(config_path: str):
    config = load_config(config_path)
    checkpoint_dir = resolve_path(config, "checkpoint_dir")
    checkpoint_path = checkpoint_dir / "world_model_best.pt"
    if not checkpoint_path.exists():
        return config, None, None, None
    model, _ = load_world_model(checkpoint_path)
    scaler = FeatureScaler.load(resolve_path(config, "processed_dir") / "scaler.npz")

    background = None
    train_path = resolve_path(config, "processed_dir") / "train.npz"
    if train_path.exists():
        train_split = load_split(resolve_path(config, "processed_dir"), "train")
        background = scaler.transform(train_split["X"])[:, -1, :]
    return config, model, scaler, background


def _process_uploads(flow_csv_path: Path, pcap_path: Path | None, config: dict) -> pd.DataFrame:
    flow_df = clean_and_normalize(load_flow_csv(flow_csv_path))
    flow_windows = build_flow_windows(flow_df, config)

    packet_windows = None
    if pcap_path is not None:
        packet_windows = compute_packet_window_features(load_pcap(pcap_path), config["windowing"]["window_seconds"])

    windows = merge_packet_features(flow_windows, packet_windows, config)
    graph_windows = build_graph_window_features(flow_df, config)
    windows = merge_graph_features(windows, graph_windows, config)
    embedding_windows = build_graph_embedding_window_features(flow_df, config)
    windows = merge_graph_embedding_features(windows, embedding_windows, config)
    windows = apply_reconnaissance_heuristic(windows, config)
    return flow_df, windows


@st.cache_data(show_spinner=False)
def _load_real_data(config_path: str) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Real CIC-IDS-2018 is ~16M flows across 10 files — this takes 1-3 minutes on first call, so
    it's cached (by config_path) rather than reprocessed on every widget interaction. No PCAP
    downloaded for real data (37 GB/day, see docs/02-dataset-and-features.md), so packet-level
    features are zero-filled — flow-only mode, exactly as the model was trained.
    """
    config = load_config(config_path)
    flow_df = clean_and_normalize(load_flow_dir(resolve_path(config, "raw_flow_dir")))
    flow_windows = build_flow_windows(flow_df, config)
    graph_windows = build_graph_window_features(flow_df, config)
    windows = merge_graph_features(flow_windows, graph_windows, config)
    embedding_windows = build_graph_embedding_window_features(flow_df, config)
    windows = merge_graph_embedding_features(windows, embedding_windows, config)
    windows = merge_packet_features(windows, None, config)
    windows = apply_reconnaissance_heuristic(windows, config)
    return flow_df, windows


def _stat_tile_html(label: str, value: str) -> str:
    return f"""
    <div class="stat-tile">
      <div class="stat-tile-label">{label}</div>
      <div class="stat-tile-value">{value}</div>
    </div>
    """


def _gauge_chart(pct: float, color: str) -> alt.Chart:
    """A ring/donut gauge for a single 0-1 probability — value arc in `color`, remainder faint.
    Built with Altair (already a Streamlit dependency) rather than a hand-rolled SVG arc, since
    Vega-Lite's arc mark handles the theta math for us."""
    pct = float(np.clip(pct, 0.0, 1.0))
    df = pd.DataFrame({"category": ["value", "remainder"], "amount": [pct, 1.0 - pct]})
    ring = alt.Chart(df).mark_arc(innerRadius=48, outerRadius=68, cornerRadius=6).encode(
        theta=alt.Theta("amount:Q", stack=True, sort=None),
        color=alt.Color(
            "category:N",
            scale=alt.Scale(domain=["value", "remainder"], range=[color, "rgba(255,255,255,0.08)"]),
            legend=None,
        ),
        order=alt.Order("amount:Q", sort="descending"),
    )
    label = alt.Chart(pd.DataFrame({"t": [f"{pct:.0%}"]})).mark_text(
        size=26, fontWeight="bold", color=color,
    ).encode(text="t:N")
    return (ring + label).properties(width=170, height=170).configure_view(strokeWidth=0)


def _stage_stepper_html(stages: list[str], current_stage: str, highlight_bg: str, highlight_fg: str) -> str:
    """A MITRE-stage kill-chain strip — every stage as a pill, the model's predicted stage lit up."""
    pills = []
    for s in stages:
        label = s.replace("_", " ")
        if s == current_stage:
            pills.append(
                f'<div class="stage-pill active" style="background:{highlight_bg}; color:{highlight_fg};">'
                f"{label}</div>"
            )
        else:
            pills.append(f'<div class="stage-pill">{label}</div>')
    return '<div class="stage-stepper">' + "".join(pills) + "</div>"


def _response_card_html(stage: str, border_color: str) -> str:
    """A compact, always-visible recommended-action callout — deliberately separate from the
    narrative paragraph below it so a scanning analyst doesn't have to read prose to find the one
    thing they came for. See models/response.py for the underlying playbook."""
    entry = recommended_action(stage)
    return f"""
    <div class="response-card" style="border-left-color:{border_color};">
      <div class="response-label">Recommended action &middot; {stage.replace('_', ' ')}</div>
      <div class="response-action">{entry['action']}</div>
      <div class="response-detail">{entry['detail']}</div>
    </div>
    """


def _forecast_chart(
    timeline_df: pd.DataFrame,
    window_s: int,
    actual_infiltration: list[float] | None,
) -> alt.Chart:
    """Layered K-step forecast: MC-dropout uncertainty band, severity threshold guide lines, the
    deterministic forecast line, and — when scrubbing history via the time-cursor slider — the
    ground-truth infiltration state that actually followed, overlaid for a direct visual check of
    whether the forecast called it right."""
    df = timeline_df.reset_index().copy()
    df["seconds"] = [(i + 1) * window_s for i in range(len(df))]

    band = alt.Chart(df).mark_area(opacity=0.18, color="#2a78d6").encode(
        x=alt.X("seconds:Q", title="seconds ahead"),
        y=alt.Y("p10 (MC-dropout):Q", title="infiltration probability", scale=alt.Scale(domain=[0, 1])),
        y2="p90 (MC-dropout):Q",
    )
    threshold_df = pd.DataFrame([{"y": t, "label": lbl} for t, lbl, *_ in SEVERITY_LEVELS])
    rules = alt.Chart(threshold_df).mark_rule(strokeDash=[4, 3], color="#898781", opacity=0.55).encode(
        y="y:Q", tooltip=["label", "y"],
    )
    line = alt.Chart(df).mark_line(point=alt.OverlayMarkDef(size=55), strokeWidth=3, color="#2a78d6").encode(
        x="seconds:Q",
        y="infiltration_probability:Q",
        tooltip=["step", "infiltration_probability", "predicted_stage"],
    )
    layers = [band, rules, line]

    if actual_infiltration:
        adf = pd.DataFrame({
            "seconds": df["seconds"].iloc[: len(actual_infiltration)],
            "actual": actual_infiltration,
        })
        layers.append(
            alt.Chart(adf).mark_line(strokeDash=[2, 2], color="#ffffff", point=alt.OverlayMarkDef(size=45)).encode(
                x="seconds:Q", y=alt.Y("actual:Q", title="infiltration probability"), tooltip=["seconds", "actual"],
            )
        )

    return alt.layer(*layers).properties(height=320)


def _attention_heat_chart(attn_pairs: list[tuple[str, float]]) -> alt.Chart:
    """A single-row heat-strip of attention weight per past window — a heatmap reads faster than a
    bar chart for 'which windows mattered', and stays compact next to the other explainability panels."""
    df = pd.DataFrame(attn_pairs, columns=["window", "attention_weight"])
    return alt.Chart(df).mark_rect(cornerRadius=3).encode(
        x=alt.X("window:N", title=None, sort=None),
        color=alt.Color("attention_weight:Q", scale=alt.Scale(scheme="oranges"), legend=None),
        tooltip=["window", "attention_weight"],
    ).properties(height=70)


def _score_all_hosts(_engine: ForecastEngine, windows: pd.DataFrame, feature_cols: list[str], seq_len: int):
    """Peak infiltration probability + predicted stage for every eligible host, via one batched
    rollout rather than one per host — see models/forecast.py::ForecastEngine.rollout_batch."""
    host_ids, sequences = latest_sequences_batch(windows, feature_cols, seq_len)
    if not host_ids:
        return None
    return _engine.rollout_batch(host_ids, sequences)


def _sort_ips_pseudo_hosts_first(ips: list[str]) -> list[str]:
    """Real data mixes genuine per-host IPs (thousands, from the one file with real IPs) with a
    handful of per-day network-wide pseudo-hosts ("NETWORK-<date>", see
    pipeline/flow_features.py::_fill_missing_ip_columns) — the pseudo-hosts are the more useful
    entries to see first in a dropdown of thousands."""
    return sorted(ips, key=lambda ip: (not ip.startswith("NETWORK-"), ip))


def main() -> None:
    st.markdown(DASHBOARD_CSS, unsafe_allow_html=True)

    title_col, status_col = st.columns([5, 1])
    with title_col:
        st.title("🛡️ Network Attack Forecasting")
        st.caption(
            "World-model alert dashboard — forecasts attacker progression before compromise "
            "completes. Runs fully offline, no cloud API calls."
        )
    with status_col:
        st.markdown(
            '<div style="text-align:right; padding-top:28px;">'
            '<span class="live-pill"><span class="live-dot"></span>Live</span></div>',
            unsafe_allow_html=True,
        )

    with st.sidebar:
        st.header("Data source")
        source_label = st.radio("Model / dataset", list(DATA_SOURCES.keys()))
        config_path = DATA_SOURCES[source_label]

    config, model, scaler, background = _load_backend(config_path)
    if model is None:
        st.error(
            f"No trained checkpoint for this data source. Run `python -m pipeline.build_dataset "
            f"--config {config_path}` then `python -m models.train --config {config_path}` first."
        )
        return

    is_real_data = config_path == DATA_SOURCES["Real CIC-IDS-2018 (trained model)"]

    if is_real_data:
        with st.sidebar:
            st.info(
                "Real CIC-IDS-2018 (10 days, 16M flows). No PCAP downloaded (37 GB/day) — flow-only, "
                "same as training. 9 of 10 days lack real IPs and fall back to one network-wide "
                "pseudo-host per day (`NETWORK-<date>`); only the DDoS day has genuine per-host IPs. "
                "See docs/02-dataset-and-features.md.",
                icon="📊",
            )
        with st.spinner("Loading and windowing real CIC-IDS-2018 data (16M flows, 1-3 min on first load)..."):
            flow_df, windows = _load_real_data(config_path)
    else:
        with st.sidebar:
            st.header("Input")
            use_synthetic = st.checkbox("Use bundled synthetic sample", value=True)
            flow_file = None if use_synthetic else st.file_uploader("Flow CSV (CICFlowMeter)", type="csv")
            pcap_file = None if use_synthetic else st.file_uploader("PCAP (optional)", type="pcap")
            if use_synthetic:
                st.info(
                    "This is a synthetic, hand-built traffic sample used to demonstrate the pipeline "
                    "end-to-end — NOT real CIC-IDS-2018 data. See docs/02-dataset-and-features.md.",
                    icon="⚠️",
                )

        if use_synthetic:
            flow_path = resolve_path(config, "raw_flow_dir") / "synthetic_sample.csv"
            pcap_path = resolve_path(config, "raw_pcap_dir") / "synthetic_sample.pcap"
            if not flow_path.exists():
                st.error("Synthetic sample not found. Run `python -m scripts.make_synthetic_sample` first.")
                return
        else:
            if flow_file is None:
                st.info("Upload a flow CSV to begin.")
                return
            tmp_dir = Path(tempfile.mkdtemp())
            flow_path = tmp_dir / "upload_flows.csv"
            flow_path.write_bytes(flow_file.getvalue())
            pcap_path = None
            if pcap_file is not None:
                pcap_path = tmp_dir / "upload.pcap"
                pcap_path.write_bytes(pcap_file.getvalue())

        with st.spinner("Running feature pipeline..."):
            flow_df, windows = _process_uploads(flow_path, pcap_path, config)

    seq_len = config["windowing"]["sequence_length"]
    eligible_ips = _sort_ips_pseudo_hosts_first(windows.groupby("src_ip").size()[lambda s: s >= seq_len].index.tolist())
    if not eligible_ips:
        st.warning(f"No source IP has {seq_len}+ consecutive windows of history yet — need more traffic.")
        return

    feature_cols = feature_columns(config)
    engine = ForecastEngine(model, scaler, config)
    window_s = config["windowing"]["window_seconds"]

    # ----------------------------------------------------------------------------------------
    # Alert dashboard — score every monitored host in one batched rollout (see
    # models/forecast.py::ForecastEngine.rollout_batch) and surface the ones crossing a severity
    # threshold as alert cards. Recomputed only when the data source or host count actually
    # changes (host count is a cheap proxy for "the underlying data changed" — avoids re-hashing
    # a multi-million-row DataFrame on every widget interaction).
    # ----------------------------------------------------------------------------------------
    score_cache_key = (config_path, len(eligible_ips))
    ledger_path = resolve_path(config, "processed_dir") / "audit_ledger.jsonl"
    if st.session_state.get("_score_cache_key") != score_cache_key:
        with st.spinner(f"Scoring {len(eligible_ips):,} monitored hosts..."):
            st.session_state._score_cache_key = score_cache_key
            st.session_state._score_result = _score_all_hosts(engine, windows, feature_cols, seq_len)

        # Log every alert-worthy host from this fresh scoring pass into the tamper-evident audit
        # ledger — tied to genuine re-scoring events (data source / host-count change), not to
        # every Streamlit rerun, so the ledger reflects real evaluation events, not UI redraws.
        ledger = AuditLedger.load_or_create(ledger_path)
        batch_result = st.session_state._score_result
        if batch_result is not None:
            for i, host in enumerate(batch_result.host_ids):
                probs_curve = batch_result.infiltration_probs[i]
                peak_step = int(np.argmax(probs_curve))
                peak_prob = float(probs_curve[peak_step])
                if _severity_for(peak_prob) is None:
                    continue
                stage_at_peak = batch_result.stage_predictions[i][peak_step]
                action = recommended_action(stage_at_peak)["action"]
                ledger.append(host, peak_prob, stage_at_peak, action)
        ledger.save(ledger_path)

    batch_result = st.session_state._score_result

    st.subheader("Alert Dashboard")

    alerts = []  # (peak_prob, peak_step, host, stage_at_peak, probs_curve)
    if batch_result is not None:
        for i, host in enumerate(batch_result.host_ids):
            probs_curve = batch_result.infiltration_probs[i]
            peak_step = int(np.argmax(probs_curve))
            peak_prob = float(probs_curve[peak_step])
            severity = _severity_for(peak_prob)
            if severity is None:
                continue
            stage_at_peak = batch_result.stage_predictions[i][peak_step]
            alerts.append((peak_prob, peak_step, host, stage_at_peak, probs_curve, severity))
    alerts.sort(key=lambda a: a[0], reverse=True)

    n_critical = sum(1 for a in alerts if a[5][0] == "critical")
    highest_risk = f"{alerts[0][0]:.0%}" if alerts else "—"

    tile_cols = st.columns(4)
    with tile_cols[0]:
        st.markdown(_stat_tile_html("Hosts monitored", f"{len(eligible_ips):,}"), unsafe_allow_html=True)
    with tile_cols[1]:
        st.markdown(_stat_tile_html("Active alerts", f"{len(alerts):,}"), unsafe_allow_html=True)
    with tile_cols[2]:
        st.markdown(_stat_tile_html("Critical", f"{n_critical:,}"), unsafe_allow_html=True)
    with tile_cols[3]:
        st.markdown(_stat_tile_html("Highest risk", highest_risk), unsafe_allow_html=True)

    st.write("")

    filter_col, search_col = st.columns([2, 3])
    with filter_col:
        severity_filter = st.segmented_control(
            "Severity",
            options=["critical", "serious", "warning"],
            default=["critical", "serious", "warning"],
            selection_mode="multi",
            label_visibility="collapsed",
        ) or []
    with search_col:
        host_query = st.text_input(
            "Search host", placeholder="Filter by IP / host…", label_visibility="collapsed",
        ).strip().lower()

    visible_alerts = [
        a for a in alerts
        if a[5][0] in severity_filter and (not host_query or host_query in a[2].lower())
    ]

    # Guard against a stale selection from a previous data source — a host id from one source
    # (e.g. real CIC-IDS-2018) won't exist in another's (e.g. the synthetic sample), which would
    # otherwise crash the selectbox below.
    if st.session_state.get("src_ip_select") not in eligible_ips:
        st.session_state.src_ip_select = alerts[0][2] if alerts else eligible_ips[0]

    if not alerts:
        st.markdown(
            '<div class="empty-state">✅ No hosts above the alert threshold right now — '
            "everything monitored looks like normal traffic.</div>",
            unsafe_allow_html=True,
        )
    elif not visible_alerts:
        st.markdown(
            '<div class="empty-state">No alerts match the current filter/search.</div>',
            unsafe_allow_html=True,
        )
    else:
        max_cards = 20
        for peak_prob, peak_step, host, stage_at_peak, probs_curve, (label, bg, fg) in visible_alerts[:max_cards]:
            card_col, btn_col = st.columns([5, 1])
            with card_col:
                st.markdown(
                    _alert_card_html(
                        host, label, bg, fg, peak_prob, (peak_step + 1) * window_s, stage_at_peak, probs_curve,
                    ),
                    unsafe_allow_html=True,
                )
            with btn_col:
                st.write("")
                if st.button("Investigate →", key=f"investigate_{host}"):
                    st.session_state.src_ip_select = host
        if len(visible_alerts) > max_cards:
            st.caption(
                f"+ {len(visible_alerts) - max_cards} more matching alerts not shown — "
                "investigate the highest-risk ones first."
            )
        if len(visible_alerts) < len(alerts):
            st.caption(f"Showing {len(visible_alerts)} of {len(alerts)} total alerts (filtered).")

    st.subheader("Audit Ledger")
    st.caption(
        "Every alert above is appended to a hash-chained, tamper-evident ledger — each entry's "
        "hash covers its own content plus the previous entry's hash, so altering any past record "
        "invalidates every hash after it. A single local append-only log, not a distributed "
        "blockchain — the tamper-evidence primitive without the multi-party consensus this "
        "single-writer use case doesn't need."
    )
    ledger = AuditLedger.load_or_create(ledger_path)
    simulate_tamper = st.checkbox(
        "Simulate tampering with the oldest entry (demo only — edits an in-memory copy, never the real ledger file)",
        key="simulate_tamper",
    )
    if simulate_tamper and ledger.entries:
        import copy
        tampered_ledger = copy.deepcopy(ledger)
        original = tampered_ledger.entries[0]
        tampered_ledger.entries[0] = original.__class__(
            **{**original.__dict__, "peak_infiltration_prob": 0.01},
        )
        ok, bad_index = tampered_ledger.verify_integrity()
    else:
        ok, bad_index = ledger.verify_integrity()

    if not ledger.entries:
        st.markdown(
            '<div class="empty-state">No ledger entries yet — alerts get logged the next time '
            "hosts are scored.</div>",
            unsafe_allow_html=True,
        )
    elif ok:
        st.markdown(
            f'<div class="ledger-status" style="background:rgba(12,163,12,0.12); color:{GOOD_COLOR};">'
            f"✅ Chain verified — {len(ledger.entries):,} entries, no tampering detected</div>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f'<div class="ledger-status" style="background:rgba(208,59,59,0.14); color:{SEVERITY_LEVELS[0][2]};">'
            f"❌ Chain broken at entry #{bad_index} — hash no longer matches recorded content</div>",
            unsafe_allow_html=True,
        )

    if ledger.entries:
        recent = ledger.entries[-10:][::-1]
        ledger_df = pd.DataFrame([{
            "index": e.index,
            "timestamp": e.timestamp,
            "host": e.host,
            "peak_prob": f"{e.peak_infiltration_prob:.0%}",
            "stage": e.peak_stage,
            "recommended_action": e.recommended_action,
            "hash": e.record_hash[:16] + "…",
        } for e in recent])
        st.dataframe(ledger_df.set_index("index"), use_container_width=True)
        st.caption(f"Showing the {len(recent)} most recent of {len(ledger.entries):,} total ledger entries.")

    st.divider()

    # ----------------------------------------------------------------------------------------
    # Investigation — full detail for one selected host (from an alert card, or picked directly).
    # ----------------------------------------------------------------------------------------
    st.subheader("Investigate a host")
    src_ip = st.selectbox("Source IP to forecast", eligible_ips, key="src_ip_select")
    horizon = config["windowing"]["forecast_horizon"]

    host_windows = windows[windows["src_ip"] == src_ip].sort_values("window_start").reset_index(drop=True)
    latest_idx = len(host_windows) - 1

    # Reset the scrub cursor to "now" whenever the investigated host changes — a leftover cursor
    # position from a different host's history is meaningless once carried over.
    if st.session_state.get("_cursor_host") != src_ip:
        st.session_state._cursor_host = src_ip
        st.session_state.time_cursor_idx = latest_idx

    if latest_idx >= seq_len:
        cursor_idx = st.slider(
            "⏱ Time cursor — replay this host's history",
            min_value=seq_len - 1,
            max_value=latest_idx,
            key="time_cursor_idx",
            help="Rewind to any earlier point in this host's traffic. The forecast below is "
                 "recomputed from only the history available up to that point — and, when real "
                 "traffic exists after it, overlaid with what actually happened next.",
        )
        cutoff_time = host_windows.loc[cursor_idx, "window_start"]
        if cursor_idx == latest_idx:
            st.caption(f"🟢 Live — most recent window ({cutoff_time})")
        else:
            st.caption(f"⏪ Replaying as of {cutoff_time} — {latest_idx - cursor_idx} window(s) before latest")
    else:
        cursor_idx = latest_idx
        cutoff_time = host_windows.loc[cursor_idx, "window_start"]

    truncated = host_windows.iloc[: cursor_idx + 1]
    raw_sequence = truncated[feature_cols].to_numpy(dtype=np.float32)[-seq_len:]

    future_rows = host_windows.iloc[cursor_idx + 1: cursor_idx + 1 + horizon]
    actual_infiltration = (
        [0.0 if s == BENIGN else 1.0 for s in future_rows["stage"]] if len(future_rows) > 0 else None
    )

    result = engine.rollout(raw_sequence)  # deterministic — drives the point predictions/explanations below
    with st.spinner("Estimating forecast uncertainty (MC-dropout)..."):
        uncertainty = engine.rollout_with_uncertainty(raw_sequence, n_samples=20)

    peak_step = int(np.argmax(result.infiltration_probs))
    peak_prob = float(result.infiltration_probs[peak_step])
    peak_stage = result.stage_predictions[peak_step]
    severity = _severity_for(peak_prob)
    if severity is not None:
        stage_bg, stage_fg = severity[1], severity[2]
    elif peak_stage == BENIGN:
        stage_bg, stage_fg = GOOD_COLOR, "#ffffff"
    else:
        stage_bg, stage_fg = "#2a78d6", "#ffffff"

    st.subheader(f"K-step infiltration forecast for {src_ip}")
    st.markdown(
        _stage_stepper_html(config["mitre_stages"], peak_stage, stage_bg, stage_fg),
        unsafe_allow_html=True,
    )

    current_observed_stage = host_windows.loc[cursor_idx, "stage"]
    narrative_col, response_col = st.columns([3, 2])
    with narrative_col:
        st.markdown("**Attack narrative**")
        narrative = generate_attack_narrative(
            src_ip, result, feature_cols, window_s, current_stage=current_observed_stage,
        )
        st.markdown(f'<div class="narrative-card">{narrative}</div>', unsafe_allow_html=True)
    with response_col:
        st.markdown("**Response playbook**")
        st.markdown(_response_card_html(peak_stage, stage_bg), unsafe_allow_html=True)

    with st.expander("Compliance report draft (CERT-In aligned)"):
        st.caption(
            "Drafts the report a compliance/SOC team would need to file under CERT-In's 2022 "
            "Directions (mandatory 6-hour reporting window, Section 70B(6) IT Act 2000) — a "
            "starting draft for human review, not a submission this system makes itself. See "
            "models/compliance.py for the honest scope caveats on the category mapping."
        )
        detected_at = cutoff_time.to_pydatetime().replace(tzinfo=timezone.utc)
        host_ledger_entries = [e for e in ledger.entries if e.host == src_ip]
        latest_hash = host_ledger_entries[-1].record_hash if host_ledger_entries else None
        compliance_report = generate_cert_in_report(
            src_ip, detected_at, peak_stage, peak_prob,
            recommended_action=recommended_action(peak_stage)["action"],
            narrative=narrative, ledger_hash=latest_hash,
        )
        if compliance_report.is_reportable:
            remaining = compliance_report.hours_remaining
            if remaining is not None:
                urgency_color = SEVERITY_LEVELS[0][2] if remaining < 1 else stage_bg
                status_line = f"⏱ {compliance_report.category} — {remaining:.1f}h remaining in the 6-hour reporting window"
            else:
                urgency_color = stage_bg
                status_line = (
                    f"⏱ {compliance_report.category} — historical/demo timestamp, "
                    "no live countdown (see draft for detail)"
                )
            st.markdown(
                f'<div class="ledger-status" style="background:rgba(208,59,59,0.10); color:{urgency_color};">'
                f"{status_line}</div>",
                unsafe_allow_html=True,
            )
            st.text_area("Draft report", compliance_report.text, height=320, key=f"cert_in_draft_{src_ip}")
            st.download_button(
                "Download draft (.txt)", compliance_report.text,
                file_name=f"cert_in_draft_{src_ip}_{detected_at.strftime('%Y%m%dT%H%M%S')}.txt",
                key=f"cert_in_download_{src_ip}",
            )
        else:
            st.caption(compliance_report.text)

    with st.expander("Related CVEs (NVD)"):
        st.caption(
            "Real, notable CVEs historically exploited to reach this forecasted MITRE stage in "
            "major reported incidents — a starting reference for an analyst's own investigation, "
            "not an automated match against this specific host (flow records carry no software/"
            "version field this system could fingerprint against). See models/cve_lookup.py."
        )
        cves = related_cves(peak_stage)
        if cves:
            for entry in cves:
                st.markdown(
                    f'<div class="ledger-status" style="background:rgba(208,59,59,0.10); color:{stage_bg};">'
                    f'<a href="{entry["url"]}" target="_blank">{entry["cve_id"]}</a> — '
                    f'CVSS {entry["cvss_v3_score"]:.1f} ({entry["severity"]}), published {entry["published"]}'
                    f'</div>',
                    unsafe_allow_html=True,
                )
                st.caption(entry["description"])
            meta = snapshot_metadata()
            st.caption(f"Source: {meta.get('source', 'NVD')} — snapshot cached {meta.get('fetched', 'n/a')}.")
        else:
            st.caption(f"No curated CVE reference for stage '{peak_stage}'.")

    timeline_df = pd.DataFrame({
        "step": [f"t+{(i + 1) * window_s}s" for i in range(horizon)],
        "infiltration_probability": result.infiltration_probs,
        "p10 (MC-dropout)": uncertainty.infiltration_p10,
        "p90 (MC-dropout)": uncertainty.infiltration_p90,
        "predicted_stage": result.stage_predictions,
    }).set_index("step")

    col1, col2 = st.columns([2, 1])
    with col1:
        st.altair_chart(_forecast_chart(timeline_df, window_s, actual_infiltration), use_container_width=True)
        caption = (
            "Blue line: deterministic forecast (dropout off, reproducible — matches eval/benchmark.py). "
            "Shaded band: 10th-90th percentile from 20 stochastic MC-dropout rollouts. "
            "Dashed gray lines: warning/serious/critical thresholds."
        )
        if actual_infiltration:
            caption += " Dashed white line: what **actually** happened next (ground truth, only visible while replaying history)."
        st.caption(caption)
    with col2:
        st.dataframe(timeline_df[["infiltration_probability", "predicted_stage"]], use_container_width=True)

    gauge_col, metric_col = st.columns([1, 2])
    with gauge_col:
        st.altair_chart(_gauge_chart(peak_prob, stage_bg), use_container_width=False)
        st.markdown(
            f'<div class="gauge-caption">Peak infiltration probability<br>'
            f'at {timeline_df.index[peak_step]} · predicted <b>{peak_stage.replace("_", " ")}</b></div>',
            unsafe_allow_html=True,
        )
    with metric_col:
        st.metric(
            "Predicted transition magnitude (step 1)",
            f"{result.transition_magnitude[0]:.2f}",
            help="Scaled-feature L2 norm of the model's predicted next-step state change — how much "
                 "the model believes conditions are about to shift. NOT a ground-truth accuracy measure; "
                 "see the novelty check below for that.",
        )

        prev_and_actual = previous_sequence_and_actual(truncated, feature_cols, src_ip, seq_len)
        if prev_and_actual is not None:
            prior_seq, actual_state = prev_and_actual
            novelty = one_step_reconstruction_error(model, scaler, prior_seq, actual_state)
            st.metric(
                "Novelty of most recently observed window",
                f"{novelty:.2f}",
                help="Ground-truth reconstruction error: how far the model's own prediction for the most "
                     "recent window (made from the history before it) was from what actually happened. "
                     "An unsupervised anomaly signal, independent of the infiltration/stage labels — a high "
                     "value means this traffic didn't match learned dynamics at all, whether or not it's "
                     "flagged as an attack.",
            )

    st.subheader("Explainability")
    exp_col1, exp_col2, exp_col3 = st.columns(3)

    with exp_col1:
        st.markdown("**Attention** — which past windows drove the first forecast step")
        attn_pairs = summarize_attention(result.attentions[0], seq_len)
        st.altair_chart(_attention_heat_chart(attn_pairs), use_container_width=True)

    with exp_col2:
        st.markdown("**Gradient x input** — instant feature attribution")
        grad_result = gradient_input_attribution(model, scaler.transform(raw_sequence), feature_cols)
        grad_df = pd.DataFrame(grad_result["top_features"], columns=["feature", "attribution"]).set_index("feature")
        st.bar_chart(grad_df)

    with exp_col3:
        st.markdown("**SHAP** — sampling-based feature attribution")
        if background is not None:
            with st.spinner("Computing SHAP attribution..."):
                shap_explainer = ShapExplainer(model, background)
                scaled_seq = scaler.transform(raw_sequence)
                shap_result = shap_explainer.explain(scaled_seq, feature_cols, nsamples=100)
            shap_df = pd.DataFrame(shap_result["top_features"], columns=["feature", "shap_value"]).set_index("feature")
            st.bar_chart(shap_df)
        else:
            st.info("No training data available to build a SHAP background distribution.")

    st.markdown("**What's about to change** — predicted feature deltas for the first forecast step")
    delta_order = np.argsort(-np.abs(result.state_deltas[0]))[:8]
    delta_df = pd.DataFrame({
        "feature": [feature_cols[i] for i in delta_order],
        "predicted_delta": result.state_deltas[0][delta_order],
    }).set_index("feature")
    st.dataframe(delta_df, use_container_width=True)

    st.subheader("What-if analysis")
    st.caption(
        "Perturb one feature on the most recently observed window and see how the K-step forecast "
        "shifts — a differentiable world model supports this natively; a black-box classifier "
        "would only tell you the new score, not let you probe it like this."
    )
    wf_col1, wf_col2 = st.columns([1, 2])
    with wf_col1:
        wf_feature = st.selectbox("Feature to perturb", feature_cols, key="whatif_feature")
        wf_feature_idx = feature_cols.index(wf_feature)
        wf_delta_std = st.slider(
            "Perturbation (standard deviations)", min_value=-5.0, max_value=5.0, value=2.0, step=0.5,
            key="whatif_delta_std",
        )
        wf_delta_raw = wf_delta_std * float(scaler.std[wf_feature_idx])
        st.caption(f"= {wf_delta_raw:+,.3g} raw units added to **{wf_feature}** on the most recent window")

    perturbed_sequence = raw_sequence.copy()
    perturbed_sequence[-1, wf_feature_idx] += wf_delta_raw
    counterfactual_result = engine.rollout(perturbed_sequence)

    with wf_col2:
        whatif_df = pd.DataFrame({
            "step": [f"t+{(i + 1) * window_s}s" for i in range(horizon)],
            "baseline": result.infiltration_probs,
            f"+{wf_delta_std:g} std {wf_feature}": counterfactual_result.infiltration_probs,
        }).set_index("step")
        st.line_chart(whatif_df)
        baseline_peak = float(result.infiltration_probs.max())
        cf_peak = float(counterfactual_result.infiltration_probs.max())
        shift = cf_peak - baseline_peak
        st.caption(
            f"Peak infiltration probability: {baseline_peak:.0%} → {cf_peak:.0%} "
            f"({'+' if shift >= 0 else ''}{shift:.0%}) after this perturbation."
        )

    flagged_label = "most recent window" if cursor_idx == latest_idx else f"window as of {cutoff_time}"
    st.subheader(f"Flagged flows — {flagged_label} for {src_ip}")
    flagged = flow_df[
        (flow_df["src_ip"] == src_ip)
        & (flow_df["timestamp"] >= cutoff_time)
        & (flow_df["timestamp"] < cutoff_time + pd.Timedelta(seconds=window_s))
    ]
    st.dataframe(
        flagged[["timestamp", "dst_ip", "dst_port", "protocol", "total_pkts", "total_bytes", "label"]],
        use_container_width=True,
    )


if __name__ == "__main__":
    main()
