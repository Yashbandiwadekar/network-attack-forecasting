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
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd
import streamlit as st

from common.config import feature_columns, load_config, resolve_path
from models.dataset import FeatureScaler, load_split
from models.explain import ShapExplainer, summarize_attention
from models.forecast import ForecastEngine, latest_sequence, load_world_model
from pipeline.flow_features import clean_and_normalize, load_flow_csv
from pipeline.packet_features import compute_packet_window_features, load_pcap
from pipeline.windowing import apply_reconnaissance_heuristic, build_flow_windows, merge_packet_features

st.set_page_config(page_title="Network Attack Forecasting", layout="wide")


@st.cache_resource
def _load_backend():
    config = load_config("configs/default.yaml")
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
    windows = apply_reconnaissance_heuristic(windows, config)
    return flow_df, windows


def main() -> None:
    st.title("AI-Based Network Attack Forecasting")
    st.caption(
        "World-model forecast of attacker progression from network traffic — runs fully offline, "
        "no cloud API calls. Upload a CICFlowMeter CSV (+ optional PCAP) or use the bundled "
        "synthetic sample."
    )

    config, model, scaler, background = _load_backend()
    if model is None:
        st.error(
            "No trained checkpoint found. Run `python -m models.train` first "
            "(after `python -m pipeline.build_dataset`)."
        )
        return

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
    eligible_ips = sorted(windows.groupby("src_ip").size()[lambda s: s >= seq_len].index.tolist())
    if not eligible_ips:
        st.warning(f"No source IP has {seq_len}+ consecutive windows of history yet — need more traffic.")
        return

    src_ip = st.selectbox("Source IP to forecast", eligible_ips)
    feature_cols = feature_columns(config)
    raw_sequence = latest_sequence(windows, feature_cols, src_ip, seq_len)

    engine = ForecastEngine(model, scaler, config)
    result = engine.rollout(raw_sequence)

    st.subheader(f"K-step infiltration forecast for {src_ip}")
    horizon = config["windowing"]["forecast_horizon"]
    window_s = config["windowing"]["window_seconds"]
    timeline_df = pd.DataFrame({
        "step": [f"t+{(i + 1) * window_s}s" for i in range(horizon)],
        "infiltration_probability": result.infiltration_probs,
        "predicted_stage": result.stage_predictions,
    }).set_index("step")

    col1, col2 = st.columns([2, 1])
    with col1:
        st.line_chart(timeline_df["infiltration_probability"])
    with col2:
        st.dataframe(timeline_df, use_container_width=True)

    peak_step = int(np.argmax(result.infiltration_probs))
    st.metric(
        "Peak infiltration probability",
        f"{result.infiltration_probs[peak_step]:.1%}",
        help=f"At {timeline_df.index[peak_step]}, predicted stage: {result.stage_predictions[peak_step]}",
    )

    st.subheader("Explainability")
    exp_col1, exp_col2 = st.columns(2)

    with exp_col1:
        st.markdown("**Attention — which past windows drove the first forecast step**")
        attn_pairs = summarize_attention(result.attentions[0], seq_len)
        st.bar_chart(pd.DataFrame(attn_pairs, columns=["window", "attention_weight"]).set_index("window"))

    with exp_col2:
        st.markdown("**SHAP — which features drove the first forecast step's infiltration score**")
        if background is not None:
            with st.spinner("Computing SHAP attribution..."):
                shap_explainer = ShapExplainer(model, background)
                scaled_seq = scaler.transform(raw_sequence)
                shap_result = shap_explainer.explain(scaled_seq, feature_cols, nsamples=100)
            shap_df = pd.DataFrame(shap_result["top_features"], columns=["feature", "shap_value"]).set_index("feature")
            st.bar_chart(shap_df)
        else:
            st.info("No training data available to build a SHAP background distribution.")

    st.subheader(f"Flagged flows — most recent window for {src_ip}")
    latest_window_start = windows[windows["src_ip"] == src_ip]["window_start"].max()
    flagged = flow_df[
        (flow_df["src_ip"] == src_ip)
        & (flow_df["timestamp"] >= latest_window_start)
        & (flow_df["timestamp"] < latest_window_start + pd.Timedelta(seconds=window_s))
    ]
    st.dataframe(
        flagged[["timestamp", "dst_ip", "dst_port", "protocol", "total_pkts", "total_bytes", "label"]],
        use_container_width=True,
    )


if __name__ == "__main__":
    main()
