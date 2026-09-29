"""
Simulated Kafka consumer for real-time streaming ingestion.
In a real deployment, this script would connect to a Kafka broker or socket,
maintain a rolling window of flows, and push predictions to the SIEM/SOAR API.

Audit H3/W15: this used to build its matrix from only the flow-level feature list (19
columns) and zero-pad the remaining 22 -- including the 8 graph_embed_* columns, which are never
zero during training, so every forecast was silently off-distribution. It now builds the full
feature vector the same way pipeline/build_dataset.py does: real flow, graph, and graph-embedding
features computed per batch (the batch already has the cross-host context a graph needs), with only
the packet-level columns zero-filled -- which matches the documented, in-distribution convention
flow-only checkpoints were trained under (see pipeline/windowing.py::merge_packet_features and
audit W3). Column order and width now come from common.config.feature_columns(config), the same
helper every other consumer uses, and are asserted against the loaded checkpoint's own
`n_features` at startup so a schema mismatch fails loudly instead of silently (see W19).
"""
import argparse
import os
import time
from pathlib import Path

import numpy as np
import pandas as pd
import requests

from common.config import feature_columns, load_config
from models.checkpoint_io import load_checkpoint, validate_feature_names
from models.dataset import FeatureScaler
from models.forecast import ForecastEngine, load_world_model
from pipeline.flow_features import clean_and_normalize, load_flow_csv
from pipeline.graph_builder import build_window_graphs
from pipeline.graph_embedding_features import build_graph_embedding_window_features
from pipeline.graph_features import build_graph_window_features
from pipeline.windowing import (
    build_flow_windows, merge_graph_embedding_features, merge_graph_features, merge_packet_features,
)


def simulate_stream(csv_path: str, batch_size: int = 100):
    """Yields batches of flows from a CSV to simulate a real-time stream. Uses the same
    load_flow_csv + clean_and_normalize path every other CSV consumer uses, so column names
    (Src IP, Timestamp, ...) and derived fields (total_pkts, is_tcp, ...) match what
    build_flow_windows expects -- a raw CICFlowMeter CSV was never in the internal schema."""
    df = clean_and_normalize(load_flow_csv(csv_path, require_label=False))
    df = df.sort_values("timestamp")

    for start in range(0, len(df), batch_size):
        yield df.iloc[start:start + batch_size]
        time.sleep(0.5)  # Simulate network delay


def _build_batch_windows(batch: pd.DataFrame, config: dict) -> pd.DataFrame:
    """Same feature-assembly steps as pipeline/build_dataset.py, run on one streaming batch.
    Packet-level columns are zero-filled (no PCAP in this path) -- that is the same,
    already-documented convention flow-only checkpoints were trained under. Graph and
    graph-embedding columns are computed for real from the batch's own flows, since a graph
    only needs the cross-host context already present in one batch."""
    windows = build_flow_windows(batch, config)
    windows = merge_graph_features(windows, build_graph_window_features(batch, config), config)
    graphs = build_window_graphs(batch, config)
    windows = merge_graph_embedding_features(
        windows, build_graph_embedding_window_features(batch, config, graphs=graphs), config,
    )
    windows = merge_packet_features(windows, None, config)
    return windows


def run_consumer(config_path: str, data_path: str, api_url: str, api_token: str | None = None):
    config = load_config(config_path)

    print("Loading model and scaler...")
    ckpt_dir = Path(config["paths"]["checkpoint_dir"])
    ckpt_path = ckpt_dir / "world_model_best.pt"
    model, _ = load_world_model(ckpt_path)
    scaler = FeatureScaler.load(Path(config["paths"]["processed_dir"]) / "scaler.npz")
    engine = ForecastEngine(model, scaler, config)

    feature_cols = feature_columns(config)
    # Audit W19: fail loudly at startup on a schema mismatch, not with a silently-wrong forecast
    # later. Checks column NAMES and ORDER against what the checkpoint was trained on, not just
    # count -- a right-width, wrong-column matrix (this file's own H3 bug) passes a width check.
    validate_feature_names(load_checkpoint(ckpt_path), feature_cols)

    sequence_length = config["windowing"]["sequence_length"]
    host_buffers: dict[str, pd.DataFrame] = {}  # {src_ip: DataFrame of recent windows}

    headers = {"Authorization": f"Bearer {api_token}"} if api_token else {}

    print(f"Starting simulated stream from {data_path}...")
    for batch in simulate_stream(data_path):
        windows = _build_batch_windows(batch, config)

        for host_ip, host_windows in windows.groupby("src_ip"):
            if host_ip not in host_buffers:
                host_buffers[host_ip] = host_windows
            else:
                host_buffers[host_ip] = pd.concat([host_buffers[host_ip], host_windows])

            buffer_len = len(host_buffers[host_ip])
            if buffer_len > sequence_length:
                host_buffers[host_ip] = host_buffers[host_ip].iloc[-sequence_length:]

            if len(host_buffers[host_ip]) == sequence_length:
                raw_seq = host_buffers[host_ip][feature_cols].to_numpy(dtype=np.float32)

                result = engine.rollout(raw_seq)

                peak_prob = float(np.max(result.infiltration_probs))
                print(f"[FORECAST] {host_ip} - peak infiltration prob: {peak_prob:.4f} - "
                      f"stage: {result.stage_predictions[int(np.argmax(result.infiltration_probs))]}")
                if peak_prob > 0.5:
                    alert = {
                        "host_ip": host_ip,
                        "infiltration_prob": peak_prob,
                        "predicted_stage": result.stage_predictions[int(np.argmax(result.infiltration_probs))],
                        "timestamp": time.time(),
                    }
                    print(f"[ALERT] {host_ip} - Prob: {peak_prob:.2f} - Stage: {alert['predicted_stage']}")
                    try:
                        requests.post(f"{api_url}/api/v1/alerts/ingest", json=alert, headers=headers, timeout=5)
                    except Exception as e:
                        print(f"API Error: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--data", default="data/raw/synthetic_sample.csv")
    parser.add_argument("--api-url", default="http://localhost:8000")
    parser.add_argument("--api-token", default=os.environ.get("NAF_API_TOKEN"),
                         help="Bearer token for app/api.py (audit H1/W13 requires auth on every "
                              "endpoint). Defaults to the NAF_API_TOKEN environment variable.")
    args = parser.parse_args()

    run_consumer(args.config, args.data, args.api_url, args.api_token)
