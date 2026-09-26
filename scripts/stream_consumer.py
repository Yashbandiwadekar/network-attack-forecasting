"""
Simulated Kafka consumer for real-time streaming ingestion.
In a real deployment, this script would connect to a Kafka broker or socket,
maintain a rolling window of flows, and push predictions to the SIEM/SOAR API.
"""
import time
import json
import argparse
import numpy as np
import pandas as pd
import requests
from pathlib import Path

from common.config import load_config
from pipeline.windowing import build_flow_windows
from models.forecast import ForecastEngine, load_world_model
from models.dataset import FeatureScaler

def simulate_stream(csv_path: str, batch_size: int = 100):
    """Yields batches of flows from a CSV to simulate a real-time stream."""
    df = pd.read_csv(csv_path)
    # Ensure it's sorted by time
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values("timestamp")
    
    for start in range(0, len(df), batch_size):
        yield df.iloc[start:start+batch_size]
        time.sleep(0.5)  # Simulate network delay

def run_consumer(config_path: str, data_path: str, api_url: str):
    config = load_config(config_path)
    
    # Load model and scaler
    print("Loading model and scaler...")
    ckpt_dir = Path(config["paths"]["checkpoint_dir"])
    model, _ = load_world_model(ckpt_dir / "world_model_best.pt")
    scaler = FeatureScaler.load(Path(config["paths"]["processed_dir"]) / "scaler.npz")
    engine = ForecastEngine(model, scaler, config)
    
    sequence_length = config["windowing"]["sequence_length"]
    feature_cols = config["features"]["flow_level"] # Simplified for demo, omitting packet/graph for speed
    
    # In-memory rolling window buffer
    # Format: {src_ip: DataFrame of recent windows}
    host_buffers = {}
    
    print(f"Starting simulated stream from {data_path}...")
    for batch in simulate_stream(data_path):
        # Process the new batch of flows into windows
        windows = build_flow_windows(batch, config)
        
        for host_ip, host_windows in windows.groupby("src_ip"):
            if host_ip not in host_buffers:
                host_buffers[host_ip] = host_windows
            else:
                host_buffers[host_ip] = pd.concat([host_buffers[host_ip], host_windows])
            
            # Keep only the latest sequence_length windows
            buffer_len = len(host_buffers[host_ip])
            if buffer_len > sequence_length:
                host_buffers[host_ip] = host_buffers[host_ip].iloc[-sequence_length:]
            
            # If we have a full sequence, run forecast
            if len(host_buffers[host_ip]) == sequence_length:
                raw_seq = host_buffers[host_ip][feature_cols].to_numpy(dtype=np.float32)
                # Pad remaining features with 0s if we only used flow_level
                total_features = len(scaler.mean)
                if raw_seq.shape[1] < total_features:
                    pad = np.zeros((sequence_length, total_features - raw_seq.shape[1]), dtype=np.float32)
                    raw_seq = np.concatenate([raw_seq, pad], axis=1)
                
                result = engine.rollout(raw_seq)
                
                # Check peak infiltration probability
                peak_prob = float(np.max(result.infiltration_probs))
                if peak_prob > 0.5:
                    alert = {
                        "host_ip": host_ip,
                        "infiltration_prob": peak_prob,
                        "predicted_stage": result.stage_predictions[int(np.argmax(result.infiltration_probs))],
                        "timestamp": time.time()
                    }
                    print(f"[ALERT] {host_ip} - Prob: {peak_prob:.2f} - Stage: {alert['predicted_stage']}")
                    try:
                        requests.post(f"{api_url}/api/v1/alerts/ingest", json=alert)
                    except Exception as e:
                        print(f"API Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--data", default="data/raw/synthetic_sample.csv")
    parser.add_argument("--api-url", default="http://localhost:8000")
    args = parser.parse_args()
    
    run_consumer(args.config, args.data, args.api_url)
