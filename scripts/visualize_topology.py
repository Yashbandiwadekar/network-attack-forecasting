"""
Generates an interactive HTML network topology visualization of a specific time window
using Pyvis (requires pip install pyvis).
"""
import argparse
import pandas as pd
import networkx as nx
from pipeline.windowing import build_flow_windows
from common.config import load_config
import os

def visualize_window(csv_path: str, config_path: str, window_idx: int = 0, out_html: str = "topology.html"):
    try:
        from pyvis.network import Network
    except ImportError:
        print("Please install pyvis: pip install pyvis")
        return

    print("Loading config and data...")
    config = load_config(config_path)
    df = pd.read_csv(csv_path)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    
    # Build windows
    windows = build_flow_windows(df, config)
    
    # Get unique window starts
    window_starts = sorted(windows["window_start"].unique())
    if window_idx >= len(window_starts):
        print(f"Window index {window_idx} out of range (max {len(window_starts)-1})")
        return
        
    target_window = window_starts[window_idx]
    print(f"Visualizing topology for window starting at {target_window}...")
    
    window_df = windows[windows["window_start"] == target_window]
    
    # Create NetworkX graph
    G = nx.Graph()
    for _, row in window_df.iterrows():
        src = row["src_ip"]
        # Since this is a window dataset, dst_ips might be aggregated or not available in the windowed format
        # If we want the raw edges, we need the original df for that time window
        pass
    
    # Let's filter original df
    window_sec = config["windowing"]["window_seconds"]
    end_window = pd.to_datetime(target_window) + pd.Timedelta(seconds=window_sec)
    raw_window = df[(df["timestamp"] >= target_window) & (df["timestamp"] < end_window)]
    
    for _, row in raw_window.iterrows():
        src = row["src_ip"]
        dst = row["dst_ip"]
        label = row.get("label", "BENIGN")
        
        G.add_node(src, color="red" if label != "BENIGN" else "blue")
        G.add_node(dst, color="blue")
        if G.has_edge(src, dst):
            G[src][dst]["weight"] += 1
        else:
            G.add_edge(src, dst, weight=1)

    # PyVis
    net = Network(height="750px", width="100%", bgcolor="#222222", font_color="white")
    net.from_nx(G)
    
    # Save
    net.save_graph(out_html)
    print(f"Topology saved to {os.path.abspath(out_html)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--data", default="data/raw/synthetic_sample.csv")
    parser.add_argument("--window", type=int, default=0, help="Window index to visualize")
    parser.add_argument("--out", default="topology.html")
    args = parser.parse_args()
    
    visualize_window(args.config, args.data, args.window, args.out)
