import numpy as np
import pandas as pd

from pipeline.mitre_mapping import BENIGN, RECONNAISSANCE
from pipeline.windowing import apply_reconnaissance_heuristic, build_flow_windows, build_sequences, merge_packet_features

FLOW_COLS = [
    "timestamp", "src_ip", "dst_ip", "dst_port", "total_bytes", "total_pkts", "duration_s",
    "syn_cnt", "ack_cnt", "fin_cnt", "rst_cnt", "psh_cnt", "urg_cnt",
    "iat_mean", "iat_std", "iat_max", "bidir_ratio", "is_tcp", "is_udp", "label",
]

TEST_CONFIG = {
    "windowing": {
        "window_seconds": 10,
        "sequence_length": 2,
        "forecast_horizon": 2,
        "recon_port_scan_threshold": 0.5,
    },
    "features": {
        "flow_level": ["flow_count", "unique_dst_ports", "total_bytes", "total_packets", "syn_ratio"],
        "packet_level": ["port_scan_score", "retransmit_ratio"],
    },
}


def _flow(t, src_ip="10.0.0.9", dst_ip="10.0.0.50", dst_port=22, label="BENIGN", **overrides):
    row = dict(
        timestamp=pd.Timestamp("2026-01-01") + pd.Timedelta(seconds=t),
        src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
        total_bytes=100, total_pkts=5, duration_s=1.0,
        syn_cnt=1, ack_cnt=2, fin_cnt=0, rst_cnt=0, psh_cnt=1, urg_cnt=0,
        iat_mean=10.0, iat_std=1.0, iat_max=20.0, bidir_ratio=0.5, is_tcp=1.0, is_udp=0.0,
        label=label,
    )
    row.update(overrides)
    return row


def test_build_flow_windows_majority_label_wins():
    # 3 benign flows + 1 attack flow in the same window -> window is labelled by the attack
    rows = [_flow(0) for _ in range(3)] + [_flow(1, label="SSH-Bruteforce")]
    df = pd.DataFrame(rows)
    windows = build_flow_windows(df, TEST_CONFIG)

    assert len(windows) == 1
    assert windows.iloc[0]["flow_count"] == 4
    assert windows.iloc[0]["stage"] == "initial_access"


def test_reconnaissance_heuristic_relabels_precursor_window():
    # window 0: benign with high port-scan score, window 1: an actual attack -> window 0 becomes recon
    windows = pd.DataFrame([
        {"src_ip": "10.0.0.9", "window_start": pd.Timestamp("2026-01-01 00:00:00"),
         "stage": BENIGN, "port_scan_score": 0.9},
        {"src_ip": "10.0.0.9", "window_start": pd.Timestamp("2026-01-01 00:00:10"),
         "stage": "initial_access", "port_scan_score": 0.0},
    ])
    out = apply_reconnaissance_heuristic(windows, TEST_CONFIG)
    assert out.iloc[0]["stage"] == RECONNAISSANCE
    assert out.iloc[1]["stage"] == "initial_access"


def test_reconnaissance_heuristic_leaves_isolated_scan_alone():
    # high port-scan score but nothing attacks afterwards -> stays benign
    windows = pd.DataFrame([
        {"src_ip": "10.0.0.9", "window_start": pd.Timestamp("2026-01-01 00:00:00"),
         "stage": BENIGN, "port_scan_score": 0.9},
        {"src_ip": "10.0.0.9", "window_start": pd.Timestamp("2026-01-01 00:00:10"),
         "stage": BENIGN, "port_scan_score": 0.0},
    ])
    out = apply_reconnaissance_heuristic(windows, TEST_CONFIG)
    assert out.iloc[0]["stage"] == BENIGN


def test_merge_packet_features_zero_fills_when_no_pcap():
    flow_windows = pd.DataFrame([{"src_ip": "10.0.0.9", "window_start": pd.Timestamp("2026-01-01"), "flow_count": 1}])
    merged = merge_packet_features(flow_windows, None, TEST_CONFIG)
    assert merged["port_scan_score"].iloc[0] == 0.0
    assert merged["retransmit_ratio"].iloc[0] == 0.0


def test_build_sequences_shapes_and_alignment():
    # 5 windows for one src_ip, seq_len=2, horizon=2 -> valid starts i=0,1 (5-2-2=1 -> range(2))
    feature_cols = ["flow_count"]
    windows = pd.DataFrame([
        {"src_ip": "a", "window_start": pd.Timestamp("2026-01-01") + pd.Timedelta(seconds=10 * i),
         "flow_count": float(i), "stage": BENIGN if i != 3 else "command_and_control"}
        for i in range(5)
    ])
    seqs = build_sequences(windows, feature_cols, TEST_CONFIG)

    assert seqs["X"].shape == (2, 2, 1)
    np.testing.assert_array_equal(seqs["X"][0, :, 0], [0.0, 1.0])
    np.testing.assert_array_equal(seqs["next_state"][0], [2.0])
    # i=0: future windows are indices 2,3 -> stage at index 3 is command_and_control (attack)
    assert seqs["infiltration"][0].tolist() == [0.0, 1.0]
