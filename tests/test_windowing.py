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


def test_build_flow_windows_defaults_has_ip_data_when_column_absent():
    # callers that don't route through flow_features.clean_and_normalize (e.g. this test file's
    # own _flow() fixture) get has_ip_data=1.0 by default, preserving old behaviour
    rows = [_flow(0, dst_ip="10.0.0.60"), _flow(1, dst_ip="10.0.0.70")]
    windows = build_flow_windows(pd.DataFrame(rows), TEST_CONFIG)
    assert windows.iloc[0]["has_ip_data"] == 1.0
    assert windows.iloc[0]["unique_dst_ips"] == 2  # real dst_ip diversity, computed normally


def test_build_flow_windows_zero_fills_unique_dst_ips_without_real_ip_data():
    # dst_ip is a constant sentinel ("UNKNOWN") when has_ip_data=0 — nunique() would trivially
    # read 1, which looks like a real "only one destination" signal but isn't
    rows = [
        _flow(0, dst_ip="UNKNOWN", has_ip_data=0.0),
        _flow(1, dst_ip="UNKNOWN", has_ip_data=0.0),
    ]
    windows = build_flow_windows(pd.DataFrame(rows), TEST_CONFIG)
    assert windows.iloc[0]["has_ip_data"] == 0.0
    assert windows.iloc[0]["unique_dst_ips"] == 0.0


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
    assert merged["has_packet_features"].iloc[0] == 0.0


def test_merge_packet_features_flags_covered_windows():
    # two windows for the same src_ip; only the first has PCAP coverage
    flow_windows = pd.DataFrame([
        {"src_ip": "a", "window_start": pd.Timestamp("2026-01-01 00:00:00"), "flow_count": 1},
        {"src_ip": "a", "window_start": pd.Timestamp("2026-01-01 00:00:10"), "flow_count": 1},
    ])
    packet_windows = pd.DataFrame([
        {"src_ip": "a", "window_start": pd.Timestamp("2026-01-01 00:00:00"),
         "port_scan_score": 0.7, "retransmit_ratio": 0.1},
    ])
    merged = merge_packet_features(flow_windows, packet_windows, TEST_CONFIG)
    assert merged["has_packet_features"].tolist() == [1.0, 0.0]
    assert merged.loc[0, "port_scan_score"] == 0.7
    assert merged.loc[1, "port_scan_score"] == 0.0  # zero-filled, not NaN, for the uncovered window


def test_has_packet_features_not_a_near_perfect_label_proxy_on_synthetic_sample():
    """Regression guard for the exact leak class a competing project's PCAP found and fixed on
    their own dataset: PCAP coverage that only spans some attack phases makes
    `has_packet_features` a proxy for "early vs late attack" rather than genuine information.
    Runs the real synthetic-sample pipeline end-to-end and checks the correlation stays low.
    """
    import pytest

    from common.config import load_config, resolve_path
    from pipeline.flow_features import load_flow_dir
    from pipeline.packet_features import compute_packet_window_features, load_pcap

    config = load_config("configs/default.yaml")
    flow_dir = resolve_path(config, "raw_flow_dir")
    pcap_dir = resolve_path(config, "raw_pcap_dir")
    if not flow_dir.exists() or not any(flow_dir.glob("*.csv")):
        pytest.skip("synthetic sample not generated yet — run `python -m scripts.make_synthetic_sample`")

    flow_df = load_flow_dir(flow_dir)
    flow_windows = build_flow_windows(flow_df, config)
    packet_windows = None
    if pcap_dir.exists() and any(pcap_dir.glob("*.pcap")):
        frames = [compute_packet_window_features(load_pcap(p), config["windowing"]["window_seconds"])
                  for p in sorted(pcap_dir.glob("*.pcap"))]
        packet_windows = pd.concat(frames, ignore_index=True)
    windows = merge_packet_features(flow_windows, packet_windows, config)
    windows = apply_reconnaissance_heuristic(windows, config)

    is_attack = (windows["stage"] != BENIGN).astype(float)
    has_pf = windows["has_packet_features"]
    if has_pf.nunique() < 2 or is_attack.nunique() < 2:
        return  # nothing to correlate against — not the failure mode this test guards
    correlation = abs(np.corrcoef(has_pf, is_attack)[0, 1])
    assert correlation < 0.6, (
        f"has_packet_features correlates with the attack label at {correlation:.2f} — PCAP "
        "coverage is acting as a label proxy instead of carrying independent information; "
        "extend PCAP generation to cover the missing phases"
    )


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
    # i=0's last INPUT window is index 1 (benign); i=1's last input window is index 2 (also benign)
    # — current_stage/current_infiltration describe the input window itself, not the future
    assert seqs["current_infiltration"].tolist() == [0.0, 0.0]
    assert seqs["current_stage"].tolist() == [0, 0]  # 0 == benign's index in STAGE_CLASSIFICATION_LABELS


def test_build_sequences_window_times_covers_every_input_step_not_just_the_last():
    # Same 5-window setup as test_build_sequences_shapes_and_alignment: seq_len=2, horizon=2 ->
    # 2 samples (i=0,1). window_times should carry the window_start of BOTH input steps per
    # sample, not just the final one window_end_time already captures.
    feature_cols = ["flow_count"]
    starts = [pd.Timestamp("2026-01-01") + pd.Timedelta(seconds=10 * i) for i in range(5)]
    windows = pd.DataFrame([
        {"src_ip": "a", "window_start": starts[i], "flow_count": float(i),
         "stage": BENIGN if i != 3 else "command_and_control"}
        for i in range(5)
    ])
    seqs = build_sequences(windows, feature_cols, TEST_CONFIG)

    assert seqs["window_times"].shape == (2, 2)
    # sample 0 uses input windows i=0,1; sample 1 uses input windows i=1,2
    np.testing.assert_array_equal(seqs["window_times"][0], np.array([starts[0], starts[1]], dtype="datetime64[ns]"))
    np.testing.assert_array_equal(seqs["window_times"][1], np.array([starts[1], starts[2]], dtype="datetime64[ns]"))
    # the last column must always match window_end_time, which was already correct before this field existed
    np.testing.assert_array_equal(seqs["window_times"][:, -1], seqs["window_end_time"])


def test_build_sequences_current_infiltration_true_when_last_input_window_is_an_attack():
    # 5 windows, index 1 (the src_ip's second window) is itself an attack
    feature_cols = ["flow_count"]
    windows = pd.DataFrame([
        {"src_ip": "a", "window_start": pd.Timestamp("2026-01-01") + pd.Timedelta(seconds=10 * i),
         "flow_count": float(i), "stage": "initial_access" if i == 1 else BENIGN}
        for i in range(5)
    ])
    seqs = build_sequences(windows, feature_cols, TEST_CONFIG)
    # i=0's last input window is index 1 -> the attack window itself
    assert seqs["current_infiltration"][0] == 1.0
    assert seqs["current_stage"][0] == 2  # initial_access's index in STAGE_CLASSIFICATION_LABELS
