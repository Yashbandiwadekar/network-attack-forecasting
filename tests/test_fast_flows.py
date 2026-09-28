"""Fast flow assembly must match the CICFlowMeter-style semantics used by the CSV path (units, counts, IAT us)."""
import numpy as np
import pytest
from scapy.all import IP, TCP, UDP, Ether, wrpcap

from pipeline.fast_packet_windows import assemble_flows, ip_to_str, read_all_frames
from pipeline.packet_features import build_flow_records, load_pcap

BASE = 1_700_000_000 - (1_700_000_000 % 10)
LINK = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")


def _ip(s):
    a, b, c, d = map(int, s.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def _pcap(tmp_path, plan):
    """plan: list of (src, dst, sport, dport, flags, t_offset, payload_len)."""
    pkts = []
    for src, dst, sp, dp, fl, t, ln in plan:
        p = LINK / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags=fl) / (b"x" * ln)
        p.time = BASE + t
        pkts.append(p)
    path = tmp_path / "c.pcap"
    wrpcap(str(path), pkts)
    return path


TWO_FLOWS = [
    ("10.0.0.1", "10.0.0.2", 40000, 80, "S", 0.10, 0), ("10.0.0.2", "10.0.0.1", 80, 40000, "SA", 0.35, 0),
    ("10.0.0.1", "10.0.0.2", 40000, 80, "A", 0.40, 0), ("10.0.0.1", "10.0.0.2", 40000, 80, "PA", 1.20, 120),
    ("10.0.0.2", "10.0.0.1", 80, 40000, "PA", 2.90, 500), ("10.0.0.1", "10.0.0.2", 40000, 80, "FA", 3.00, 0),
    ("10.0.0.1", "10.0.0.3", 40001, 443, "S", 0.50, 0), ("10.0.0.3", "10.0.0.1", 443, 40001, "SA", 0.62, 0),
]


def test_assembled_flows_match_independently_computed_values(tmp_path):
    flows = assemble_flows(read_all_frames(_pcap(tmp_path, TWO_FLOWS)))
    f = flows[flows["dst_ip"] == _ip("10.0.0.2")].iloc[0]
    times = np.array([0.10, 0.35, 0.40, 1.20, 2.90, 3.00])
    iat_us = np.diff(times) * 1e6
    assert len(flows) == 2
    assert f["total_pkts"] == 6 and f["total_bytes"] == 620  # L4 payload only, both directions
    assert f["duration_s"] == pytest.approx(2.90) and f["is_tcp"] == 1.0 and f["is_udp"] == 0.0
    assert (f["syn_cnt"], f["ack_cnt"], f["fin_cnt"], f["psh_cnt"], f["rst_cnt"]) == (2, 5, 1, 2, 0)
    assert f["iat_mean"] == pytest.approx(iat_us.mean(), rel=1e-6)   # microseconds, like CICFlowMeter
    assert f["iat_std"] == pytest.approx(iat_us.std(), rel=1e-6)
    assert f["iat_max"] == pytest.approx(iat_us.max(), rel=1e-6)
    assert f["bidir_ratio"] == pytest.approx(2 / 6)                  # 4 fwd, 2 bwd
    assert f["src_ip"] == _ip("10.0.0.1")                            # initiator = first packet's sender


def test_agrees_with_the_slow_scapy_flow_builder(tmp_path):
    path = _pcap(tmp_path, TWO_FLOWS)
    slow = build_flow_records(load_pcap(path)).sort_values("dst_port").reset_index(drop=True)
    fast = assemble_flows(read_all_frames(path)).sort_values("dst_port").reset_index(drop=True)
    for col in ("total_pkts", "total_bytes", "syn_cnt", "ack_cnt", "fin_cnt", "psh_cnt", "bidir_ratio", "is_tcp"):
        np.testing.assert_allclose(fast[col], slow[col], rtol=1e-9, err_msg=col)
    # timestamps in a classic PCAP have microsecond resolution and the two readers round differently (~1 us)
    np.testing.assert_allclose(fast["duration_s"], slow["duration_s"], atol=5e-6, err_msg="duration_s")
    for col in ("iat_mean", "iat_std", "iat_max"):  # these are in microseconds
        np.testing.assert_allclose(fast[col], slow[col], atol=5.0, rtol=1e-4, err_msg=col)


def test_flow_is_cut_after_the_120s_timeout(tmp_path):
    plan = [("10.0.0.1", "10.0.0.2", 5000, 21, "PA", t, 10) for t in (0.0, 30.0, 119.0, 121.0, 200.0)]
    flows = assemble_flows(read_all_frames(_pcap(tmp_path, plan))).sort_values("timestamp_s")
    assert list(flows["total_pkts"]) == [3, 2]  # 0/30/119 s, then 121/200 s


def test_flow_kept_only_in_its_initiators_capture(tmp_path):
    path = _pcap(tmp_path, TWO_FLOWS)
    cols = read_all_frames(path)
    captured = np.array([_ip("10.0.0.1"), _ip("10.0.0.2")], dtype=np.uint32)  # 10.0.0.3 has no capture
    at_1 = assemble_flows(cols, captured, _ip("10.0.0.1"))
    at_2 = assemble_flows(cols, captured, _ip("10.0.0.2"))
    assert len(at_1) == 2      # host 1 initiated both flows (to a captured .2 and an uncaptured .3)
    assert len(at_2) == 0      # host 2 only *received* the flow host 1 started -> counted at host 1


def test_ip_to_str_roundtrip():
    import pandas as pd
    assert list(ip_to_str(pd.Series([_ip("18.221.219.4"), _ip("172.31.69.25")], dtype=np.uint32))) == ["18.221.219.4", "172.31.69.25"]
