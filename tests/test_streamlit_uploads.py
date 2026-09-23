"""Integration coverage for the app's upload path (audit S4/S5) -- calls _process_uploads
directly, the same function the Streamlit UI calls, so this exercises the real pipeline without
needing a live browser session."""
import numpy as np
from scapy.all import IP, TCP, wrpcap

from app.streamlit_app import _process_uploads
from common.config import load_config


def _make_pcap_only_capture(tmp_path):
    """A synthetic-looking SYN scan: one source hitting many destination ports fast -- gives the
    port-scan-score / reconnaissance heuristic something real to find, and spans several distinct
    10s windows so build_flow_windows produces more than one row."""
    import datetime

    base = datetime.datetime(2026, 1, 1, 0, 0, 0)
    pkts = []
    for i in range(80):
        pkt = IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=40000 + i, dport=1000 + i, flags="S")
        pkt.time = (base + datetime.timedelta(seconds=i * 3)).timestamp()
        pkts.append(pkt)
    path = tmp_path / "scan.pcap"
    wrpcap(str(path), pkts)
    return path


def test_pcap_only_upload_produces_real_windows_with_nonzero_packet_features(tmp_path):
    config = load_config("configs/default.yaml")
    pcap_path = _make_pcap_only_capture(tmp_path)

    flow_df, windows = _process_uploads(None, pcap_path, config)

    assert len(flow_df) > 0
    assert (flow_df["has_ip_data"] == 1.0).all()  # PCAP always carries real IPs
    assert len(windows) > 0
    assert "10.0.0.5" in set(windows["src_ip"])
    # Real packet-level features (not the zero-filled convention used when no PCAP is available).
    assert windows["has_packet_features"].max() == 1.0
    assert windows["mean_ttl"].max() > 0


def test_upload_with_neither_csv_nor_pcap_raises_clear_error():
    config = load_config("configs/default.yaml")
    try:
        _process_uploads(None, None, config)
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "flow CSV" in str(exc) or "PCAP" in str(exc)
