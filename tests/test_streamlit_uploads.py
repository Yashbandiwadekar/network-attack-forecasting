"""Integration coverage for the app's upload path (audit S4/S5) -- calls _process_uploads
directly, the same function the Streamlit UI calls, so this exercises the real pipeline without
needing a live browser session."""
import numpy as np
from scapy.all import IP, TCP, wrpcap

from app.streamlit_app import _process_uploads
from common.config import load_config


def _packet_trained_config(tmp_path):
    """Config whose processed_dir has no flow_only metadata, i.e. a hypothetical model trained
    with packet features. (Neither shipped checkpoint is one: audit G11.)"""
    config = load_config("configs/default.yaml")
    config["paths"]["processed_dir"] = str(tmp_path / "packet_trained_processed")
    return config


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
    config = _packet_trained_config(tmp_path)
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


def test_flow_only_models_get_zero_packet_features(tmp_path):
    """Audit G11/W3: both shipped models (real and synthetic-data) are flow-only per their own
    metadata.json, so a PCAP upload must not feed them packet features."""
    pcap_path = _make_pcap_only_capture(tmp_path)
    for cfg_path in ("configs/real_data.yaml", "configs/default.yaml"):
        cfg = load_config(cfg_path)
        _, w = _process_uploads(None, pcap_path, cfg)
        pk = list(cfg["features"]["packet_level"])
        print(cfg_path, "max packet features:", w[pk].max().to_dict())
        assert (w[pk] == 0).all().all()
        assert (w["has_packet_features"] == 0).all()
    _, w2 = _process_uploads(None, pcap_path, _packet_trained_config(tmp_path))
    print("packet-trained (hypothetical):", w2[pk].max().to_dict())
    assert w2["has_packet_features"].max() == 1.0 and w2["mean_ttl"].max() > 0
