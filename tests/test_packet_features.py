from pathlib import Path

import pytest
from scapy.all import IP, TCP, UDP, wrpcap
from scapy.utils import PcapNgWriter

from pipeline.packet_features import build_flow_records, load_pcap


def _write_pcap(path: Path, packets: list) -> None:
    wrpcap(str(path), packets)


def _write_pcapng(path: Path, packets: list) -> None:
    writer = PcapNgWriter(str(path))
    for pkt in packets:
        writer.write(pkt)
    writer.close()


# ---------------------------------------------------------------------------
# S4: PCAPNG must parse, not just classic PCAP
# ---------------------------------------------------------------------------

def test_load_pcap_reads_classic_pcap(tmp_path):
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S")
    path = tmp_path / "capture.pcap"
    _write_pcap(path, [pkt])

    df = load_pcap(path)

    assert len(df) == 1
    assert df.loc[0, "src_ip"] == "10.0.0.1"
    assert df.loc[0, "protocol"] == "TCP"


def test_load_pcap_reads_genuine_pcapng(tmp_path):
    """Audit S4: a real pcapng-magic file (not just a renamed .pcap) must parse. Confirms scapy's
    PcapReader dispatches on magic bytes -- the fix is only in the Streamlit uploader's `type=`."""
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S")
    path = tmp_path / "capture.pcapng"
    _write_pcapng(path, [pkt])
    assert path.read_bytes()[:4] == b"\x0a\x0d\x0d\x0a"  # genuine pcapng magic, not renamed pcap

    df = load_pcap(path)

    assert len(df) == 1
    assert df.loc[0, "src_ip"] == "10.0.0.1"


def test_load_pcap_captures_tcp_flags(tmp_path):
    pkts = [
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1111, dport=80, flags="S"),
        IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1111, flags="SA"),
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1111, dport=80, flags="A"),
    ]
    path = tmp_path / "capture.pcap"
    _write_pcap(path, pkts)

    df = load_pcap(path)

    assert df.loc[0, ["flag_syn", "flag_ack"]].tolist() == [1, 0]
    assert df.loc[1, ["flag_syn", "flag_ack"]].tolist() == [1, 1]
    assert df.loc[2, ["flag_syn", "flag_ack"]].tolist() == [0, 1]


def test_load_pcap_raises_on_no_ip_packets(tmp_path):
    from scapy.all import Ether

    path = tmp_path / "no_ip.pcap"
    _write_pcap(path, [Ether()])

    with pytest.raises(ValueError, match="No IP packets"):
        load_pcap(path)


# ---------------------------------------------------------------------------
# S4: PCAP-only flow-record derivation (no CSV needed)
# ---------------------------------------------------------------------------

def test_build_flow_records_merges_both_directions_into_one_flow(tmp_path):
    pkts = [
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1111, dport=80, flags="S"),
        IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1111, flags="SA"),
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1111, dport=80, flags="A"),
    ]
    path = tmp_path / "capture.pcap"
    _write_pcap(path, pkts)
    packet_df = load_pcap(path)

    records = build_flow_records(packet_df)

    assert len(records) == 1  # both directions of the same conversation -> one flow
    row = records.iloc[0]
    assert row["total_pkts"] == 3
    assert row["syn_cnt"] == 2  # packets 1 (S) and 2 (SA) both set SYN
    assert row["ack_cnt"] == 2  # packets 2 (SA) and 3 (A) both set ACK
    assert row["is_tcp"] == 1.0
    assert row["has_ip_data"] == 1.0
    assert row["label"] == "BENIGN"
    # forward = the first packet's direction (10.0.0.1 -> 10.0.0.2): 2 forward, 1 backward
    assert 0.0 < row["bidir_ratio"] <= 0.5


def test_build_flow_records_keeps_separate_flows_separate(tmp_path):
    pkts = [
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1111, dport=80, flags="S"),
        IP(src="10.0.0.3", dst="10.0.0.4") / UDP(sport=53, dport=5353),
    ]
    path = tmp_path / "capture.pcap"
    _write_pcap(path, pkts)
    packet_df = load_pcap(path)

    records = build_flow_records(packet_df)

    assert len(records) == 2
    assert set(records["is_tcp"]) == {1.0, 0.0}


def test_build_flow_records_drops_icmp_only_capture(tmp_path):
    from scapy.all import ICMP

    path = tmp_path / "icmp_only.pcap"
    _write_pcap(path, [IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()])
    packet_df = load_pcap(path)

    with pytest.raises(ValueError, match="No TCP/UDP packets"):
        build_flow_records(packet_df)
