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


# ---------------------------------------------------------------------------
# G5: PCAP path and CSV path must agree on units (audit W2)
# ---------------------------------------------------------------------------

def test_pcap_and_csv_paths_produce_matching_window_features(tmp_path):
    """Same traffic, two routes: (a) a real multi-packet PCAP -> load_pcap -> build_flow_records,
    (b) a CICFlowMeter-format CSV whose values are computed here INDEPENDENTLY from the packet
    list (not by calling build_flow_records) -> load_flow_csv -> clean_and_normalize. Both go
    through build_flow_windows; the resulting window features must agree.

    data/raw/pcap/synthetic_sample.pcap cannot exercise this: all 944 of its flows are
    single-packet, so it has no inter-arrival times at all. This capture is generated here.
    """
    import numpy as np
    import pandas as pd

    from pipeline.flow_features import clean_and_normalize, load_flow_csv
    from pipeline.windowing import build_flow_windows

    base = 1_700_000_000 - (1_700_000_000 % 10)  # start of a 10s window
    # (src, dst, sport, dport, [(t_offset_s, direction, flags, payload_len), ...]) direction 0=fwd 1=bwd
    flows = [
        ("10.0.0.1", "10.0.0.2", 40000, 80, [(0.10, 0, "S", 0), (0.35, 1, "SA", 0), (0.40, 0, "A", 0),
                                              (1.20, 0, "PA", 120), (2.90, 1, "PA", 500), (3.00, 0, "FA", 0)]),
        ("10.0.0.1", "10.0.0.3", 40001, 443, [(0.50, 0, "S", 0), (0.62, 1, "SA", 0), (0.70, 0, "A", 0),
                                               (5.10, 0, "PA", 64)]),
    ]
    pkts, csv_rows = [], []
    for src, dst, sport, dport, plan in flows:
        times = np.array([base + t for t, *_ in plan])
        fwd = [d == 0 for _, d, _, _ in plan]
        for (t, d, fl, ln) in plan:
            a, b, sp, dp = (src, dst, sport, dport) if d == 0 else (dst, src, dport, sport)
            pkt = IP(src=a, dst=b) / TCP(sport=sp, dport=dp, flags=fl) / (b"x" * ln)
            pkt.time = base + t
            pkts.append(pkt)
        iats_us = np.diff(times) * 1e6
        csv_rows.append({
            "Src IP": src, "Dst IP": dst, "Src Port": sport, "Dst Port": dport, "Protocol": 6,
            "Timestamp": pd.Timestamp(times[0], unit="s").isoformat(),
            "Flow Duration": (times[-1] - times[0]) * 1e6,
            "Tot Fwd Pkts": sum(fwd), "Tot Bwd Pkts": len(fwd) - sum(fwd),
            "TotLen Fwd Pkts": sum(ln for (_, d, _, ln) in plan if d == 0),
            "TotLen Bwd Pkts": sum(ln for (_, d, _, ln) in plan if d == 1),
            "SYN Flag Cnt": sum("S" in fl for (_, _, fl, _) in plan),
            "ACK Flag Cnt": sum("A" in fl for (_, _, fl, _) in plan),
            "FIN Flag Cnt": sum("F" in fl for (_, _, fl, _) in plan),
            "RST Flag Cnt": 0, "URG Flag Cnt": 0,
            "PSH Flag Cnt": sum("P" in fl for (_, _, fl, _) in plan),
            "Flow IAT Mean": iats_us.mean(), "Flow IAT Std": iats_us.std(), "Flow IAT Max": iats_us.max(),
            "Label": "BENIGN",
        })

    pcap_path = tmp_path / "flows.pcap"
    _write_pcap(pcap_path, pkts)
    csv_path = tmp_path / "flows.csv"
    pd.DataFrame(csv_rows).to_csv(csv_path, index=False)
    config = {"windowing": {"window_seconds": 10}}

    from_pcap = build_flow_windows(build_flow_records(load_pcap(pcap_path)), config)
    from_csv = build_flow_windows(clean_and_normalize(load_flow_csv(csv_path)), config)

    cols = ["flow_count", "total_packets", "total_bytes", "mean_duration", "syn_ratio", "ack_ratio",
            "fin_ratio", "psh_ratio", "mean_iat", "var_iat", "max_iat", "bidir_ratio", "tcp_ratio"]
    assert len(from_pcap) == len(from_csv) == 1
    for col in cols:
        assert from_pcap[col].iloc[0] == pytest.approx(from_csv[col].iloc[0], rel=1e-3, abs=1e-6), col
    # and the IAT features really are on the microsecond scale the model was trained on
    assert from_pcap["mean_iat"].iloc[0] > 1e5
