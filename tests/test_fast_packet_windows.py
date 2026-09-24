"""The fast parser must agree with the Scapy path (load_pcap + compute_packet_window_features)."""
import numpy as np
import pandas as pd
import pytest
from scapy.all import ICMP, IP, TCP, UDP, Ether, IPv6, wrpcap
from scapy.layers.l2 import CookedLinux
from scapy.utils import PcapNgWriter

from pipeline.fast_packet_windows import PACKET_FEATURES, process_pcap, to_window_frame
from pipeline.packet_features import compute_packet_window_features, load_pcap

BASE = 1_700_000_000 - (1_700_000_000 % 10)


def _packets(link):
    """Three 10 s windows: a scan-ish host, a retransmitting TCP host, a UDP/frag host, and an IPv6 frame."""
    pkts = []

    def add(ip, l4, t, payload=b""):
        pkt = link / ip / l4 / payload if payload else link / ip / l4
        pkt.time = BASE + t
        pkts.append(pkt)

    for w in range(3):
        o = w * 10
        for i in range(20):  # host .5 scans many ports
            add(IP(src="10.0.0.5", dst="10.0.0.9", ttl=64), TCP(sport=4000 + i, dport=1000 + i + w, flags="S", window=1024 + i), o + 0.1 + i * 0.3)
        for i in range(6):  # host .6 sends a duplicated seq (retransmission)
            add(IP(src="10.0.0.6", dst="10.0.0.9", ttl=128), TCP(sport=5000, dport=80, seq=100 + (i % 3), flags="PA", window=8192), o + 1.0 + i * 0.4, b"x" * (10 * i))
        for i in range(4):  # host .7 UDP, some fragments
            add(IP(src="10.0.0.7", dst="10.0.0.8", ttl=32, flags="MF" if i == 1 else 0), UDP(sport=53, dport=5353), o + 2.0 + i * 0.5, b"y" * 50)
        p = link / IPv6(src="::1", dst="::2") / TCP(dport=80)
        p.time = BASE + o + 3.3
        pkts.append(p)  # not IPv4: both paths must skip it
    return pkts


@pytest.mark.parametrize("link_name,link", [("ethernet", Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")), ("linux_sll", CookedLinux())])
def test_fast_path_matches_scapy_path(tmp_path, link_name, link):
    path = tmp_path / f"{link_name}.pcap"
    wrpcap(str(path), _packets(link))
    ref = compute_packet_window_features(load_pcap(path), 10)

    feats, stats = process_pcap(path, 10)
    new = to_window_frame(feats)

    assert stats["frames"] > 0
    merged = ref.merge(new, on=["src_ip", "window_start"], suffixes=("_ref", "_new"))
    # first & last windows of a file are dropped by design, so only the middle window overlaps
    assert len(new) == 3 and len(merged) == 3
    for col in PACKET_FEATURES:
        np.testing.assert_allclose(merged[col + "_new"], merged[col + "_ref"].fillna(0.0), atol=1e-9, err_msg=col)
    # the scan host really has a high port-scan score and the retransmitter a non-zero retransmit ratio
    by_ip = merged.set_index("src_ip")
    assert by_ip.loc["10.0.0.5", "port_scan_score_new"] > 0.5
    assert by_ip.loc["10.0.0.6", "retransmit_ratio_new"] > 0.0
    assert by_ip.loc["10.0.0.7", "frag_ratio_new"] > 0.0


def test_fast_path_reads_pcapng(tmp_path):
    path = tmp_path / "cap.pcapng"
    writer = PcapNgWriter(str(path))
    for pkt in _packets(Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")):
        writer.write(pkt)
    writer.close()
    assert path.read_bytes()[:4] == b"\x0a\x0d\x0d\x0a"

    feats, _ = process_pcap(path, 10)

    assert len(feats) == 3


def test_chunking_does_not_change_the_result(tmp_path):
    path = tmp_path / "cap.pcap"
    wrpcap(str(path), _packets(Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")))
    whole, _ = process_pcap(path, 10)
    chunked, _ = process_pcap(path, 10, chunk_packets=17)  # forces the carry-over path many times
    key = ["src", "window_start_s"]
    pd.testing.assert_frame_equal(whole.sort_values(key).reset_index(drop=True),
                                  chunked.sort_values(key).reset_index(drop=True))


def test_unsupported_link_type_is_rejected(tmp_path):
    from scapy.all import RawPcapWriter
    path = tmp_path / "raw.pcap"
    w = RawPcapWriter(str(path), linktype=101, sync=True)  # raw IP, not handled
    w._write_header(None)
    w._write_packet(bytes(IP()), linktype=101, sec=BASE, usec=0, caplen=20, wirelen=20)
    w.close()
    with pytest.raises(ValueError, match="unsupported link type"):
        process_pcap(path, 10)


def test_sender_rule_keeps_each_packet_only_at_its_sender(tmp_path):
    """Host-based captures: a packet between two captured machines is in both captures; the rule keeps it only
    in the sender's. A sender with no capture of its own (external attacker) is kept wherever it was seen."""
    def ip_int(s):
        a, b, c, d = map(int, s.split("."))
        return (a << 24) | (b << 16) | (c << 8) | d

    link = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
    pkts = []
    for i in range(3):
        for src in ("10.0.0.1", "10.0.0.2", "99.9.9.9"):  # .1 and .2 are captured hosts; 99.9.9.9 is not
            p = link / IP(src=src, dst="10.0.0.1" if src != "10.0.0.1" else "10.0.0.2") / TCP(sport=1000 + i, dport=80)
            p.time = BASE + 12 + i  # all in the middle window
            pkts.append(p)
    for extra in (0, 25):  # pad first/last windows (dropped by design)
        p = link / IP(src="10.0.0.9", dst="10.0.0.1") / TCP(); p.time = BASE + extra; pkts.append(p)
    path = tmp_path / "cap.pcap"
    wrpcap(str(path), pkts)
    captured = np.array([ip_int("10.0.0.1"), ip_int("10.0.0.2")], dtype=np.uint32)

    at_host1, _ = process_pcap(path, 10, sender_rule=(ip_int("10.0.0.1"), captured))
    srcs = set(at_host1["src"].tolist())

    assert ip_int("10.0.0.1") in srcs          # host 1's own sent packets kept
    assert ip_int("99.9.9.9") in srcs          # uncaptured external sender kept
    assert ip_int("10.0.0.2") not in srcs      # host 2's packets belong to host 2's own capture


def test_output_names_are_unique_for_extensionless_captures_with_dots():
    from pipeline.fast_packet_windows import output_name

    names = [output_name(f"/x/pcap/capPC1-172.31.64.{i}") for i in (37, 52, 23)] + [output_name("/x/pcap/UCAP172.31.69.25")]
    assert len(set(names)) == len(names)  # Path.stem would have collapsed the first three to one name
