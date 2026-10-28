"""Byte counts and timestamps from the fast parser on awkward captures (docs/11): Ethernet padding,
snaplen truncation, nanosecond pcaps, and frames the parser skips."""
import struct

import numpy as np
from scapy.all import IP, TCP, UDP, Ether, Padding, wrpcap

from pipeline.fast_packet_windows import assemble_flows, read_all_frames, read_all_frames_counted
from pipeline.packet_features import build_flow_records, load_pcap

LINK = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")


def _classic_pcap(path, frames, snaplen=65535, nano=False, linktype=1):
    """frames: list of (ts_seconds, raw_bytes, wire_len). Hand-written so truncation is real."""
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = struct.pack("<IHHiIII", magic, 2, 4, 0, 0, snaplen, linktype)
    for ts, data, wire in frames:
        sec = int(ts)
        frac = int(round((ts - sec) * (1e9 if nano else 1e6)))
        out += struct.pack("<IIII", sec, frac, len(data), wire) + data
    path.write_bytes(out)
    return path


def test_ethernet_padding_is_not_payload(tmp_path):
    """A pure ACK is 54 bytes; Ethernet pads it to 60, and those 6 bytes are not TCP payload."""
    pkt = LINK / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2, flags="A") / Padding(b"\x00" * 6)
    pkt.time = 1_700_000_000.0
    assert len(bytes(pkt)) == 60
    path = tmp_path / "pad.pcap"
    wrpcap(str(path), [pkt])
    assert read_all_frames(path)["l4pay"][0] == 0
    assert build_flow_records(load_pcap(path))["total_bytes"].iloc[0] == 0  # the Scapy path agrees


def test_snaplen_truncated_frames_still_report_the_real_payload(tmp_path):
    full = bytes(LINK / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000, dport=80, flags="PA") / (b"x" * 1460))
    assert len(full) == 1514
    cut = full[:54]  # headers only, like dumpcap -s 54
    path = _classic_pcap(tmp_path / "trunc.pcap", [(1_700_000_000.0, cut, 1514)], snaplen=54)
    cols = read_all_frames(path)
    assert len(cols["ts"]) == 1 and cols["l4pay"][0] == 1460
    flows = assemble_flows(cols)
    assert flows["total_bytes"].iloc[0] == 1460


def test_udp_payload_from_ip_length_and_tso_fallback(tmp_path):
    udp = bytes(LINK / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53) / (b"q" * 30))
    # IP total length 0 (segmentation offload) -> fall back to the captured length
    tso = bytearray(bytes(LINK / IP(src="10.0.0.1", dst="10.0.0.3") / TCP(sport=1, dport=2, flags="PA") / (b"y" * 100)))
    tso[16:18] = b"\x00\x00"
    path = _classic_pcap(tmp_path / "u.pcap", [(1_700_000_000.0, udp, len(udp)), (1_700_000_000.5, bytes(tso), len(tso))])
    cols = read_all_frames(path)
    assert list(cols["l4pay"]) == [30, 100]


def test_nanosecond_pcap_timestamps(tmp_path):
    f = bytes(LINK / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53) / b"q")
    path = _classic_pcap(tmp_path / "nano.pcap", [(1_700_000_000.250000, f, len(f)), (1_700_000_001.500000, f, len(f))], nano=True)
    ts = read_all_frames(path)["ts"]
    np.testing.assert_allclose(ts, [1_700_000_000.25, 1_700_000_001.5], atol=1e-6)


def test_unparsed_frames_are_counted(tmp_path):
    ok = bytes(LINK / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53) / b"q")
    arp = bytes(Ether(dst="ff:ff:ff:ff:ff:ff", type=0x0806) / (b"\x00" * 28))
    vlan = bytes(Ether(type=0x8100) / (b"\x00\x05\x08\x00" + bytes(IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2))))
    path = _classic_pcap(tmp_path / "mix.pcap", [(1.0, ok, len(ok)), (2.0, arp, len(arp)), (3.0, vlan, len(vlan))])
    cols, n = read_all_frames_counted(path)
    assert n == 3 and len(cols["ts"]) == 1   # ARP and 802.1Q-tagged frames are skipped (documented limitation)


def test_raw_ip_link_types_are_parsed(tmp_path):
    """data/raw/pcap/synthetic_sample.pcap is LINKTYPE_IPV4 (228): no Ethernet header at all."""
    ip = bytes(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000, dport=80, flags="PA") / (b"x" * 77))
    for lt in (101, 228):
        path = _classic_pcap(tmp_path / f"raw{lt}.pcap", [(1_700_000_000.0, ip, len(ip))], linktype=lt)
        cols = read_all_frames(path)
        assert len(cols["ts"]) == 1 and cols["l4pay"][0] == 77 and cols["dport"][0] == 80
