"""Unit tests for scripts/check_events_in_pcap.py."""
from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path

import pytest
from scapy.all import Ether, IP, TCP, wrpcap

from pipeline.label_standard import CANONICAL_EVENT_COLUMNS
from scripts.check_events_in_pcap import check_events_in_pcap


def _write_sample_events(path: Path, rows: list[dict]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CANONICAL_EVENT_COLUMNS)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


def test_check_events_matching_both_directions(tmp_path: Path):
    """Test packet matching in both forward and reverse directions, plus timestamp extraction."""
    events_file = tmp_path / "events.csv"
    pcap_file = tmp_path / "traffic.pcap"
    out_file = tmp_path / "check.csv"

    # Event starting at 2026-11-06T12:00:00Z
    event_start = datetime(2026, 11, 6, 12, 0, 0, tzinfo=timezone.utc)
    base_epoch = event_start.timestamp()

    _write_sample_events(events_file, [
        {
            "campaign_id": "test_camp_01",
            "attacker_ip": "10.0.0.100",
            "victim_ip": "10.0.0.200",
            "dst_port": "80",
            "start_ts": "2026-11-06T12:00:00Z",
            "end_ts": "2026-11-06T12:30:00Z",
            "attack_family": "dos",
            "attack_variant": "syn_flood",
            "mitre_tactic": "TA0040",
            "mitre_technique": "T1499",
            "label_source": "synthetic",
            "label_confidence": "exact",
            "original_label": "DoS",
            "citation": "test_suite",
        }
    ])

    # Packet 1 (forward): attacker -> victim at epoch + 60s
    pkt1 = Ether() / IP(src="10.0.0.100", dst="10.0.0.200") / TCP(sport=54321, dport=80)
    pkt1.time = base_epoch + 60.0

    # Packet 2 (reverse): victim -> attacker at epoch + 120s
    pkt2 = Ether() / IP(src="10.0.0.200", dst="10.0.0.100") / TCP(sport=80, dport=54321)
    pkt2.time = base_epoch + 120.0

    wrpcap(str(pcap_file), [pkt1, pkt2])

    results = check_events_in_pcap(
        events_csv_path=events_file,
        pcap_path=pcap_file,
        out_csv_path=out_file,
        window_hours=1.0,
        prefer_scapy=True,
    )

    assert len(results) == 1
    res = results[0]
    assert res["campaign_id"] == "test_camp_01"
    assert res["found"] == "yes"
    assert res["first_pkt_utc"] == "2026-11-06T12:01:00Z"
    assert res["last_pkt_utc"] == "2026-11-06T12:02:00Z"
    assert float(res["offset_from_published_start"]) == 60.0
    assert res["observed_attacker_ip"] == "10.0.0.100"
    assert res["observed_victim_ip"] == "10.0.0.200"


def test_check_events_missing_reporting(tmp_path: Path):
    """Test that absent events correctly report found: no."""
    events_file = tmp_path / "events.csv"
    pcap_file = tmp_path / "traffic.pcap"
    out_file = tmp_path / "check.csv"

    _write_sample_events(events_file, [
        {
            "campaign_id": "absent_camp",
            "attacker_ip": "1.2.3.4",
            "victim_ip": "5.6.7.8",
            "dst_port": "443",
            "start_ts": "2026-11-06T12:00:00Z",
            "end_ts": "2026-11-06T12:10:00Z",
            "attack_family": "bruteforce",
            "attack_variant": "ssh",
            "mitre_tactic": "TA0006",
            "mitre_technique": "T1110",
            "label_source": "test",
            "label_confidence": "exact",
            "original_label": "BruteForce",
            "citation": "test_suite",
        }
    ])

    pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1000, dport=22)
    pkt.time = 1700000000.0
    wrpcap(str(pcap_file), [pkt])

    results = check_events_in_pcap(
        events_csv_path=events_file,
        pcap_path=pcap_file,
        out_csv_path=out_file,
        window_hours=1.0,
        prefer_scapy=True,
    )

    assert len(results) == 1
    assert results[0]["found"] == "no"
    assert results[0]["first_pkt_utc"] == ""
    assert results[0]["offset_from_published_start"] == ""


def test_check_events_nat_resolution(tmp_path: Path):
    """Test that traffic matching the NAT address 172.16.0.1 matches 205.174.165.73."""
    events_file = tmp_path / "events.csv"
    pcap_file = tmp_path / "traffic.pcap"
    out_file = tmp_path / "check.csv"

    base_time = datetime(2017, 7, 4, 9, 20, 0, tzinfo=timezone.utc)
    base_epoch = base_time.timestamp()

    _write_sample_events(events_file, [
        {
            "campaign_id": "cic2017_tue_bruteforce_01",
            "attacker_ip": "205.174.165.73",
            "victim_ip": "192.168.10.50",
            "dst_port": "21",
            "start_ts": "2017-07-04T09:20:00Z",
            "end_ts": "2017-07-04T10:20:00Z",
            "attack_family": "bruteforce",
            "attack_variant": "ftp_patator",
            "mitre_tactic": "TA0006",
            "mitre_technique": "T1110",
            "label_source": "schedule",
            "label_confidence": "window",
            "original_label": "FTP-Patator",
            "citation": "cic_table4",
        }
    ])

    # Traffic in capture shows NAT internal IP 172.16.0.1
    pkt = Ether() / IP(src="172.16.0.1", dst="192.168.10.50") / TCP(sport=43210, dport=21)
    pkt.time = base_epoch + 120.0
    wrpcap(str(pcap_file), [pkt])

    results = check_events_in_pcap(
        events_csv_path=events_file,
        pcap_path=pcap_file,
        out_csv_path=out_file,
        window_hours=2.0,
        prefer_scapy=True,
    )

    assert len(results) == 1
    assert results[0]["found"] == "yes"
    assert results[0]["observed_attacker_ip"] == "172.16.0.1"
    assert float(results[0]["offset_from_published_start"]) == 120.0

