"""Unit tests for scripts/check_events_in_pcap.py."""
from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path

import pytest
from scapy.all import Ether, IP, TCP, wrpcap

from pipeline.label_standard import CANONICAL_EVENT_COLUMNS
from scripts.check_events_in_pcap import check_events_in_pcap, load_nat_mapping


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


def test_check_events_utf8_bom_and_unicode(tmp_path: Path):
    """Test reading events file with UTF-8 BOM and unicode characters (such as en-dash)."""
    events_file = tmp_path / "events_bom.csv"
    pcap_file = tmp_path / "traffic.pcap"
    out_file = tmp_path / "check.csv"

    # Write file with explicit BOM via utf-8-sig
    content = (
        "campaign_id,attacker_ip,victim_ip,dst_port,start_ts,end_ts,"
        "attack_family,attack_variant,mitre_tactic,mitre_technique,"
        "label_source,label_confidence,original_label,citation\n"
        "cic2017_thu_web_01,205.174.165.73,192.168.10.50,80,"
        "2017-07-06T09:20:00Z,2017-07-06T10:00:00Z,web_exploit,brute_force,"
        "TA0001,T1190,schedule,exact,Web Attack \u2013 Brute Force,https://example.com\n"
    )
    events_file.write_text(content, encoding="utf-8-sig")

    base_time = datetime(2017, 7, 6, 9, 25, 0, tzinfo=timezone.utc)
    pkt = Ether() / IP(src="205.174.165.73", dst="192.168.10.50") / TCP(sport=50000, dport=80)
    pkt.time = base_time.timestamp()
    wrpcap(str(pcap_file), [pkt])

    results = check_events_in_pcap(
        events_csv_path=events_file,
        pcap_path=pcap_file,
        out_csv_path=out_file,
        window_hours=1.0,
        prefer_scapy=True,
    )

    assert len(results) == 1
    assert results[0]["campaign_id"] == "cic2017_thu_web_01"
    assert results[0]["found"] == "yes"


def test_tshark_truncated_capture_exit_14(monkeypatch, tmp_path: Path):
    """Test that tshark returning exit code 14 (truncated capture) still parses stdout and notes error."""
    import subprocess
    from scripts.check_events_in_pcap import scan_pcap_with_tshark

    pcap_file = tmp_path / "truncated.pcap"
    pcap_file.write_bytes(b"dummy pcap header and truncated frame")

    mock_stdout = "1518618720.0 18.221.219.4 172.31.69.25\n1518624540.0 172.31.69.25 18.221.219.4\n"
    mock_stderr = "tshark: The capture file appears to have been cut short in the middle of a packet."

    class MockCompletedProcess:
        returncode = 14
        stdout = mock_stdout
        stderr = mock_stderr

    def mock_run(*args, **kwargs):
        return MockCompletedProcess()

    monkeypatch.setattr(subprocess, "run", mock_run)

    start_dt = datetime(2018, 2, 14, 14, 32, 0, tzinfo=timezone.utc)
    end_dt = datetime(2018, 2, 14, 16, 9, 0, tzinfo=timezone.utc)

    found, f_epoch, l_epoch, o_att, o_vic, note = scan_pcap_with_tshark(
        pcap_files=[pcap_file],
        candidate_attackers={"18.221.219.4"},
        candidate_victims={"172.31.69.25"},
        dst_port=21,
        start_dt=start_dt,
        end_dt=end_dt,
        window_seconds=3600.0,
        tshark_exe="mock_tshark",
    )

    assert found is True
    assert f_epoch == 1518618720.0
    assert l_epoch == 1518624540.0
    assert o_att == "18.221.219.4"
    assert o_vic == "172.31.69.25"
    assert "tshark returned code 14" in note
    assert "cut short" in note


def test_load_nat_mapping_valid(tmp_path: Path):
    """Test loading valid NAT mapping configuration file."""
    import json
    cfg_file = tmp_path / "nat.json"
    cfg_file.write_text(json.dumps({
        "description": "Test NAT",
        "mappings": [
            {"published_ip": "198.51.100.1", "observed_ip": "10.0.0.1", "description": "Host 1"},
            {"published_ip": "198.51.100.2", "observed_ip": "10.0.0.2"}
        ]
    }), encoding="utf-8")

    mapping = load_nat_mapping(cfg_file)
    assert "198.51.100.1" in mapping
    assert "10.0.0.1" in mapping["198.51.100.1"]
    assert "10.0.0.1" in mapping
    assert "198.51.100.1" in mapping["10.0.0.1"]
    assert "10.0.0.2" in mapping["198.51.100.2"]


def test_load_nat_mapping_invalid_ip(tmp_path: Path):
    """Test that malformed IP address raises ValueError."""
    import json
    cfg_file = tmp_path / "invalid_ip.json"
    cfg_file.write_text(json.dumps({
        "mappings": [
            {"published_ip": "999.999.999.999", "observed_ip": "10.0.0.1"}
        ]
    }), encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid published IP"):
        load_nat_mapping(cfg_file)


def test_load_nat_mapping_duplicate_pair(tmp_path: Path):
    """Test that duplicate mapping pair raises ValueError."""
    import json
    cfg_file = tmp_path / "dup.json"
    cfg_file.write_text(json.dumps({
        "mappings": [
            {"published_ip": "198.51.100.1", "observed_ip": "10.0.0.1"},
            {"published_ip": "198.51.100.1", "observed_ip": "10.0.0.1"}
        ]
    }), encoding="utf-8")

    with pytest.raises(ValueError, match="Duplicate NAT mapping"):
        load_nat_mapping(cfg_file)


def test_check_events_custom_nat_map(tmp_path: Path):
    """Test check_events_in_pcap with a custom NAT mapping path and verify notes reporting."""
    import json
    events_file = tmp_path / "events.csv"
    pcap_file = tmp_path / "traffic.pcap"
    out_file = tmp_path / "check.csv"
    nat_file = tmp_path / "custom_nat.json"

    nat_file.write_text(json.dumps({
        "mappings": [
            {"published_ip": "203.0.113.5", "observed_ip": "192.168.1.99"}
        ]
    }), encoding="utf-8")

    base_time = datetime(2026, 11, 7, 10, 0, 0, tzinfo=timezone.utc)
    base_epoch = base_time.timestamp()

    _write_sample_events(events_file, [
        {
            "campaign_id": "custom_nat_camp",
            "attacker_ip": "203.0.113.5",
            "victim_ip": "192.168.1.10",
            "dst_port": "8080",
            "start_ts": "2026-11-07T10:00:00Z",
            "end_ts": "2026-11-07T10:30:00Z",
            "attack_family": "dos",
            "attack_variant": "http_flood",
            "mitre_tactic": "TA0040",
            "mitre_technique": "T1499",
            "label_source": "synthetic",
            "label_confidence": "exact",
            "original_label": "DoS",
            "citation": "test_suite",
        }
    ])

    # Traffic in capture uses observed IP 192.168.1.99
    pkt = Ether() / IP(src="192.168.1.99", dst="192.168.1.10") / TCP(sport=50000, dport=8080)
    pkt.time = base_epoch + 15.0
    wrpcap(str(pcap_file), [pkt])

    results = check_events_in_pcap(
        events_csv_path=events_file,
        pcap_path=pcap_file,
        out_csv_path=out_file,
        window_hours=1.0,
        prefer_scapy=True,
        nat_map_path=nat_file,
    )

    assert len(results) == 1
    res = results[0]
    assert res["found"] == "yes"
    assert res["observed_attacker_ip"] == "192.168.1.99"
    assert "NAT mapping applied: published attacker 203.0.113.5 -> observed 192.168.1.99" in res["notes"]



