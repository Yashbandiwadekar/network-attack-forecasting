"""Unit tests for CIC-IDS-2018 Wednesday 14-02 Ground Truth Events."""
from __future__ import annotations

import csv
from pathlib import Path

import pytest

from pipeline.label_standard import CANONICAL_EVENT_COLUMNS, lookup_standard_mapping
from scripts.check_events_in_pcap import check_events_in_pcap


def test_cic2018_events_csv_structure():
    """Verify ground_truth/cic2018/events.csv satisfies canonical 14-column schema."""
    events_path = Path("ground_truth/cic2018/events.csv")
    assert events_path.is_file(), "ground_truth/cic2018/events.csv must exist"

    with open(events_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        assert list(reader.fieldnames) == CANONICAL_EVENT_COLUMNS

        rows = list(reader)
        assert len(rows) == 2, "Expected exactly 2 events for Wednesday 14-02 (FTP and SSH brute force)"

        ftp_row = rows[0]
        ssh_row = rows[1]

        # FTP brute force assertions
        assert ftp_row["campaign_id"] == "cic2018_wed_bruteforce_01"
        assert ftp_row["attacker_ip"] == "18.221.219.4"
        assert ftp_row["victim_ip"] == "172.31.69.25"
        assert ftp_row["dst_port"] == "21"
        assert ftp_row["start_ts"] == "2018-02-14T10:30:00Z"
        assert ftp_row["end_ts"] == "2018-02-14T11:30:00Z"
        assert ftp_row["attack_family"] == "bruteforce"
        assert ftp_row["mitre_tactic"] == "TA0006"
        assert ftp_row["mitre_technique"] == "T1110"
        assert ftp_row["original_label"] == "FTP-BruteForce"
        assert "ids-2018.html" in ftp_row["citation"]

        # SSH brute force assertions
        assert ssh_row["campaign_id"] == "cic2018_wed_bruteforce_02"
        assert ssh_row["attacker_ip"] == "18.221.219.4"
        assert ssh_row["victim_ip"] == "172.31.69.25"
        assert ssh_row["dst_port"] == "22"
        assert ssh_row["start_ts"] == "2018-02-14T14:00:00Z"
        assert ssh_row["end_ts"] == "2018-02-14T15:00:00Z"
        assert ssh_row["attack_family"] == "bruteforce"
        assert ssh_row["mitre_tactic"] == "TA0006"
        assert ssh_row["mitre_technique"] == "T1110"
        assert ssh_row["original_label"] == "SSH-Bruteforce"


def test_cic2018_notes_documentation():
    """Verify ground_truth/cic2018/NOTES.md documents timezone uncertainty and victim PCAPs."""
    notes_path = Path("ground_truth/cic2018/NOTES.md")
    assert notes_path.is_file()
    content = notes_path.read_text(encoding="utf-8")
    assert "Timezone Offset" in content or "Time Zone" in content
    assert "172.31.69.25" in content
    assert "Friday 23-02-2018" in content  # Held-out protection documented
