"""Unit tests for CIC-IDS-2018 Multi-Day Ground Truth Events."""
from __future__ import annotations

import csv
from pathlib import Path

import pytest

from pipeline.label_standard import (
    CANONICAL_EVENT_COLUMNS,
    STANDARD_FAMILY_TABLE,
    lookup_standard_mapping,
)
from scripts.check_events_in_pcap import check_events_in_pcap


def test_cic2018_events_csv_structure():
    """Verify ground_truth/cic2018/events.csv satisfies canonical 14-column schema and multi-day coverage."""
    events_path = Path("ground_truth/cic2018/events.csv")
    assert events_path.is_file(), "ground_truth/cic2018/events.csv must exist"

    with open(events_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        assert list(reader.fieldnames) == CANONICAL_EVENT_COLUMNS

        rows = list(reader)
        assert len(rows) == 19, f"Expected 19 events for all non-held-out attack days, got {len(rows)}"

        # 1. Preservation of Wednesday 14-02 events
        ftp_row = rows[0]
        ssh_row = rows[1]

        assert ftp_row["campaign_id"] == "cic2018_wed_bruteforce_01"
        assert ftp_row["attacker_ip"] == "18.221.219.4"
        assert ftp_row["victim_ip"] == "172.31.69.25"
        assert ftp_row["dst_port"] == "21"
        assert ftp_row["start_ts"] == "2018-02-14T14:32:00Z"
        assert ftp_row["end_ts"] == "2018-02-14T16:09:00Z"
        assert ftp_row["attack_family"] == "bruteforce"
        assert ftp_row["mitre_tactic"] == "TA0006"
        assert ftp_row["mitre_technique"] == "T1110"
        assert ftp_row["label_source"] == "ground_truth_schedule"
        assert ftp_row["original_label"] == "FTP-BruteForce"
        assert "ids-2018.html" in ftp_row["citation"]

        assert ssh_row["campaign_id"] == "cic2018_wed_bruteforce_02"
        assert ssh_row["attacker_ip"] == "13.58.98.64"
        assert ssh_row["victim_ip"] == "172.31.69.25"
        assert ssh_row["dst_port"] == "22"
        assert ssh_row["start_ts"] == "2018-02-14T18:01:00Z"
        assert ssh_row["end_ts"] == "2018-02-14T19:31:00Z"
        assert ssh_row["attack_family"] == "bruteforce"
        assert ssh_row["mitre_tactic"] == "TA0006"
        assert ssh_row["mitre_technique"] == "T1110"
        assert ssh_row["label_source"] == "ground_truth_schedule"
        assert ssh_row["original_label"] == "SSH-Bruteforce"

        # 2. Multi-day coverage across all eligible days
        campaign_ids = [r["campaign_id"] for r in rows]
        assert len(campaign_ids) == len(set(campaign_ids)), "Duplicate campaign IDs detected"

        citations = " ".join(r["citation"] for r in rows)
        assert "Thurs-15-02-2018" in citations
        assert "Fri-16-02-2018" in citations
        assert "Tues-20-02-2018" in citations
        assert "Wed-21-02-2018" in citations
        assert "Thurs-22-02-2018" in citations
        assert "Wed-28-02-2018" in citations
        assert "Thursday-01-03-2018" in citations
        assert "Friday-02-03-2018" in citations

        # 3. Held-out test day Friday 23-02-2018 strictly excluded
        assert "Fri-23-02-2018" not in citations
        assert "23-02" not in citations
        assert not any("2018-02-23" in r["start_ts"] for r in rows)

        # 4. Unmeasured days have blank UTC timestamps pending PCAP check
        for r in rows[2:]:
            assert r["start_ts"] == "", f"Expected blank start_ts for unmeasured row {r['campaign_id']}"
            assert r["end_ts"] == "", f"Expected blank end_ts for unmeasured row {r['campaign_id']}"
            assert r["attack_family"] in STANDARD_FAMILY_TABLE
            assert r["mitre_tactic"] == STANDARD_FAMILY_TABLE[r["attack_family"]]["mitre_tactic"]
            assert r["mitre_technique"] == STANDARD_FAMILY_TABLE[r["attack_family"]]["mitre_technique"]
            assert r["citation"].startswith("https://www.unb.ca/cic/datasets/ids-2018.html")


def test_cic2018_notes_documentation():
    """Verify ground_truth/cic2018/NOTES.md documents multi-day schedules, timezone uncertainty and victim PCAPs."""
    notes_path = Path("ground_truth/cic2018/NOTES.md")
    assert notes_path.is_file()
    content = notes_path.read_text(encoding="utf-8")
    assert "Timezone Offset" in content or "Time Zone" in content
    assert "172.31.69.25" in content
    assert "Friday 23-02-2018" in content  # Held-out protection documented
    assert "Thurs-15-02-2018" in content or "15 February 2018" in content
    assert "Friday 02-03-2018" in content or "02-03-2018" in content


def test_cic2018_datasheet_documentation():
    """Verify ground_truth/cic2018/DATASHEET.md documents multi-day authored coverage and open questions."""
    sheet_path = Path("ground_truth/cic2018/DATASHEET.md")
    assert sheet_path.is_file()
    content = sheet_path.read_text(encoding="utf-8")
    assert "19 events" in content or "19" in content
    assert "Friday 23-02-2018" in content
    assert "Open Questions" in content

