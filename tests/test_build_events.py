"""Unit tests for Stage 3 Ground-Truth Event Builder (scripts/build_events.py)."""
from __future__ import annotations

import csv
from pathlib import Path

import pandas as pd
import pytest

from pipeline.label_standard import CANONICAL_EVENT_COLUMNS
from scripts.build_events import build_unsw_nb15_events


def _create_unsw_fixture(csv_path: Path, rows: list[dict]) -> None:
    headers = [
        "Start time",
        "Last time",
        "Attack category",
        "Attack subcategory",
        "Protocol",
        "Source IP",
        "Source Port",
        "Destination IP",
        "Destination Port",
        "Attack Name",
        "Attack Reference",
    ]
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


def test_build_events_unsw_standard_mapping(tmp_path: Path):
    """Test 5-row fixture for field mapping, UTC conversion, campaign ID, duplicates, and Parquet schema."""
    gt_file = tmp_path / "NUSW-NB15_GT.csv"
    out_file = tmp_path / "events.parquet"

    # Unix epochs: 1421927000 = 2015-01-22T11:43:20Z
    #             1421927300 = 2015-01-22T11:48:20Z
    #             1424160000 = 2015-02-17T08:00:00Z
    rows = [
        # Row 1: DoS (standard mapped family: dos / TA0040 / T1499)
        {
            "Start time": "1421927000",
            "Last time": "1421927300",
            "Attack category": "DoS",
            "Attack subcategory": "Hulk",
            "Protocol": "tcp",
            "Source IP": "175.45.176.0",
            "Source Port": "12345",
            "Destination IP": "149.171.126.100",
            "Destination Port": "80",
            "Attack Name": "Hulk flood",
            "Attack Reference": "CVE-2015-XXXX",
        },
        # Row 2: Exact duplicate of Row 1
        {
            "Start time": "1421927000",
            "Last time": "1421927300",
            "Attack category": "DoS",
            "Attack subcategory": "Hulk",
            "Protocol": "tcp",
            "Source IP": "175.45.176.0",
            "Source Port": "12345",
            "Destination IP": "149.171.126.100",
            "Destination Port": "80",
            "Attack Name": "Hulk flood",
            "Attack Reference": "CVE-2015-XXXX",
        },
        # Row 3: PortScan (standard mapped family: portscan / TA0043 / T1595)
        {
            "Start time": "1421928000",
            "Last time": "1421928500",
            "Attack category": "PortScan",
            "Attack subcategory": "SYN Scan",
            "Protocol": "tcp",
            "Source IP": "175.45.176.1",
            "Source Port": "45678",
            "Destination IP": "149.171.126.101",
            "Destination Port": "80",
            "Attack Name": "Nmap Port Scan",
            "Attack Reference": "SecLists",
        },
        # Row 4: DoS (another instance on day 2)
        {
            "Start time": "1424160000",
            "Last time": "1424160300",
            "Attack category": "DoS",
            "Attack subcategory": "Slowloris",
            "Protocol": "tcp",
            "Source IP": "175.45.176.2",
            "Source Port": "33333",
            "Destination IP": "149.171.126.102",
            "Destination Port": "80",
            "Attack Name": "HTTP Exhaustion",
            "Attack Reference": "",
        },
    ]

    _create_unsw_fixture(gt_file, rows)

    df_out = build_unsw_nb15_events(gt_file, out_file)

    # 1. Exact duplicate removal: 4 input rows -> 3 unique events
    assert len(df_out) == 3

    # 2. Canonical 14-column schema
    assert list(df_out.columns) == CANONICAL_EVENT_COLUMNS

    # 3. Timestamp conversion to UTC ISO 8601 with Z
    assert df_out.iloc[0]["start_ts"] == "2015-01-22T11:43:20Z"
    assert df_out.iloc[0]["end_ts"] == "2015-01-22T11:48:20Z"

    # 4. Campaign ID formatting: unsw_<YYYYMMDD>_<src_ip>
    assert df_out.iloc[0]["campaign_id"] == "unsw_20150122_175.45.176.0"
    assert df_out.iloc[2]["campaign_id"] == "unsw_20150217_175.45.176.2"

    # 5. Original label preservation
    assert df_out.iloc[0]["original_label"] == "DoS"
    assert df_out.iloc[1]["original_label"] == "PortScan"
    assert df_out.iloc[2]["original_label"] == "DoS"

    # 6. Attack variant preservation
    assert df_out.iloc[0]["attack_variant"] == "Hulk"
    assert df_out.iloc[1]["attack_variant"] == "SYN Scan"

    # 7. MITRE mapping lookup
    assert df_out.iloc[0]["attack_family"] == "dos"
    assert df_out.iloc[0]["mitre_tactic"] == "TA0040"
    assert df_out.iloc[0]["mitre_technique"] == "T1499"

    assert df_out.iloc[1]["attack_family"] == "portscan"
    assert df_out.iloc[1]["mitre_tactic"] == "TA0043"
    assert df_out.iloc[1]["mitre_technique"] == "T1595"

    assert df_out.iloc[2]["attack_family"] == "dos"
    assert df_out.iloc[2]["mitre_tactic"] == "TA0040"
    assert df_out.iloc[2]["mitre_technique"] == "T1499"

    # 8. Fixed label_source and label_confidence
    assert (df_out["label_source"] == "dataset_flow_label").all()
    assert (df_out["label_confidence"] == "exact").all()

    # 9. Citation preservation
    assert "CVE-2015-XXXX" in df_out.iloc[0]["citation"]

    # 10. Check Parquet on disk
    assert out_file.is_file()
    read_back = pd.read_parquet(out_file)
    assert len(read_back) == 3
    assert list(read_back.columns) == CANONICAL_EVENT_COLUMNS


def test_build_events_unmapped_category_error(tmp_path: Path):
    """Test that unmapped categories (including Reconnaissance and Exploits) stop execution."""
    gt_file = tmp_path / "NUSW-NB15_GT_unmapped.csv"
    out_file = tmp_path / "events.parquet"

    unmapped_rows = [
        {
            "Start time": "1421927000",
            "Last time": "1421927300",
            "Attack category": "Reconnaissance",
            "Attack subcategory": "Port Scan",
            "Protocol": "tcp",
            "Source IP": "175.45.176.0",
            "Source Port": "1234",
            "Destination IP": "149.171.126.100",
            "Destination Port": "80",
            "Attack Name": "Scanning probe",
            "Attack Reference": "",
        },
        {
            "Start time": "1421928000",
            "Last time": "1421928300",
            "Attack category": "Exploits",
            "Attack subcategory": "Solaris rwalld",
            "Protocol": "udp",
            "Source IP": "175.45.176.1",
            "Source Port": "5678",
            "Destination IP": "149.171.126.101",
            "Destination Port": "1024",
            "Attack Name": "UDP Exploit",
            "Attack Reference": "",
        },
        {
            "Start time": "1421929000",
            "Last time": "1421929300",
            "Attack category": "Fuzzers",
            "Attack subcategory": "FTP",
            "Protocol": "tcp",
            "Source IP": "175.45.176.2",
            "Source Port": "1234",
            "Destination IP": "149.171.126.102",
            "Destination Port": "21",
            "Attack Name": "Fuzzing probe",
            "Attack Reference": "",
        },
    ]

    _create_unsw_fixture(gt_file, unmapped_rows)

    # Process must raise ValueError without fabricating mappings
    with pytest.raises(ValueError, match="Unmapped attack categories in ground truth"):
        build_unsw_nb15_events(gt_file, out_file, allow_unmapped=False)

    # Output file must NOT have been generated
    assert not out_file.exists()


def test_build_events_allow_unmapped_flag(tmp_path: Path):
    """Test --allow-unmapped flag leaves unmapped MITRE fields blank instead of guessing."""
    gt_file = tmp_path / "NUSW-NB15_GT_unmapped.csv"
    out_file = tmp_path / "events.parquet"

    rows = [
        {
            "Start time": "1421927000",
            "Last time": "1421927300",
            "Attack category": "Generic",
            "Attack subcategory": "Cryptographic",
            "Protocol": "tcp",
            "Source IP": "175.45.176.0",
            "Source Port": "1234",
            "Destination IP": "149.171.126.100",
            "Destination Port": "80",
            "Attack Name": "Crypto block",
            "Attack Reference": "",
        }
    ]
    _create_unsw_fixture(gt_file, rows)

    df_out = build_unsw_nb15_events(gt_file, out_file, allow_unmapped=True)
    assert len(df_out) == 1
    assert df_out.iloc[0]["original_label"] == "Generic"
    # Unmapped fields must be blank, not guessed
    assert df_out.iloc[0]["attack_family"] == ""
    assert df_out.iloc[0]["mitre_tactic"] == ""
    assert df_out.iloc[0]["mitre_technique"] == ""
