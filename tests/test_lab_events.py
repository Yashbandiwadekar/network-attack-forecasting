"""Unit tests for Lab Synthetic Campaign Event Generation in scripts/build_events.py."""
from __future__ import annotations

import csv
from pathlib import Path

import pandas as pd
import pytest

from pipeline.label_standard import CANONICAL_EVENT_COLUMNS
from scripts.build_events import build_lab_events


def _create_lab_sidecar_fixture(path: Path, rows: list[dict]) -> None:
    headers = ["src_ip", "dst_ip", "start", "end", "label", "dst_port"]
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


def test_build_lab_events_conversion(tmp_path: Path):
    """Test converting synthetic lab sidecar labels.csv to canonical 14-column events."""
    sidecar_file = tmp_path / "labels.csv"
    out_file = tmp_path / "events.parquet"

    rows = [
        # SSH Brute Force
        {
            "src_ip": "10.0.0.66",
            "dst_ip": "10.0.0.5",
            "start": "2026-10-10 14:03:00",
            "end": "2026-10-10 14:09:30",
            "label": "SSH-Bruteforce",
            "dst_port": "22",
        },
        # PortScan
        {
            "src_ip": "10.0.0.66",
            "dst_ip": "10.0.0.5",
            "start": "2026-10-10 14:15:00",
            "end": "2026-10-10 14:18:00",
            "label": "PortScan",
            "dst_port": "",
        },
        # Bot C2
        {
            "src_ip": "10.0.0.66",
            "dst_ip": "10.0.0.99",
            "start": "2026-10-10 14:20:00",
            "end": "2026-10-10 14:25:00",
            "label": "Bot",
            "dst_port": "8080",
        },
    ]

    _create_lab_sidecar_fixture(sidecar_file, rows)

    df_out = build_lab_events(sidecar_file, out_file)

    assert len(df_out) == 3
    assert list(df_out.columns) == CANONICAL_EVENT_COLUMNS

    # Row 0: SSH-Bruteforce
    r0 = df_out.iloc[0]
    assert r0["attacker_ip"] == "10.0.0.66"
    assert r0["victim_ip"] == "10.0.0.5"
    assert r0["dst_port"] == "22"
    assert r0["start_ts"] == "2026-10-10T14:03:00Z"
    assert r0["end_ts"] == "2026-10-10T14:09:30Z"
    assert r0["attack_family"] == "bruteforce"
    assert r0["mitre_tactic"] == "TA0006"
    assert r0["mitre_technique"] == "T1110"
    assert r0["label_source"] == "lab_driver_log"
    assert r0["label_confidence"] == "exact"
    assert r0["original_label"] == "SSH-Bruteforce"
    assert "lab_" in r0["campaign_id"]

    # Row 1: PortScan
    r1 = df_out.iloc[1]
    assert r1["attack_family"] == "portscan"
    assert r1["mitre_tactic"] == "TA0043"
    assert r1["mitre_technique"] == "T1595"
    assert r1["dst_port"] == ""

    # Row 2: Bot
    r2 = df_out.iloc[2]
    assert r2["attack_family"] == "botnet_c2"
    assert r2["mitre_tactic"] == "TA0011"
    assert r2["mitre_technique"] == "T1071"
    assert r2["dst_port"] == "8080"


def test_build_lab_events_missing_label_column(tmp_path: Path):
    """Test error when required 'label' column is missing from sidecar."""
    bad_sidecar = tmp_path / "bad_labels.csv"
    bad_sidecar.write_text("src_ip,dst_ip,start,end\n10.0.0.1,10.0.0.2,1,2\n", encoding="utf-8")
    out_file = tmp_path / "events.parquet"

    with pytest.raises(ValueError, match="missing 'label' column"):
        build_lab_events(bad_sidecar, out_file)


def test_build_lab_events_unmapped_labels_raise_error(tmp_path: Path):
    """Test that unmapped labels raise ValueError and list all unmapped labels (P-01)."""
    sidecar_file = tmp_path / "unmapped_labels.csv"
    out_file = tmp_path / "events.parquet"

    rows = [
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "start": "2026-10-10 12:00:00", "end": "2026-10-10 12:05:00", "label": "custom_initial_access", "dst_port": "80"},
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "start": "2026-10-10 12:10:00", "end": "2026-10-10 12:15:00", "label": "unknown_impact_label", "dst_port": "80"},
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "start": "2026-10-10 12:20:00", "end": "2026-10-10 12:25:00", "label": "SSH-Bruteforce", "dst_port": "22"},
    ]
    _create_lab_sidecar_fixture(sidecar_file, rows)

    with pytest.raises(ValueError) as excinfo:
        build_lab_events(sidecar_file, out_file)

    err_msg = str(excinfo.value)
    assert "Unmapped lab attack labels" in err_msg
    assert "custom_initial_access" in err_msg
    assert "unknown_impact_label" in err_msg
    assert "project-approved standard mapping" in err_msg


def test_build_lab_events_all_approved_families(tmp_path: Path):
    """Test positive mapping across standard approved lab labels."""
    sidecar_file = tmp_path / "all_families.csv"
    out_file = tmp_path / "events.parquet"

    rows = [
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "start": "2026-10-10 10:00:00", "end": "2026-10-10 10:05:00", "label": "DoS attacks-Hulk", "dst_port": "80"},
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "start": "2026-10-10 10:10:00", "end": "2026-10-10 10:15:00", "label": "Brute Force -Web", "dst_port": "80"},
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "start": "2026-10-10 10:20:00", "end": "2026-10-10 10:25:00", "label": "SQL Injection", "dst_port": "80"},
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "start": "2026-10-10 10:30:00", "end": "2026-10-10 10:35:00", "label": "SYNTH-Exfiltration", "dst_port": "443"},
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "start": "2026-10-10 10:40:00", "end": "2026-10-10 10:45:00", "label": "DDoS attacks-LOIC-HTTP", "dst_port": "80"},
    ]
    _create_lab_sidecar_fixture(sidecar_file, rows)

    df = build_lab_events(sidecar_file, out_file)
    assert len(df) == 5
    families = df["attack_family"].tolist()
    assert families == ["dos", "bruteforce", "web_exploit", "exfiltration", "ddos"]


