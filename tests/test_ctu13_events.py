"""Unit tests for CTU-13 Event Generation in scripts/build_events.py."""
from __future__ import annotations

import csv
from pathlib import Path

import pandas as pd
import pytest

from pipeline.label_standard import CANONICAL_EVENT_COLUMNS
from scripts.build_events import build_ctu13_events


def _create_binetflow_fixture(file_path: Path, rows: list[dict]) -> None:
    headers = [
        "StartTime", "Dur", "Proto", "SrcAddr", "Sport", "Dir",
        "DstAddr", "Dport", "State", "sTos", "dTos", "TotPkts", "TotBytes", "SrcBytes", "Label"
    ]
    with open(file_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


def test_ctu13_binetflow_parsing_and_events(tmp_path: Path):
    """Test scenario 1 (Neris) flow processing: botnet grouping, background exclusion, normal host handling."""
    binet_file = tmp_path / "scenario_01.binetflow"
    out_file = tmp_path / "events.parquet"

    # Scenario 1 metadata:
    # infected_hosts: ["147.32.84.165"]
    # normal_hosts: ["147.32.84.170", "147.32.84.134", "147.32.84.164"]
    rows = [
        # 1. Botnet flow 1: C&C HTTP
        {
            "StartTime": "2011/08/10 09:46:53.047277", "Dur": "2.5", "Proto": "tcp",
            "SrcAddr": "147.32.84.165", "Sport": "1025", "Dir": "->",
            "DstAddr": "147.32.80.13", "Dport": "80", "State": "PA_PA",
            "sTos": "0", "dTos": "0", "TotPkts": "10", "TotBytes": "1024", "SrcBytes": "512",
            "Label": "flow=From-Botnet-V42-TCP-Established-HTTP-Ad-1",
        },
        # 2. Botnet flow 2: same behaviour later
        {
            "StartTime": "2011/08/10 09:50:00.000000", "Dur": "1.0", "Proto": "tcp",
            "SrcAddr": "147.32.84.165", "Sport": "1026", "Dir": "->",
            "DstAddr": "147.32.80.13", "Dport": "80", "State": "PA_PA",
            "sTos": "0", "dTos": "0", "TotPkts": "5", "TotBytes": "500", "SrcBytes": "250",
            "Label": "flow=From-Botnet-V42-TCP-Established-HTTP-Ad-1",
        },
        # 3. Botnet flow 3: DNS beacon
        {
            "StartTime": "2011/08/10 09:47:10.000000", "Dur": "0.1", "Proto": "udp",
            "SrcAddr": "147.32.84.165", "Sport": "1030", "Dir": "->",
            "DstAddr": "147.32.80.9", "Dport": "53", "State": "CON",
            "sTos": "0", "dTos": "0", "TotPkts": "2", "TotBytes": "120", "SrcBytes": "60",
            "Label": "flow=From-Botnet-V42-UDP-DNS",
        },
        # 4. Background flow 1: MUST NOT produce event
        {
            "StartTime": "2011/08/10 09:48:00.000000", "Dur": "5.0", "Proto": "tcp",
            "SrcAddr": "192.168.1.50", "Sport": "4567", "Dir": "->",
            "DstAddr": "8.8.8.8", "Dport": "53", "State": "PA_PA",
            "sTos": "0", "dTos": "0", "TotPkts": "20", "TotBytes": "2000", "SrcBytes": "1000",
            "Label": "flow=Background",
        },
        # 5. Background flow 2: To-Background
        {
            "StartTime": "2011/08/10 09:48:30.000000", "Dur": "1.0", "Proto": "udp",
            "SrcAddr": "10.0.0.1", "Sport": "1234", "Dir": "->",
            "DstAddr": "10.0.0.2", "Dport": "123", "State": "CON",
            "sTos": "0", "dTos": "0", "TotPkts": "2", "TotBytes": "100", "SrcBytes": "50",
            "Label": "flow=To-Background-UDP-CVUT-DNS-Server",
        },
        # 6. Normal flow from verified normal host (147.32.84.170) -> produces benign event
        {
            "StartTime": "2011/08/10 09:49:00.000000", "Dur": "3.0", "Proto": "tcp",
            "SrcAddr": "147.32.84.170", "Sport": "2222", "Dir": "->",
            "DstAddr": "147.32.80.1", "Dport": "80", "State": "PA_PA",
            "sTos": "0", "dTos": "0", "TotPkts": "15", "TotBytes": "1500", "SrcBytes": "600",
            "Label": "flow=Normal-V42-HTTP-windowsupdate",
        },
        # 7. Normal flow from unverified random host -> MUST NOT produce event
        {
            "StartTime": "2011/08/10 09:49:30.000000", "Dur": "1.0", "Proto": "tcp",
            "SrcAddr": "198.51.100.5", "Sport": "3333", "Dir": "->",
            "DstAddr": "147.32.80.1", "Dport": "80", "State": "PA_PA",
            "sTos": "0", "dTos": "0", "TotPkts": "8", "TotBytes": "800", "SrcBytes": "400",
            "Label": "flow=Normal-Unverified-Host",
        },
    ]

    _create_binetflow_fixture(binet_file, rows)

    df_out = build_ctu13_events(binet_file, out_file, scenario_id=1)

    # Output assertions:
    # 2 botnet behaviour groups + 1 verified normal group = 3 events total
    assert len(df_out) == 3

    # Schema check
    assert list(df_out.columns) == CANONICAL_EVENT_COLUMNS

    # Check botnet event 1
    http_ev = df_out[df_out["original_label"] == "flow=From-Botnet-V42-TCP-Established-HTTP-Ad-1"].iloc[0]
    assert http_ev["attacker_ip"] == "147.32.84.165"
    assert http_ev["victim_ip"] == "147.32.80.13"
    assert http_ev["attack_family"] == "botnet_c2"
    assert http_ev["mitre_tactic"] == "TA0011"
    assert http_ev["mitre_technique"] == "T1071"
    assert http_ev["start_ts"] == "2011-08-10T09:46:53Z"
    assert http_ev["end_ts"] == "2011-08-10T09:50:01Z"
    assert "ctu13_scen1_147.32.84.165" in http_ev["campaign_id"]

    # Check botnet event 2 (DNS)
    dns_ev = df_out[df_out["original_label"] == "flow=From-Botnet-V42-UDP-DNS"].iloc[0]
    assert dns_ev["attacker_ip"] == "147.32.84.165"
    assert dns_ev["attack_family"] == "botnet_c2"

    # Check normal event from verified normal host
    norm_ev = df_out[df_out["original_label"] == "flow=Normal-V42-HTTP-windowsupdate"].iloc[0]
    assert norm_ev["attacker_ip"] == "147.32.84.170"
    assert norm_ev["attack_family"] == "benign"
    assert norm_ev["mitre_tactic"] == ""
    assert norm_ev["mitre_technique"] == ""

    # Verify background flows produced NO events and are not marked benign
    labels = df_out["original_label"].tolist()
    assert "flow=Background" not in labels
    assert "flow=To-Background-UDP-CVUT-DNS-Server" not in labels
    assert "flow=Normal-Unverified-Host" not in labels


def test_ctu13_malformed_input(tmp_path: Path):
    """Test error handling on missing required columns."""
    bad_file = tmp_path / "bad.binetflow"
    bad_file.write_text("Col1,Col2\n1,2\n", encoding="utf-8")
    out_file = tmp_path / "events.parquet"

    with pytest.raises(ValueError, match="missing required"):
        build_ctu13_events(bad_file, out_file, scenario_id=1)
