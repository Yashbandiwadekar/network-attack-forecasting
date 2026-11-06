"""Unit tests for Stage 6 Unified Events Validator (scripts/validate_standard_events.py)."""
from __future__ import annotations

from pathlib import Path
import pandas as pd
import pytest

from pipeline.label_standard import CANONICAL_EVENT_COLUMNS
from scripts.validate_standard_events import validate_events_df, validate_events_file


def _build_valid_row() -> dict:
    return {
        "campaign_id": "test_camp_01",
        "attacker_ip": "10.0.0.1",
        "victim_ip": "10.0.0.2",
        "dst_port": "80",
        "start_ts": "2026-11-06T12:00:00Z",
        "end_ts": "2026-11-06T12:30:00Z",
        "attack_family": "dos",
        "attack_variant": "syn_flood",
        "mitre_tactic": "TA0040",
        "mitre_technique": "T1499",
        "label_source": "test",
        "label_confidence": "exact",
        "original_label": "DoS",
        "citation": "test_ref",
    }


def test_validator_accepts_valid_dataframe():
    """Valid canonical event row must produce no validation errors."""
    df = pd.DataFrame([_build_valid_row()], columns=CANONICAL_EVENT_COLUMNS)
    errors = validate_events_df(df)
    assert len(errors) == 0


def test_validator_detects_schema_mismatch():
    """Missing or reordered columns must trigger a schema mismatch error."""
    bad_cols = ["campaign_id", "attacker_ip", "victim_ip"]
    df = pd.DataFrame([{"campaign_id": "c1", "attacker_ip": "1.1.1.1", "victim_ip": "2.2.2.2"}], columns=bad_cols)
    errors = validate_events_df(df)
    assert any("Column mismatch" in e for e in errors)


def test_validator_detects_reversed_timestamps():
    """start_ts > end_ts must be rejected."""
    row = _build_valid_row()
    row["start_ts"] = "2026-11-06T13:00:00Z"
    row["end_ts"] = "2026-11-06T12:00:00Z"
    df = pd.DataFrame([row], columns=CANONICAL_EVENT_COLUMNS)
    errors = validate_events_df(df)
    assert any("start_ts" in e and "> end_ts" in e for e in errors)


def test_validator_detects_non_utc_timestamp():
    """Timestamps without Z or not ISO 8601 must be rejected."""
    row = _build_valid_row()
    row["start_ts"] = "2026-11-06 12:00:00"  # missing T and Z
    df = pd.DataFrame([row], columns=CANONICAL_EVENT_COLUMNS)
    errors = validate_events_df(df)
    assert any("not UTC ISO 8601 ending in 'Z'" in e for e in errors)


def test_validator_detects_malformed_mitre():
    """Malformed MITRE tactic or technique must be rejected."""
    row = _build_valid_row()
    row["mitre_tactic"] = "INVALID_TACTIC"
    row["mitre_technique"] = "INVALID_TECHNIQUE"
    df = pd.DataFrame([row], columns=CANONICAL_EVENT_COLUMNS)
    errors = validate_events_df(df)
    assert any("Malformed mitre_tactic" in e for e in errors)
    assert any("Malformed mitre_technique" in e for e in errors)


def test_validator_rejects_background_as_benign():
    """Background traffic marked as benign must be rejected."""
    row = _build_valid_row()
    row["original_label"] = "flow=Background"
    row["attack_family"] = "benign"
    df = pd.DataFrame([row], columns=CANONICAL_EVENT_COLUMNS)
    errors = validate_events_df(df)
    assert any("Background traffic incorrectly labeled as benign" in e for e in errors)


def test_validator_detects_held_out_friday_contamination():
    """Events containing CIC-2018 Friday 23-02-2018 must trigger contamination error."""
    row = _build_valid_row()
    row["campaign_id"] = "cic2018_fri_ddos_01"
    row["start_ts"] = "2018-02-23T10:00:00Z"
    row["end_ts"] = "2018-02-23T11:00:00Z"
    df = pd.DataFrame([row], columns=CANONICAL_EVENT_COLUMNS)
    errors = validate_events_df(df)
    assert any("Held-out test day Friday 23-02-2018 detected" in e for e in errors)
