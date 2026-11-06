"""Stage 6 - Unified Standard Events Validator (scripts/validate_standard_events.py).

Validates canonical 14-column event tables (.csv or .parquet) across all datasets.
Enforces:
  1. Exact 14-column schema and column order
  2. UTC ISO 8601 timestamps ending in 'Z' with start_ts <= end_ts
  3. Valid MITRE tactic (TA####) and technique (T####[.###]) format
  4. Permitted standard attack families
  5. Non-empty citations and original labels
  6. Prevention of background traffic being classified as benign
  7. Held-out test day protection (ensuring CIC-2018 Friday 23-02 is absent from training)
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from pipeline.label_standard import (
    CANONICAL_EVENT_COLUMNS,
    STANDARD_FAMILY_TABLE,
)

PERMITTED_FAMILIES = set(STANDARD_FAMILY_TABLE.keys()) | {"unknown"}

TACTIC_REGEX = re.compile(r"^TA\d{4}$")
TECHNIQUE_REGEX = re.compile(r"^T\d{4}(?:\.\d{3})?$")
UTC_ISO_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")


class EventValidationError(Exception):
    """Raised when an event table violates standardisation requirements."""
    pass


def validate_events_df(df: pd.DataFrame, source_name: str = "events") -> List[str]:
    """Validate a canonical events DataFrame. Returns list of error messages (empty if valid)."""
    errors: List[str] = []

    # 1. Schema and Column Order
    cols = list(df.columns)
    if cols != CANONICAL_EVENT_COLUMNS:
        errors.append(
            f"{source_name}: Column mismatch.\n"
            f"Expected: {CANONICAL_EVENT_COLUMNS}\n"
            f"Found:    {cols}"
        )
        return errors  # Cannot perform subsequent row checks if schema is malformed

    # 2. Row-level checks
    for idx, row in df.iterrows():
        row_id = f"Row {idx} (campaign_id={row.get('campaign_id', '')})"

        # Mandatory fields
        for field in ("campaign_id", "attacker_ip", "original_label", "citation"):
            val = str(row.get(field, "")).strip()
            if not val or val.lower() == "nan":
                errors.append(f"{source_name} {row_id}: Missing mandatory field '{field}'")

        start_ts = str(row.get("start_ts", "")).strip()
        end_ts = str(row.get("end_ts", "")).strip()
        if start_ts.lower() == "nan":
            start_ts = ""
        if end_ts.lower() == "nan":
            end_ts = ""

        # Timestamp format checks
        if start_ts and not UTC_ISO_REGEX.match(start_ts):
            errors.append(f"{source_name} {row_id}: start_ts '{start_ts}' is not UTC ISO 8601 ending in 'Z'")

        if end_ts and not UTC_ISO_REGEX.match(end_ts):
            errors.append(f"{source_name} {row_id}: end_ts '{end_ts}' is not UTC ISO 8601 ending in 'Z'")

        if start_ts and end_ts and UTC_ISO_REGEX.match(start_ts) and UTC_ISO_REGEX.match(end_ts):
            try:
                dt_start = datetime.fromisoformat(start_ts.replace("Z", "+00:00"))
                dt_end = datetime.fromisoformat(end_ts.replace("Z", "+00:00"))
                if dt_start > dt_end:
                    errors.append(f"{source_name} {row_id}: start_ts ({start_ts}) > end_ts ({end_ts})")
            except Exception as e:
                errors.append(f"{source_name} {row_id}: Unparsable timestamp: {e}")

        # Family check
        family = str(row.get("attack_family", "")).strip().lower()
        if family and family not in PERMITTED_FAMILIES:
            errors.append(f"{source_name} {row_id}: Invalid attack_family '{family}'. Permitted: {sorted(PERMITTED_FAMILIES)}")

        # MITRE format checks
        tactic = str(row.get("mitre_tactic", "")).strip()
        if tactic and not TACTIC_REGEX.match(tactic):
            errors.append(f"{source_name} {row_id}: Malformed mitre_tactic '{tactic}'. Expected format: TA####")

        technique = str(row.get("mitre_technique", "")).strip()
        if technique and not TECHNIQUE_REGEX.match(technique):
            errors.append(f"{source_name} {row_id}: Malformed mitre_technique '{technique}'. Expected format: T####[.###]")

        # Background traffic check (critical: background must never be marked benign)
        orig = str(row.get("original_label", "")).lower()
        if "background" in orig and family == "benign":
            errors.append(f"{source_name} {row_id}: Background traffic incorrectly labeled as benign!")

        # Held-out Friday 23-02-2018 protection check
        camp = str(row.get("campaign_id", "")).lower()
        cite = str(row.get("citation", "")).lower()
        if "2018-02-23" in start_ts or "23-02" in camp or "23-02" in cite or "cic2018_fri_ddos" in camp:
            errors.append(f"{source_name} {row_id}: Contamination alert! Held-out test day Friday 23-02-2018 detected in event table.")

    return errors


def validate_events_file(file_path: Path | str) -> Tuple[bool, List[str]]:
    """Validate an events file (.csv or .parquet). Returns (is_valid, errors)."""
    p = Path(file_path).resolve()
    if not p.is_file():
        return False, [f"File not found: {p}"]

    try:
        if p.suffix.lower() == ".parquet":
            df = pd.read_parquet(p)
        else:
            df = pd.read_csv(p, dtype=str, keep_default_na=False)
    except Exception as e:
        return False, [f"Failed to read {p}: {e}"]

    errors = validate_events_df(df, source_name=p.name)
    return len(errors) == 0, errors


def validate_dataset_events(path: Path | str) -> bool:
    """Validate events file or all event files in a directory."""
    target = Path(path).resolve()
    all_files: List[Path] = []

    if target.is_file():
        all_files.append(target)
    elif target.is_dir():
        for r, _, files in os.walk(target):
            for f in files:
                if f in ("events.csv", "events.parquet"):
                    all_files.append(Path(r) / f)

    if not all_files:
        print(f"[validate_standard_events] No events.csv or events.parquet found at: {target}")
        return False

    print("\n" + "=" * 60)
    print("UNIFIED STANDARD EVENTS VALIDATION")
    print("=" * 60)

    total_valid = 0
    total_checked = len(all_files)

    for f in all_files:
        valid, errors = validate_events_file(f)
        if valid:
            total_valid += 1
            print(f"  [PASS] {f.relative_to(target.parent) if target.parent in f.parents else f.name}")
        else:
            print(f"  [FAIL] {f.name} ({len(errors)} errors):")
            for err in errors[:5]:
                print(f"         * {err}")
            if len(errors) > 5:
                print(f"         * ... and {len(errors) - 5} more errors")

    print("\n" + "=" * 60)
    print(f"VALIDATION SUMMARY: {total_valid}/{total_checked} files passed.")
    print("=" * 60 + "\n")
    return total_valid == total_checked


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate canonical standard events files.")
    parser.add_argument("path", help="Path to events.csv / events.parquet or root ground_truth directory")
    args = parser.parse_args()

    success = validate_dataset_events(args.path)
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()

