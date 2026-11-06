"""Stage 3 - Ground-Truth Event Builder (scripts/build_events.py).

Builds canonical 14-column events.parquet from dataset ground-truth sources.
Currently implements the UNSW-NB15 ground-truth parser (--dataset unsw_nb15).
Enforces exact duplicate dropping, UTC ISO 8601 formatting, campaign ID grouping,
strict validation against pipeline.label_standard, and reports unmapped categories.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from pipeline.label_standard import (
    CANONICAL_EVENT_COLUMNS,
    lookup_standard_mapping,
)


def format_epoch_to_utc_iso(epoch_val: Any) -> str:
    """Convert Unix epoch timestamp to UTC ISO 8601 string ending in Z."""
    sec = float(epoch_val)
    dt = datetime.fromtimestamp(sec, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def format_epoch_to_utc_date(epoch_val: Any) -> str:
    """Convert Unix epoch timestamp to YYYYMMDD date string for campaign ID."""
    sec = float(epoch_val)
    dt = datetime.fromtimestamp(sec, tz=timezone.utc)
    return dt.strftime("%Y%m%d")


def build_unsw_nb15_events(
    gt_csv_path: Path | str,
    out_parquet_path: Path | str,
    allow_unmapped: bool = False,
) -> pd.DataFrame:
    """Transform NUSW-NB15_GT.csv into canonical events.parquet."""
    gt_file = Path(gt_csv_path).resolve()
    out_file = Path(out_parquet_path).resolve()

    if not gt_file.is_file():
        raise FileNotFoundError(f"UNSW ground-truth file not found: {gt_file}")

    print(f"\n[build_events] Reading UNSW-NB15 ground-truth file: {gt_file}")
    df_raw = pd.read_csv(gt_file, dtype=str, keep_default_na=False)
    total_input_rows = len(df_raw)

    # Clean whitespace in column names
    df_raw.columns = [c.strip() for c in df_raw.columns]

    # Required raw columns check
    required_cols = [
        "Start time",
        "Last time",
        "Attack category",
        "Attack subcategory",
        "Source IP",
        "Destination IP",
        "Destination Port",
    ]
    missing = [c for c in required_cols if c not in df_raw.columns]
    if missing:
        raise ValueError(f"Missing required columns in UNSW ground-truth CSV: {missing}")

    # Remove exact duplicate rows
    df_dedup = df_raw.drop_duplicates()
    duplicates_removed = total_input_rows - len(df_dedup)
    print(f"[build_events] Input rows: {total_input_rows} | Deduplicated: {len(df_dedup)} | Duplicates removed: {duplicates_removed}")

    # Inspect attack categories and check mappings
    unique_categories = sorted(df_dedup["Attack category"].str.strip().unique())
    unmapped_categories: Dict[str, List[str]] = {}

    for cat in unique_categories:
        if not cat:
            continue
        mapping = lookup_standard_mapping(cat)
        if mapping is None:
            # Find sample subcategories / attack names as context
            samples = (
                df_dedup[df_dedup["Attack category"].str.strip() == cat]["Attack subcategory"]
                .str.strip()
                .unique()
                .tolist()[:3]
            )
            unmapped_categories[cat] = [s for s in samples if s]

    if unmapped_categories and not allow_unmapped:
        print("\n" + "!" * 60)
        print("ERROR: UNMAPPED ATTACK CATEGORIES DETECTED IN UNSW-NB15 GROUND TRUTH")
        print("!" * 60)
        print("The following attack categories have no entry in pipeline.label_standard:")
        for cat, samples in unmapped_categories.items():
            sample_str = f" (sample subcategories: {samples})" if samples else ""
            print(f"  * {cat}{sample_str}")
        print("\nAs required by Rule 6 and Section 8.6:")
        print("- Generation stopped.")
        print("- No independent mappings have been fabricated.")
        print("- Please report this list to Yash for official mapping inclusion.")
        print("!" * 60 + "\n")
        raise ValueError(
            f"Unmapped attack categories in ground truth: {list(unmapped_categories.keys())}. "
            f"Process stopped to avoid unverified labels."
        )

    # Build canonical records
    records: List[Dict[str, Any]] = []
    events_per_category: Dict[str, int] = {}
    events_per_day: Dict[str, int] = {}

    gt_filename = gt_file.name

    for _, row in df_dedup.iterrows():
        start_raw = row["Start time"].strip()
        last_raw = row["Last time"].strip()
        cat_raw = row["Attack category"].strip()
        subcat_raw = row["Attack subcategory"].strip()
        src_ip = row["Source IP"].strip()
        dst_ip = row["Destination IP"].strip()
        dst_port_raw = row["Destination Port"].strip()
        attack_name = row.get("Attack Name", "").strip()
        attack_ref = row.get("Attack Reference", "").strip()

        if not start_raw:
            continue

        start_ts = format_epoch_to_utc_iso(start_raw)
        end_ts = format_epoch_to_utc_iso(last_raw) if last_raw else start_ts
        date_str = format_epoch_to_utc_date(start_raw)

        campaign_id = f"unsw_{date_str}_{src_ip}"

        dst_port = ""
        if dst_port_raw.isdigit():
            dst_port = str(int(dst_port_raw))

        attack_variant = subcat_raw if subcat_raw else attack_name

        mapping = lookup_standard_mapping(cat_raw)
        if mapping:
            attack_family = mapping["attack_family"]
            mitre_tactic = mapping["mitre_tactic"]
            mitre_technique = mapping["mitre_technique"]
        else:
            attack_family = ""
            mitre_tactic = ""
            mitre_technique = ""

        citation = f"{gt_filename}: {attack_ref}" if attack_ref else gt_filename

        events_per_category[cat_raw] = events_per_category.get(cat_raw, 0) + 1
        events_per_day[date_str] = events_per_day.get(date_str, 0) + 1

        rec = {
            "campaign_id": campaign_id,
            "attacker_ip": src_ip,
            "victim_ip": dst_ip,
            "dst_port": dst_port,
            "start_ts": start_ts,
            "end_ts": end_ts,
            "attack_family": attack_family,
            "attack_variant": attack_variant,
            "mitre_tactic": mitre_tactic,
            "mitre_technique": mitre_technique,
            "label_source": "dataset_flow_label",
            "label_confidence": "exact",
            "original_label": cat_raw,
            "citation": citation,
        }
        records.append(rec)

    df_out = pd.DataFrame(records, columns=CANONICAL_EVENT_COLUMNS)

    # Save to Parquet
    out_file.parent.mkdir(parents=True, exist_ok=True)
    df_out.to_parquet(out_file, index=False, engine="pyarrow")
    print(f"\n[build_events] Successfully wrote {len(df_out)} events to {out_file}")

    print("\n" + "=" * 60)
    print("UNSW-NB15 EVENT GENERATION SUMMARY")
    print("=" * 60)
    print(f"Total input rows:            {total_input_rows}")
    print(f"Total output events:         {len(df_out)}")
    print(f"Exact duplicates removed:    {duplicates_removed}")
    print("\nEvents per attack category:")
    for c, cnt in sorted(events_per_category.items()):
        print(f"  - {c}: {cnt}")
    print("\nEvents per day:")
    for d, cnt in sorted(events_per_day.items()):
        print(f"  - {d}: {cnt}")
    if unmapped_categories:
        print(f"\nUnmapped categories handled with --allow-unmapped ({len(unmapped_categories)}):")
        for u in unmapped_categories:
            print(f"  * {u}")
    else:
        print("\nUnmapped categories: None")
    print("=" * 60 + "\n")

    return df_out


def main() -> None:
    parser = argparse.ArgumentParser(description="Stage 3 - Ground-Truth Event Builder.")
    parser.add_argument("--dataset", required=True, choices=["unsw_nb15"], help="Dataset name to process")
    parser.add_argument("--gt", required=True, help="Path to raw ground-truth file (e.g. NUSW-NB15_GT.csv)")
    parser.add_argument("--out", required=True, help="Path to write output events.parquet")
    parser.add_argument(
        "--allow-unmapped",
        action="store_true",
        help="Proceed with empty family/MITRE fields if unmapped categories are found (default False: stop & report)",
    )

    args = parser.parse_args()

    if args.dataset == "unsw_nb15":
        build_unsw_nb15_events(
            gt_csv_path=args.gt,
            out_parquet_path=args.out,
            allow_unmapped=args.allow_unmapped,
        )


if __name__ == "__main__":
    main()
