"""Stage 3 - Ground-Truth Event Builder (scripts/build_events.py).

Builds canonical 14-column events (.parquet or .csv) from dataset ground-truth sources.
Supports:
  --dataset unsw_nb15 : transforms official NUSW-NB15_GT.csv
  --dataset ctu13     : transforms CTU-13 .binetflow scenario files
  --dataset lab       : transforms synthetic lab recording sidecars (labels.csv)

Enforces exact duplicate dropping, UTC ISO 8601 formatting, campaign ID grouping,
strict validation against pipeline.label_standard and pipeline.mitre_mapping,
and enforces that background traffic is never marked benign.
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from pipeline.label_standard import (
    CANONICAL_EVENT_COLUMNS,
    lookup_standard_mapping,
)
from pipeline.mitre_mapping import (
    BENIGN,
    COMMAND_AND_CONTROL,
    EXFILTRATION,
    IMPACT,
    INITIAL_ACCESS,
    LATERAL_MOVEMENT,
    RECONNAISSANCE,
    ctu13_label_to_stage,
    label_to_stage,
)

# ---------------------------------------------------------------------------
# CTU-13 Official Scenario Metadata (Stratosphere IPS https://www.stratosphereips.org/datasets-ctu13)
# ---------------------------------------------------------------------------
CTU13_SCENARIOS: Dict[int, Dict[str, Any]] = {
    1: {
        "bot_name": "Neris",
        "infected_hosts": ["147.32.84.165"],
        "normal_hosts": ["147.32.84.170", "147.32.84.134", "147.32.84.164"],
        "description": "IRC bot, spam, HTTP C&C",
    },
    2: {
        "bot_name": "Neris",
        "infected_hosts": ["147.32.84.165"],
        "normal_hosts": ["147.32.84.170", "147.32.84.164"],
        "description": "IRC bot, spam, HTTP C&C",
    },
    3: {
        "bot_name": "Rbot",
        "infected_hosts": ["147.32.84.165"],
        "normal_hosts": ["147.32.84.170", "147.32.84.134", "147.32.84.164"],
        "description": "IRC botnet, portscan, USer-to-User",
    },
    4: {
        "bot_name": "Rbot",
        "infected_hosts": ["147.32.84.165"],
        "normal_hosts": ["147.32.84.170", "147.32.84.134", "147.32.84.164"],
        "description": "IRC botnet, ICMP and TCP flood (DDoS)",
    },
    5: {
        "bot_name": "Virut",
        "infected_hosts": ["147.32.84.165"],
        "normal_hosts": ["147.32.84.170", "147.32.84.134", "147.32.84.164"],
        "description": "HTTP C&C, SPAM, scanning",
    },
    6: {
        "bot_name": "Menti",
        "infected_hosts": ["147.32.84.165"],
        "normal_hosts": ["147.32.84.170", "147.32.84.134", "147.32.84.164"],
        "description": "HTTP C&C, custom encryption, binary download",
    },
    7: {
        "bot_name": "Sogou",
        "infected_hosts": ["147.32.84.165"],
        "normal_hosts": ["147.32.84.170", "147.32.84.134", "147.32.84.164"],
        "description": "HTTP C&C, portscan",
    },
    8: {
        "bot_name": "Murlo",
        "infected_hosts": ["147.32.84.165"],
        "normal_hosts": ["147.32.84.170", "147.32.84.134", "147.32.84.164"],
        "description": "Custom encryption C&C, portscan",
    },
    9: {
        "bot_name": "Neris",
        "infected_hosts": [
            "147.32.84.165", "147.32.84.191", "147.32.84.192", "147.32.84.193",
            "147.32.84.204", "147.32.84.205", "147.32.84.206", "147.32.84.207",
            "147.32.84.208", "147.32.84.209"
        ],
        "normal_hosts": ["147.32.84.170", "147.32.84.134", "147.32.84.164"],
        "description": "IRC botnet, 10 infected hosts, spam, portscan",
    },
    10: {
        "bot_name": "Rbot",
        "infected_hosts": [
            "147.32.84.165", "147.32.84.191", "147.32.84.192", "147.32.84.193",
            "147.32.84.204", "147.32.84.205", "147.32.84.206", "147.32.84.207",
            "147.32.84.208", "147.32.84.209"
        ],
        "normal_hosts": ["147.32.84.170", "147.32.84.134", "147.32.84.164"],
        "description": "IRC botnet, 10 infected hosts, ICMP DDoS, portscan",
    },
    11: {
        "bot_name": "Rbot",
        "infected_hosts": ["147.32.84.165", "147.32.84.191", "147.32.84.192"],
        "normal_hosts": ["147.32.84.170", "147.32.84.134", "147.32.84.164"],
        "description": "IRC botnet, 3 infected hosts, ICMP DDoS",
    },
    12: {
        "bot_name": "NSIS.ay",
        "infected_hosts": ["147.32.84.165"],
        "normal_hosts": ["147.32.84.170", "147.32.84.134", "147.32.84.164"],
        "description": "P2P and HTTP C&C",
    },
    13: {
        "bot_name": "Virut",
        "infected_hosts": ["147.32.84.165"],
        "normal_hosts": ["147.32.84.170", "147.32.84.134", "147.32.84.164"],
        "description": "HTTP C&C, SPAM, scanning",
    },
}


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


def parse_timestamp_to_utc_iso(ts_val: Any) -> str:
    """Convert arbitrary timestamp string or numeric value to UTC ISO 8601 with Z."""
    if ts_val is None or pd.isna(ts_val):
        return ""
    txt = str(ts_val).strip()
    if not txt:
        return ""
    # Try numeric epoch
    try:
        val_float = float(txt)
        return format_epoch_to_utc_iso(val_float)
    except ValueError:
        pass

    # Parse ISO / datetime string
    dt = pd.to_datetime(txt, errors="coerce")
    if pd.isna(dt):
        return ""
    if dt.tzinfo is None:
        dt = dt.tz_localize("UTC")
    else:
        dt = dt.tz_convert("UTC")
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_dataframe_output(df: pd.DataFrame, out_path: Path) -> None:
    """Write output in Parquet or CSV format based on destination suffix."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.suffix.lower() == ".csv":
        df.to_csv(out_path, index=False, encoding="utf-8")
    else:
        df.to_parquet(out_path, index=False, engine="pyarrow")


# ===========================================================================
# 1. UNSW-NB15 Ground-Truth Builder
# ===========================================================================

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

    df_raw.columns = [c.strip() for c in df_raw.columns]

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

    df_dedup = df_raw.drop_duplicates()
    duplicates_removed = total_input_rows - len(df_dedup)
    print(f"[build_events] Input rows: {total_input_rows} | Deduplicated: {len(df_dedup)} | Duplicates removed: {duplicates_removed}")

    unique_categories = sorted(df_dedup["Attack category"].str.strip().unique())
    unmapped_categories: Dict[str, List[str]] = {}

    for cat in unique_categories:
        if not cat:
            continue
        mapping = lookup_standard_mapping(cat)
        if mapping is None:
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
    _write_dataframe_output(df_out, out_file)
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
    print("=" * 60 + "\n")
    return df_out


# ===========================================================================
# 2. CTU-13 Ground-Truth Builder
# ===========================================================================

def detect_ctu13_scenario_id(file_or_dir: Path, explicit_id: Optional[int] = None) -> int:
    """Infer CTU-13 scenario ID (1..13) from path or explicit argument."""
    if explicit_id is not None:
        if explicit_id in CTU13_SCENARIOS:
            return explicit_id
        raise ValueError(f"Invalid CTU-13 scenario ID: {explicit_id}. Must be between 1 and 13.")

    # Match scenario number in path: e.g. "scenario 1", "scenario_01", "/1/", "1.binetflow"
    p_str = str(file_or_dir).replace("\\", "/")
    m = re.search(r"(?:scenario|ctu13|capture)[_-]?(\d{1,2})", p_str, re.IGNORECASE)
    if m:
        scen_id = int(m.group(1))
        if scen_id in CTU13_SCENARIOS:
            return scen_id

    # Check parent directory name
    if file_or_dir.parent.name.isdigit():
        scen_id = int(file_or_dir.parent.name)
        if scen_id in CTU13_SCENARIOS:
            return scen_id

    # Default fallback to Scenario 1 if unspecified
    return 1


def build_ctu13_events(
    input_path: Path | str,
    out_path: Path | str,
    scenario_id: Optional[int] = None,
) -> pd.DataFrame:
    """Transform CTU-13 .binetflow flows into canonical events."""
    in_file = Path(input_path).resolve()
    out_file = Path(out_path).resolve()

    if in_file.is_dir():
        # Look for .binetflow file inside directory
        binetflows = list(in_file.glob("*.binetflow"))
        if not binetflows:
            raise FileNotFoundError(f"No .binetflow file found in directory: {in_file}")
        in_file = binetflows[0]

    if not in_file.is_file():
        raise FileNotFoundError(f"CTU-13 BINETFLOW file not found: {in_file}")

    scen_id = detect_ctu13_scenario_id(in_file, explicit_id=scenario_id)
    meta = CTU13_SCENARIOS[scen_id]
    bot_name = meta["bot_name"]
    infected_hosts = set(meta["infected_hosts"])
    normal_hosts = set(meta["normal_hosts"])

    print(f"\n[build_events] Processing CTU-13 Scenario {scen_id} ({bot_name}) from: {in_file}")

    # Read BINETFLOW
    df_raw = pd.read_csv(in_file, dtype=str, keep_default_na=False)
    # Normalize headers
    clean_cols = {}
    for c in df_raw.columns:
        clean_name = c.strip().lstrip("#").strip()
        clean_cols[c] = clean_name
    df_raw = df_raw.rename(columns=clean_cols)

    total_input_flows = len(df_raw)
    background_flows_excluded = 0
    records: List[Dict[str, Any]] = []

    # Map necessary columns
    col_start = "StartTime" if "StartTime" in df_raw.columns else "timestamp"
    col_src = "SrcAddr" if "SrcAddr" in df_raw.columns else "src_ip"
    col_dst = "DstAddr" if "DstAddr" in df_raw.columns else "dst_ip"
    col_dport = "Dport" if "Dport" in df_raw.columns else "dst_port"
    col_label = "Label" if "Label" in df_raw.columns else "label"
    col_dur = "Dur" if "Dur" in df_raw.columns else "duration_s"

    if col_start not in df_raw.columns or col_label not in df_raw.columns:
        raise ValueError(f"BINETFLOW missing required StartTime or Label columns. Found: {list(df_raw.columns)}")

    # Parse timestamps
    df_raw["parsed_ts"] = pd.to_datetime(df_raw[col_start].str.strip(), errors="coerce")
    df_raw["dur_num"] = pd.to_numeric(df_raw.get(col_dur, 0), errors="coerce").fillna(0.0)

    # Filter out unusable rows
    valid_df = df_raw.dropna(subset=["parsed_ts"])

    # Separate flows:
    # 1. Background flows -> STRICTLY EXCLUDED from event generation
    # 2. Botnet flows -> Group by (infected_host, behaviour)
    # 3. Normal flows -> Only generate benign events for explicitly documented normal_hosts

    botnet_rows: List[dict] = []
    normal_rows: List[dict] = []

    for row in valid_df.itertuples(index=False):
        raw_label = getattr(row, col_label).strip()
        label_lower = raw_label.lower()

        # Rule 3.4: Background traffic produces NO event
        if "background" in label_lower or label_lower.startswith("flow=background"):
            background_flows_excluded += 1
            continue

        src_ip = getattr(row, col_src).strip()
        dst_ip = getattr(row, col_dst).strip()

        # Normal traffic check
        if "normal" in label_lower or label_lower.startswith("flow=normal"):
            # Only include if traffic involves explicitly documented normal hosts
            if src_ip in normal_hosts or dst_ip in normal_hosts:
                normal_rows.append({
                    "host": src_ip if src_ip in normal_hosts else dst_ip,
                    "peer": dst_ip if src_ip in normal_hosts else src_ip,
                    "ts": getattr(row, "parsed_ts"),
                    "dur": getattr(row, "dur_num"),
                    "label": raw_label,
                    "dport": getattr(row, col_dport, ""),
                })
            else:
                # Undocumented host claiming normal -> treat as unverified background (exclude)
                background_flows_excluded += 1
            continue

        # Botnet traffic check
        is_botnet = (
            "from-botnet" in label_lower
            or "botnet" in label_lower
            or src_ip in infected_hosts
            or dst_ip in infected_hosts
        )

        if is_botnet:
            inf_host = src_ip if src_ip in infected_hosts else (dst_ip if dst_ip in infected_hosts else src_ip)
            peer_host = dst_ip if inf_host == src_ip else src_ip
            botnet_rows.append({
                "infected_host": inf_host,
                "peer": peer_host,
                "ts": getattr(row, "parsed_ts"),
                "dur": getattr(row, "dur_num"),
                "label": raw_label,
                "dport": getattr(row, col_dport, ""),
            })
        else:
            # Other unknown labels -> exclude from ground truth event table
            background_flows_excluded += 1

    # Group botnet rows by (infected_host, behaviour)
    events_per_family: Dict[str, int] = {}

    if botnet_rows:
        df_bots = pd.DataFrame(botnet_rows)
        for (inf_host, beh_label), group in df_bots.groupby(["infected_host", "label"]):
            start_dt = group["ts"].min()
            max_start = group["ts"].max()
            max_dur = group.loc[group["ts"] == max_start, "dur"].max()
            end_dt = max_start + pd.Timedelta(seconds=max_dur)

            # Determine MITRE stage using pipeline.mitre_mapping.ctu13_label_to_stage
            stage = ctu13_label_to_stage(beh_label)
            label_lower = beh_label.lower()

            if stage == COMMAND_AND_CONTROL:
                family = "botnet_c2"
                tactic = "TA0011"
                technique = "T1071"
            elif stage == INITIAL_ACCESS:
                family = "web_exploit"
                tactic = "TA0001"
                technique = "T1190"
            elif "icmp" in label_lower or "flood" in label_lower:
                family = "ddos"
                tactic = "TA0040"
                technique = "T1498"
            elif "scan" in label_lower:
                family = "portscan"
                tactic = "TA0043"
                technique = "T1595"
            else:
                family = "botnet_c2"
                tactic = "TA0011"
                technique = "T1071"

            # Determine dominant peer and port
            peers = group["peer"].value_counts()
            victim_ip = peers.index[0] if len(peers) > 0 else ""

            dports = group["dport"].replace("", pd.NA).dropna().unique()
            dst_port = str(int(float(dports[0]))) if len(dports) == 1 and str(dports[0]).replace(".","").isdigit() else ""

            clean_tag = re.sub(r"[^a-zA-Z0-9]+", "_", beh_label.replace("flow=", "")).strip("_").lower()
            campaign_id = f"ctu13_scen{scen_id}_{inf_host}_{clean_tag}"

            rec = {
                "campaign_id": campaign_id,
                "attacker_ip": inf_host,
                "victim_ip": victim_ip,
                "dst_port": dst_port,
                "start_ts": parse_timestamp_to_utc_iso(start_dt),
                "end_ts": parse_timestamp_to_utc_iso(end_dt),
                "attack_family": family,
                "attack_variant": f"{bot_name.lower()}_{clean_tag}",
                "mitre_tactic": tactic,
                "mitre_technique": technique,
                "label_source": "dataset_flow_label",
                "label_confidence": "exact",
                "original_label": beh_label,
                "citation": f"https://www.stratosphereips.org/datasets-ctu13 (Scenario {scen_id}: {bot_name})",
            }
            records.append(rec)
            events_per_family[family] = events_per_family.get(family, 0) + 1

    # Group normal rows by (normal_host, label)
    normal_events_count = 0
    if normal_rows:
        df_norm = pd.DataFrame(normal_rows)
        for (norm_host, beh_label), group in df_norm.groupby(["host", "label"]):
            start_dt = group["ts"].min()
            max_start = group["ts"].max()
            max_dur = group.loc[group["ts"] == max_start, "dur"].max()
            end_dt = max_start + pd.Timedelta(seconds=max_dur)

            peers = group["peer"].value_counts()
            victim_ip = peers.index[0] if len(peers) > 0 else ""
            clean_tag = re.sub(r"[^a-zA-Z0-9]+", "_", beh_label.replace("flow=", "")).strip("_").lower()
            campaign_id = f"ctu13_scen{scen_id}_{norm_host}_normal"

            rec = {
                "campaign_id": campaign_id,
                "attacker_ip": norm_host,
                "victim_ip": victim_ip,
                "dst_port": "",
                "start_ts": parse_timestamp_to_utc_iso(start_dt),
                "end_ts": parse_timestamp_to_utc_iso(end_dt),
                "attack_family": "benign",
                "attack_variant": "normal",
                "mitre_tactic": "",
                "mitre_technique": "",
                "label_source": "dataset_flow_label",
                "label_confidence": "exact",
                "original_label": beh_label,
                "citation": f"https://www.stratosphereips.org/datasets-ctu13 (Scenario {scen_id}: Normal verified host)",
            }
            records.append(rec)
            normal_events_count += 1
            events_per_family["benign"] = events_per_family.get("benign", 0) + 1

    df_out = pd.DataFrame(records, columns=CANONICAL_EVENT_COLUMNS)
    _write_dataframe_output(df_out, out_file)

    print("\n" + "=" * 60)
    print(f"CTU-13 SCENARIO {scen_id} EVENT GENERATION SUMMARY")
    print("=" * 60)
    print(f"Total input flows:            {total_input_flows}")
    print(f"Background flows excluded:    {background_flows_excluded}")
    print(f"Total events generated:       {len(df_out)}")
    print(f"Normal benign events:         {normal_events_count}")
    print("\nEvents per attack family:")
    for fam, cnt in sorted(events_per_family.items()):
        print(f"  - {fam}: {cnt}")
    print("=" * 60 + "\n")
    return df_out


# ===========================================================================
# 3. Lab Campaign Sidecar Builder
# ===========================================================================

def build_lab_events(
    labels_csv_path: Path | str,
    out_path: Path | str,
) -> pd.DataFrame:
    """Transform synthetic lab recording labels.csv into canonical events."""
    lab_file = Path(labels_csv_path).resolve()
    out_file = Path(out_path).resolve()

    if not lab_file.is_file():
        raise FileNotFoundError(f"Lab sidecar file not found: {lab_file}")

    print(f"\n[build_events] Reading synthetic lab sidecar: {lab_file}")
    df_raw = pd.read_csv(lab_file, dtype=str, keep_default_na=False)

    # Normalize aliases per pipeline/adapters/sidecar.py
    aliases = {
        "attacker_ip": "src_ip", "attacker": "src_ip", "source_ip": "src_ip", "src": "src_ip",
        "victim_ip": "dst_ip", "victim": "dst_ip", "destination_ip": "dst_ip", "dst": "dst_ip",
        "start_time": "start", "begin": "start", "end_time": "end", "stop": "end",
        "attack": "label", "attack_label": "label", "class": "label",
    }
    df_raw.columns = [aliases.get(c.strip().lower(), c.strip().lower()) for c in df_raw.columns]

    if "label" not in df_raw.columns:
        raise ValueError(f"Sidecar {lab_file} missing 'label' column (found {list(df_raw.columns)})")

    for col in ("src_ip", "dst_ip", "start", "end", "dst_port"):
        if col not in df_raw.columns:
            df_raw[col] = ""

    records: List[Dict[str, Any]] = []
    events_per_family: Dict[str, int] = {}

    for idx, row in df_raw.iterrows():
        raw_label = row["label"].strip()
        src_ip = row["src_ip"].strip()
        dst_ip = row["dst_ip"].strip()
        start_raw = row["start"].strip()
        end_raw = row["end"].strip()
        dst_port_raw = row["dst_port"].strip()

        start_ts = parse_timestamp_to_utc_iso(start_raw)
        end_ts = parse_timestamp_to_utc_iso(end_raw) if end_raw else start_ts

        # Date for campaign ID
        date_str = start_ts[:10].replace("-", "") if start_ts else "20261010"

        # Lookup standard mapping
        mapping = lookup_standard_mapping(raw_label)
        if mapping:
            family = mapping["attack_family"]
            tactic = mapping["mitre_tactic"]
            technique = mapping["mitre_technique"]
        else:
            # Fallback to mitre_mapping.label_to_stage
            stg = label_to_stage(raw_label)
            if stg == RECONNAISSANCE:
                family = "portscan"
                tactic = "TA0043"
                technique = "T1595"
            elif stg == INITIAL_ACCESS:
                family = "bruteforce"
                tactic = "TA0006"
                technique = "T1110"
            elif stg == LATERAL_MOVEMENT:
                family = "infiltration"
                tactic = "TA0008"
                technique = "T1021"
            elif stg == COMMAND_AND_CONTROL:
                family = "botnet_c2"
                tactic = "TA0011"
                technique = "T1071"
            elif stg == EXFILTRATION:
                family = "exfiltration"
                tactic = "TA0010"
                technique = "T1041"
            elif stg == IMPACT:
                family = "dos"
                tactic = "TA0040"
                technique = "T1499"
            else:
                family = "benign"
                tactic = ""
                technique = ""

        dst_port = ""
        if dst_port_raw.isdigit():
            dst_port = str(int(dst_port_raw))

        clean_label = re.sub(r"[^a-zA-Z0-9]+", "_", raw_label).strip("_").lower()
        campaign_id = f"lab_{date_str}_{src_ip}_{clean_label}_{idx:02d}"

        rec = {
            "campaign_id": campaign_id,
            "attacker_ip": src_ip,
            "victim_ip": dst_ip,
            "dst_port": dst_port,
            "start_ts": start_ts,
            "end_ts": end_ts,
            "attack_family": family,
            "attack_variant": clean_label,
            "mitre_tactic": tactic,
            "mitre_technique": technique,
            "label_source": "lab_driver_log",
            "label_confidence": "exact",
            "original_label": raw_label,
            "citation": "scripts/record_lab_campaigns.py: synthetic lab recording (controlled local research)",
        }
        records.append(rec)
        events_per_family[family] = events_per_family.get(family, 0) + 1

    df_out = pd.DataFrame(records, columns=CANONICAL_EVENT_COLUMNS)
    _write_dataframe_output(df_out, out_file)

    print("\n" + "=" * 60)
    print("LAB SYNTHETIC CAMPAIGN EVENT GENERATION SUMMARY")
    print("=" * 60)
    print(f"Total input rows:            {len(df_raw)}")
    print(f"Total events generated:       {len(df_out)}")
    print("\nEvents per attack family:")
    for fam, cnt in sorted(events_per_family.items()):
        print(f"  - {fam}: {cnt}")
    print("=" * 60 + "\n")
    return df_out


def main() -> None:
    parser = argparse.ArgumentParser(description="Stage 3 - Ground-Truth Event Builder.")
    parser.add_argument(
        "--dataset",
        required=True,
        choices=["unsw_nb15", "ctu13", "lab"],
        help="Dataset name to process",
    )
    parser.add_argument("--gt", "--input", dest="input_path", required=True, help="Path to raw ground-truth or BINETFLOW or sidecar file")
    parser.add_argument("--out", required=True, help="Path to write output events file (.parquet or .csv)")
    parser.add_argument("--scenario", type=int, default=None, help="Explicit CTU-13 scenario ID (1..13)")
    parser.add_argument(
        "--allow-unmapped",
        action="store_true",
        help="Proceed with empty family/MITRE fields if unmapped categories are found (default False: stop & report)",
    )

    args = parser.parse_args()

    if args.dataset == "unsw_nb15":
        build_unsw_nb15_events(
            gt_csv_path=args.input_path,
            out_parquet_path=args.out,
            allow_unmapped=args.allow_unmapped,
        )
    elif args.dataset == "ctu13":
        build_ctu13_events(
            input_path=args.input_path,
            out_path=args.out,
            scenario_id=args.scenario,
        )
    elif args.dataset == "lab":
        build_lab_events(
            labels_csv_path=args.input_path,
            out_path=args.out,
        )


if __name__ == "__main__":
    main()
