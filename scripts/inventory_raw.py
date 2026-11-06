"""Stage 2 - Raw Dataset Inventory Tool.

Recursively inspects a dataset directory and produces `<dataset_folder>/inventory.csv`.
Supports resumability, magic-number file kind detection, 8 MB chunked SHA-256,
capinfos packet metadata extraction, and warning flags (e.g. Excel row cap).
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

EXCEL_ROW_CAP = 1048575
CHUNK_SIZE = 8 * 1024 * 1024  # 8 MB

MAGIC_NUMBERS: List[Tuple[bytes, str]] = [
    (b"\xa1\xb2\xc3\xd4", "pcap"),       # Standard microsecond
    (b"\xd4\xc3\xb2\xa1", "pcap"),       # Swapped microsecond
    (b"\xa1\xb2\x3c\x4d", "pcap"),       # Standard nanosecond
    (b"\x4d\x3c\xb2\xa1", "pcap"),       # Swapped nanosecond
    (b"\x0a\x0d\x0d\x0a", "pcapng"),     # PCAP-NG Section Header Block
    (b"PK\x03\x04", "zip"),              # ZIP archive
]

CSV_COLUMNS = [
    "rel_path",
    "size_bytes",
    "sha256",
    "kind",
    "packets",
    "first_ts_utc",
    "last_ts_utc",
    "rows",
    "flags",
]


def detect_kind(file_path: Path) -> str:
    """Detect file kind by magic bytes first, then by extension."""
    try:
        with open(file_path, "rb") as f:
            header = f.read(4)
            for magic, kind in MAGIC_NUMBERS:
                if header.startswith(magic):
                    return kind
    except (OSError, PermissionError):
        pass

    suffix = file_path.suffix.lower().lstrip(".")
    if suffix == "csv":
        return "csv"
    if suffix == "binetflow":
        return "binetflow"
    if suffix == "pdf":
        return "pdf"
    return "other"


def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 in 8 MB chunks."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def count_data_rows(file_path: Path) -> int:
    """Count data rows excluding header efficiently for text / csv / binetflow."""
    lines = 0
    with open(file_path, "rb") as f:
        buf = f.read(1024 * 1024)
        if not buf:
            return 0
        last_byte = None
        while buf:
            lines += buf.count(b"\n")
            last_byte = buf[-1]
            buf = f.read(1024 * 1024)
        if last_byte != ord(b"\n"):
            lines += 1
    return max(0, lines - 1)


def find_capinfos_path() -> Optional[str]:
    """Find capinfos executable in PATH or common Wireshark locations."""
    which_path = shutil.which("capinfos")
    if which_path:
        return which_path
    standard_win = Path(r"C:\Program Files\Wireshark\capinfos.exe")
    if standard_win.exists():
        return str(standard_win)
    standard_win_x86 = Path(r"C:\Program Files (x86)\Wireshark\capinfos.exe")
    if standard_win_x86.exists():
        return str(standard_win_x86)
    return None


def run_capinfos(
    file_path: Path, capinfos_exe: Optional[str] = None
) -> Tuple[Optional[int], Optional[str], Optional[str], List[str]]:
    """Run capinfos to extract packet count and UTC timestamps.
    
    Returns (packets, first_ts_utc, last_ts_utc, flags).
    """
    flags: List[str] = []
    exe = capinfos_exe or find_capinfos_path()
    if not exe:
        flags.append("capinfos_failed")
        return None, None, None, flags

    cmd = [exe, "-T", "-m", "-c", "-a", "-e", "-S", str(file_path)]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        stderr_lower = res.stderr.lower()
        if "cut short" in stderr_lower or "truncated" in stderr_lower or "error occurred" in stderr_lower:
            flags.append("truncated_capture")

        if res.returncode != 0 and not res.stdout.strip():
            flags.append("capinfos_failed")
            return None, None, None, flags

        lines = [line.strip() for line in res.stdout.strip().splitlines() if line.strip()]
        if len(lines) < 2:
            if "truncated_capture" not in flags:
                flags.append("capinfos_failed")
            return None, None, None, flags

        reader = csv.reader(lines)
        header = next(reader)
        row = next(reader, None)
        if not row or len(row) < 4:
            flags.append("capinfos_failed")
            return None, None, None, flags

        # Columns: File name,Number of packets,Start time,End time
        packets_str, start_str, end_str = row[1], row[2], row[3]
        try:
            packets = int(packets_str)
        except ValueError:
            packets = None

        def parse_epoch(val: str) -> Optional[str]:
            val_clean = val.strip()
            if not val_clean or val_clean.lower() == "n/a":
                return None
            try:
                sec = float(val_clean)
                dt = datetime.fromtimestamp(sec, tz=timezone.utc)
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except (ValueError, OSError, OverflowError):
                return None

        first_ts = parse_epoch(start_str)
        last_ts = parse_epoch(end_str)
        return packets, first_ts, last_ts, flags

    except Exception:
        flags.append("capinfos_failed")
        return None, None, None, flags


def get_cache_path(dataset_folder: Path) -> Path:
    return dataset_folder / ".inventory_cache.json"


def load_cache(dataset_folder: Path) -> Dict[str, Dict[str, Any]]:
    cache_file = get_cache_path(dataset_folder)
    if cache_file.exists():
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_cache(dataset_folder: Path, cache: Dict[str, Dict[str, Any]]) -> None:
    cache_file = get_cache_path(dataset_folder)
    tmp_file = dataset_folder / ".inventory_cache.json.tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
        os.replace(tmp_file, cache_file)
    except Exception:
        if tmp_file.exists():
            try:
                tmp_file.unlink()
            except OSError:
                pass


def inventory_dataset(
    dataset_folder: Path | str,
    no_hash: bool = False,
    capinfos_exe: Optional[str] = None,
    row_cap_threshold: int = EXCEL_ROW_CAP,
) -> Dict[str, Any]:
    """Scan dataset directory and build/update inventory.csv."""
    root = Path(dataset_folder).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Dataset path {root} is not a valid directory.")

    inventory_file = root / "inventory.csv"
    cache = load_cache(root)

    # If inventory.csv exists but cache is empty, seed cache from inventory.csv if possible
    if inventory_file.exists() and not cache:
        try:
            with open(inventory_file, "r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                for r in reader:
                    rp = r.get("rel_path")
                    if rp:
                        norm_rp = rp.replace("\\", "/")
                        cache[norm_rp] = {
                            "size_bytes": int(r["size_bytes"]) if r.get("size_bytes") else 0,
                            "mtime": None,
                            "sha256": r.get("sha256", ""),
                            "kind": r.get("kind", ""),
                            "packets": int(r["packets"]) if r.get("packets") else None,
                            "first_ts_utc": r.get("first_ts_utc") or None,
                            "last_ts_utc": r.get("last_ts_utc") or None,
                            "rows": int(r["rows"]) if r.get("rows") else None,
                            "flags": r.get("flags", ""),
                        }
        except Exception:
            cache = {}

    all_files: List[Path] = []
    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            if fname in ("inventory.csv", ".inventory_cache.json", ".inventory_cache.json.tmp"):
                continue
            all_files.append(Path(dirpath) / fname)

    # Sort files for deterministic ordering
    all_files.sort()

    updated_cache: Dict[str, Dict[str, Any]] = {}
    rows_out: List[Dict[str, Any]] = []

    hashes_calculated = 0
    reused_count = 0
    kind_counts: Dict[str, int] = {}
    flagged_files: List[Tuple[str, str]] = []
    total_bytes = 0

    for file_path in all_files:
        rel_path = file_path.relative_to(root).as_posix()
        stat = file_path.stat()
        size_bytes = stat.st_size
        mtime = stat.st_mtime
        total_bytes += size_bytes

        cached = cache.get(rel_path)
        can_reuse = False

        if cached is not None and cached.get("size_bytes") == size_bytes:
            # Check modification time if cached
            cached_mtime = cached.get("mtime")
            if cached_mtime is None or abs(cached_mtime - mtime) < 1e-4:
                # If hashing is requested, check that sha256 was already computed
                if no_hash or cached.get("sha256"):
                    can_reuse = True

        if can_reuse:
            reused_count += 1
            item = dict(cached)
            item["mtime"] = mtime
            if no_hash:
                item["sha256"] = ""
            updated_cache[rel_path] = item
            rows_out.append(item)
            k = item.get("kind", "other")
            kind_counts[k] = kind_counts.get(k, 0) + 1
            if item.get("flags"):
                flagged_files.append((rel_path, item["flags"]))
            continue

        # Otherwise, process the file
        kind = detect_kind(file_path)
        kind_counts[kind] = kind_counts.get(kind, 0) + 1

        file_flags: List[str] = []
        if size_bytes == 0:
            file_flags.append("empty")

        sha256_val = ""
        if not no_hash and size_bytes > 0:
            sha256_val = compute_sha256(file_path)
            hashes_calculated += 1

        packets: Optional[int] = None
        first_ts: Optional[str] = None
        last_ts: Optional[str] = None
        row_count: Optional[int] = None

        if kind in ("pcap", "pcapng"):
            if size_bytes > 0:
                pkts, fts, lts, cap_flags = run_capinfos(file_path, capinfos_exe=capinfos_exe)
                packets = pkts
                first_ts = fts
                last_ts = lts
                file_flags.extend(cap_flags)
            else:
                packets = 0

        elif kind in ("csv", "binetflow"):
            if size_bytes > 0:
                cnt = count_data_rows(file_path)
                row_count = cnt
                if cnt == 0:
                    file_flags.append("empty")
                elif cnt == row_cap_threshold:
                    file_flags.append("excel_row_cap")
            else:
                row_count = 0

        flags_str = ";".join(sorted(set(file_flags)))
        if flags_str:
            flagged_files.append((rel_path, flags_str))

        entry: Dict[str, Any] = {
            "rel_path": rel_path,
            "size_bytes": size_bytes,
            "mtime": mtime,
            "sha256": sha256_val,
            "kind": kind,
            "packets": packets,
            "first_ts_utc": first_ts or "",
            "last_ts_utc": last_ts or "",
            "rows": row_count if row_count is not None else "",
            "flags": flags_str,
        }
        updated_cache[rel_path] = entry
        rows_out.append(entry)

    # Write inventory.csv atomically
    tmp_inventory = root / "inventory.csv.tmp"
    with open(tmp_inventory, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for r in rows_out:
            row_dict = {col: ("" if r.get(col) is None else str(r[col])) for col in CSV_COLUMNS}
            writer.writerow(row_dict)
    os.replace(tmp_inventory, inventory_file)

    # Save cache
    save_cache(root, updated_cache)

    total_files = len(rows_out)
    total_gb = total_bytes / (1024 ** 3)
    pcap_count = kind_counts.get("pcap", 0) + kind_counts.get("pcapng", 0)
    csv_count = kind_counts.get("csv", 0)
    binetflow_count = kind_counts.get("binetflow", 0)

    summary = {
        "total_files": total_files,
        "kind_counts": kind_counts,
        "total_gb": total_gb,
        "total_pcap": pcap_count,
        "total_csv": csv_count,
        "total_binetflow": binetflow_count,
        "flagged_files": flagged_files,
        "hashes_calculated": hashes_calculated,
        "reused_count": reused_count,
    }

    _print_summary(summary)
    return summary


def _print_summary(summary: Dict[str, Any]) -> None:
    print("\n" + "=" * 60)
    print("RAW DATASET INVENTORY SUMMARY")
    print("=" * 60)
    print(f"Total files:                  {summary['total_files']}")
    print(f"Total size:                   {summary['total_gb']:.4f} GB")
    print(f"Detected kinds:")
    for kind, count in sorted(summary["kind_counts"].items()):
        print(f"  - {kind}: {count}")
    print(f"Total PCAP/PCAPNG files:      {summary['total_pcap']}")
    print(f"Total CSV files:              {summary['total_csv']}")
    print(f"Total BINETFLOW files:        {summary['total_binetflow']}")
    print(f"Hashes calculated this run:   {summary['hashes_calculated']}")
    print(f"Files reused from cache:      {summary['reused_count']}")

    if summary["flagged_files"]:
        print(f"\nFlagged files ({len(summary['flagged_files'])}):")
        for rp, flag in summary["flagged_files"]:
            print(f"  * {rp}: [{flag}]")
    else:
        print("\nFlagged files: None")
    print("=" * 60 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Stage 2 - Raw Dataset Inventory Tool.")
    parser.add_argument("dataset_folder", help="Root folder of the raw dataset to inventory")
    parser.add_argument(
        "--no-hash",
        action="store_true",
        help="Skip SHA-256 calculation for speed",
    )
    args = parser.parse_args()

    inventory_dataset(args.dataset_folder, no_hash=args.no_hash)


if __name__ == "__main__":
    main()

