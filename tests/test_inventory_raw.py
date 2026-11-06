"""Unit tests for Stage 2 Raw Dataset Inventory tool (scripts/inventory_raw.py)."""
from __future__ import annotations

import csv
import hashlib
import os
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest
from scapy.all import Ether, IP, TCP, wrpcap

from scripts import inventory_raw
from scripts.inventory_raw import (
    CSV_COLUMNS,
    compute_sha256,
    count_data_rows,
    detect_kind,
    find_capinfos_path,
    inventory_dataset,
    run_capinfos,
)


def test_magic_number_pcap_variants(tmp_path: Path):
    """Test all 4 PCAP magic number variants and ensure kind is 'pcap'."""
    magics = [
        b"\xa1\xb2\xc3\xd4",  # Standard microsecond
        b"\xd4\xc3\xb2\xa1",  # Swapped microsecond
        b"\xa1\xb2\x3c\x4d",  # Standard nanosecond
        b"\x4d\x3c\xb2\xa1",  # Swapped nanosecond
    ]
    for i, magic in enumerate(magics):
        p = tmp_path / f"test_{i}.bin"
        p.write_bytes(magic + b"\x00" * 20)
        assert detect_kind(p) == "pcap"


def test_magic_number_pcapng(tmp_path: Path):
    """Test PCAPNG section header block magic number."""
    p = tmp_path / "test.custom_ext"
    p.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 16)
    assert detect_kind(p) == "pcapng"


def test_magic_number_zip(tmp_path: Path):
    """Test ZIP file magic number."""
    p = tmp_path / "archive.dat"
    p.write_bytes(b"PK\x03\x04" + b"\x00" * 10)
    assert detect_kind(p) == "zip"


def test_extension_csv_and_binetflow(tmp_path: Path):
    """Test extension fallback for CSV and binetflow."""
    csv_file = tmp_path / "flows.csv"
    csv_file.write_text("header1,header2\nval1,val2\n", encoding="utf-8")
    assert detect_kind(csv_file) == "csv"

    binet_file = tmp_path / "capture.binetflow"
    binet_file.write_text("StartTime,Dur,Proto\n", encoding="utf-8")
    assert detect_kind(binet_file) == "binetflow"

    pdf_file = tmp_path / "report.pdf"
    pdf_file.write_bytes(b"%PDF-1.4\n...")
    assert detect_kind(pdf_file) == "pdf"


def test_unknown_file_detection(tmp_path: Path):
    """Test unrecognized file kinds fallback to 'other'."""
    p = tmp_path / "data.xyz"
    p.write_bytes(b"\xff\xee\xdd\xcc")
    assert detect_kind(p) == "other"


def test_csv_and_binetflow_row_counting(tmp_path: Path):
    """Test data row counting excluding the header."""
    csv_file = tmp_path / "data.csv"
    csv_file.write_text("h1,h2\na,1\nb,2\nc,3\n", encoding="utf-8")
    assert count_data_rows(csv_file) == 3

    binet_file = tmp_path / "test.binetflow"
    binet_file.write_text("h1\nrow1\nrow2\n", encoding="utf-8")
    assert count_data_rows(binet_file) == 2

    # Single-line header only
    header_only = tmp_path / "header_only.csv"
    header_only.write_text("h1,h2\n", encoding="utf-8")
    assert count_data_rows(header_only) == 0


def test_empty_file_flag(tmp_path: Path):
    """Test empty file detection and 'empty' flag."""
    empty_file = tmp_path / "empty.bin"
    empty_file.write_bytes(b"")

    empty_csv = tmp_path / "empty.csv"
    empty_csv.write_text("", encoding="utf-8")

    res = inventory_dataset(tmp_path, no_hash=True)
    assert res["total_files"] == 2
    for rp, flag in res["flagged_files"]:
        assert "empty" in flag


def test_excel_row_cap_detection(tmp_path: Path):
    """Test excel_row_cap flag using a lowered threshold."""
    csv_file = tmp_path / "capped.csv"
    lines = ["header\n"] + [f"data_{i}\n" for i in range(10)]
    csv_file.write_text("".join(lines), encoding="utf-8")

    # Set threshold to 10 rows
    res = inventory_dataset(tmp_path, no_hash=True, row_cap_threshold=10)
    flagged = dict(res["flagged_files"])
    assert "excel_row_cap" in flagged.get("capped.csv", "")


def test_sha256_correctness(tmp_path: Path):
    """Test streamed SHA-256 computation against hashlib."""
    p = tmp_path / "test.data"
    content = b"antigravity test dataset payload 12345" * 1000
    p.write_bytes(content)

    expected = hashlib.sha256(content).hexdigest()
    assert compute_sha256(p) == expected


def test_no_hash_flag(tmp_path: Path):
    """Test --no-hash leaves sha256 column blank."""
    p = tmp_path / "sample.csv"
    p.write_text("col1,col2\nval1,val2\n", encoding="utf-8")

    res = inventory_dataset(tmp_path, no_hash=True)
    inv_file = tmp_path / "inventory.csv"
    assert inv_file.exists()

    with open(inv_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["sha256"] == ""


def test_resumability_and_metadata_change(tmp_path: Path):
    """Test caching and re-computation when file changes."""
    p = tmp_path / "data.csv"
    p.write_text("h1,h2\nv1,v2\n", encoding="utf-8")

    # Run 1: Compute hash
    res1 = inventory_dataset(tmp_path, no_hash=False)
    assert res1["hashes_calculated"] == 1
    assert res1["reused_count"] == 0

    # Run 2: Without changes, it should reuse cache
    res2 = inventory_dataset(tmp_path, no_hash=False)
    assert res2["hashes_calculated"] == 0
    assert res2["reused_count"] == 1

    # Modify file: size and mtime change
    p.write_text("h1,h2\nv1,v2\nv3,v4\n", encoding="utf-8")
    res3 = inventory_dataset(tmp_path, no_hash=False)
    assert res3["hashes_calculated"] == 1
    assert res3["reused_count"] == 0


def test_capinfos_integration_with_scapy(tmp_path: Path):
    """Create a 2-packet PCAP via scapy and check capinfos output."""
    exe = find_capinfos_path()
    if not exe:
        pytest.skip("capinfos executable not found on system.")

    pcap_path = tmp_path / "two_packets.pcap"
    pkt1 = Ether() / IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=1234, dport=80)
    pkt2 = Ether() / IP(src="192.168.1.20", dst="192.168.1.10") / TCP(sport=80, dport=1234)
    wrpcap(str(pcap_path), [pkt1, pkt2])

    res = inventory_dataset(tmp_path, no_hash=False)
    inv_file = tmp_path / "inventory.csv"

    with open(inv_file, "r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
        assert len(rows) == 1
        r = rows[0]
        assert r["kind"] == "pcap"
        assert r["packets"] == "2"
        assert r["first_ts_utc"].endswith("Z")
        assert r["last_ts_utc"].endswith("Z")
        assert len(r["sha256"]) == 64
