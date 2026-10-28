"""UNSW-NB15 raw-CSV adapter (UNSW-NB15_1..4.csv, no header row, 49 columns).

WRAPS pipeline/adapters/unsw_nb15.py::_normalize_columns (flag derivation, ms->us IAT, label prefix
'unsw=') -- only chunked reading + the canonical column selection are new.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

import pandas as pd

from pipeline.adapters import unsw_nb15 as base_unsw
from pipeline.adapters.base import (
    APPROX, CANONICAL_COLUMNS, DERIVED, DatasetAdapter, HeaderInfo, ReadStats, ZERO, register_adapter,
)

_CANON = list(CANONICAL_COLUMNS)
_PROTO_WORDS = {"tcp", "udp", "icmp", "arp", "ospf", "sctp", "unas", "igmp", "rtp", "ipv6"}


@register_adapter
class UNSWNB15Adapter(DatasetAdapter):
    name = "unsw_nb15"
    version = "1.0.0"
    description = ("UNSW-NB15 raw per-flow CSVs UNSW-NB15_1..4.csv (Argus/Bro flows, real IPs, Unix times). "
                   "The pre-split 'Training and Testing Sets' have no IPs/times and are NOT supported.")
    wraps = ["pipeline.adapters.unsw_nb15"]
    file_globs = ["UNSW-NB15_[0-9]*.csv"]
    unit_kind = "all"
    default_split = "chronological"
    sort_keys = ["src_ip", "timestamp"]
    intentional_impact = {"unsw=generic", "unsw=dos", "unsw=fuzzers", "unsw=analysis"}
    max_plausible_duration_s = 1e5
    bytes_include_headers = True
    field_coverage = {
        "syn_cnt": (APPROX, "no TCP flag counts in UNSW: 0/1 from synack>0 (tcp only)"),
        "ack_cnt": (APPROX, "0/1 from ackdat>0 (tcp only)"),
        "fin_cnt": (APPROX, "0/1 from state==FIN (tcp only)"),
        "rst_cnt": (APPROX, "0/1 from state==RST (tcp only)"),
        "psh_cnt": (ZERO, "no PSH signal anywhere in UNSW-NB15"),
        "urg_cnt": (ZERO, "no URG signal anywhere in UNSW-NB15"),
        "iat_mean": (DERIVED, "mean of sintpkt,dintpkt (ms) x1000 -> us; absent direction counts as 0"),
        "iat_std": (ZERO, "no per-flow IAT variance in UNSW-NB15"),
        "iat_max": (ZERO, "no per-flow IAT max in UNSW-NB15"),
        "bidir_ratio": (APPROX, "BYTE-based min(src,dst)/total, not packet-based like CIC"),
    }
    unit_assumptions = {
        "duration": "dur is SECONDS (native)",
        "iat": "sintpkt/dintpkt are MILLISECONDS -> x1000 to MICROSECONDS (audit G4)",
        "timestamp": "stime is Unix epoch seconds (flow start), tz-naive UTC",
        "bytes": "sbytes/dbytes IP-level bytes",
        "flags": "synthetic 0/1 per flow derived from state + handshake timers; PSH/URG zero",
        "label": "'unsw=<attack_cat>' ('unsw=Normal' when attack_cat blank)",
    }
    caveats = [
        "Only protocols tcp/udp/icmp survive (protocol map in pipeline/adapters/unsw_nb15.py); every other Argus "
        "protocol (arp, ospf, unas, sctp ...) is DROPPED -- see rows_dropped in the validator.",
        "Flag ratios are NOT the same measurement as CIC's; the cross-dataset flag/IAT distributions differ in kind.",
        "sport/dsport contain hex ('0x20205321') and '-' values -> NaN (nunique ignores them).",
        "Fuzzers/Analysis/Generic/DoS map to IMPACT by design (documented in mitre_mapping.UNSW_LABEL_TO_STAGE).",
        "Row order inside the files is not time-sorted; the adapter sorts by (src_ip, timestamp).",
    ]

    @classmethod
    def detect_file(cls, info: HeaderInfo) -> tuple[float, list[str]]:
        if info.columns:  # raw UNSW files have no header row
            return 0.0, []
        f = info.first_line
        if len(f) != 49:
            return 0.0, []
        ok_ports = f[1].strip().lstrip("0x").isalnum() and f[3].strip() != ""
        proto_ok = f[4].strip().lower() in _PROTO_WORDS
        if proto_ok and ok_ports and re.match(r"^\d+\.\d+\.\d+\.\d+$", f[0].strip().lstrip("﻿")):
            ev = ["49 headerless columns; col5 is a protocol word; col1 is an IPv4 address"]
            if re.match(r"unsw-nb15_\d", info.path.name.lower()):
                ev.append("filename UNSW-NB15_<n>.csv")
                return 0.99, ev
            return 0.85, ev
        return 0.0, []

    def _read(self, path: Path, **kw):
        return pd.read_csv(path, header=None, names=base_unsw.RAW_COLUMNS, low_memory=False,
                           encoding="utf-8-sig", **kw)

    def iter_flows(self, path: Path, chunksize: int = 500_000, max_rows: int | None = None,
                   stats: ReadStats | None = None) -> Iterator[pd.DataFrame]:
        for raw in self._read(path, chunksize=chunksize, nrows=max_rows):
            raw["source_file"] = Path(path).name
            out = base_unsw._normalize_columns(raw)
            if stats is not None:
                stats.rows_read += len(raw)
                stats.rows_kept += len(out)
            for c in ("src_ip", "dst_ip", "label"):
                out[c] = out[c].astype(str)
            yield out[_CANON + ["source_file"]]

    def iter_label_chunks(self, path: Path, chunksize: int = 1_000_000,
                          max_rows: int | None = None) -> Iterator[pd.DataFrame]:
        reader = self._read(path, chunksize=chunksize, nrows=max_rows, usecols=["attack_cat", "stime"])
        for raw in reader:
            cat = raw["attack_cat"].astype("string").str.strip().fillna("Normal").replace("", "Normal")
            thin = pd.to_datetime(pd.to_numeric(raw["stime"].iloc[::20], errors="coerce"), unit="s", errors="coerce")
            yield pd.DataFrame({"label": ("unsw=" + cat).astype(str)}).assign(timestamp=thin.reindex(raw.index))
