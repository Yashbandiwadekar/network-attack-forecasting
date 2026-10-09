"""Dataset-adapter toolkit: canonical contract, adapter base class, registry and detection.

The *canonical flow frame* is what `pipeline.windowing.build_flow_windows`, `graph_features`,
`graph_builder` and `graph_embedding_features` already consume (see docs/08-dataset-adapter-guide.md).
Every adapter turns one raw dataset format into that frame, and declares -- per field -- whether the
value is native, derived, approximated or zero-filled, so nothing is silently invented.

Existing low-level modules (flow_features.py, adapters/ctu13*.py, adapters/unsw_nb15.py) are WRAPPED,
never re-implemented; this file only adds the interface around them.
"""
from __future__ import annotations

import csv
import io
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, ClassVar, Iterator

import numpy as np
import pandas as pd

from pipeline.mitre_mapping import IMPACT, label_to_stage

CONTRACT_VERSION = "1.0"

# --------------------------------------------------------------------------------------------
# Canonical flow-frame contract
# --------------------------------------------------------------------------------------------

# column -> (dtype kind, unit / meaning). Order is the documented column order.
CANONICAL_COLUMNS: dict[str, tuple[str, str]] = {
    "timestamp": ("datetime64[ns]", "flow START time, tz-naive"),
    "src_ip": ("str", "source host key; pseudo-host 'NETWORK-<date>' when has_ip_data == 0"),
    "dst_ip": ("str", "destination host; 'UNKNOWN' when has_ip_data == 0"),
    "src_port": ("float", "0 when unavailable"),
    "dst_port": ("float", "NaN allowed (ignored by nunique)"),
    "protocol": ("float", "IANA number: 6 tcp, 17 udp, 1 icmp"),
    "duration_s": ("float", "SECONDS (CIC Flow Duration is microseconds and is converted)"),
    "fwd_pkts": ("float", "packets, initiator -> responder"),
    "bwd_pkts": ("float", "packets, responder -> initiator"),
    "total_pkts": ("float", "packets (count, not rate)"),
    "fwd_bytes": ("float", "bytes, initiator -> responder"),
    "bwd_bytes": ("float", "bytes, responder -> initiator"),
    "total_bytes": ("float", "bytes (count, not rate)"),
    "syn_cnt": ("float", "COUNT of packets with the flag per flow (not a ratio, not a bitmask)"),
    "ack_cnt": ("float", "count"),
    "fin_cnt": ("float", "count"),
    "rst_cnt": ("float", "count"),
    "psh_cnt": ("float", "count"),
    "urg_cnt": ("float", "count"),
    "iat_mean": ("float", "MICROSECONDS, mean packet inter-arrival time within the flow"),
    "iat_std": ("float", "MICROSECONDS"),
    "iat_max": ("float", "MICROSECONDS"),
    "is_tcp": ("float", "0/1"),
    "is_udp": ("float", "0/1"),
    "bidir_ratio": ("float", "in [0,1]; min(fwd,bwd)/total (packets for CIC, bytes for CTU/UNSW)"),
    "has_ip_data": ("float", "1.0 = real source/destination IPs, 0.0 = pseudo-host fallback"),
    "label": ("str", "raw label string that pipeline.mitre_mapping.label_to_stage understands"),
}
REQUIRED_COLUMNS = list(CANONICAL_COLUMNS)
OPTIONAL_COLUMNS = {"scenario_id": "set ONLY where existing builders set it (CTU-13)", "source_file": "provenance"}
FLAG_COLUMNS = ["syn_cnt", "ack_cnt", "fin_cnt", "rst_cnt", "psh_cnt", "urg_cnt"]
IAT_COLUMNS = ["iat_mean", "iat_std", "iat_max"]

# status vocabulary for a canonical field (worst last)
NATIVE, DERIVED, APPROX, ZERO = "native", "derived", "approximated", "zero_filled"
_STATUS_RANK = {NATIVE: 0, DERIVED: 1, APPROX: 2, ZERO: 3}

# 41-feature schema: window feature -> canonical flow fields it is computed from.
FLOW_FEATURE_SOURCES: dict[str, list[str]] = {
    "flow_count": ["timestamp"],
    "unique_dst_ports": ["dst_port"],
    "unique_dst_ips": ["dst_ip", "has_ip_data"],
    "has_ip_data": ["has_ip_data"],
    "total_bytes": ["total_bytes"],
    "total_packets": ["total_pkts"],
    "mean_duration": ["duration_s"],
    "syn_ratio": ["syn_cnt", "total_pkts"],
    "ack_ratio": ["ack_cnt", "total_pkts"],
    "fin_ratio": ["fin_cnt", "total_pkts"],
    "rst_ratio": ["rst_cnt", "total_pkts"],
    "psh_ratio": ["psh_cnt", "total_pkts"],
    "urg_ratio": ["urg_cnt", "total_pkts"],
    "mean_iat": ["iat_mean"],
    "var_iat": ["iat_std"],
    "max_iat": ["iat_max"],
    "bidir_ratio": ["bidir_ratio"],
    "tcp_ratio": ["is_tcp"],
    "udp_ratio": ["is_udp"],
}
IP_DEPENDENT_PREFIXES = ("graph_",)  # graph_* and graph_embed_* all need real IPs
UNIVERSAL_ZERO_PACKET_NOTE = (
    "packet-level features (8 + has_packet_features) are zero-filled for every flow-only dataset; "
    "they need a PCAP (pipeline/packet_features.py)"
)


@dataclass
class Detection:
    adapter: str | None
    confidence: float
    evidence: list[str] = field(default_factory=list)
    per_file: dict[str, tuple[str | None, float]] = field(default_factory=dict)
    mixed: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter, "confidence": round(self.confidence, 3), "evidence": self.evidence,
            "mixed": self.mixed, "per_file": {k: [v[0], round(v[1], 3)] for k, v in self.per_file.items()},
        }


@dataclass
class ReadStats:
    """Row accounting for one read (what the adapter's cleaning threw away)."""
    rows_read: int = 0
    rows_kept: int = 0

    @property
    def rows_dropped(self) -> int:
        return self.rows_read - self.rows_kept


@dataclass
class HeaderInfo:
    """Cheap peek at a file: first line split, first data row, and whether it looks like a header."""
    path: Path
    first_line: list[str]
    second_line: list[str]
    columns: list[str]  # stripped; empty when the file has no header row
    n_fields: int


def peek_file(path: Path) -> HeaderInfo:
    with open(path, "rb") as fh:
        raw = fh.read(65536)
    text = raw.decode("utf-8-sig", errors="replace")
    lines = text.splitlines()
    first = next(csv.reader([lines[0]])) if lines else []
    second = next(csv.reader([lines[1]])) if len(lines) > 1 else []
    # A header row has no purely-numeric cells; UNSW raw files have no header at all.
    def _num(s: str) -> bool:
        try:
            float(s)
            return True
        except ValueError:
            return False
    has_header = bool(first) and not any(_num(c.strip()) for c in first)
    return HeaderInfo(path, first, second, [c.strip() for c in first] if has_header else [], len(first))


# --------------------------------------------------------------------------------------------
# Adapter base class
# --------------------------------------------------------------------------------------------

class DatasetAdapter:
    """Interface every dataset adapter implements. Subclass, set the class attributes, implement
    `detect_file`, `iter_flows` and `iter_label_chunks`, then decorate with `@register_adapter`."""

    name: ClassVar[str] = "base"
    version: ClassVar[str] = "1.0.0"
    status: ClassVar[str] = "stable"  # stable | experimental | stub | unsupported
    description: ClassVar[str] = ""
    wraps: ClassVar[list[str]] = []
    file_globs: ClassVar[list[str]] = ["*.csv"]
    #: how `prepare_dataset` partitions the data into independently-windowed units
    unit_kind: ClassVar[str] = "file"  # file | scenario | all
    #: default split strategy for prepare_dataset: by_day | by_unit | chronological
    default_split: ClassVar[str] = "chronological"
    default_unit_split: ClassVar[dict[str, list[str]] | None] = None
    #: canonical labels that are deliberately mapped to IMPACT (not an unknown fall-through)
    intentional_impact: ClassVar[set[str]] = set()
    #: labels that are not data (e.g. repeated CSV header rows)
    ignorable_labels: ClassVar[set[str]] = set()
    max_plausible_duration_s: ClassVar[float] = 1e5
    bytes_include_headers: ClassVar[bool] = False
    #: canonical field -> (status, note); anything absent is assumed native
    field_coverage: ClassVar[dict[str, tuple[str, str]]] = {}
    unit_assumptions: ClassVar[dict[str, str]] = {}
    caveats: ClassVar[list[str]] = []
    synthetic: ClassVar[bool] = False
    #: how-to / reason when status is stub or unsupported
    howto: ClassVar[str] = ""

    # ---- detection ------------------------------------------------------------------------
    @classmethod
    def detect_file(cls, info: HeaderInfo) -> tuple[float, list[str]]:
        """Return (confidence 0..1, evidence) that `info.path` is this format."""
        return 0.0, []

    def claims_file(self, path: Path) -> bool:
        return self.detect_file(peek_file(path))[0] >= 0.5

    def discover_files(self, path: str | Path) -> tuple[list[Path], list[tuple[Path, str]]]:
        """(files this adapter will read, [(skipped file, reason)])."""
        p = Path(path)
        if p.is_file():
            return [p], []
        cands = sorted({f for g in self.file_globs for f in p.rglob(g) if f.is_file()})
        files: list[Path] = []
        skipped: list[tuple[Path, str]] = []
        for f in cands:
            conf, ev = self.detect_file(peek_file(f))
            if conf >= 0.5:
                files.append(f)
            else:
                other = detect_file_adapter(f)
                skipped.append((f, f"claimed by '{other[0]}' ({other[1]:.2f})" if other[0] else "not recognised by this adapter"))
        return files, skipped

    # ---- reading --------------------------------------------------------------------------
    def iter_flows(self, path: Path, chunksize: int = 500_000, max_rows: int | None = None,
                   stats: ReadStats | None = None) -> Iterator[pd.DataFrame]:
        """Yield canonical flow frames for ONE file, in file (raw) order. `max_rows` = contiguous
        prefix of the file (rows of the RAW file, before cleaning)."""
        raise NotImplementedError(self.howto or f"{self.name}: iter_flows not implemented")

    def iter_label_chunks(self, path: Path, chunksize: int = 1_000_000,
                          max_rows: int | None = None) -> Iterator[pd.DataFrame]:
        """Yield frames with columns `label` (canonical label string as it will appear in the flow
        frame) and `timestamp` (parsed, thinned 1-in-20) reading ONLY the needed raw columns.
        `max_rows` = contiguous prefix (same rows iter_flows(max_rows=...) reads)."""
        raise NotImplementedError(self.howto or f"{self.name}: iter_label_chunks not implemented")

    def finalize(self, df: pd.DataFrame) -> pd.DataFrame:
        """Hook: global post-processing after all chunks of a unit are concatenated + sorted."""
        return df

    sort_keys: ClassVar[list[str]] = ["timestamp"]

    def read_flows(self, files: Path | list[Path], max_rows: int | None = None,
                   chunksize: int = 500_000, stats: ReadStats | None = None) -> pd.DataFrame:
        """Load canonical flows for one unit (one or more files), sorted like the original loaders."""
        flist = [files] if isinstance(files, (str, Path)) else list(files)
        frames = []
        for f in flist:
            frames.extend(self.iter_flows(Path(f), chunksize=chunksize, max_rows=max_rows, stats=stats))
        if not frames:
            return self._empty_frame()
        df = pd.concat(frames, ignore_index=True)
        df = df.sort_values(self.sort_keys).reset_index(drop=True)
        return self.finalize(df)

    def _empty_frame(self) -> pd.DataFrame:
        return pd.DataFrame({c: pd.Series(dtype="float64") for c in REQUIRED_COLUMNS})

    def units(self, files: list[Path]) -> dict[str, list[Path]]:
        """Partition files into independently windowed units (id -> files)."""
        if self.unit_kind == "all":
            return {"all": list(files)}
        return {Path(f).stem: [Path(f)] for f in files}

    # ---- labels ---------------------------------------------------------------------------
    def label_status(self, label: str) -> tuple[str, str]:
        """(stage, status) with status in mapped | impact_by_design | unknown_fallthrough | ignorable."""
        if label in self.ignorable_labels:
            return IMPACT, "ignorable"
        stage = label_to_stage(label)
        if stage != IMPACT:
            return stage, "mapped"
        if label.strip().lower() in {x.lower() for x in self.intentional_impact}:
            return stage, "impact_by_design"
        return stage, "unknown_fallthrough"

    # ---- metadata -------------------------------------------------------------------------
    def info(self) -> dict[str, Any]:
        return {
            "name": self.name, "version": self.version, "status": self.status,
            "description": self.description, "wraps": list(self.wraps),
            "unit_kind": self.unit_kind, "default_split": self.default_split,
            "unit_assumptions": dict(self.unit_assumptions),
            "field_coverage": {k: list(v) for k, v in self.field_coverage.items()},
            "caveats": list(self.caveats), "synthetic": self.synthetic,
        }

    def coverage_of(self, fld: str) -> tuple[str, str]:
        return self.field_coverage.get(fld, (NATIVE, ""))

    def expected_feature_status(self, ip_fraction: float | None = None) -> dict[str, tuple[str, str]]:
        """Static expectation for each of the 41 window features: (status, reason). `ip_fraction` is
        the observed share of flows with real IPs (None = assume adapter default)."""
        out: dict[str, tuple[str, str]] = {}
        for feat, srcs in FLOW_FEATURE_SOURCES.items():
            worst, note = NATIVE, ""
            for s in srcs:
                st, nt = self.coverage_of(s)
                if _STATUS_RANK[st] > _STATUS_RANK[worst]:
                    worst, note = st, f"{s}: {nt}"
            out[feat] = (worst, note)
        for feat in _graph_features():
            out[feat] = (NATIVE, "")
        for feat in _embed_features():
            out[feat] = (APPROX, "frozen random-init GraphSAGE embedding (not trained)")
        for feat in _packet_features():
            out[feat] = (ZERO, UNIVERSAL_ZERO_PACKET_NOTE)
        # no-IP override
        if ip_fraction is not None:
            for feat in list(out):
                if feat.startswith(IP_DEPENDENT_PREFIXES) or feat == "unique_dst_ips":
                    if ip_fraction <= 0.0:
                        out[feat] = (ZERO, "no real IPs: pseudo-host per day, graph degenerate")
                    elif ip_fraction < 1.0 and out[feat][0] != ZERO:
                        out[feat] = (APPROX, f"only {ip_fraction:.0%} of flows have real IPs")
        return out


def _graph_features() -> list[str]:
    from pipeline.graph_features import GRAPH_FEATURE_NAMES
    return list(GRAPH_FEATURE_NAMES)


def _embed_features() -> list[str]:
    from pipeline.graph_embedding_features import GRAPH_EMBEDDING_FEATURE_NAMES
    return list(GRAPH_EMBEDDING_FEATURE_NAMES)


def _packet_features() -> list[str]:
    return ["mean_ttl", "var_ttl", "mean_window_size", "frag_ratio", "mean_payload_size",
            "std_payload_size", "port_scan_score", "retransmit_ratio", "has_packet_features"]


# --------------------------------------------------------------------------------------------
# Registry + detection
# --------------------------------------------------------------------------------------------

_REGISTRY: dict[str, type[DatasetAdapter]] = {}


def register_adapter(cls: type[DatasetAdapter]) -> type[DatasetAdapter]:
    if cls.name in _REGISTRY and _REGISTRY[cls.name] is not cls:
        raise ValueError(f"adapter name '{cls.name}' already registered")
    _REGISTRY[cls.name] = cls
    return cls


def list_adapters() -> dict[str, type[DatasetAdapter]]:
    return dict(_REGISTRY)


def get_adapter(name: str) -> DatasetAdapter:
    if name not in _REGISTRY:
        raise KeyError(f"unknown adapter '{name}'. Registered: {sorted(_REGISTRY)}")
    return _REGISTRY[name]()


_DATA_SUFFIXES = {".csv", ".binetflow", ".txt", ".tsv"}


def detect_file_adapter(path: str | Path) -> tuple[str | None, float, list[str]]:
    """Best adapter for one file: (name, confidence, evidence)."""
    info = peek_file(Path(path))
    best: tuple[str | None, float, list[str]] = (None, 0.0, [])
    for name, cls in _REGISTRY.items():
        conf, ev = cls.detect_file(info)
        if conf > best[1]:
            best = (name, conf, ev)
    return best


def detect_dataset(path: str | Path, max_files: int = 64) -> Detection:
    """Auto-detect the adapter for a file or a dataset folder from headers / first rows only."""
    p = Path(path)
    if not p.exists():
        return Detection(None, 0.0, [f"path does not exist: {p}"])
    if p.is_file():
        name, conf, ev = detect_file_adapter(p)
        return Detection(name, conf, ev, {p.name: (name, conf)})
    files = sorted(f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in _DATA_SUFFIXES)[:max_files]
    if not files:
        return Detection(None, 0.0, [f"no data files (*.csv, *.binetflow) under {p}"])
    per_file: dict[str, tuple[str | None, float]] = {}
    votes: dict[str, list[float]] = {}
    for f in files:
        name, conf, _ = detect_file_adapter(f)
        per_file[str(f.relative_to(p))] = (name, conf)
        if name and conf >= 0.5:
            votes.setdefault(name, []).append(conf)
    if not votes:
        return Detection(None, 0.0, ["no file in the folder matched a registered adapter"], per_file)
    # ties prefer a real-data adapter over a synthetic one (never silently call real data synthetic... or vice versa:
    # the 'mixed' flag + per_file always expose the other formats)
    winner = max(votes, key=lambda n: (len(votes[n]), not _REGISTRY[n].synthetic, float(np.mean(votes[n]))))
    ev = [f"{len(v)}/{len(files)} files match '{n}'" for n, v in sorted(votes.items(), key=lambda kv: -len(kv[1]))]
    return Detection(winner, float(np.mean(votes[winner])), ev, per_file, mixed=len(votes) > 1 or
                     len([1 for v in per_file.values() if v[0] is None]) > 0)


# --------------------------------------------------------------------------------------------
# Contract check (used by the validator and by prepare_dataset)
# --------------------------------------------------------------------------------------------

def check_canonical_frame(df: pd.DataFrame) -> list[str]:
    """Return a list of contract violations for a canonical flow frame (empty = conforming)."""
    problems: list[str] = []
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        problems.append(f"missing canonical columns: {missing}")
        return problems
    if not np.issubdtype(df["timestamp"].dtype, np.datetime64):
        problems.append(f"timestamp dtype is {df['timestamp'].dtype}, expected datetime64")
    for c in REQUIRED_COLUMNS:
        kind = CANONICAL_COLUMNS[c][0]
        if kind == "float" and not pd.api.types.is_numeric_dtype(df[c]):
            problems.append(f"{c} is not numeric ({df[c].dtype})")
    for c in ("src_ip", "dst_ip", "label"):
        if df[c].isna().any():
            problems.append(f"{c} contains nulls")
    for c in FLAG_COLUMNS:
        if pd.api.types.is_numeric_dtype(df[c]) and len(df) and (df[c].dropna() % 1 != 0).any():
            problems.append(f"{c} has fractional values: flag columns must be integer COUNTS, not ratios")
    return problems
