"""CTU-13 .binetflow adapter.

WRAPS pipeline/adapters/ctu13.py::_normalize_columns + pipeline/adapters/ctu13_features.py::
add_ctu13_features (the pair build_ctu13_dataset.py applies) and pipeline.mitre_mapping.
ctu13_label_to_stage via label_to_stage, unchanged. Nothing here edits those modules.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pandas as pd

from pipeline.adapters import ctu13 as base_ctu
from pipeline.adapters.base import (
    APPROX, CANONICAL_COLUMNS, DERIVED, DatasetAdapter, HeaderInfo, ReadStats, ZERO, register_adapter,
)
from pipeline.adapters.ctu13_features import add_ctu13_features

_CANON = list(CANONICAL_COLUMNS) + ["scenario_id"]
_MARKERS = {"Dur", "Proto", "SrcAddr", "DstAddr", "Dport", "TotPkts", "SrcBytes", "Label"}


@register_adapter
class CTU13Adapter(DatasetAdapter):
    name = "ctu13"
    version = "1.0.0"
    description = "CTU-13 botnet scenarios (.binetflow, Argus bidirectional NetFlow, real IPs, 13 scenarios)."
    wraps = ["pipeline.adapters.ctu13", "pipeline.adapters.ctu13_features", "pipeline.mitre_mapping"]
    file_globs = ["*.binetflow"]
    unit_kind = "scenario"
    default_split = "by_unit"
    default_unit_split = {  # same scenario-disjoint lists as pipeline/build_ctu13_dataset.py
        "train": [str(i) for i in range(1, 10)], "val": ["10", "11"], "test": ["12", "13"],
    }
    sort_keys = ["scenario_id", "timestamp"]
    intentional_impact: set[str] = set()   # no CTU-13 label is IMPACT by design: any IMPACT is a fall-through
    max_plausible_duration_s = 1e5
    bytes_include_headers = True
    field_coverage = {
        "syn_cnt": (ZERO, "binetflow has no TCP flag counts"),
        "ack_cnt": (ZERO, "binetflow has no TCP flag counts"),
        "fin_cnt": (ZERO, "binetflow has no TCP flag counts"),
        "rst_cnt": (ZERO, "binetflow has no TCP flag counts"),
        "psh_cnt": (ZERO, "binetflow has no TCP flag counts"),
        "urg_cnt": (ZERO, "binetflow has no TCP flag counts"),
        "iat_mean": (ZERO, "binetflow has no packet inter-arrival data"),
        "iat_std": (ZERO, "binetflow has no packet inter-arrival data"),
        "iat_max": (ZERO, "binetflow has no packet inter-arrival data"),
        "bwd_pkts": (ZERO, "fwd_pkts := TotPkts, bwd_pkts := 0 (no per-direction packet counts)"),
        "bwd_bytes": (DERIVED, "TotBytes - SrcBytes"),
        "bidir_ratio": (APPROX, "BYTE-based min(src,dst)/total (add_ctu13_features overrides the adapter's 0.0)"),
    }
    unit_assumptions = {
        "duration": "Dur is SECONDS (native)",
        "iat": "n/a: zero-filled (so 'IAT in microseconds' is vacuous here)",
        "timestamp": "StartTime 'YYYY/MM/DD HH:MM:SS.ffffff', flow start, no timezone",
        "bytes": "TotBytes incl. headers; SrcBytes = source->dest bytes",
        "scenario_id": "int of the parent folder name; windowing never crosses scenarios",
        "label": "raw 'flow=...' string",
    }
    caveats = [
        "Raw rows are not time-sorted; the adapter sorts by (scenario_id, timestamp).",
        "Background traffic (~97% of rows) maps to benign although it is unlabeled, not verified-clean.",
        "9 of the 41 features (6 flag ratios + 3 IAT) are constant zero and bidir_ratio is a byte proxy.",
        "Label mapping is mitre_mapping.ctu13_label_to_stage as-is (includes the D-1 benign-label fix).",
    ]

    @classmethod
    def detect_file(cls, info: HeaderInfo) -> tuple[float, list[str]]:
        cols = {c.lstrip("#") for c in info.columns}
        if _MARKERS.issubset(cols):
            return 0.99, ["Argus binetflow header (StartTime,Dur,Proto,SrcAddr,...,SrcBytes,Label)"]
        if info.path.suffix.lower() == ".binetflow":
            return 0.6, ["*.binetflow extension"]
        return 0.0, []

    def units(self, files: list[Path]) -> dict[str, list[Path]]:
        out: dict[str, list[Path]] = {}
        for f in files:
            out.setdefault(Path(f).parent.name, []).append(Path(f))
        return out

    @staticmethod
    def _scenario(path: Path):
        try:
            return int(path.parent.name)
        except ValueError:
            return path.parent.name

    def iter_flows(self, path: Path, chunksize: int = 500_000, max_rows: int | None = None,
                   stats: ReadStats | None = None) -> Iterator[pd.DataFrame]:
        path = Path(path)
        for raw in pd.read_csv(path, low_memory=False, chunksize=chunksize, nrows=max_rows):
            raw.columns = [c.strip() for c in raw.columns]
            df = base_ctu._normalize_columns(raw)
            df["scenario_id"] = self._scenario(path)
            df["source_file"] = path.name
            df = add_ctu13_features(df)
            df["has_ip_data"] = 1.0  # every binetflow row has real IPs (windowing defaults to 1.0 too)
            for c in ("src_ip", "dst_ip", "label"):
                df[c] = df[c].astype(str)
            if stats is not None:
                stats.rows_read += len(raw)
                stats.rows_kept += len(df)
            yield df[_CANON + ["source_file"]].reset_index(drop=True)

    def iter_label_chunks(self, path: Path, chunksize: int = 1_000_000,
                          max_rows: int | None = None) -> Iterator[pd.DataFrame]:
        header = pd.read_csv(path, nrows=0).columns
        ts_col = next(c for c in header if c.lstrip("#") == "StartTime")
        for raw in pd.read_csv(path, low_memory=False, usecols=[ts_col, "Label"], chunksize=chunksize,
                               nrows=max_rows):
            thin = pd.to_datetime(raw[ts_col].iloc[::20], errors="coerce")
            yield pd.DataFrame({"label": raw["Label"].astype(str).str.strip()}).assign(
                timestamp=thin.reindex(raw.index))
