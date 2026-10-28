"""CIC-IDS-2018 (CICFlowMeter 'Processed Traffic Data for ML Algorithms') + synthetic-sample adapters.

WRAPS pipeline/flow_features.py (COLUMN_RENAME, clean_and_normalize, pseudo-host handling) -- the
only new thing is chunked reading, so multi-GB days can be validated without loading them whole.
Row-wise cleaning makes chunked == whole-file output (tests/test_adapter_registry.py checks it).
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pandas as pd

from pipeline import flow_features as ff
from pipeline.adapters.base import (
    APPROX, CANONICAL_COLUMNS, DatasetAdapter, HeaderInfo, OPTIONAL_COLUMNS, ReadStats, ZERO, register_adapter,
)
from pipeline.mitre_mapping import CIC_LABEL_TO_STAGE, IMPACT

_CANON = list(CANONICAL_COLUMNS)
_REDUCED_MAX_FIELDS = 40   # real CICFlowMeter CSVs have 79-84 columns; the synthetic ones 21
_FULL_MARKERS = {"Flow IAT Mean", "Tot Fwd Pkts", "Timestamp", "Label"}


def _has_cic2018_header(cols: list[str]) -> bool:
    return _FULL_MARKERS.issubset(set(cols))


class _CICFlowMeterBase(DatasetAdapter):
    """Shared chunked reader for CICFlowMeter-shaped CSVs (rename map = flow_features.COLUMN_RENAME)."""

    file_globs = ["*.csv"]
    sort_keys = ["timestamp"]
    rename_map = ff.COLUMN_RENAME
    timestamp_note = "dd/mm/YYYY HH:MM:SS (CIC-IDS-2018) or ISO; parsed by flow_features._parse_timestamp"

    def _relevant(self) -> set[str]:
        return set(self.rename_map)

    def _prepare_chunk(self, raw: pd.DataFrame) -> pd.DataFrame:
        """Hook for subclasses that must fix columns before flow_features.clean_and_normalize."""
        return raw

    def iter_flows(self, path: Path, chunksize: int = 500_000, max_rows: int | None = None,
                   stats: ReadStats | None = None) -> Iterator[pd.DataFrame]:
        rel = self._relevant()
        reader = pd.read_csv(path, low_memory=False, usecols=lambda c: c.strip() in rel,
                             chunksize=chunksize, nrows=max_rows, encoding=getattr(self, "encoding", "utf-8"), encoding_errors="replace")
        for raw in reader:
            n_raw = len(raw)
            raw.columns = [c.strip() for c in raw.columns]
            raw = raw.rename(columns=self.rename_map)
            raw = self._prepare_chunk(raw)
            missing = [c for c in ff.STRICTLY_REQUIRED_COLUMNS if c not in raw.columns]
            if missing:
                raise ValueError(f"{path}: missing required columns after rename: {missing}")
            keep = ff.STRICTLY_REQUIRED_COLUMNS + [c for c in ff.OPTIONAL_IP_COLUMNS if c in raw.columns]
            clean = ff.clean_and_normalize(raw[keep].copy())
            clean["source_file"] = Path(path).name
            if stats is not None:
                stats.rows_read += n_raw
                stats.rows_kept += len(clean)
            yield clean[_CANON + ["source_file"]]

    def iter_label_chunks(self, path: Path, chunksize: int = 1_000_000,
                          max_rows: int | None = None) -> Iterator[pd.DataFrame]:
        reader = pd.read_csv(path, low_memory=False, usecols=lambda c: c.strip() in {"Label", "Timestamp"},
                             chunksize=chunksize, nrows=max_rows, encoding=getattr(self, "encoding", "utf-8"), encoding_errors="replace")
        for raw in reader:
            raw.columns = [c.strip() for c in raw.columns]
            thin = raw["Timestamp"].iloc[::20]
            ts = self._parse_ts_series(thin)
            yield pd.DataFrame({"label": raw["Label"].astype(str).str.strip()}).assign(
                timestamp=ts.reindex(raw.index)
            )

    def _parse_ts_series(self, s: pd.Series) -> pd.Series:
        return ff._parse_timestamp(s)


@register_adapter
class CICIDS2018Adapter(_CICFlowMeterBase):
    name = "cicids2018"
    version = "1.0.0"
    description = ("CIC-IDS-2018 CICFlowMeter CSVs. 9 of 10 days ship WITHOUT Src/Dst IP: those days get one "
                   "pseudo-host 'NETWORK-<date>' (has_ip_data=0). Only Tuesday 20-02 (DDoS) has real IPs.")
    wraps = ["pipeline.flow_features"]
    unit_kind = "file"
    default_split = "by_day"
    intentional_impact = {k for k, v in CIC_LABEL_TO_STAGE.items() if v == IMPACT}
    ignorable_labels = {"Label"}  # repeated header rows inside some day files
    max_plausible_duration_s = 1000.0
    bytes_include_headers = False
    # src_ip/dst_ip/src_port availability is per FILE (9/10 days lack them): it is handled dynamically by
    # expected_feature_status(ip_fraction) from the observed has_ip_data, not by a static class-level claim.
    field_coverage = {
        "has_ip_data": ("native", "0.0 on the 9 IP-less days"),
    }
    unit_assumptions = {
        "duration": "Flow Duration is MICROSECONDS in the file -> converted to seconds (duration_s)",
        "iat": "Flow IAT Mean/Std/Max are MICROSECONDS, kept as-is (iat_std squared into var_iat by windowing)",
        "bytes": "TotLen Fwd/Bwd Pkts are PAYLOAD bytes (exclude headers)",
        "flags": "Flag Cnt columns are per-flow packet COUNTS (many are 0/1), converted to ratios per window",
        "timestamp": "dd/mm/YYYY HH:MM:SS, flow start, local capture time (no timezone)",
        "bidir_ratio": "packet-based: min(fwd_pkts,bwd_pkts)/total_pkts",
    }
    caveats = [
        "Nine of ten days have no IPs: windowing collapses each day to ONE network-wide time series; "
        "chronological-per-host splits on such data are the E1 snooping split -- use a day-disjoint split.",
        "Files may contain repeated header rows; they are dropped by numeric coercion (reported by the validator).",
        "Rows with inf/NaN rates or zero packets are dropped by flow_features.clean_and_normalize.",
        "No CIC-IDS-2018 label maps to reconnaissance or exfiltration.",
    ]

    @classmethod
    def detect_file(cls, info: HeaderInfo) -> tuple[float, list[str]]:
        cols = info.columns
        if not cols or not _has_cic2018_header(cols):
            return 0.0, []
        name = info.path.name.lower()
        if "synthetic" in name or info.n_fields < _REDUCED_MAX_FIELDS:
            return 0.0, []  # belongs to the synthetic adapter
        ev = [f"CICFlowMeter-2018 header ({info.n_fields} columns: 'Tot Fwd Pkts', 'Flow IAT Mean', 'Timestamp')"]
        ev.append("has Src IP/Dst IP" if "Src IP" in cols else "NO Src IP/Dst IP -> pseudo-host days")
        return 0.95, ev


@register_adapter
class SyntheticAdapter(_CICFlowMeterBase):
    name = "synthetic"
    version = "1.0.0"
    description = ("Hand-built / fabricated CICFlowMeter-style CSVs with the reduced 21-column schema "
                   "(data/raw/flows/synthetic_sample.csv, flows_real/Synthetic-BenignHighVolume*). NOT real traffic.")
    wraps = ["pipeline.flow_features", "scripts.make_synthetic_sample", "scripts.augment_benign_high_volume"]
    unit_kind = "all"
    default_split = "chronological"
    synthetic = True
    intentional_impact = {k for k, v in CIC_LABEL_TO_STAGE.items() if v == IMPACT}
    ignorable_labels = {"Label"}
    max_plausible_duration_s = 1000.0
    unit_assumptions = CICIDS2018Adapter.unit_assumptions
    caveats = [
        "Synthetic: must never be reported as real-data evidence (the demo captions it).",
        "SYNTH-Exfiltration is the only source of the 'exfiltration' stage in the whole project.",
        "Synthetic-BenignHighVolume_* in flows_real is a fabricated benign-only augmentation (the "
        "04-01/04-02 days dropped by configs/real_data_v2_converged.yaml); keep it out of real-data runs.",
    ]

    @classmethod
    def detect_file(cls, info: HeaderInfo) -> tuple[float, list[str]]:
        cols = info.columns
        if not cols or "Flow IAT Mean" not in cols or "Label" not in cols or "Timestamp" not in cols:
            return 0.0, []
        name = info.path.name.lower()
        reduced = info.n_fields < _REDUCED_MAX_FIELDS
        if reduced and "Tot Fwd Pkts" in cols:
            ev = [f"reduced CICFlowMeter schema ({info.n_fields} columns) -> fabricated/synthetic flow file"]
            if "synthetic" in name:
                ev.append("filename contains 'synthetic'")
            return (0.97 if "synthetic" in name else 0.9), ev
        if "synthetic" in name and "Tot Fwd Pkts" in cols:
            return 0.6, ["filename contains 'synthetic' (full-width schema)"]
        return 0.0, []
