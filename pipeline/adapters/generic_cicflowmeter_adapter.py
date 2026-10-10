"""Generic CICFlowMeter-style CSVs, matched by NORMALISED header names.

Catches the CICFlowMeter family that the dedicated adapters do not claim: CICFlowMeter-py / cicflowmeter output
("src_ip, dst_ip, flow_duration, tot_fwd_pkts, ..."), other releases of CIC-IDS with different spellings, and
lab recordings run through CICFlowMeter. Confidence is capped at 0.6 so a dedicated adapter always wins a tie.

Assumptions you must check with the validator: Flow Duration and Flow IAT * are MICROSECONDS (true for every
CICFlowMeter release), TCP flag columns are per-flow packet counts, timestamps are one of dd/mm/YYYY, mm/dd/YYYY,
ISO or epoch. Files WITHOUT a label column are accepted as 'unlabelled' (BENIGN unless a sidecar is attached).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

import numpy as np
import pandas as pd

from pipeline import flow_features as ff
from pipeline.adapters.base import CANONICAL_COLUMNS, DatasetAdapter, HeaderInfo, ReadStats, peek_file, register_adapter
from pipeline.mitre_mapping import CIC_LABEL_TO_STAGE, IMPACT

_CANON = list(CANONICAL_COLUMNS)


def norm(c: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(c).lower())


_SYN = {
    "src_ip": ["srcip", "sourceip", "srcaddr"], "src_port": ["srcport", "sourceport"],
    "dst_ip": ["dstip", "destinationip", "destip", "dstaddr"], "dst_port": ["dstport", "destinationport", "destport"],
    "protocol": ["protocol", "proto"], "timestamp": ["timestamp", "starttime", "flowstarttime"],
    "duration_us": ["flowduration"],
    "fwd_pkts": ["totfwdpkts", "totalfwdpackets", "totalfwdpacket", "totfwdpackets"],
    "bwd_pkts": ["totbwdpkts", "totalbackwardpackets", "totalbwdpackets", "totbwdpackets"],
    "fwd_bytes": ["totlenfwdpkts", "totallengthoffwdpackets", "totallengthoffwdpacket", "totlenfwdpackets"],
    "bwd_bytes": ["totlenbwdpkts", "totallengthofbwdpackets", "totallengthofbwdpacket", "totlenbwdpackets"],
    "syn_cnt": ["synflagcnt", "synflagcount"], "ack_cnt": ["ackflagcnt", "ackflagcount"],
    "fin_cnt": ["finflagcnt", "finflagcount"], "rst_cnt": ["rstflagcnt", "rstflagcount"],
    "psh_cnt": ["pshflagcnt", "pshflagcount"], "urg_cnt": ["urgflagcnt", "urgflagcount"],
    "iat_mean": ["flowiatmean"], "iat_std": ["flowiatstd"], "iat_max": ["flowiatmax"],
    "label": ["label"],
}
_NORM_TO_INTERNAL = {n: k for k, ns in _SYN.items() for n in ns}
_MUST = {"timestamp", "duration_us", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "iat_mean", "iat_std",
         "iat_max", "syn_cnt", "ack_cnt", "fin_cnt", "rst_cnt", "psh_cnt", "urg_cnt", "dst_port", "protocol"}


def parse_any_timestamp(s: pd.Series) -> pd.Series:
    """Epoch (s or ms) or text; for text pick the format with the most parsed values (ties: day-first, as CIC)."""
    num = pd.to_numeric(s, errors="coerce")
    if num.notna().mean() > 0.9:
        unit = "ms" if num.dropna().median() > 1e11 else "s"
        return pd.to_datetime(num, unit=unit, errors="coerce")
    txt = s.astype(str).str.strip()
    best, best_rate = None, -1.0
    for fmt in ("%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S", "ISO8601", "%d/%m/%Y %H:%M", "%m/%d/%Y %H:%M",
                "%Y/%m/%d %H:%M:%S.%f"):
        t = pd.to_datetime(txt, format=fmt, errors="coerce")
        rate = float(t.notna().mean())
        if rate > best_rate + 1e-9:
            best, best_rate = t, rate
    return best


@register_adapter
class GenericCICFlowMeterAdapter(DatasetAdapter):
    name = "cicflowmeter_generic"
    version = "1.0.0"
    status = "experimental"
    description = "Any CICFlowMeter-style per-flow CSV recognised by normalised header names (src/dst IP optional)."
    wraps = ["pipeline.flow_features"]
    unit_kind = "file"
    default_split = "by_day"
    sort_keys = ["timestamp"]
    intentional_impact = {k for k, v in CIC_LABEL_TO_STAGE.items() if v == IMPACT}
    ignorable_labels = {"Label"}
    max_plausible_duration_s = 1000.0
    unit_assumptions = {
        "duration": "Flow Duration MICROSECONDS -> seconds (CICFlowMeter convention; validator checks it)",
        "iat": "Flow IAT * MICROSECONDS",
        "timestamp": "auto-detected: epoch s/ms, dd/mm/YYYY, mm/dd/YYYY or ISO (best parse rate wins)",
        "flags": "per-flow packet counts",
    }
    caveats = [
        "Header matching is heuristic: always read the validator report before training.",
        "Without IP columns it behaves like CIC-IDS-2018's IP-less days (pseudo-host per day).",
        "A file without a label column is treated as unlabelled (BENIGN unless --labels-sidecar is given).",
    ]

    @classmethod
    def _mapped(cls, columns: list[str]) -> set[str]:
        return {_NORM_TO_INTERNAL[norm(c)] for c in columns if norm(c) in _NORM_TO_INTERNAL}

    @classmethod
    def detect_file(cls, info: HeaderInfo) -> tuple[float, list[str]]:
        if not info.columns:
            return 0.0, []
        m = cls._mapped(info.columns)
        missing = _MUST - m
        if missing:
            return 0.0, []
        ev = ["CICFlowMeter-style header matched by normalised names (generic)"]
        ev.append("has IPs" if {"src_ip", "dst_ip"} <= m else "no src/dst IP columns")
        ev.append("labelled" if "label" in m else "NO label column (unlabelled capture)")
        return 0.6, ev

    def _unlabelled(self, path) -> bool:
        return "label" not in self._mapped(peek_file(Path(path)).columns)

    def _rename(self, cols: list[str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for c in cols:
            k = _NORM_TO_INTERNAL.get(norm(c))
            if k and k not in out.values():
                out[c] = k
        return out

    def iter_flows(self, path: Path, chunksize: int = 500_000, max_rows: int | None = None,
                   stats: ReadStats | None = None) -> Iterator[pd.DataFrame]:
        path = Path(path)
        for raw in pd.read_csv(path, low_memory=False, usecols=lambda c: norm(c) in _NORM_TO_INTERNAL,
                               chunksize=chunksize, nrows=max_rows, encoding_errors="replace"):
            n_raw = len(raw)
            raw = raw.rename(columns=self._rename(list(raw.columns)))
            raw = raw.loc[:, ~raw.columns.duplicated()]
            if "label" not in raw.columns:
                raw["label"] = self.default_label
            raw["timestamp"] = parse_any_timestamp(raw["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S.%f")
            missing = [c for c in ff.STRICTLY_REQUIRED_COLUMNS if c not in raw.columns]
            if missing:
                raise ValueError(f"{path}: missing required columns after rename: {missing}")
            keep = ff.STRICTLY_REQUIRED_COLUMNS + [c for c in ff.OPTIONAL_IP_COLUMNS if c in raw.columns]
            clean = ff.clean_and_normalize(raw[keep].copy())
            clean["source_file"] = path.name
            if stats is not None:
                stats.rows_read += n_raw
                stats.rows_kept += len(clean)
            yield clean[_CANON + ["source_file"]]

    def iter_label_chunks(self, path: Path, chunksize: int = 1_000_000,
                          max_rows: int | None = None) -> Iterator[pd.DataFrame]:
        for raw in pd.read_csv(path, low_memory=False, chunksize=chunksize, nrows=max_rows, encoding_errors="replace",
                               usecols=lambda c: _NORM_TO_INTERNAL.get(norm(c)) in ("label", "timestamp")):
            raw = raw.rename(columns=self._rename(list(raw.columns)))
            ts = parse_any_timestamp(raw["timestamp"].iloc[::20])
            yield pd.DataFrame({"label": raw["label"].astype(str).str.strip()}).assign(timestamp=ts.reindex(raw.index))
