"""NF-*-v2 NetFlow datasets (NF-UNSW-NB15-v2, NF-CSE-CIC-IDS2018-v2, NF-ToN-IoT-v2, NF-BoT-IoT-v2).

Implemented from the PUBLISHED NetFlow-v2 column names; NO NF-* file was on disk when this was written, so it
is verified only against synthetic fixtures (status 'experimental'). The first real file must be run through
`python -m scripts.validate_dataset` before it is trusted -- in particular the IAT unit check and the label table.

Mapping (NF column -> canonical):
  IPV4_SRC_ADDR/IPV4_DST_ADDR, L4_SRC_PORT/L4_DST_PORT, PROTOCOL           -> src_ip/dst_ip, ports, protocol
  FLOW_START_MILLISECONDS (epoch ms)                                       -> timestamp   (REQUIRED)
  FLOW_DURATION_MILLISECONDS (ms)                                          -> duration_s  (/1000)
  IN_PKTS / OUT_PKTS, IN_BYTES / OUT_BYTES                                 -> fwd/bwd packets and bytes (L3 bytes)
  TCP_FLAGS (bitmask OR of all flags in the flow)                          -> syn/ack/fin/rst/psh/urg_cnt as 0/1 (APPROXIMATED)
  SRC_TO_DST_IAT_AVG / DST_TO_SRC_IAT_AVG (ms)                             -> iat_mean (us, mean of the directions that have one)
  *_IAT_STDDEV / *_IAT_MAX (ms)                                            -> iat_std / iat_max (us, max over directions; APPROXIMATED)
  Attack (string)  [else Label 0/1]                                        -> label "nf=<Attack>" (mitre_mapping.nf_classify)
Zero-filled when the columns are absent: iat_*.  Always zero-filled: nothing else in the 41-feature schema is lost.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

import numpy as np
import pandas as pd

from pipeline.adapters.base import (
    APPROX, CANONICAL_COLUMNS, DERIVED, DatasetAdapter, HeaderInfo, ReadStats, register_adapter,
)
from pipeline.mitre_mapping import IMPACT, nf_classify

_CANON = list(CANONICAL_COLUMNS)
_REQUIRED = ["IPV4_SRC_ADDR", "IPV4_DST_ADDR", "L4_SRC_PORT", "L4_DST_PORT", "PROTOCOL", "IN_BYTES", "IN_PKTS",
             "OUT_BYTES", "OUT_PKTS", "FLOW_DURATION_MILLISECONDS"]
_OPTIONAL = ["FLOW_START_MILLISECONDS", "TCP_FLAGS", "SRC_TO_DST_IAT_AVG", "DST_TO_SRC_IAT_AVG",
             "SRC_TO_DST_IAT_STDDEV", "DST_TO_SRC_IAT_STDDEV", "SRC_TO_DST_IAT_MAX", "DST_TO_SRC_IAT_MAX",
             "Label", "Attack"]
_FLAG_BITS = {"fin_cnt": 0x01, "syn_cnt": 0x02, "rst_cnt": 0x04, "psh_cnt": 0x08, "ack_cnt": 0x10, "urg_cnt": 0x20}


@register_adapter
class NetFlowV2Adapter(DatasetAdapter):
    name = "netflow_v2"
    version = "0.1.0"
    status = "experimental"
    description = "NF-*-v2 NetFlow CSVs (real IPs, epoch-ms start). Implemented from the published schema; unverified on real files."
    wraps = ["pipeline.mitre_mapping.nf_classify"]
    unit_kind = "all"
    default_split = "chronological"
    sort_keys = ["src_ip", "timestamp"]
    intentional_impact: set[str] = set()
    max_plausible_duration_s = 1e5
    bytes_include_headers = True
    field_coverage = {
        "syn_cnt": (APPROX, "TCP_FLAGS is a bitmask: 0/1 per flow, not a packet count"),
        "ack_cnt": (APPROX, "bitmask -> 0/1"), "fin_cnt": (APPROX, "bitmask -> 0/1"),
        "rst_cnt": (APPROX, "bitmask -> 0/1"), "psh_cnt": (APPROX, "bitmask -> 0/1"),
        "urg_cnt": (APPROX, "bitmask -> 0/1"),
        "iat_mean": (DERIVED, "mean of the per-direction IAT averages (ms x1000); zero if columns absent"),
        "iat_std": (APPROX, "max of the per-direction IAT std-devs, not a flow-wide std"),
        "iat_max": (APPROX, "max of the per-direction IAT maxima"),
    }
    unit_assumptions = {
        "duration": "FLOW_DURATION_MILLISECONDS -> /1000 -> seconds",
        "iat": "NetFlow-v2 *_IAT_* columns are MILLISECONDS -> x1000 -> microseconds (validator IAT check confirms)",
        "timestamp": "FLOW_START_MILLISECONDS epoch ms, UTC naive",
        "flags": "TCP_FLAGS bitmask decoded per bit; 0/1 per flow",
        "bytes": "IN_/OUT_BYTES (IP level incl. headers)",
        "label": "'nf=<Attack>' (Attack string; falls back to Label 0/1 -> nf=Benign / nf=Attack)",
    }
    caveats = [
        "Unverified on real NF-* files (none on disk). Run the validator on the first one.",
        "Files without FLOW_START_MILLISECONDS cannot be windowed and are rejected with an error.",
        "Label stage mapping is keyword-based (mitre_mapping.nf_classify); unknown attack names fall through to IMPACT "
        "and are reported by the validator.",
        "Several NF datasets are IoT/host-based: attack families other than the CIC/UNSW ones map mostly to impact.",
    ]

    @classmethod
    def detect_file(cls, info: HeaderInfo) -> tuple[float, list[str]]:
        cols = set(info.columns)
        if {"IPV4_SRC_ADDR", "IPV4_DST_ADDR", "IN_BYTES", "IN_PKTS"} <= cols:
            ev = ["NetFlow-v2 header (IPV4_SRC_ADDR, IN_BYTES, ...)"]
            if "FLOW_START_MILLISECONDS" not in cols:
                ev.append("WARNING: no FLOW_START_MILLISECONDS column -> cannot be windowed")
            return 0.95, ev
        return 0.0, []

    def label_status(self, label: str):
        stage, known = nf_classify(label)
        if stage != IMPACT:
            return stage, "mapped"
        return stage, ("impact_by_design" if known else "unknown_fallthrough")

    def _usecols(self, header: list[str]) -> list[str]:
        miss = [c for c in _REQUIRED if c not in header]
        if miss:
            raise ValueError(f"NetFlow-v2 file is missing required columns {miss}")
        if "FLOW_START_MILLISECONDS" not in header:
            raise ValueError("NetFlow-v2 file has no FLOW_START_MILLISECONDS column: flows cannot be placed in time, "
                             "so windowing/forecasting is impossible")
        return [c for c in _REQUIRED + _OPTIONAL if c in header]

    @staticmethod
    def _label(raw: pd.DataFrame) -> pd.Series:
        if "Attack" in raw.columns:
            a = raw["Attack"].astype(str).str.strip()
        elif "Label" in raw.columns:
            a = np.where(pd.to_numeric(raw["Label"], errors="coerce").fillna(0) > 0, "Attack", "Benign")
            a = pd.Series(a, index=raw.index)
        else:
            a = pd.Series("Benign", index=raw.index)
        return "nf=" + a

    def iter_flows(self, path: Path, chunksize: int = 500_000, max_rows: int | None = None,
                   stats: ReadStats | None = None) -> Iterator[pd.DataFrame]:
        header = [c.strip() for c in pd.read_csv(path, nrows=0).columns]
        use = self._usecols(header)
        for raw in pd.read_csv(path, usecols=lambda c: c.strip() in use, chunksize=chunksize, nrows=max_rows,
                               low_memory=False):
            raw.columns = [c.strip() for c in raw.columns]
            n_raw = len(raw)
            num = {c: pd.to_numeric(raw[c], errors="coerce") for c in raw.columns if c not in ("IPV4_SRC_ADDR", "IPV4_DST_ADDR", "Attack")}
            df = pd.DataFrame(index=raw.index)
            df["timestamp"] = pd.to_datetime(num["FLOW_START_MILLISECONDS"], unit="ms", errors="coerce")
            df["src_ip"] = raw["IPV4_SRC_ADDR"].astype(str).str.strip()
            df["dst_ip"] = raw["IPV4_DST_ADDR"].astype(str).str.strip()
            df["src_port"] = num["L4_SRC_PORT"].fillna(0)
            df["dst_port"] = num["L4_DST_PORT"]
            df["protocol"] = num["PROTOCOL"]
            df["duration_s"] = num["FLOW_DURATION_MILLISECONDS"] / 1000.0
            df["fwd_pkts"], df["bwd_pkts"] = num["IN_PKTS"], num["OUT_PKTS"]
            df["total_pkts"] = df["fwd_pkts"] + df["bwd_pkts"]
            df["fwd_bytes"], df["bwd_bytes"] = num["IN_BYTES"], num["OUT_BYTES"]
            df["total_bytes"] = df["fwd_bytes"] + df["bwd_bytes"]
            is_tcp = df["protocol"] == 6
            flags = num["TCP_FLAGS"].fillna(0).astype("int64") if "TCP_FLAGS" in num else pd.Series(0, index=raw.index)
            for col, bit in _FLAG_BITS.items():
                df[col] = ((flags & bit) > 0).where(is_tcp, False).astype(float)

            def pair(a: str, b: str, how: str) -> pd.Series:
                cols = [num[c] for c in (a, b) if c in num]
                if not cols:
                    return pd.Series(0.0, index=raw.index)
                m = pd.concat(cols, axis=1)
                m = m.where(m > 0)           # a direction with a single packet reports 0: ignore it
                r = m.mean(axis=1) if how == "mean" else m.max(axis=1)
                return r.fillna(0.0) * 1000.0   # ms -> us

            df["iat_mean"] = pair("SRC_TO_DST_IAT_AVG", "DST_TO_SRC_IAT_AVG", "mean")
            df["iat_std"] = pair("SRC_TO_DST_IAT_STDDEV", "DST_TO_SRC_IAT_STDDEV", "max")
            df["iat_max"] = pair("SRC_TO_DST_IAT_MAX", "DST_TO_SRC_IAT_MAX", "max")
            df["is_tcp"] = is_tcp.astype(float)
            df["is_udp"] = (df["protocol"] == 17).astype(float)
            df["bidir_ratio"] = np.where(df["total_pkts"] > 0, np.minimum(df["fwd_pkts"], df["bwd_pkts"]) / df["total_pkts"].replace(0, np.nan), 0.0)
            df["has_ip_data"] = 1.0
            df["label"] = self._label(raw)
            df["source_file"] = Path(path).name
            df = df.replace([np.inf, -np.inf], np.nan)
            df = df.dropna(subset=["timestamp", "protocol", "src_ip", "dst_ip", "total_pkts", "total_bytes", "duration_s"])
            df = df[df["total_pkts"] > 0].reset_index(drop=True).fillna({"bidir_ratio": 0.0})
            if stats is not None:
                stats.rows_read += n_raw
                stats.rows_kept += len(df)
            yield df[_CANON + ["source_file"]]

    def iter_label_chunks(self, path: Path, chunksize: int = 1_000_000,
                          max_rows: int | None = None) -> Iterator[pd.DataFrame]:
        header = [c.strip() for c in pd.read_csv(path, nrows=0).columns]
        use = [c for c in ("Attack", "Label", "FLOW_START_MILLISECONDS") if c in header]
        if "FLOW_START_MILLISECONDS" not in header:
            raise ValueError("NetFlow-v2 file has no FLOW_START_MILLISECONDS column")
        for raw in pd.read_csv(path, usecols=lambda c: c.strip() in use, chunksize=chunksize, nrows=max_rows,
                               low_memory=False):
            raw.columns = [c.strip() for c in raw.columns]
            thin = pd.to_datetime(pd.to_numeric(raw["FLOW_START_MILLISECONDS"].iloc[::20], errors="coerce"), unit="ms", errors="coerce")
            yield pd.DataFrame({"label": self._label(raw).astype(str)}).assign(timestamp=thin.reindex(raw.index))
