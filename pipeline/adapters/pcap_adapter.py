"""PCAP-first datasets: a folder of captures becomes CICFlowMeter-shaped flows.

WRAPS pipeline/fast_packet_windows.py (`read_all_frames` + `assemble_flows`): IPv4 TCP/UDP only, Ethernet or
Linux-cooked link layers, bidirectional 5-tuple flows cut at CICFlowMeter's 120 s timeout, IAT in MICROSECONDS,
byte counts = L4 payload, flag counts = packets carrying the flag. A capture is read whole into memory (the
fast_packet_windows limit: one host capture < ~1 GB); `--max-rows-per-file` caps FRAMES for big files.

A PCAP has no labels. Pass a labels sidecar (pipeline/adapters/sidecar.py) -- attacker/victim IP + time ranges --
or everything is labelled BENIGN (the validator then WARNs: single-class data cannot train a forecaster).
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

import numpy as np
import pandas as pd

from pipeline.adapters.base import APPROX, CANONICAL_COLUMNS, DatasetAdapter, HeaderInfo, ReadStats, ZERO, register_adapter
from pipeline.fast_packet_windows import assemble_flows, ip_to_str, read_all_frames

_CANON = list(CANONICAL_COLUMNS)
_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}


@register_adapter
class PcapFlowsAdapter(DatasetAdapter):
    name = "pcap"
    version = "1.0.0"
    description = "Raw PCAP/PCAPNG captures (lab recordings, host captures) assembled into flows; labels via sidecar."
    wraps = ["pipeline.fast_packet_windows"]
    file_globs = ["*.pcap", "*.pcapng", "*.cap"]
    unit_kind = "all"
    default_split = "chronological"
    sort_keys = ["src_ip", "timestamp"]
    unlabelled_format = True
    max_plausible_duration_s = 1000.0
    bytes_include_headers = False
    field_coverage = {
        "fwd_pkts": (APPROX, "all packets counted as forward (per-direction split is not kept by assemble_flows)"),
        "bwd_pkts": (ZERO, "see fwd_pkts; bidir_ratio is computed from the true split"),
        "fwd_bytes": (APPROX, "= total payload bytes"), "bwd_bytes": (ZERO, "see fwd_bytes"),
        "src_port": (APPROX, "initiator port"),
    }
    unit_assumptions = {
        "duration": "last-first packet time, seconds",
        "iat": "gaps between ALL packets of the flow, MICROSECONDS (mean/std/max)",
        "bytes": "L4 payload bytes only (same as CIC TotLen)",
        "flags": "packets carrying the flag (tcp only)",
        "timestamp": "first packet time, capture epoch interpreted as UTC, tz-naive",
        "label": "from the labels sidecar, else BENIGN",
    }
    caveats = [
        "IPv4 TCP/UDP only: ICMP, IPv6 and ARP frames are skipped.",
        "CICFlowMeter's FIN-based flow termination is NOT emulated (only the 120 s timeout).",
        "No labels in a PCAP: supply --labels-sidecar or the data is single-class BENIGN.",
        "Captures are read whole into RAM; use --max-rows-per-file (frames) for large files.",
    ]

    @classmethod
    def detect_file(cls, info: HeaderInfo) -> tuple[float, list[str]]:
        if info.magic in _MAGIC:
            return 0.99, ["PCAP/PCAPNG magic number"]
        return 0.0, []

    def iter_flows(self, path: Path, chunksize: int = 500_000, max_rows: int | None = None,
                   stats: ReadStats | None = None) -> Iterator[pd.DataFrame]:
        path = Path(path)
        cols = read_all_frames(path, max_frames=max_rows)
        fl = assemble_flows(cols)
        if fl.empty:
            return
        df = pd.DataFrame({
            "timestamp": pd.to_datetime(fl["timestamp_s"], unit="s"),
            "src_ip": ip_to_str(fl["src_ip"]).astype(str), "dst_ip": ip_to_str(fl["dst_ip"]).astype(str),
            "src_port": fl["src_port"].astype(float), "dst_port": fl["dst_port"].astype(float),
            "protocol": np.where(fl["is_tcp"] > 0, 6.0, 17.0),
            "duration_s": fl["duration_s"].astype(float),
            "fwd_pkts": fl["total_pkts"].astype(float), "bwd_pkts": 0.0, "total_pkts": fl["total_pkts"].astype(float),
            "fwd_bytes": fl["total_bytes"].astype(float), "bwd_bytes": 0.0, "total_bytes": fl["total_bytes"].astype(float),
            **{c: fl[c].astype(float) for c in ("syn_cnt", "ack_cnt", "fin_cnt", "rst_cnt", "psh_cnt", "urg_cnt",
                                                 "iat_mean", "iat_std", "iat_max", "is_tcp", "is_udp", "bidir_ratio")},
            "has_ip_data": 1.0, "label": self.default_label, "source_file": path.name,
        })
        if stats is not None:                # frames are not flows: report flows read == kept (nothing is cleaned away)
            stats.rows_read += len(df)
            stats.rows_kept += len(df)
        yield df[_CANON + ["source_file"]]

    def iter_label_chunks(self, path: Path, chunksize: int = 1_000_000,
                          max_rows: int | None = None) -> Iterator[pd.DataFrame]:
        # unreachable: the base wrapper routes unlabelled formats through iter_flows
        raise NotImplementedError("pcap labels come from iter_flows")
