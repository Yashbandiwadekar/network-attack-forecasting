"""Registered stubs / unsupported formats, so `detect_dataset` recognises them and says WHY they can't run.

* NetFlowV2Stub     -- NF-UNSW-NB15-v2 / NF-CSE-CIC-IDS2018-v2 / NF-ToN-IoT-v2 / NF-BoT-IoT-v2 (skeleton + how-to)
* CICIoT2023Unsupported -- merged CICIoT2023 CSVs: feature-only rows, no IPs, no timestamps
* UNSWSplitSetsUnsupported -- UNSW-NB15 'Training and Testing Sets': no srcip/dstip/Stime
* CICIDS2017MLCVEUnsupported -- CIC-IDS-2017 MachineLearningCVE release: no IPs, no Timestamp

The NF-v2 column list below is from the published NetFlow-v2 schema and is UNVERIFIED against a file
(no NF-* data is on disk). Follow docs/08-dataset-adapter-guide.md section 'Adding a dataset'.
"""
from __future__ import annotations

from pipeline.adapters.base import DatasetAdapter, HeaderInfo, register_adapter

NF_V2_COLUMN_MAP = {  # NetFlow-v2 column -> canonical field (UNVERIFIED, from the published schema)
    "IPV4_SRC_ADDR": "src_ip", "IPV4_DST_ADDR": "dst_ip", "L4_SRC_PORT": "src_port", "L4_DST_PORT": "dst_port",
    "PROTOCOL": "protocol", "IN_PKTS": "fwd_pkts", "OUT_PKTS": "bwd_pkts", "IN_BYTES": "fwd_bytes",
    "OUT_BYTES": "bwd_bytes", "FLOW_START_MILLISECONDS": "timestamp (ms epoch)",
    "FLOW_DURATION_MILLISECONDS": "duration_s (ms -> /1000)",
    "SRC_TO_DST_IAT_AVG": "iat_mean (ms -> *1000 us; mean of both directions)",
    "SRC_TO_DST_IAT_MAX": "iat_max (ms -> *1000 us)", "SRC_TO_DST_IAT_STDDEV": "iat_std (ms -> *1000 us)",
    "TCP_FLAGS": "BITMASK (OR of all flags seen) -> NOT a count: derive 0/1 per flag, mark APPROX",
    "Label": "0/1 binary", "Attack": "family string -> label (needs an explicit mitre_mapping entry)",
}


class _Unrunnable(DatasetAdapter):
    def iter_flows(self, *a, **k):
        raise NotImplementedError(f"[{self.name}] {self.status}: {self.howto}")

    def iter_label_chunks(self, *a, **k):
        raise NotImplementedError(f"[{self.name}] {self.status}: {self.howto}")


@register_adapter
class NetFlowV2Stub(_Unrunnable):
    name = "netflow_v2"
    version = "0.0.1"
    status = "stub"
    description = "NF-*-v2 NetFlow datasets (IPs + FLOW_START_MILLISECONDS present) -- skeleton only."
    howto = ("Implement iter_flows/iter_label_chunks using NF_V2_COLUMN_MAP (see stubs.py and "
             "docs/08-dataset-adapter-guide.md). Key traps: durations/IAT are MILLISECONDS, TCP_FLAGS is a bitmask, "
             "timestamps are epoch milliseconds, 'Attack' strings need explicit mitre_mapping entries.")
    caveats = ["No NF-* data on disk: column list unverified."]

    @classmethod
    def detect_file(cls, info: HeaderInfo) -> tuple[float, list[str]]:
        cols = set(info.columns)
        if {"IPV4_SRC_ADDR", "IPV4_DST_ADDR", "IN_BYTES", "IN_PKTS"} <= cols:
            return 0.9, ["NetFlow-v2 header (IPV4_SRC_ADDR, IN_BYTES, ...)"]
        return 0.0, []


@register_adapter
class CICIoT2023Unsupported(_Unrunnable):
    name = "ciciot2023"
    version = "0.0.1"
    status = "unsupported"
    description = "CICIoT2023 merged CSVs: per-flow feature rows with no IP and no timestamp."
    howto = ("Cannot be windowed per host/time. Needs the raw PCAPs -> CICFlowMeter (keeps 5-tuple + timestamp) "
             "-> use the cicids2018-style adapter, or write a new adapter on the regenerated CSVs.")

    @classmethod
    def detect_file(cls, info: HeaderInfo) -> tuple[float, list[str]]:
        cols = set(info.columns)
        if {"Header_Length", "Protocol Type", "Rate", "Srate"} <= cols:
            return 0.95, ["CICIoT2023 feature schema (Header_Length, Protocol Type, Rate, Srate); no IP/Timestamp"]
        return 0.0, []


@register_adapter
class UNSWSplitSetsUnsupported(_Unrunnable):
    name = "unsw_nb15_split_sets"
    version = "0.0.1"
    status = "unsupported"
    description = "UNSW-NB15 'Training and Testing Sets' (UNSW_NB15_training-set.csv ...): no srcip/dstip/Stime."
    howto = "Use the raw UNSW-NB15_1..4.csv files (adapter 'unsw_nb15'), not the pre-split sets."

    @classmethod
    def detect_file(cls, info: HeaderInfo) -> tuple[float, list[str]]:
        cols = set(info.columns)
        if {"spkts", "sbytes", "attack_cat", "label"} <= cols and "srcip" not in cols:
            return 0.95, ["UNSW-NB15 pre-split set header (spkts, sbytes, attack_cat, label) without srcip/Stime"]
        return 0.0, []


@register_adapter
class CICIDS2017MLCVEUnsupported(_Unrunnable):
    name = "cicids2017_mlcve"
    version = "0.0.1"
    status = "unsupported"
    description = "CIC-IDS-2017 MachineLearningCVE release: no Source/Destination IP, no Timestamp."
    howto = "Use the TrafficLabelling release (adapter 'cicids2017', experimental)."

    @classmethod
    def detect_file(cls, info: HeaderInfo) -> tuple[float, list[str]]:
        cols = set(info.columns)
        if "Destination Port" in cols and "Flow Duration" in cols and "Label" in cols \
                and "Timestamp" not in cols and "Source IP" not in cols:
            return 0.9, ["CIC-IDS-2017 ML-CVE header: Destination Port present, Timestamp/Source IP absent"]
        return 0.0, []
