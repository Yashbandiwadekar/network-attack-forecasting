"""CIC-IDS-2017 (GeneratedLabelledFlows / TrafficLabelling release) -- EXPERIMENTAL adapter.

Found on disk at V:/Datasets/CIC-IDS-2017 (8 day files, ~1.2 GB) but NOT yet used by any project run.
It keeps Source/Destination IP every day (the reason docs/AUDIT.md names it as the next dataset), so
it can be windowed per host. What is verified from a head-read of Tuesday-WorkingHours:
  * headers carry LEADING SPACES and long/plural names ("Total Fwd Packets", "Flow IAT Mean") that
    flow_features.COLUMN_RENAME does NOT cover -> extended map below;
  * Timestamp is "4/7/2017 8:54" = d/m/Y H:MM (4 July 2017, a Tuesday; the Monday file starts "3/7/2017") with NO seconds and NO AM/PM;
  * Label text contains a non-UTF-8 dash ("Web Attack \x96 Brute Force") -> read as cp1252.
What is NOT decided (owner decision): label -> stage for FTP-Patator, SSH-Patator, PortScan, Web Attack*,
Heartbleed. mitre_mapping.label_to_stage sends them to IMPACT (silent fall-through), so the validator
FAILs this dataset on purpose until pipeline/mitre_mapping.py gets explicit entries.
"""
from __future__ import annotations

import pandas as pd

from pipeline import flow_features as ff
from pipeline.adapters.base import APPROX, HeaderInfo, register_adapter
from pipeline.adapters.cicids2018_adapter import _CICFlowMeterBase
from pipeline.mitre_mapping import CIC_LABEL_TO_STAGE, IMPACT

_RENAME_2017 = dict(ff.COLUMN_RENAME)
_RENAME_2017.update({
    "Total Fwd Packets": "fwd_pkts",
    "Total Backward Packets": "bwd_pkts",
    "Total Length of Fwd Packets": "fwd_bytes",
    "Total Length of Bwd Packets": "bwd_bytes",
})
_MARKERS_2017 = {"Source IP", "Destination IP", "Timestamp", "Total Fwd Packets", "Flow IAT Mean", "Label"}


@register_adapter
class CICIDS2017Adapter(_CICFlowMeterBase):
    name = "cicids2017"
    version = "0.1.0"
    status = "experimental"
    description = "CIC-IDS-2017 TrafficLabelling CSVs (real IPs every day). Experimental: label mapping undecided."
    wraps = ["pipeline.flow_features"]
    rename_map = _RENAME_2017
    encoding = "cp1252"
    unit_kind = "file"
    default_split = "by_day"
    # DoS/DDoS are IMPACT in the 2018 table too, so IMPACT here is consistent, not an unknown.
    intentional_impact = {k for k, v in CIC_LABEL_TO_STAGE.items() if v == IMPACT} | {
        "dos hulk", "dos goldeneye", "dos slowloris", "dos slowhttptest", "ddos"}
    ignorable_labels = {"Label"}
    max_plausible_duration_s = 1000.0
    field_coverage = {
        "timestamp": (APPROX, "minute resolution, no AM/PM: hours 1-7 shifted +12h by heuristic"),
    }
    unit_assumptions = {
        "duration": "Flow Duration MICROSECONDS -> seconds",
        "iat": "Flow IAT * MICROSECONDS (same CICFlowMeter family as 2018)",
        "timestamp": "d/m/YYYY H:MM, local time, AM/PM stripped (heuristic: capture 08:00-17:00)",
        "bytes": "payload bytes (as 2018)",
    }
    caveats = [
        "Timestamps have only minute resolution: all flows within a minute share one timestamp, so the 10 s "
        "windows are coarse -- flows pile into the first window of each minute.",
        "FTP-Patator / SSH-Patator / PortScan / Web Attack / Heartbleed have no entry in mitre_mapping "
        "(silently IMPACT). Owner must decide the mapping before use.",
        "Only the TrafficLabelling release works; the MachineLearningCVE release has no IP/Timestamp.",
    ]

    @classmethod
    def detect_file(cls, info: HeaderInfo) -> tuple[float, list[str]]:
        if _MARKERS_2017.issubset(set(info.columns)):
            return 0.95, ["CIC-IDS-2017 TrafficLabelling header (Source IP, Total Fwd Packets, Timestamp ...)"]
        return 0.0, []

    def _prepare_chunk(self, raw: pd.DataFrame) -> pd.DataFrame:
        ts = pd.to_datetime(raw["timestamp"].astype(str).str.strip(), format="%d/%m/%Y %H:%M", errors="coerce")
        ts2 = pd.to_datetime(raw["timestamp"].astype(str).str.strip(), format="%d/%m/%Y %H:%M:%S", errors="coerce")
        ts = ts.fillna(ts2)
        ts = ts.where(~((ts.dt.hour >= 1) & (ts.dt.hour <= 7)), ts + pd.Timedelta(hours=12))
        raw = raw.copy()
        # flow_features.clean_and_normalize re-parses 'timestamp' (day-first slash, then ISO8601):
        # hand it ISO text so the pre-parsed value survives.
        raw["timestamp"] = ts.dt.strftime("%Y-%m-%d %H:%M:%S")
        return raw

    def _parse_ts_series(self, s: pd.Series) -> pd.Series:
        ts = pd.to_datetime(s.astype(str).str.strip(), format="%d/%m/%Y %H:%M", errors="coerce")
        return ts.where(~((ts.dt.hour >= 1) & (ts.dt.hour <= 7)), ts + pd.Timedelta(hours=12))
