"""CIC-IDS-2017 (GeneratedLabelledFlows / TrafficLabelling release) -- EXPERIMENTAL adapter.

Found on disk at V:/Datasets/CIC-IDS-2017 (8 day files, ~1.2 GB) but NOT yet used by any project run.
It keeps Source/Destination IP every day (the reason docs/AUDIT.md names it as the next dataset), so
it can be windowed per host. What is verified from a head-read of Tuesday-WorkingHours:
  * headers carry LEADING SPACES and long/plural names ("Total Fwd Packets", "Flow IAT Mean") that
    flow_features.COLUMN_RENAME does NOT cover -> extended map below;
  * Timestamp is "4/7/2017 8:54" = d/m/Y H:MM (4 July 2017, a Tuesday; the Monday file starts "3/7/2017") with NO seconds and NO AM/PM;
  * Label text contains a non-UTF-8 dash ("Web Attack \x96 Brute Force") -> read as cp1252.
Labels (mapped 2026-10-10, see mitre_mapping.CIC2017_LABEL_TO_STAGE): FTP-Patator, SSH-Patator, PortScan, Web Attack*,
Heartbleed now have explicit entries (PortScan is real labelled reconnaissance).
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
    description = "CIC-IDS-2017 TrafficLabelling CSVs (real IPs every day). Experimental only because the AM/PM timestamp heuristic is unverified; labels are mapped (mitre_mapping.CIC2017_LABEL_TO_STAGE)."
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
        "Timestamps have only minute resolution on every day except Monday (which has seconds): all flows within a "
        "minute share one timestamp, so 10 s windows pile into the :00 slot of each minute. Per-host windows are then "
        ">= 60 s apart and `require_contiguous_windows` at 10 s yields ZERO sequences on Tue-Fri (docs/15); use 60 s "
        "windows for those days. Monday works at 10 s.",
        "Labels are mapped explicitly (mitre_mapping.CIC2017_LABEL_TO_STAGE): Patator -> initial_access, PortScan -> "
        "reconnaissance, Web Attack -> initial_access, Heartbleed -> initial_access, Bot -> command_and_control, "
        "Infiltration -> lateral_movement, DoS/DDoS -> impact. The AM/PM heuristic was checked against the published "
        "attack schedule and the hours present (docs/15) but not against the PCAPs.",
        "The Thursday-Morning WebAttacks file has ~288k empty trailing rows that are dropped (unparsable timestamp).",
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
        txt = s.astype(str).str.strip()
        ts = pd.to_datetime(txt, format="%d/%m/%Y %H:%M", errors="coerce")
        ts = ts.fillna(pd.to_datetime(txt, format="%d/%m/%Y %H:%M:%S", errors="coerce"))
        return ts.where(~((ts.dt.hour >= 1) & (ts.dt.hour <= 7)), ts + pd.Timedelta(hours=12))
