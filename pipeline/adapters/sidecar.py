"""Labels sidecar: ground truth for captures that carry no labels (lab-recorded PCAPs, CICFlowMeter-py output).

A sidecar is a small CSV, one rule per row:

    src_ip,dst_ip,start,end,label[,dst_port]
    10.0.0.66,10.0.0.5,2026-10-10 14:03:00,2026-10-10 14:09:30,SSH-Bruteforce
    10.0.0.66,,2026-10-10 14:20:00,2026-10-10 14:25:00,Bot

* columns may also be named attacker_ip / victim_ip / start_time / end_time / attack (aliases);
* an empty `src_ip` or `dst_ip` is a wildcard; `start`/`end` accept ISO text or Unix epoch seconds, empty = unbounded;
* a rule matches a flow when its START time lies in [start, end] and the IPs match in EITHER direction
  (the attacker may be the initiator or the responder in the flow's 5-tuple), unless `bidirectional=False`;
* later rules override earlier ones; flows matching no rule keep `default_label` (BENIGN unless told otherwise);
* labels must be names `pipeline.mitre_mapping.label_to_stage` understands (e.g. the CIC-IDS names); the validator
  reports any that are not as `unknown_fallthrough`.

Times are compared as tz-naive; give them in the same clock as the capture (PCAP epoch -> UTC).
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

_ALIASES = {
    "attacker_ip": "src_ip", "attacker": "src_ip", "source_ip": "src_ip", "src": "src_ip",
    "victim_ip": "dst_ip", "victim": "dst_ip", "destination_ip": "dst_ip", "dst": "dst_ip",
    "start_time": "start", "begin": "start", "end_time": "end", "stop": "end",
    "attack": "label", "attack_label": "label", "class": "label",
}


def _to_time(series: pd.Series) -> pd.Series:
    num = pd.to_numeric(series, errors="coerce")
    if num.notna().any() and num.notna().sum() >= series.notna().sum():
        return pd.to_datetime(num, unit="s", errors="coerce")
    return pd.to_datetime(series, errors="coerce")


class LabelSidecar:
    def __init__(self, rules: pd.DataFrame, bidirectional: bool = True):
        self.rules = rules.reset_index(drop=True)
        self.bidirectional = bidirectional

    @classmethod
    def load(cls, path: str | Path, bidirectional: bool = True) -> "LabelSidecar":
        df = pd.read_csv(path, dtype=str, keep_default_na=False)
        df.columns = [_ALIASES.get(c.strip().lower(), c.strip().lower()) for c in df.columns]
        if "label" not in df.columns:
            raise ValueError(f"{path}: sidecar needs a 'label' column (found {list(df.columns)})")
        for c in ("src_ip", "dst_ip", "start", "end", "dst_port"):
            if c not in df.columns:
                df[c] = ""
        if (df["src_ip"].str.strip() == "").all() and (df["dst_ip"].str.strip() == "").all() \
                and (df["start"].str.strip() == "").all() and (df["end"].str.strip() == "").all():
            raise ValueError(f"{path}: every rule is unconstrained (no IP and no time): it would relabel everything")
        out = pd.DataFrame({
            "src_ip": df["src_ip"].str.strip(), "dst_ip": df["dst_ip"].str.strip(),
            "start": _to_time(df["start"].replace("", np.nan)), "end": _to_time(df["end"].replace("", np.nan)),
            "dst_port": pd.to_numeric(df["dst_port"].replace("", np.nan), errors="coerce"),
            "label": df["label"].str.strip(),
        })
        bad = [i for i, (raw_s, t) in enumerate(zip(df["start"], out["start"])) if raw_s.strip() and pd.isna(t)]
        bad += [i for i, (raw_e, t) in enumerate(zip(df["end"], out["end"])) if raw_e.strip() and pd.isna(t)]
        if bad:
            raise ValueError(f"{path}: unparsable start/end time in rule row(s) {sorted(set(bad))}")
        return cls(out, bidirectional)

    def apply(self, flows: pd.DataFrame, default_label: str = "BENIGN") -> pd.DataFrame:
        """Return `flows` with `label` replaced: default_label, then each rule in order."""
        labels = np.full(len(flows), default_label, dtype=object)
        src, dst, ts = flows["src_ip"].astype(str).to_numpy(), flows["dst_ip"].astype(str).to_numpy(), flows["timestamp"]
        dport = pd.to_numeric(flows["dst_port"], errors="coerce").to_numpy() if "dst_port" in flows else None
        for r in self.rules.itertuples(index=False):
            m = np.ones(len(flows), dtype=bool)
            if pd.notna(r.start):
                m &= (ts >= r.start).to_numpy()
            if pd.notna(r.end):
                m &= (ts <= r.end).to_numpy()
            fwd = np.ones(len(flows), dtype=bool)
            rev = np.ones(len(flows), dtype=bool)
            if r.src_ip:
                fwd &= src == r.src_ip
                rev &= dst == r.src_ip
            if r.dst_ip:
                fwd &= dst == r.dst_ip
                rev &= src == r.dst_ip
            ipm = (fwd | rev) if self.bidirectional else fwd
            if pd.notna(r.dst_port) and dport is not None:
                ipm &= dport == r.dst_port
            labels[m & ipm] = r.label
        out = flows.copy()
        out["label"] = labels
        return out

    def summary(self) -> dict:
        return {"rules": int(len(self.rules)), "labels": sorted(self.rules["label"].unique().tolist()),
                "bidirectional": self.bidirectional}
