"""Stage-event builder: the interface between a per-window DETECTOR (or ground-truth labels) and the
coarser stage FORECASTER (models/stage_forecaster.py).  Design and definitions: docs/14-stage-forecasting.md.

    labelled flows (any adapter, incl. labels-sidecar PCAP captures)  --\
                                                                         >-- stage events --> chains --> forecaster
    detector output (host, window_start, stage, confidence)           --/

A *stage event* is one maximal run of one stage for one entity: consecutive items of that stage (flows or
detector windows) are merged while the silence between them is <= `merge_gap_s`; runs shorter than
`min_duration_s` or with fewer than `min_flows` items are dropped (counted in the report, never silently).

Entity views (a kill chain flips direction after compromise, so no single key sees it all):
    attacker  entity = src_ip                      what a source host does to others
    victim    entity = dst_ip                      what is done to a host
    pair      entity = "src->dst"                  one attacker-victim relationship
    host      entity = dst for reconnaissance / initial_access / impact (it is acted ON),
                       src for lateral_movement / command_and_control / exfiltration (it acts)
              the compromised-host chain: recon -> initial access -> c2 -> exfil follows the victim.
Every event records the src and dst sets with counts, so the reconnaissance event of an attacker carries the
targets touched (the forecaster ranks likely next victims from them).

IP-less data (CIC-2018 pseudo-hosts `NETWORK-<date>`, `dst_ip == 'UNKNOWN'`, `has_ip_data == 0`) is refused per
unit: no entity is invented; the report says which units were refused and why.

pipeline/mitre_mapping.py is used as-is (`label_to_stage`).  `python -m pipeline.stage_events --help`.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

import numpy as np
import pandas as pd

from pipeline.mitre_mapping import (
    BENIGN, COMMAND_AND_CONTROL, EXFILTRATION, IMPACT, INITIAL_ACCESS, LATERAL_MOVEMENT, RECONNAISSANCE,
    label_to_stage,
)

STAGES = [RECONNAISSANCE, INITIAL_ACCESS, LATERAL_MOVEMENT, COMMAND_AND_CONTROL, EXFILTRATION, IMPACT]
VIEWS = ("attacker", "victim", "pair", "host")
# host view: stages in which the entity is the thing being acted ON (dst); the others it acts (src)
DST_ATTRIBUTED = {RECONNAISSANCE, INITIAL_ACCESS, IMPACT}
MAX_KEEP = 50          # top-N src / dst entries kept per event (the true distinct count is kept separately)
DEFAULT_MERGE_GAP_S = 300.0
DEFAULT_MAX_CHAIN_GAP_S = 7200.0
PSEUDO_SRC_PREFIX = "NETWORK-"


class UnusableForEntityTracking(RuntimeError):
    """Raised by callers that insist on entities; the builders themselves return a report instead."""


# ---------------------------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------------------------

@dataclass
class BuildReport:
    source: str                                   # 'label' | 'detector'
    view: str
    merge_gap_s: float
    min_duration_s: float
    min_flows: int
    usable: bool = True
    reason: str = ""
    n_rows_in: int = 0
    n_rows_benign: int = 0
    n_rows_dropped_pseudo: int = 0
    n_rows_dropped_no_dst: int = 0
    n_rows_dropped_unknown_stage: int = 0
    n_rows_dropped_low_confidence: int = 0
    n_runs_before_filter: int = 0
    n_runs_dropped_filter: int = 0
    n_events: int = 0
    n_entities: int = 0
    observed_from: str | None = None
    observed_until: str | None = None
    events_by_stage: dict[str, int] = field(default_factory=dict)
    units: dict[str, dict[str, Any]] = field(default_factory=dict)
    labels_by_stage: dict[str, dict[str, int]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def pseudo_row_mask(df: pd.DataFrame, need_dst: bool = True) -> np.ndarray:
    """Rows that carry no real host identity: has_ip_data == 0, pseudo-host source, or unknown destination."""
    m = df["src_ip"].astype(str).str.startswith(PSEUDO_SRC_PREFIX).to_numpy().copy()
    if "has_ip_data" in df.columns:
        m |= (pd.to_numeric(df["has_ip_data"], errors="coerce").fillna(1.0).to_numpy() == 0.0)
    if need_dst:
        m |= (df["dst_ip"].astype(str) == "UNKNOWN").to_numpy()
    return m


# ---------------------------------------------------------------------------------------------
# core: stage rows -> events
# ---------------------------------------------------------------------------------------------

def _entity_series(df: pd.DataFrame, view: str, unit_scoped: bool) -> pd.Series:
    src, dst = df["src_ip"].astype(str), df["dst_ip"].astype(str)
    if view == "attacker":
        ent = src
    elif view == "victim":
        ent = dst
    elif view == "pair":
        ent = src + "->" + dst
    elif view == "host":
        ent = pd.Series(np.where(df["stage"].isin(DST_ATTRIBUTED), dst, src), index=df.index)
    else:
        raise ValueError(f"unknown view {view!r}; choose from {VIEWS}")
    if unit_scoped and "unit" in df.columns:
        ent = df["unit"].astype(str) + "|" + ent
    return ent


def _topn(counter: dict[str, int], n: int = MAX_KEEP) -> dict[str, int]:
    return dict(sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:n])


def _runs_to_events(df: pd.DataFrame, view: str, merge_gap_s: float, min_duration_s: float, min_flows: int,
                    source: str, unit_scoped: bool, report: BuildReport) -> pd.DataFrame:
    """df has: stage, src_ip, dst_ip, t (float epoch s), t_end (float epoch s), confidence, label (optional),
    unit (optional)."""
    cols = ["event_id", "view", "entity", "stage", "start_s", "end_s", "duration_s", "n_flows", "n_src", "n_dst",
            "srcs", "dsts", "source", "confidence", "labels", "unit"]
    if df.empty:
        return pd.DataFrame({c: [] for c in cols})
    df = df.copy()
    df["entity"] = _entity_series(df, view, unit_scoped)
    df = df.sort_values(["entity", "stage", "t"], kind="mergesort").reset_index(drop=True)
    ent_c = pd.factorize(df["entity"])[0]
    st_c = pd.factorize(df["stage"])[0]
    t = df["t"].to_numpy()
    prev_end = np.concatenate([[-np.inf], df["t_end"].to_numpy()[:-1]])
    new = np.ones(len(df), bool)
    new[1:] = (ent_c[1:] != ent_c[:-1]) | (st_c[1:] != st_c[:-1]) | ((t[1:] - prev_end[1:]) > merge_gap_s)
    df["run"] = np.cumsum(new) - 1
    # detector rows are exploded to one row per destination: count/average over the ORIGINAL windows
    base = df.drop_duplicates(["run", "row_id"]) if "row_id" in df.columns else df
    g = base.groupby("run", sort=True)
    agg = g.agg(entity=("entity", "first"), stage=("stage", "first"), start_s=("t", "min"), end_s=("t_end", "max"),
                n_flows=("t", "size"), confidence=("confidence", "mean"))
    agg["unit"] = g["unit"].first() if "unit" in df.columns else ""
    srcs: dict[int, dict[str, int]] = {}
    dsts: dict[int, dict[str, int]] = {}
    for key, store in (("src_ip", srcs), ("dst_ip", dsts)):
        cnt = df.groupby(["run", key], sort=False).size()
        for (r, ip), n in cnt.items():
            store.setdefault(int(r), {})[str(ip)] = int(n)
    labs: dict[int, dict[str, int]] = {}
    if "label" in df.columns:
        for (r, lb), n in base.groupby(["run", "label"], sort=False).size().items():
            labs.setdefault(int(r), {})[str(lb)] = int(n)
    agg["duration_s"] = agg["end_s"] - agg["start_s"]
    report.n_runs_before_filter = int(len(agg))
    keep = (agg["duration_s"] >= min_duration_s) & (agg["n_flows"] >= min_flows)
    report.n_runs_dropped_filter = int((~keep).sum())
    agg = agg[keep]
    out = pd.DataFrame({
        "view": view, "entity": agg["entity"].to_numpy(), "stage": agg["stage"].to_numpy(),
        "start_s": agg["start_s"].to_numpy(), "end_s": agg["end_s"].to_numpy(),
        "duration_s": agg["duration_s"].to_numpy(), "n_flows": agg["n_flows"].to_numpy().astype(int),
        "n_src": [len(srcs[r]) for r in agg.index], "n_dst": [len(dsts[r]) for r in agg.index],
        "srcs": [_topn(srcs[r]) for r in agg.index], "dsts": [_topn(dsts[r]) for r in agg.index],
        "source": source, "confidence": agg["confidence"].to_numpy(),
        "labels": [_topn(labs.get(r, {}), 8) for r in agg.index], "unit": agg["unit"].to_numpy(),
    })
    out = out.sort_values(["start_s", "entity"], kind="mergesort").reset_index(drop=True)
    out.insert(0, "event_id", [f"{view[0]}{i:06d}" for i in range(len(out))])
    return out[cols]


def _finish_report(report: BuildReport, events: pd.DataFrame, t_min: float | None, t_max: float | None) -> None:
    report.n_events = int(len(events))
    report.n_entities = int(events["entity"].nunique()) if len(events) else 0
    report.events_by_stage = {s: int((events["stage"] == s).sum()) for s in STAGES} if len(events) else {}
    iso = lambda x: None if x is None else pd.Timestamp(x, unit="s").isoformat()
    report.observed_from, report.observed_until = iso(t_min), iso(t_max)
    if len(events):
        for s in STAGES:
            tot: dict[str, int] = {}
            for d in events.loc[events["stage"] == s, "labels"]:
                for k, v in d.items():
                    tot[k] = tot.get(k, 0) + v
            if tot:
                report.labels_by_stage[s] = _topn(tot, 12)


def _epoch_s(ts: pd.Series) -> np.ndarray:
    return pd.to_datetime(ts).astype("datetime64[ns]").astype(np.int64).to_numpy() / 1e9


# ---------------------------------------------------------------------------------------------
# public builders
# ---------------------------------------------------------------------------------------------

def events_from_flows(flows: pd.DataFrame, view: str = "attacker", merge_gap_s: float = DEFAULT_MERGE_GAP_S,
                      min_duration_s: float = 0.0, min_flows: int = 1, unit_col: str | None = "unit",
                      min_ip_fraction: float = 0.5, unit_scoped: bool = False,
                      stage_fn: Callable[[pd.DataFrame], pd.Series] | None = None,
                      ) -> tuple[pd.DataFrame, BuildReport]:
    """Ground-truth events from labelled flows (canonical flow frame: timestamp, src_ip, dst_ip, label,
    optional has_ip_data / unit).  `stage_fn(df) -> Series[str]` overrides the stage assignment (evaluation
    relabels such as the CTU-13 ICMP flood = impact); the default is `label_to_stage(label)`, with 'BENIGN'
    spellings dropped.  Returns (events, report); `report.usable` is False when no unit has real IPs."""
    rep = BuildReport("label", view, merge_gap_s, min_duration_s, min_flows, n_rows_in=len(flows))
    if view not in VIEWS:
        raise ValueError(f"unknown view {view!r}; choose from {VIEWS}")
    need = {"timestamp", "src_ip", "dst_ip", "label"} - set(flows.columns)
    if need:
        raise ValueError(f"flows frame lacks columns {sorted(need)}")
    df = flows
    if unit_col and unit_col in df.columns:
        df = df.assign(unit=df[unit_col].astype(str))
    else:
        df = df.assign(unit="all")
    # ---- IP-less refusal, per unit ----
    pseudo = pseudo_row_mask(df)
    keep_unit = np.ones(len(df), bool)
    for u, idx in df.groupby("unit", sort=False).indices.items():
        frac_usable = 1.0 - float(pseudo[idx].mean())
        ok = frac_usable >= min_ip_fraction
        rep.units[str(u)] = {"rows": int(len(idx)), "usable_ip_fraction": round(frac_usable, 6), "usable": bool(ok),
                             "reason": "" if ok else "no real host identity (has_ip_data==0 / NETWORK-* pseudo-host / "
                                                     "dst UNKNOWN): refused, no entities invented"}
        if not ok:
            keep_unit[idx] = False
    rep.n_rows_dropped_pseudo = int((pseudo & keep_unit).sum() + (~keep_unit).sum())
    df = df[keep_unit & ~pseudo]
    if df.empty:
        rep.usable = False
        rep.reason = ("no unit has real source/destination IPs; this dataset cannot be used for entity tracking "
                      f"({sum(1 for u in rep.units.values() if not u['usable'])} unit(s) refused)")
        return _runs_to_events(df.assign(stage="", t=0.0, t_end=0.0, confidence=1.0), view, merge_gap_s,
                               min_duration_s, min_flows, "label", unit_scoped, rep), rep
    # ---- stage assignment ----
    if stage_fn is not None:
        stage = stage_fn(df).astype(str)
        rep.notes.append("stage_fn override in use (evaluation relabel): " + getattr(stage_fn, "__doc__", "").strip().split("\n")[0])
    else:
        lab = df["label"].astype(str)
        stage = pd.Series(lab.map({l: label_to_stage(l) for l in lab.unique()}), index=df.index)
        stage[lab.str.strip().str.upper().isin({"BENIGN", "NORMAL"})] = BENIGN
    df = df.assign(stage=stage.to_numpy())
    rep.n_rows_benign = int((df["stage"] == BENIGN).sum())
    t_all = _epoch_s(df["timestamp"])
    t_min, t_max = float(t_all.min()), float(t_all.max())
    df = df.assign(t=t_all, t_end=t_all, confidence=1.0)
    df = df[df["stage"] != BENIGN]
    if stage_fn is None and (df["stage"] == IMPACT).any():
        unk = df.loc[df["stage"] == IMPACT, "label"].astype(str)
        rep.notes.append("labels mapped to 'impact' (explicit DoS/DDoS entries AND unknown fall-throughs): "
                         + json.dumps(_topn(unk.value_counts().to_dict(), 8)))
    ev = _runs_to_events(df, view, merge_gap_s, min_duration_s, min_flows, "label", unit_scoped, rep)
    _finish_report(rep, ev, t_min, t_max)
    return ev, rep


def events_from_detections(det: pd.DataFrame, view: str = "attacker", window_s: float | None = None,
                           merge_gap_s: float = DEFAULT_MERGE_GAP_S, min_duration_s: float = 0.0,
                           min_windows: int = 1, min_confidence: float = 0.0, unit_scoped: bool = False,
                           ) -> tuple[pd.DataFrame, BuildReport]:
    """Events from DETECTOR output.  `det` has one row per (host, window): `host` (or `src_ip`),
    `window_start` (datetime or epoch s), `stage` (one of STAGES, 'benign' = no stage), `confidence` in [0,1]
    (default 1), optional `window_s` (else the `window_s` argument), optional `dst_ips` ('a;b;c' or list) and
    `unit`.  Windows are keyed by source host only, so a detector that has no destination set can serve the
    'attacker' view only; 'victim'/'pair' rows without destinations are dropped and counted, and the 'host'
    view keeps just the src-attributed stages (lateral movement, C2, exfiltration) for such rows."""
    rep = BuildReport("detector", view, merge_gap_s, min_duration_s, min_windows, n_rows_in=len(det))
    if view not in VIEWS:
        raise ValueError(f"unknown view {view!r}; choose from {VIEWS}")
    d = det.copy()
    if "src_ip" not in d.columns:
        if "host" not in d.columns:
            raise ValueError("detector table needs a 'host' (or 'src_ip') column")
        d["src_ip"] = d["host"]
    for c in ("window_start", "stage"):
        if c not in d.columns:
            raise ValueError(f"detector table lacks column {c!r}")
    ws = d["window_s"].astype(float) if "window_s" in d.columns else pd.Series(window_s, index=d.index, dtype=float)
    if ws.isna().any():
        raise ValueError("window length unknown: pass window_s= or a window_s column")
    d["confidence"] = pd.to_numeric(d["confidence"], errors="coerce").fillna(1.0) if "confidence" in d.columns else 1.0
    ws_ = ws.to_numpy()
    start = d["window_start"]
    t0 = pd.to_numeric(start, errors="coerce").to_numpy(dtype=float) if pd.api.types.is_numeric_dtype(start) \
        else _epoch_s(start)
    d["t"], d["t_end"] = t0, t0 + ws_
    d["stage"] = d["stage"].astype(str)
    d["unit"] = d["unit"].astype(str) if "unit" in d.columns else "all"
    # pseudo-host sources are refused exactly as for flows
    pseudo = pseudo_row_mask(d, need_dst=False)
    for u, idx in d.groupby("unit", sort=False).indices.items():
        f = 1.0 - float(pseudo[idx].mean())
        rep.units[str(u)] = {"rows": int(len(idx)), "usable_ip_fraction": round(f, 6), "usable": f >= 0.5,
                             "reason": "" if f >= 0.5 else "pseudo-host sources: refused, no entities invented"}
    bad_unit = d["unit"].map(lambda u: not rep.units[str(u)]["usable"]).to_numpy()
    rep.n_rows_dropped_pseudo = int((pseudo | bad_unit).sum())
    d = d[~(pseudo | bad_unit)]
    if d.empty:
        rep.usable = False
        rep.reason = "all detector rows are pseudo-hosts (no real source IPs): cannot track entities"
        return _runs_to_events(d.assign(dst_ip="UNKNOWN"), view, merge_gap_s, min_duration_s, min_windows,
                               "detector", unit_scoped, rep), rep
    t_min, t_max = float(d["t"].min()), float(d["t_end"].max())
    unknown = ~d["stage"].isin(STAGES + [BENIGN])
    rep.n_rows_dropped_unknown_stage = int(unknown.sum())
    d = d[~unknown]
    rep.n_rows_benign = int((d["stage"] == BENIGN).sum())
    d = d[d["stage"] != BENIGN]
    low = d["confidence"] < min_confidence
    rep.n_rows_dropped_low_confidence = int(low.sum())
    d = d[~low]
    d["row_id"] = np.arange(len(d))
    # explode destinations
    if "dst_ips" in d.columns:
        dl = d["dst_ips"].map(lambda x: [] if x is None or (isinstance(x, float) and np.isnan(x))
                              else (x if isinstance(x, (list, tuple, set)) else [p for p in str(x).split(";") if p]))
        d = d.assign(dst_ip=dl.map(lambda l: list(l) or ["UNKNOWN"])).explode("dst_ip")
    elif "dst_ip" not in d.columns:
        d = d.assign(dst_ip="UNKNOWN")
    d["dst_ip"] = d["dst_ip"].astype(str)
    no_dst = (d["dst_ip"] == "UNKNOWN").to_numpy()
    if view in ("victim", "pair"):
        rep.n_rows_dropped_no_dst = int(no_dst.sum())
        d = d[~no_dst]
        if no_dst.any():
            rep.notes.append("rows without destination dropped for this view")
    elif view == "host":
        drop = no_dst & d["stage"].isin(DST_ATTRIBUTED).to_numpy()
        rep.n_rows_dropped_no_dst = int(drop.sum())
        d = d[~drop]
    d["label"] = d["stage"]
    if "confidence" in d.columns and len(d):
        pass
    ev = _runs_to_events(d, view, merge_gap_s, min_duration_s, min_windows, "detector", unit_scoped, rep)
    _finish_report(rep, ev, t_min, t_max)
    return ev, rep


# ---------------------------------------------------------------------------------------------
# chains
# ---------------------------------------------------------------------------------------------

@dataclass
class Chain:
    """Time-ordered events of ONE entity with no silence longer than max_chain_gap_s between consecutive
    events.  `terminated` is True when the chain provably ended (nothing followed within max_chain_gap_s and the
    data kept going at least that long); False = right-censored (the data ended while it could still continue)."""
    chain_id: str
    view: str
    entity: str
    events: list[dict[str, Any]]
    terminated: bool
    day: str = ""

    @property
    def stages(self) -> list[str]:
        return [e["stage"] for e in self.events]


def _merge_events(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    out = dict(a)
    out["end_s"] = max(a["end_s"], b["end_s"])
    out["duration_s"] = out["end_s"] - a["start_s"]
    tot = a["n_flows"] + b["n_flows"]
    out["confidence"] = (a["confidence"] * a["n_flows"] + b["confidence"] * b["n_flows"]) / max(tot, 1)
    out["n_flows"] = tot
    for k in ("srcs", "dsts", "labels"):
        m = dict(a[k])
        for kk, v in b[k].items():
            m[kk] = m.get(kk, 0) + v
        out[k] = _topn(m)
    out["n_src"] = max(a["n_src"], b["n_src"])
    out["n_dst"] = max(a["n_dst"], b["n_dst"])
    out["collapsed"] = a.get("collapsed", 1) + b.get("collapsed", 1)
    return out


def link_chains(events: pd.DataFrame, max_chain_gap_s: float = DEFAULT_MAX_CHAIN_GAP_S,
                observed_until: float | None = None, collapse_same_stage: bool = True) -> list[Chain]:
    """Group events per entity into chains.  Events are ordered by START (concurrent events of different
    stages stay visible as overlaps; the transition is start-to-start).  With `collapse_same_stage`, adjacent
    events of the same stage in a chain are merged into one (the stage persisted; it is not a transition)."""
    if events.empty:
        return []
    if observed_until is None:
        observed_until = float(events["end_s"].max())
    chains: list[Chain] = []
    for (view, ent), grp in events.groupby(["view", "entity"], sort=False):
        evs = [dict(r) for r in grp.sort_values(["start_s", "end_s"], kind="mergesort").to_dict("records")]
        cur: list[dict[str, Any]] = []
        cur_end = -np.inf
        groups: list[list[dict[str, Any]]] = []
        for e in evs:
            if cur and e["start_s"] - cur_end > max_chain_gap_s:
                groups.append(cur)
                cur = []
                cur_end = -np.inf
            cur.append(e)
            cur_end = max(cur_end, e["end_s"])
        if cur:
            groups.append(cur)
        for k, g in enumerate(groups):
            if collapse_same_stage:
                merged: list[dict[str, Any]] = []
                for e in g:
                    if merged and merged[-1]["stage"] == e["stage"]:
                        merged[-1] = _merge_events(merged[-1], e)
                    else:
                        merged.append(e)
                g = merged
            last_end = max(e["end_s"] for e in g)
            terminated = (observed_until - last_end) > max_chain_gap_s
            day = pd.Timestamp(g[0]["start_s"], unit="s").strftime("%Y-%m-%d")
            chains.append(Chain(f"{ent}#{k}", view, ent, g, bool(terminated), day))
    return chains


# ---------------------------------------------------------------------------------------------
# persistence
# ---------------------------------------------------------------------------------------------

_JSON_COLS = ("srcs", "dsts", "labels")


def save_events(events: pd.DataFrame, path: str | Path) -> None:
    out = events.copy()
    for c in _JSON_COLS:
        out[c] = out[c].map(lambda d: json.dumps(d, sort_keys=True))
    out["start"] = pd.to_datetime(out["start_s"], unit="s").dt.strftime("%Y-%m-%d %H:%M:%S")
    out["end"] = pd.to_datetime(out["end_s"], unit="s").dt.strftime("%Y-%m-%d %H:%M:%S")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(path, index=False)


def load_events(path: str | Path) -> pd.DataFrame:
    df = pd.read_csv(path, keep_default_na=False)
    for c in _JSON_COLS:
        df[c] = df[c].map(json.loads)
    return df.drop(columns=[c for c in ("start", "end") if c in df.columns])


# ---------------------------------------------------------------------------------------------
# evaluation-only relabels (clearly NOT a change to pipeline/mitre_mapping.py)
# ---------------------------------------------------------------------------------------------

def ctu13_icmp_flood_as_impact(df: pd.DataFrame) -> pd.Series:
    """EVALUATION RELABEL (CTU-13 scenarios 4, 10, 11 only): botnet ICMP flows = the ICMP DDoS = 'impact';
    every other flow keeps pipeline.mitre_mapping.label_to_stage.  Not applied to any training data."""
    lab = df["label"].astype(str)
    stage = pd.Series(lab.map({l: label_to_stage(l) for l in lab.unique()}), index=df.index)
    stage[lab.str.strip().str.upper().isin({"BENIGN", "NORMAL"})] = BENIGN
    icmp = pd.to_numeric(df.get("protocol", pd.Series(0, index=df.index)), errors="coerce").fillna(0).eq(1)
    scen = df["unit"].astype(str).str.extract(r"(\d+)")[0].astype(float) if "unit" in df.columns else pd.Series(np.nan, index=df.index)
    flood_scn = scen.isin([4, 10, 11])
    botnet = lab.str.lower().str.contains("from-botnet")
    stage[icmp & botnet & flood_scn] = IMPACT
    return stage


RELABELS: dict[str, Callable[[pd.DataFrame], pd.Series]] = {"ctu13-icmp-impact": ctu13_icmp_flood_as_impact}


# ---------------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------------

def _load_flows(path: Path, adapter_name: str | None, sidecar: str | None, default_label: str | None,
                max_rows: int | None) -> pd.DataFrame:
    from pipeline.adapters.registry import detect_dataset, get_adapter
    name = adapter_name or detect_dataset(path).adapter
    if not name:
        raise SystemExit(f"cannot detect an adapter for {path}; pass --adapter")
    ad = get_adapter(name)
    if sidecar:
        ad.with_sidecar(sidecar, default_label)
    files, _ = ad.discover_files(path)
    if not files:
        raise SystemExit(f"adapter '{name}' found no files under {path}")
    frames = []
    for unit, fl in ad.units(files).items():
        df = ad.read_flows(fl, max_rows=max_rows)
        df = df[[c for c in ("timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "label", "has_ip_data") if c in df.columns]].copy()
        df["unit"] = unit
        frames.append(df)
        print(f"  read unit {unit}: {len(df)} flows", file=sys.stderr)
    return pd.concat(frames, ignore_index=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--input", help="dataset file/folder read through the adapter registry (labels or --labels-sidecar)")
    src.add_argument("--detections", help="CSV of detector output: host,window_start,stage,confidence[,window_s,dst_ips]")
    ap.add_argument("--adapter", default=None, help="adapter name (default: auto-detect)")
    ap.add_argument("--labels-sidecar", default=None, help="labels sidecar CSV (pipeline/adapters/sidecar.py)")
    ap.add_argument("--default-label", default=None)
    ap.add_argument("--relabel", default=None, choices=sorted(RELABELS), help="evaluation-only stage relabel")
    ap.add_argument("--views", default="attacker,victim,pair,host", help="comma list of " + "|".join(VIEWS))
    ap.add_argument("--merge-gap", type=float, default=DEFAULT_MERGE_GAP_S, help="seconds of silence that split a run")
    ap.add_argument("--min-duration", type=float, default=0.0, help="drop events shorter than this (s)")
    ap.add_argument("--min-flows", type=int, default=1, help="drop events with fewer flows (windows for detections)")
    ap.add_argument("--min-confidence", type=float, default=0.0, help="detections only")
    ap.add_argument("--window-seconds", type=float, default=10.0, help="detections without a window_s column")
    ap.add_argument("--unit-scoped", action="store_true", help="prefix entities with their unit (e.g. CTU-13 scenario)")
    ap.add_argument("--max-rows", type=int, default=None, help="cap raw rows per file (smoke tests)")
    ap.add_argument("--name", required=True, help="output goes to data/processed_adapter/stage_events_<name>")
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--show", type=int, default=30, help="print the first N events of each view")
    a = ap.parse_args(argv)

    out_dir = Path(a.out_dir) if a.out_dir else Path(__file__).resolve().parents[1] / "data" / "processed_adapter" / f"stage_events_{a.name}"
    out_dir.mkdir(parents=True, exist_ok=True)
    views = [v.strip() for v in a.views.split(",") if v.strip()]
    if a.input:
        flows = _load_flows(Path(a.input), a.adapter, a.labels_sidecar, a.default_label, a.max_rows)
    else:
        det = pd.read_csv(a.detections)
    reports: dict[str, Any] = {}
    rc = 0
    for v in views:
        if a.input:
            ev, rep = events_from_flows(flows, v, a.merge_gap, a.min_duration, a.min_flows, unit_scoped=a.unit_scoped,
                                        stage_fn=RELABELS.get(a.relabel) if a.relabel else None)
        else:
            ev, rep = events_from_detections(det, v, a.window_seconds, a.merge_gap, a.min_duration, a.min_flows,
                                             a.min_confidence, a.unit_scoped)
        reports[v] = rep.as_dict()
        if not rep.usable:
            print(f"[{v}] UNUSABLE FOR ENTITY TRACKING: {rep.reason}")
            rc = 2
            continue
        save_events(ev, out_dir / f"events_{v}.csv")
        print(f"[{v}] {rep.n_events} events, {rep.n_entities} entities, by stage {rep.events_by_stage}"
              f" (runs dropped by filters: {rep.n_runs_dropped_filter})")
        if a.show:
            show = ev.head(a.show)[["event_id", "entity", "stage", "start_s", "end_s", "n_flows", "n_dst"]].copy()
            show["start_s"] = pd.to_datetime(show["start_s"], unit="s").dt.strftime("%m-%d %H:%M:%S")
            show["end_s"] = pd.to_datetime(show["end_s"], unit="s").dt.strftime("%m-%d %H:%M:%S")
            print(show.to_string(index=False))
    (out_dir / "report.json").write_text(json.dumps({"args": vars(a), "views": reports}, indent=1, default=str), encoding="utf-8")
    print(f"wrote {out_dir}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
