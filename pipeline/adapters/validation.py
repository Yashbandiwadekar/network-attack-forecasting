"""Dataset validation: stream a dataset through its adapter and decide PASS / WARN / FAIL.

Two kinds of numbers, always labelled in the report:
  * "full pass"  -- every row, label (+ thinned timestamp) column only, streamed in chunks;
  * "sampled N rows" -- a contiguous prefix of each file (random rows would make windows meaningless)
    run through the adapter, then the real windowing/graph/embedding code for the 41-feature check.

Thresholds are module constants (T_*) so tests can pin each branch.
"""
from __future__ import annotations

import json
import os
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from pipeline.adapters.base import (
    APPROX, DERIVED, FLAG_COLUMNS, NATIVE, ZERO, CANONICAL_COLUMNS, REQUIRED_COLUMNS, DatasetAdapter,
    ReadStats, check_canonical_frame, detect_dataset,
)
from pipeline.adapters.registry import get_adapter  # noqa: F401  (registers adapters)

# ---- thresholds -----------------------------------------------------------------------------
T_FALLTHROUGH_FAIL_FRAC = 0.01      # >= this share of rows on unmapped labels -> FAIL (any > 0 -> WARN)
T_DROP_WARN_FRAC = 0.01             # adapter cleaning drops >= this share of sampled rows -> WARN
T_DROP_FAIL_FRAC = 0.50             # ... >= this share -> FAIL (adapter/format mismatch)
T_NEGATIVE_WARN_FRAC = 0.001
T_NEGATIVE_FAIL_FRAC = 0.05
T_FLAGS_GT_PKTS_WARN_FRAC = 0.01
IAT_OK_RANGE = (0.2, 5.0)           # median iat_us*(pkts-1)/(dur_us) should be ~1
RATIO_TOL = 1e-9
MIN_PLAUSIBLE_YEAR, MAX_PLAUSIBLE_YEAR = 2000, 2031
ALL_RATIO_FEATURES = ["syn_ratio", "ack_ratio", "fin_ratio", "rst_ratio", "psh_ratio", "urg_ratio",
                      "bidir_ratio", "tcp_ratio", "udp_ratio", "has_ip_data", "has_packet_features"]

LEVEL_RANK = {"INFO": 0, "WARN": 1, "FAIL": 2}


class _Findings:
    def __init__(self) -> None:
        self.items: list[dict[str, str]] = []

    def add(self, level: str, code: str, msg: str) -> None:
        self.items.append({"level": level, "code": code, "message": msg})

    def verdict(self) -> str:
        worst = max((LEVEL_RANK[i["level"]] for i in self.items), default=0)
        return {0: "PASS", 1: "WARN", 2: "FAIL"}[worst]


def _log(msg: str) -> None:
    print(msg, file=__import__("sys").stderr, flush=True)


# ---- full pass: labels + thinned timestamps -----------------------------------------------------
def scan_labels(adapter: DatasetAdapter, files: list[Path], progress: bool = True,
                max_rows: int | None = None) -> dict[str, Any]:
    counts: Counter = Counter()
    per_file: dict[str, dict[str, Any]] = {}
    tmin = tmax = None
    days: set[str] = set()
    for f in files:
        t0 = time.time()
        n = 0
        fmin = fmax = None
        for chunk in adapter.iter_label_chunks(f, max_rows=max_rows):
            n += len(chunk)
            counts.update(chunk["label"].value_counts().to_dict())
            ts = chunk["timestamp"].dropna()
            if len(ts):
                fmin = ts.min() if fmin is None else min(fmin, ts.min())
                fmax = ts.max() if fmax is None else max(fmax, ts.max())
                days.update(ts.dt.strftime("%Y-%m-%d").unique().tolist())
        per_file[f.name] = {"rows": n, "time_min": str(fmin) if fmin is not None else None,
                            "time_max": str(fmax) if fmax is not None else None, "size_bytes": f.stat().st_size}
        if fmin is not None:
            tmin = fmin if tmin is None else min(tmin, fmin)
            tmax = fmax if tmax is None else max(tmax, fmax)
        if progress:
            _log(f"  label scan {f.name}: {n:,} rows in {time.time() - t0:.1f}s")
    return {"counts": dict(counts), "per_file": per_file,
            "time_min": str(tmin) if tmin is not None else None,
            "time_max": str(tmax) if tmax is not None else None, "days": sorted(days),
            "rows": int(sum(counts.values()))}


def label_table(adapter: DatasetAdapter, counts: dict[str, int], F: _Findings) -> dict[str, Any]:
    total = sum(counts.values())
    rows, stage_counts = [], Counter()
    fall_rows = ignorable_rows = 0
    fall_labels = []
    for lab, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        stage, status = adapter.label_status(lab)
        rows.append({"label": lab, "count": int(n), "fraction": n / total if total else 0.0,
                     "stage": stage, "status": status})
        if status == "ignorable":
            ignorable_rows += n
            continue
        stage_counts[stage] += n
        if status == "unknown_fallthrough":
            fall_rows += n
            fall_labels.append(lab)
    real_total = total - ignorable_rows
    frac = fall_rows / real_total if real_total else 0.0
    if fall_labels:
        lvl = "FAIL" if frac >= T_FALLTHROUGH_FAIL_FRAC else "WARN"
        F.add(lvl, "label_fallthrough",
              f"{len(fall_labels)} label(s) hit the unknown fall-through (silently IMPACT, i.e. a positive): "
              f"{fall_labels[:8]} = {fall_rows:,} rows ({frac:.2%}). Add explicit entries to mitre_mapping.")
    if ignorable_rows:
        F.add("INFO", "label_ignorable", f"{ignorable_rows:,} rows are not data (e.g. repeated CSV header rows); "
              "removed by the adapter's numeric coercion")
    return {"rows": rows, "stage_counts": {k: int(v) for k, v in stage_counts.items()},
            "fallthrough_labels": fall_labels, "fallthrough_rows": int(fall_rows),
            "fallthrough_fraction": frac, "ignorable_rows": int(ignorable_rows)}


# ---- flow-level checks ------------------------------------------------------------------------
def flow_checks(adapter: DatasetAdapter, df: pd.DataFrame, F: _Findings) -> dict[str, Any]:
    out: dict[str, Any] = {"rows": int(len(df))}
    problems = check_canonical_frame(df)
    for p in problems:
        F.add("FAIL", "contract", p)
    if any(p.startswith("missing canonical") for p in problems) or df.empty:
        return out
    num_cols = [c for c in REQUIRED_COLUMNS if CANONICAL_COLUMNS[c][0] == "float"]
    arr = df[num_cols].to_numpy(dtype="float64")
    nonfinite = ~np.isfinite(arr)
    # dst_port/src_port NaN is allowed by contract; everything else must be finite
    allowed = [num_cols.index(c) for c in ("dst_port", "src_port") if c in num_cols]
    strict = np.delete(nonfinite, allowed, axis=1) if allowed else nonfinite
    out["nonfinite_fraction_strict"] = float(strict.mean()) if strict.size else 0.0
    out["dst_port_nan_fraction"] = float(df["dst_port"].isna().mean())
    if strict.any():
        bad = [c for j, c in enumerate([c for i, c in enumerate(num_cols) if i not in allowed]) if strict[:, j].any()]
        F.add("FAIL", "nonfinite", f"NaN/inf in canonical columns {bad}")
    if out["dst_port_nan_fraction"] > 0.001:
        F.add("WARN", "dst_port_nan", f"dst_port NaN in {out['dst_port_nan_fraction']:.2%} of flows (ignored by nunique)")

    # units ---------------------------------------------------------------------------------
    dur = df["duration_s"]
    neg_frac = float(((dur < 0) | (df["total_pkts"] < 0) | (df["total_bytes"] < 0)).mean())
    out["negative_fraction"] = neg_frac
    if neg_frac >= T_NEGATIVE_FAIL_FRAC:
        F.add("FAIL", "negative_values", f"{neg_frac:.2%} of flows have negative duration/packets/bytes")
    elif neg_frac >= T_NEGATIVE_WARN_FRAC:
        F.add("WARN", "negative_values", f"{neg_frac:.2%} of flows have negative duration/packets/bytes")
    p50, p99 = float(dur.quantile(0.5)), float(dur.quantile(0.99))
    out["duration_s"] = {"p50": p50, "p99": p99, "max": float(dur.max())}
    if p99 > adapter.max_plausible_duration_s:
        F.add("FAIL", "duration_units",
              f"duration_s p99={p99:.3g}s exceeds the plausible {adapter.max_plausible_duration_s:g}s -- "
              "microseconds/milliseconds not converted to seconds?")
    bpp = (df["total_bytes"] / df["total_pkts"].replace(0, np.nan)).dropna()
    out["bytes_per_packet_median"] = float(bpp.median()) if len(bpp) else None
    if len(bpp):
        if bpp.median() > 65535:
            F.add("FAIL", "bytes_vs_packets", f"median bytes/packet = {bpp.median():.3g} (> 65535): bytes and packets swapped or rates used")
        elif adapter.bytes_include_headers and bpp.median() < 20:
            F.add("FAIL", "bytes_vs_packets", f"median bytes/packet = {bpp.median():.3g} (< 20 incl. headers): columns swapped?")
    gt = float((df[FLAG_COLUMNS].max(axis=1) > df["total_pkts"]).mean())
    out["flag_gt_packets_fraction"] = gt
    if gt >= T_FLAGS_GT_PKTS_WARN_FRAC:
        F.add("WARN", "flag_counts", f"{gt:.2%} of flows have a TCP flag count larger than total packets")
    ratio_like = [c for c in FLAG_COLUMNS if len(df) and ((df[c] > 0) & (df[c] < 1)).any()]
    if ratio_like:
        F.add("FAIL", "flags_are_ratios", f"{ratio_like} contain values strictly between 0 and 1: ratios, not counts")

    # IAT physical invariant ----------------------------------------------------------------
    iat_status = adapter.coverage_of("iat_mean")[0]
    out["iat"] = {"status": iat_status}
    if iat_status != ZERO:
        m = (df["total_pkts"] >= 2) & (df["duration_s"] > 0) & (df["iat_mean"] > 0)
        if m.sum() >= 20:
            r = df.loc[m, "iat_mean"] * (df.loc[m, "total_pkts"] - 1) / (df.loc[m, "duration_s"] * 1e6)
            med = float(r.median())
            out["iat"].update({"median_ratio_vs_duration": med, "n": int(m.sum()),
                               "iat_mean_p50_us": float(df.loc[m, "iat_mean"].median())})
            lo, hi = IAT_OK_RANGE
            if lo <= med <= hi:
                pass
            elif 5e-4 <= med <= 5e-3:
                F.add("FAIL", "iat_units", f"IAT looks like MILLISECONDS (iat*(pkts-1)/duration = {med:.2e}, expected ~1)")
            elif 5e-7 <= med <= 5e-6:
                F.add("FAIL", "iat_units", f"IAT looks like SECONDS (ratio {med:.2e}, expected ~1)")
            elif 200 <= med <= 5e3:
                F.add("FAIL", "iat_units", f"IAT is ~{med:.0f}x too large vs duration (IAT in ns, or duration in ms?)")
            else:
                F.add("WARN", "iat_units", f"IAT inconsistent with duration/packets (ratio {med:.3g}, expected ~1)")
        else:
            out["iat"]["note"] = "fewer than 20 multi-packet flows with IAT; unit check skipped"
            F.add("WARN", "iat_units", "IAT unit check skipped: too few multi-packet flows with non-zero IAT")

    # time / hosts ----------------------------------------------------------------------------
    ts = df["timestamp"]
    out["time"] = {"min": str(ts.min()), "max": str(ts.max())}
    if ts.min().year < MIN_PLAUSIBLE_YEAR or ts.max().year > MAX_PLAUSIBLE_YEAR:
        F.add("WARN", "timestamp_range", f"timestamps span {ts.min()} .. {ts.max()} (epoch/units problem?)")
    ip_frac = float(df["has_ip_data"].mean())
    out["hosts"] = {"has_ip_fraction": ip_frac, "unique_src_ip": int(df["src_ip"].nunique()),
                    "unique_dst_ip": int(df["dst_ip"].nunique()),
                    "pseudo_hosts": int(df.loc[df["has_ip_data"] == 0, "src_ip"].nunique())}
    if ip_frac < 1.0:
        F.add("WARN", "no_ip_data", f"{1 - ip_frac:.0%} of sampled flows have no real IPs: pseudo-host "
              "'NETWORK-<date>' windows (graph + unique_dst_ips features are zero there; use a day-disjoint split)")
    return out


# ---- window / 41-feature check ----------------------------------------------------------------
def window_checks(adapter: DatasetAdapter, flows: pd.DataFrame, config: dict[str, Any], F: _Findings,
                  embeddings: bool = True) -> dict[str, Any]:
    from common.config import feature_columns
    from pipeline.graph_builder import build_window_graphs
    from pipeline.graph_embedding_features import build_graph_embedding_window_features
    from pipeline.graph_features import build_graph_window_features
    from pipeline.windowing import (
        build_flow_windows, merge_graph_embedding_features, merge_graph_features, merge_packet_features,
    )

    feats = feature_columns(config)
    n_expected = len(feats)
    windows = build_flow_windows(flows, config)
    windows = merge_graph_features(windows, build_graph_window_features(flows, config), config)
    if embeddings:
        graphs = build_window_graphs(flows, config)
        emb = build_graph_embedding_window_features(flows, config, graphs=graphs)
        windows = merge_graph_embedding_features(windows, emb, config)
    else:
        for c in config["features"].get("graph_embedding", []):
            windows[c] = 0.0
    windows = merge_packet_features(windows, None, config)

    ip_frac = float(flows["has_ip_data"].mean()) if len(flows) else 0.0
    expected = adapter.expected_feature_status(ip_frac)
    missing = [f for f in feats if f not in windows.columns]
    if missing:
        F.add("FAIL", "schema_missing", f"features missing from the built windows: {missing}")
    rows = []
    groups = {"flow": config["features"]["flow_level"], "graph": config["features"].get("graph_level", []),
              "graph_embedding": config["features"].get("graph_embedding", []),
              "packet": config["features"]["packet_level"]}
    group_of = {f: g for g, fs in groups.items() for f in fs}
    unexpected_const, nonfinite_feats, ratio_viol, mismatch_nonzero = [], [], [], []
    for f in feats:
        if f not in windows.columns:
            rows.append({"name": f, "group": group_of.get(f), "present": False})
            continue
        v = windows[f].to_numpy(dtype="float64")
        fin = np.isfinite(v)
        vv = v[fin]
        st, why = expected.get(f, (NATIVE, ""))
        row = {"name": f, "group": group_of.get(f), "present": True, "expected_status": st, "reason": why,
               "min": float(vv.min()) if len(vv) else None, "max": float(vv.max()) if len(vv) else None,
               "mean": float(vv.mean()) if len(vv) else None,
               "zero_fraction": float((vv == 0).mean()) if len(vv) else None,
               "nonfinite_fraction": float((~fin).mean()), "constant_zero": bool(len(vv) and np.all(vv == 0))}
        rows.append(row)
        if (~fin).any():
            nonfinite_feats.append(f)
        if f in ALL_RATIO_FEATURES and len(vv) and (vv.min() < -RATIO_TOL or vv.max() > 1 + RATIO_TOL):
            ratio_viol.append(f"{f}[{vv.min():.3g},{vv.max():.3g}]")
        if row["constant_zero"] and st in (NATIVE, DERIVED, APPROX):
            unexpected_const.append(f)
        if st == ZERO and len(vv) and np.any(vv != 0) and group_of.get(f) != "packet":
            mismatch_nonzero.append(f)
    if nonfinite_feats:
        F.add("FAIL", "feature_nonfinite", f"NaN/inf in window features {nonfinite_feats}")
    if ratio_viol:
        F.add("FAIL", "ratio_range", f"ratio features outside [0,1]: {ratio_viol}")
    if unexpected_const:
        F.add("WARN", "unexpected_constant_zero",
              f"{unexpected_const} are constant zero in the sample although the adapter claims they carry data")
    if mismatch_nonzero:
        F.add("WARN", "zero_claim_violated", f"{mismatch_nonzero} are documented zero-filled but have non-zero values")

    zero_filled = [f for f in feats if expected.get(f, (NATIVE,))[0] == ZERO]
    approx = [f for f in feats if expected.get(f, (NATIVE,))[0] in (APPROX, DERIVED)]
    non_packet_zero = [f for f in zero_filled if group_of.get(f) != "packet"]
    non_embed_approx = [f for f in approx if group_of.get(f) != "graph_embedding"]
    if non_packet_zero:
        F.add("WARN", "zero_filled_features",
              f"{len(non_packet_zero)} non-packet feature(s) are zero-filled by this dataset: {non_packet_zero}")
    if non_embed_approx:
        F.add("WARN", "approximated_features",
              f"{len(non_embed_approx)} feature(s) are approximated/derived rather than native: {non_embed_approx}")
    F.add("INFO", "packet_zero_fill", "packet-level features (9/41) are zero-filled: flow-only dataset, no PCAP")
    F.add("INFO", "embedding_caveat", "graph_embed_* (8/41) come from a frozen random-init GraphSAGE, not a trained encoder")

    # how many sequences would these windows give (sample only)
    L = int(config["windowing"]["sequence_length"])
    K = int(config["windowing"]["forecast_horizon"])
    gcols = ["scenario_id", "src_ip"] if "scenario_id" in windows.columns else ["src_ip"]
    n_seq = int(windows.groupby(gcols, observed=True).size().sub(L + K - 1).clip(lower=0).sum())
    if n_seq == 0:
        F.add("WARN", "no_sequences_in_sample", f"the sample yields 0 sequences (needs >= {L + K} windows per host); "
              "increase --sample-rows")
    stage_counts = windows["stage"].value_counts().to_dict()
    return {"n_features_expected": n_expected, "n_features_found": n_expected - len(missing),
            "missing_features": missing, "zero_filled": zero_filled, "approximated": approx,
            "n_windows": int(len(windows)), "n_sequences_in_sample": n_seq,
            "window_stage_counts": {k: int(v) for k, v in stage_counts.items()},
            "ip_fraction": ip_frac, "features": rows, "embeddings_evaluated": embeddings}


# ---- orchestration ------------------------------------------------------------------------------
def validate_dataset(path: str | Path, adapter_name: str | None = None, **kw) -> dict[str, Any]:
    """Never raises: an adapter/IO exception becomes a FAIL finding (`adapter_error`)."""
    try:
        return _validate_dataset(path, adapter_name, **kw)
    except Exception as e:  # noqa: BLE001
        import traceback
        det = detect_dataset(path)
        return {"tool": "scripts.validate_dataset", "path": str(path), "detection": det.as_dict(),
                "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "findings": [{"level": "FAIL", "code": "adapter_error",
                              "message": f"{type(e).__name__}: {e}"}],
                "traceback": traceback.format_exc(), "verdict": "FAIL"}


def _validate_dataset(path, adapter_name=None, *, sample_rows: int = 300_000,
                     min_rows_per_file: int = 20_000, max_sample_files: int = 16,
                     label_scan: str = "full", config_path: str = "configs/default.yaml",
                     embeddings: bool = True, progress: bool = True) -> dict[str, Any]:
    from common.config import load_config
    F = _Findings()
    path = Path(path)
    report: dict[str, Any] = {"tool": "scripts.validate_dataset", "contract_version": "1.0",
                              "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                              "path": str(path), "config": config_path}
    det = detect_dataset(path)
    report["detection"] = det.as_dict()
    name = adapter_name or det.adapter
    if name is None:
        F.add("FAIL", "no_adapter", f"no adapter recognised {path}: {det.evidence}")
        report.update(findings=F.items, verdict=F.verdict())
        return report
    adapter = get_adapter(name)
    report["adapter"] = adapter.info()
    if adapter_name and det.adapter and adapter_name != det.adapter:
        F.add("WARN", "adapter_override", f"--adapter {adapter_name} overrides auto-detection ({det.adapter})")
    if det.mixed and not adapter_name:
        F.add("WARN", "mixed_folder", "folder contains files of different formats; see detection.per_file")
    if adapter.status in ("stub", "unsupported"):
        F.add("FAIL", f"adapter_{adapter.status}", f"adapter '{name}' is {adapter.status}: {adapter.howto}")
        report.update(findings=F.items, verdict=F.verdict())
        return report
    if adapter.status == "experimental":
        F.add("WARN", "adapter_experimental", f"adapter '{name}' v{adapter.version} is experimental: see its caveats")
    if adapter.synthetic:
        F.add("WARN", "synthetic_data", "dataset is SYNTHETIC/fabricated: not valid as real-data evidence")

    files, skipped = adapter.discover_files(path)
    report["files"] = [str(f) for f in files]
    report["skipped_files"] = [{"file": str(f), "reason": r} for f, r in skipped]
    for f, r in skipped:
        lvl = "WARN" if "synthetic" in r else "INFO"
        F.add(lvl, "file_skipped", f"{f.name}: {r}")
    if not files:
        F.add("FAIL", "no_files", f"adapter '{name}' found no readable files under {path}")
        report.update(findings=F.items, verdict=F.verdict())
        return report

    # full pass -------------------------------------------------------------------------------
    if label_scan == "full":
        if progress:
            _log(f"[{name}] full label pass over {len(files)} file(s) ...")
        scan = scan_labels(adapter, files, progress)
        report["label_scan"] = {"mode": "full pass", **{k: v for k, v in scan.items() if k != "counts"}}
        report["labels"] = {"mode": "full pass", **label_table(adapter, scan["counts"], F)}
        report["rows_full_pass"] = scan["rows"]
        if scan["days"]:
            report["days"] = scan["days"]
    else:
        report["label_scan"] = {"mode": "skipped"}

    # sample -----------------------------------------------------------------------------------
    sample_files = files if len(files) <= max_sample_files else [files[i] for i in
                                                                 np.linspace(0, len(files) - 1, max_sample_files).astype(int)]
    per = max(min_rows_per_file, sample_rows // max(1, len(sample_files)))
    frames, stats, ordering = [], ReadStats(), []
    for f in sample_files:
        st = ReadStats()
        parts = list(adapter.iter_flows(f, chunksize=max(per, 1), max_rows=per, stats=st))
        if parts:
            d = pd.concat(parts, ignore_index=True)
            ts = d["timestamp"].to_numpy()
            ordering.append(float((ts[1:] < ts[:-1]).mean()) if len(ts) > 1 else 0.0)
            frames.append(d)
        stats.rows_read += st.rows_read
        stats.rows_kept += st.rows_kept
    drop_frac = stats.rows_dropped / stats.rows_read if stats.rows_read else 0.0
    report["sample"] = {"mode": f"sampled {stats.rows_read:,} rows (contiguous prefix of {len(sample_files)} file(s), "
                                f"{per:,} rows each)", "rows_read": stats.rows_read, "rows_kept": stats.rows_kept,
                        "rows_dropped": stats.rows_dropped, "drop_fraction": drop_frac}
    if stats.rows_dropped:
        raw_prefix: Counter = Counter()
        for f in sample_files:
            for ch in adapter.iter_label_chunks(f, max_rows=per):
                raw_prefix.update(ch["label"].value_counts().to_dict())
        kept = Counter(pd.concat(frames, ignore_index=True)["label"].value_counts().to_dict())
        lost = {k: int(raw_prefix[k] - kept.get(k, 0)) for k in raw_prefix if raw_prefix[k] - kept.get(k, 0) > 0
                and adapter.label_status(k)[1] != "ignorable"}
        rep_loss = []
        for k, n in sorted(lost.items(), key=lambda kv: -kv[1]):
            stage = adapter.label_status(k)[0]
            rep_loss.append({"label": k, "stage": stage, "raw_rows": int(raw_prefix[k]), "dropped": n,
                             "dropped_fraction": n / raw_prefix[k]})
        report["sample"]["dropped_by_label"] = rep_loss[:25]
        total_attack = sum(v for k, v in raw_prefix.items() if adapter.label_status(k)[0] not in ("benign",)
                           and adapter.label_status(k)[1] != "ignorable")
        lost_attack = sum(r["dropped"] for r in rep_loss if r["stage"] != "benign")
        if total_attack and lost_attack / total_attack >= 0.01:
            F.add("WARN", "attack_rows_dropped",
                  f"adapter cleaning drops {lost_attack / total_attack:.1%} of the NON-BENIGN rows in the sample "
                  f"({lost_attack:,}/{total_attack:,}); worst: " +
                  ", ".join(f"{r['label']} ({r['dropped_fraction']:.0%})" for r in rep_loss if r['stage'] != 'benign')[:240])
    if drop_frac >= T_DROP_FAIL_FRAC:
        F.add("FAIL", "rows_dropped", f"adapter cleaning dropped {drop_frac:.1%} of sampled rows")
    elif drop_frac >= T_DROP_WARN_FRAC:
        F.add("WARN", "rows_dropped", f"adapter cleaning dropped {drop_frac:.1%} of sampled rows "
              "(unsupported protocols / NaN / inf / zero packets) -- label mix of the survivors may differ")
    if not frames:
        F.add("FAIL", "no_rows", "adapter produced zero rows from the sample")
        report.update(findings=F.items, verdict=F.verdict())
        return report
    flows = pd.concat(frames, ignore_index=True)
    mean_dec = float(np.mean(ordering)) if ordering else 0.0
    report["ordering"] = {"fraction_decreasing_adjacent_timestamps_raw_order": mean_dec,
                          "note": ("raw file order is time-sorted" if mean_dec < 0.001 else
                                   "raw file order is NOT time-sorted; adapter sorts before windowing")}
    if mean_dec >= 0.001:
        F.add("INFO", "unsorted", f"raw rows not time-sorted ({mean_dec:.1%} adjacent decreases); adapter sorts by {adapter.sort_keys}")
    flows = flows.sort_values(adapter.sort_keys).reset_index(drop=True)
    report["flow_checks"] = {"mode": report["sample"]["mode"], **flow_checks(adapter, flows, F)}
    sample_labels = flows["label"].value_counts()
    report["sample_labels"] = {str(k): int(v) for k, v in sample_labels.head(30).items()}
    if flows["label"].map(lambda x: adapter.label_status(x)[0]).nunique() == 1:
        F.add("INFO", "single_stage_sample", "the sampled prefix contains a single stage (attacks may start later in the files)")

    if not any(i["code"] in ("contract", "no_rows") for i in F.items if i["level"] == "FAIL"):
        config = load_config(config_path)
        report["window_checks"] = {"mode": report["sample"]["mode"], **window_checks(adapter, flows, config, F, embeddings)}
    report["findings"] = F.items
    report["verdict"] = F.verdict()
    return report


# ---- rendering ---------------------------------------------------------------------------------
def render_markdown(r: dict[str, Any]) -> str:
    L: list[str] = []
    a = r.get("adapter", {})
    L.append(f"# Dataset validation: `{r['path']}`")
    L.append("")
    L.append(f"**Verdict: {r['verdict']}**  |  adapter `{a.get('name')}` v{a.get('version')} ({a.get('status')})  |  {r['generated_at']}")
    det = r.get("detection", {})
    L.append(f"\nDetection: `{det.get('adapter')}` (confidence {det.get('confidence')}); {', '.join(det.get('evidence', []))}")
    L.append("\n## Findings")
    for lvl in ("FAIL", "WARN", "INFO"):
        for i in r["findings"]:
            if i["level"] == lvl:
                L.append(f"- **{lvl}** `{i['code']}`: {i['message']}")
    if "labels" in r:
        lt = r["labels"]
        L.append(f"\n## Labels ({lt['mode']}, {r.get('rows_full_pass', 0):,} rows)")
        L.append("\n| label | rows | share | stage | status |\n|---|---:|---:|---|---|")
        for row in lt["rows"][:40]:
            L.append(f"| {row['label']} | {row['count']:,} | {row['fraction']:.3%} | {row['stage']} | {row['status']} |")
        if len(lt["rows"]) > 40:
            L.append(f"| ... {len(lt['rows']) - 40} more | | | | |")
        L.append("\nStage totals: " + ", ".join(f"{k}={v:,}" for k, v in lt["stage_counts"].items()))
    ls = r.get("label_scan", {})
    if ls.get("time_min"):
        L.append(f"\nTime range ({ls['mode']}, thinned 1-in-20): {ls['time_min']} .. {ls['time_max']}; days: {', '.join(r.get('days', []))}")
    if "sample" in r:
        s = r["sample"]
        L.append(f"\n## Adapter output ({s['mode']})")
        L.append(f"rows read {s['rows_read']:,}, kept {s['rows_kept']:,}, dropped {s['rows_dropped']:,} ({s['drop_fraction']:.2%})")
        for d in s.get("dropped_by_label", [])[:8]:
            L.append(f"- dropped {d['dropped']:,}/{d['raw_rows']:,} ({d['dropped_fraction']:.0%}) of `{d['label']}` [{d['stage']}]")
    fc = r.get("flow_checks")
    if fc and "hosts" in fc:
        L.append(f"\nHosts: real-IP share {fc['hosts']['has_ip_fraction']:.0%}, unique src {fc['hosts']['unique_src_ip']:,}, "
                 f"unique dst {fc['hosts']['unique_dst_ip']:,}, pseudo-hosts {fc['hosts']['pseudo_hosts']}")
        L.append(f"Duration p50/p99/max (s): {fc['duration_s']['p50']:.3g} / {fc['duration_s']['p99']:.3g} / {fc['duration_s']['max']:.3g}; "
                 f"median bytes/packet {fc['bytes_per_packet_median']:.3g}; IAT check: {fc['iat']}")
        L.append(f"Sample time range: {fc['time']['min']} .. {fc['time']['max']}; ordering: {r['ordering']['note']}")
    wc = r.get("window_checks")
    if wc:
        L.append(f"\n## 41-feature schema ({wc['mode']}; {wc['n_windows']:,} windows, ~{wc['n_sequences_in_sample']:,} sequences)")
        L.append(f"found {wc['n_features_found']}/{wc['n_features_expected']}; zero-filled by design {len(wc['zero_filled'])}; "
                 f"approximated/derived {len(wc['approximated'])}")
        L.append("\n| feature | group | status | min | max | mean | zero% | note |\n|---|---|---|---:|---:|---:|---:|---|")
        for f in wc["features"]:
            if not f.get("present"):
                L.append(f"| {f['name']} | {f['group']} | MISSING | | | | | |")
                continue
            note = ("CONSTANT ZERO; " if f["constant_zero"] else "") + (f["reason"] or "")
            L.append(f"| {f['name']} | {f['group']} | {f['expected_status']} | {f['min']:.4g} | {f['max']:.4g} | "
                     f"{f['mean']:.4g} | {f['zero_fraction']:.0%} | {note[:90]} |")
    return "\n".join(L) + "\n"


def write_report(report: dict[str, Any], out_dir: str | Path, stem: str) -> tuple[Path, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    jp, mp = out_dir / f"{stem}.json", out_dir / f"{stem}.md"
    jp.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    mp.write_text(render_markdown(report), encoding="utf-8")
    return jp, mp
