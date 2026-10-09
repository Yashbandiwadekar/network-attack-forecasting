"""raw dataset -> adapter -> windowing -> graph/embedding/packet features -> sequences -> train/val/test .npz

The step order is a line-for-line mirror of pipeline/build_dataset.py / build_unsw_dataset.py /
build_ctu13_dataset.py (same windowing/graph/merge/heuristic/sequence functions); only the loader is
swapped for a registered adapter, and units (CIC day files / CTU scenarios) are windowed one at a
time to bound memory. tests/test_adapter_prepare.py asserts array-level equality with build_dataset.

Writes ONLY into a new directory (see check_out_dir); never touches data/processed*, checkpoints*,
configs/ or data/raw.
"""
from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import yaml

from common.config import PROJECT_ROOT, feature_columns, load_config
from pipeline.adapters.base import DatasetAdapter, ReadStats, check_canonical_frame, detect_dataset
from pipeline.adapters.registry import get_adapter
from pipeline.build_dataset import chronological_split, day_disjoint_split, save_splits
from pipeline.graph_builder import build_window_graphs, save_window_graphs
from pipeline.graph_embedding_features import build_graph_embedding_window_features
from pipeline.graph_features import build_graph_window_features
from pipeline.windowing import (
    apply_reconnaissance_heuristic, build_flow_windows, build_sequences, merge_graph_embedding_features,
    merge_graph_features, merge_packet_features,
)

TOOL_VERSION = "1.0.0"
T_FALLTHROUGH_ABORT_FRAC = 0.01


class PrepareError(RuntimeError):
    pass


# ---- output-directory guard -------------------------------------------------------------------
def protected_paths() -> list[Path]:
    root, data = PROJECT_ROOT, PROJECT_ROOT / "data"
    prot = [p for p in data.glob("processed*") if p.name != "processed_adapter"]
    prot += list(root.glob("checkpoints*")) + [root / "configs", data / "raw", data / "threat_intel",
                                                root / "pipeline", root / "models", root / "docs"]
    return [p.resolve() for p in prot]


def check_out_dir(out: str | Path, force: bool = False) -> Path:
    """Refuse an --out that equals / sits inside / contains a protected path (path COMPONENTS, not
    string prefixes: data/processed_adapter/x is fine, data/processed/x and data/processed_real_v2 are not)."""
    out = Path(out).resolve()
    for p in protected_paths():
        if out == p or p in out.parents or out in p.parents:
            raise PrepareError(f"refusing --out {out}: it overlaps protected path {p}. "
                               "Use a NEW directory, e.g. data/processed_adapter/<name>/")
    if out.exists():
        if not out.is_dir():
            raise PrepareError(f"--out {out} exists and is not a directory")
        if any(out.iterdir()):
            marker = out / "metadata.json"
            ours = False
            if marker.exists():
                try:
                    ours = json.loads(marker.read_text(encoding="utf-8")).get("tool") == "scripts.prepare_dataset"
                except Exception:
                    ours = False
            if not (force and ours):
                raise PrepareError(f"--out {out} is not empty. Pass a new directory"
                                   + (" (--force only re-uses directories this tool created)." if force else "."))
    return out


# ---- helpers ------------------------------------------------------------------------------------
def _sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _natural_key(s: str):
    import re
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", s)]


def auto_assign(counts: dict[str, int], train_frac: float, val_frac: float) -> dict[str, list[str]]:
    """Chronological/greedy assignment of whole keys (days or units) to train/val/test by sequence count."""
    keys = list(counts)
    n, total = len(keys), sum(counts.values())
    if n < 3:
        raise PrepareError(f"need >= 3 {'days/units'} with sequences for a disjoint split, found {n}: {keys}. "
                           "Use --split chronological, or pass explicit --train-* lists.")
    out: dict[str, list[str]] = {"train": [], "val": [], "test": []}
    cum = 0
    for i, k in enumerate(keys):
        frac = cum / total if total else 0.0
        if frac < train_frac and i < n - 2:
            out["train"].append(k)
        elif (frac < train_frac + val_frac and i < n - 1) or (i == n - 2 and not out["val"]):
            out["val"].append(k)
        else:
            out["test"].append(k)
        cum += counts[k]
    if not out["val"] or not out["test"]:
        raise PrepareError(f"auto split could not fill val/test from {counts}")
    return out


def _split_by_unit(sequences: dict[str, np.ndarray], unit_tags: np.ndarray, assign: dict[str, list[str]]):
    result = {}
    for name in ("train", "val", "test"):
        idx = np.flatnonzero(np.isin(unit_tags, [str(u) for u in assign[name]]))
        idx = idx[np.argsort(np.asarray(sequences["window_end_time"])[idx], kind="stable")]
        result[name] = {k: np.asarray(v)[idx] for k, v in sequences.items()}
    return result


def _unit_windows(adapter: DatasetAdapter, files: list[Path], config: dict, feature_cols: list[str],
                  max_rows: int | None, embeddings_dir: None = None):
    stats = ReadStats()
    flows = adapter.read_flows(files, max_rows=max_rows, stats=stats)
    problems = check_canonical_frame(flows)
    if problems:
        raise PrepareError(f"adapter '{adapter.name}' output violates the canonical contract: {problems}")
    if flows.empty:
        return None
    label_counts = flows["label"].value_counts().to_dict()
    ip_frac = float(flows["has_ip_data"].mean())
    time_rng = (str(flows["timestamp"].min()), str(flows["timestamp"].max()))

    windows = build_flow_windows(flows, config)
    windows = merge_graph_features(windows, build_graph_window_features(flows, config), config)
    graphs = build_window_graphs(flows, config)
    emb = build_graph_embedding_window_features(flows, config, graphs=graphs)
    windows = merge_graph_embedding_features(windows, emb, config)
    windows = merge_packet_features(windows, None, config)
    windows = apply_reconnaissance_heuristic(windows, config)
    seqs = build_sequences(windows, feature_cols, config)
    info = {"flows": int(len(flows)), "rows_read": stats.rows_read, "rows_dropped": stats.rows_dropped,
            "windows": int(len(windows)), "sequences": int(len(seqs["X"])), "ip_fraction": ip_frac,
            "time_range": list(time_rng),
            "window_stages": {k: int(v) for k, v in windows["stage"].value_counts().items()}}
    return seqs, graphs, label_counts, info


# ---- main ---------------------------------------------------------------------------------------
def prepare_dataset(path: str | Path, out_dir: str | Path, config_path: str | Path, *,
                    adapter_name: str | None = None, split: str | None = None,
                    train_units: list[str] | None = None, val_units: list[str] | None = None,
                    test_units: list[str] | None = None, max_rows_per_file: int | None = None,
                    max_files: int | None = None, only_units: list[str] | None = None, allow_experimental: bool = False,
                    allow_fallthrough: bool = False, force: bool = False,
                    log=print) -> dict[str, Any]:
    out = check_out_dir(out_dir, force)
    path = Path(path)
    config = load_config(config_path)
    feature_cols = feature_columns(config)
    det = detect_dataset(path)
    name = adapter_name or det.adapter
    if name is None:
        raise PrepareError(f"no adapter recognised {path}: {det.evidence}")
    adapter = get_adapter(name)
    if adapter.status in ("stub", "unsupported"):
        raise PrepareError(f"adapter '{name}' is {adapter.status}: {adapter.howto}")
    if adapter.status == "experimental" and not allow_experimental:
        raise PrepareError(f"adapter '{name}' is experimental; pass --allow-experimental after reading its caveats: "
                           f"{adapter.caveats}")
    files, skipped = adapter.discover_files(path)
    if max_files:
        files = files[:max_files]
    if not files:
        raise PrepareError(f"adapter '{name}' found no files under {path}")
    units = adapter.units(files)
    if only_units:
        unknown = [u for u in only_units if u not in units]
        if unknown:
            raise PrepareError(f"--only-units {unknown} not found; available units: {sorted(units, key=_natural_key)}")
        units = {u: units[u] for u in only_units}
    log(f"[prepare] adapter {name} v{adapter.version}; {len(files)} file(s) in {len(units)} unit(s); "
        f"skipped {len(skipped)}: {[s[0].name for s in skipped]}")

    all_seqs: list[dict[str, np.ndarray]] = []
    unit_tags: list[np.ndarray] = []
    graphs_all: dict[Any, Any] = {}
    label_counts: Counter = Counter()
    unit_info: dict[str, Any] = {}
    for uid, ufiles in units.items():
        log(f"[prepare] unit {uid}: {[f.name for f in ufiles]}")
        res = _unit_windows(adapter, ufiles, config, feature_cols, max_rows_per_file)
        if res is None:
            unit_info[uid] = {"flows": 0, "note": "adapter produced no rows"}
            continue
        seqs, graphs, lc, info = res
        label_counts.update(lc)
        unit_info[uid] = info
        graphs_all.update(graphs)
        if info["sequences"] == 0:
            info["note"] = "0 sequences (too few windows per host)"
            continue
        all_seqs.append(seqs)
        unit_tags.append(np.full(info["sequences"], str(uid)))
        log(f"[prepare]   {info['flows']:,} flows -> {info['windows']:,} windows -> {info['sequences']:,} sequences")

    if not all_seqs:
        raise PrepareError("no sequences were created (check sequence_length/forecast_horizon vs data volume)")

    # label -> stage audit (abort on silent fall-through unless explicitly allowed)
    table, fall_rows, total_rows = {}, 0, sum(label_counts.values())
    for lab, n in label_counts.items():
        stage, status = adapter.label_status(lab)
        table[lab] = {"rows": int(n), "stage": stage, "status": status}
        if status == "unknown_fallthrough":
            fall_rows += n
    if fall_rows / max(1, total_rows) >= T_FALLTHROUGH_ABORT_FRAC and not allow_fallthrough:
        bad = [k for k, v in table.items() if v["status"] == "unknown_fallthrough"]
        raise PrepareError(f"{fall_rows:,} rows ({fall_rows / total_rows:.1%}) carry labels with NO explicit stage mapping "
                           f"(silently IMPACT): {bad[:10]}. Add them to pipeline/mitre_mapping.py or pass --allow-fallthrough.")

    keys = all_seqs[0].keys()
    sequences = {k: np.concatenate([s[k] for s in all_seqs], axis=0) for k in keys}
    tags = np.concatenate(unit_tags)
    order = np.argsort(sequences["window_end_time"], kind="stable")
    sequences = {k: v[order] for k, v in sequences.items()}
    tags = tags[order]

    # split -------------------------------------------------------------------------------------
    scfg = dict(config["split"])
    if split:
        mode, source = split, "cli"
    elif scfg.get("mode") == "by_day":
        mode, source = "by_day", "config.split.mode"
    else:
        mode, source = adapter.default_split, f"adapter default ({adapter.name})"
    ws, hz = int(config["windowing"]["window_seconds"]), int(config["windowing"]["forecast_horizon"])
    split_notes: list[str] = []
    assignment: dict[str, Any] = {}
    if mode == "by_day":
        days = pd.to_datetime(sequences["window_end_time"]).strftime("%m-%d")
        if train_units or val_units or test_units:
            assign = {"train": train_units or [], "val": val_units or [], "test": test_units or []}
        elif all(scfg.get(f"{n}_days") for n in ("train", "val", "test")):
            assign = {n: [str(d) for d in scfg[f"{n}_days"]] for n in ("train", "val", "test")}
            split_notes.append("day lists taken from the config's split section")
        else:
            counts = Counter(days.tolist())
            assign = auto_assign(dict(sorted(counts.items())), float(scfg["train_frac"]), float(scfg["val_frac"]))
            split_notes.append("day lists AUTO-assigned greedily in date order by sequence count; "
                               "pass --train-units/--val-units/--test-units (MM-DD) for a curated split")
        splits = day_disjoint_split(sequences, {f"{n}_days": assign[n] for n in assign}, ws, hz)
        assignment = assign
    elif mode == "by_unit":
        if train_units or val_units or test_units:
            assign = {"train": train_units or [], "val": val_units or [], "test": test_units or []}
        elif adapter.default_unit_split and set(sum(adapter.default_unit_split.values(), [])) & set(tags.tolist()):
            present = set(tags.tolist())
            assign = {k: [u for u in v if u in present] for k, v in adapter.default_unit_split.items()}
            if not all(assign.values()):
                counts = Counter(tags.tolist())
                assign = auto_assign({k: counts[k] for k in sorted(counts, key=_natural_key)},
                                     float(scfg["train_frac"]), float(scfg["val_frac"]))
                split_notes.append("adapter default unit lists incomplete for the units present -> AUTO-assigned")
            else:
                split_notes.append("unit lists = adapter default (same scenario-disjoint lists as build_ctu13_dataset)")
        else:
            counts = Counter(tags.tolist())
            assign = auto_assign({k: counts[k] for k in sorted(counts, key=_natural_key)},
                                 float(scfg["train_frac"]), float(scfg["val_frac"]))
            split_notes.append("units AUTO-assigned greedily by sequence count")
        splits = _split_by_unit(sequences, tags, assign)
        assignment = assign
    elif mode == "chronological":
        splits = chronological_split(sequences, scfg)
        pseudo = [u for u, i in unit_info.items() if i.get("ip_fraction", 1.0) < 1.0]
        if pseudo:
            split_notes.append(f"WARNING: chronological per-host split on pseudo-host data ({pseudo}) is the E1 "
                               "snooping split (attack sessions shared between train and test)")
        assignment = {"train_frac": scfg["train_frac"], "val_frac": scfg["val_frac"]}
    else:
        raise PrepareError(f"unknown split mode {mode}")

    sizes = {n: int(len(d["X"])) for n, d in splits.items()}
    positives = {n: (float(d["infiltration"][:, 0].mean()) if len(d["X"]) else None) for n, d in splits.items()}
    warnings = list(split_notes)
    for n, size in sizes.items():
        if size == 0:
            raise PrepareError(f"split '{n}' is empty (sizes {sizes}); adjust the split lists")
        if not positives[n]:
            warnings.append(f"split '{n}' has ZERO positive (non-benign) next-step targets: metrics on it are undefined")
    for n, d in splits.items():
        for k in ("X", "next_state"):
            if not np.isfinite(d[k]).all():
                raise PrepareError(f"non-finite values in {n}/{k}")

    # write -------------------------------------------------------------------------------------
    out.mkdir(parents=True, exist_ok=True)
    save_splits(splits, out)
    save_window_graphs(graphs_all, out / "window_graphs.pkl")
    mm = PROJECT_ROOT / "pipeline" / "mitre_mapping.py"
    stage_counts: Counter = Counter()
    for v in table.values():
        stage_counts[v["stage"]] += v["rows"]
    metadata = {
        "tool": "scripts.prepare_dataset", "tool_version": TOOL_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": adapter.name, "adapter": adapter.info(),
        "source_directory": str(path), "files_used": [str(f) for f in files],
        "files_skipped": [{"file": str(f), "reason": r} for f, r in skipped],
        "max_rows_per_file": max_rows_per_file, "max_files": max_files, "only_units": only_units,
        "config": str(config_path),
        "feature_columns": feature_cols,
        "sequence_length": int(config["windowing"]["sequence_length"]),
        "forecast_horizon": hz, "window_seconds": ws,
        "flow_only": True, "packet_features_available": False,
        "num_windows": int(sum(i.get("windows", 0) for i in unit_info.values())),
        "num_sequences": int(len(sequences["X"])),
        "splits": sizes, "split_mode": mode, "split_mode_source": source, "split_assignment": assignment,
        "positive_rate_next_step": positives, "units": unit_info,
        "label_mapping": dict(sorted(table.items(), key=lambda kv: -kv[1]["rows"])),
        "flow_rows_by_stage": {k: int(v) for k, v in stage_counts.items()},
        "unit_assumptions": adapter.unit_assumptions, "field_coverage": adapter.info()["field_coverage"],
        "caveat": (" | ".join(adapter.caveats)
                   + " | packet-level features zero-filled (no PCAP); graph_embed_* from a frozen random-init encoder."),
        "warnings": warnings,
        "mitre_mapping": {"sha256": _sha256(mm), "mtime": datetime.fromtimestamp(mm.stat().st_mtime, timezone.utc).isoformat()},
        "train_command": f"python -m models.train --config {out / 'config.yaml'}   # DO NOT run while the GPU is busy",
    }
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2, default=str), encoding="utf-8")
    cfg_out = json.loads(json.dumps(config))
    cfg_out["paths"]["raw_flow_dir"] = str(path)
    cfg_out["paths"]["processed_dir"] = str(out)
    cfg_out["paths"]["checkpoint_dir"] = f"checkpoints_adapter_{adapter.name}"
    cfg_out["paths"]["eval_report"] = f"docs/04-evaluation-adapter-{adapter.name}.md"
    cfg_out["split"] = {**{k: v for k, v in scfg.items() if k not in ("train_days", "val_days", "test_days", "mode")},
                        **({"mode": "by_day", **{f"{n}_days": assignment[n] for n in ("train", "val", "test")}}
                           if mode == "by_day" else {})}
    header = (f"# Derived by scripts.prepare_dataset from {config_path} for adapter '{adapter.name}'.\n"
              "# Only paths.* (and, for by_day, split.*) differ. Nothing in configs/ was modified.\n")
    (out / "config.yaml").write_text(header + yaml.safe_dump(cfg_out, sort_keys=False), encoding="utf-8")
    log(f"[prepare] wrote {out} (splits {sizes}, mode {mode})")
    return metadata
