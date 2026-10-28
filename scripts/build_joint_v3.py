"""docs/15: build the B+ training set = CIC-2018 contiguous dataset (B) + CIC-IDS-2017 Monday in TRAIN only.

    python -m scripts.build_joint_v3 --base data/processed_adapter/cic18c_v3 \
        --out data/processed_adapter/cic18c_mon17_v3 --config configs/joint_v3_Bplus.yaml

B is built first with `scripts.prepare_dataset` (CIC-2018, require_contiguous_windows true, day-disjoint).
Monday is windowed with the same functions at 10 s (contiguous on); its sequences are appended to B's
train split, val/test are copied unchanged. Monday is benign by label (no attack in the file). Nothing existing
is modified; --out must be a new/empty directory under data/processed_adapter. CPU only.
"""
from __future__ import annotations

import os

os.environ.setdefault("CUDA_VISIBLE_DEVICES", "-1")

import argparse
import json
import shutil
from pathlib import Path

import numpy as np

from common.config import PROJECT_ROOT, feature_columns, load_config
from pipeline.adapters.prepare import PrepareError, _unit_windows, check_out_dir
from pipeline.adapters.registry import get_adapter
from pipeline.build_dataset import day_disjoint_split, save_splits


def build(base: Path, out: Path, config_path: str, monday_csv: Path, log=print) -> dict:
    cfg = load_config(config_path)
    if not cfg["windowing"].get("require_contiguous_windows"):
        raise PrepareError("config must set windowing.require_contiguous_windows: true")
    if int(cfg["windowing"]["window_seconds"]) != 10:
        raise PrepareError("B+ is a 10 s dataset")
    out = check_out_dir(out)
    feats = feature_columns(cfg)
    ad = get_adapter("cicids2017")
    res = _unit_windows(ad, [monday_csv], cfg, feats, None)
    if res is None:
        raise PrepareError("Monday produced no flows")
    seqs, _graphs, label_counts, info = res
    if set(label_counts) != {"BENIGN"}:
        raise PrepareError(f"Monday is expected to be all BENIGN, found {label_counts}")
    mon = day_disjoint_split(seqs, {"train_days": ["07-03"], "val_days": [], "test_days": []},
                             10, int(cfg["windowing"]["forecast_horizon"]))["train"]
    base_train = dict(np.load(base / "train.npz", allow_pickle=False))
    keys = list(base_train)
    if set(keys) != set(mon):
        raise PrepareError(f"key mismatch {set(keys) ^ set(mon)}")
    merged = {k: np.concatenate([base_train[k], np.asarray(mon[k])]) for k in keys}
    order = np.argsort(merged["window_end_time"], kind="stable")
    merged = {k: v[order] for k, v in merged.items()}
    splits = {"train": merged,
              "val": dict(np.load(base / "val.npz", allow_pickle=False)),
              "test": dict(np.load(base / "test.npz", allow_pickle=False))}
    save_splits(splits, out)
    meta = json.loads((base / "metadata.json").read_text(encoding="utf-8"))
    meta.update({"tool": "scripts.build_joint_v3", "base_dir": str(base), "added_to_train": "CIC-IDS-2017 Monday (benign)",
                 "monday_sequences": int(len(mon["X"])), "monday_info": info,
                 "splits": {k: int(len(v["X"])) for k, v in splits.items()}})
    (out / "metadata.json").write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")
    shutil.copy(PROJECT_ROOT / config_path if not Path(config_path).is_absolute() else config_path, out / "config.yaml")
    log(f"wrote {out}: {meta['splits']} (Monday +{len(mon['X'])})")
    return meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--monday", default=r"V:\Datasets\CIC-IDS-2017\Monday-WorkingHours.pcap_ISCX.csv")
    a = ap.parse_args()
    try:
        build(Path(a.base), Path(a.out), a.config, Path(a.monday))
    except PrepareError as e:
        print(f"FAILED: {e}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
