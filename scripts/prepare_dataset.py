"""One command: raw dataset -> adapter -> windows -> train/val/test .npz in the layout models/train.py reads.

    python -m scripts.prepare_dataset <path> --out data/processed_adapter/<name> --config configs/default.yaml
        [--adapter NAME] [--split by_day|by_unit|chronological]
        [--train-units A,B --val-units C --test-units D]   (MM-DD days for by_day, unit ids for by_unit)
        [--max-rows-per-file N] [--max-files N] [--only-units A,B] [--allow-experimental] [--allow-fallthrough]

--out must be a NEW (or empty) directory and may not overlap data/processed*, checkpoints*, configs/ or
data/raw. Only --config's windowing/features/split sections are used; its paths.* are ignored. CPU only.
"""
from __future__ import annotations

import os

os.environ.setdefault("CUDA_VISIBLE_DEVICES", "-1")

import argparse
import sys

from pipeline.adapters.prepare import PrepareError, prepare_dataset


def _csv(s: str | None) -> list[str] | None:
    return [x.strip() for x in s.split(",") if x.strip()] if s else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--out", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--adapter", default=None)
    ap.add_argument("--split", choices=["by_day", "by_unit", "chronological"], default=None,
                    help="default: config split.mode if by_day, else the adapter's default")
    ap.add_argument("--train-units", default=None)
    ap.add_argument("--val-units", default=None)
    ap.add_argument("--test-units", default=None)
    ap.add_argument("--max-rows-per-file", type=int, default=None, help="contiguous prefix of each file (memory cap)")
    ap.add_argument("--max-files", type=int, default=None)
    ap.add_argument("--only-units", default=None, help="comma list of unit ids to use (file stems / scenario numbers)")
    ap.add_argument("--allow-experimental", action="store_true")
    ap.add_argument("--allow-fallthrough", action="store_true",
                    help="continue although >=1%% of rows have labels with no explicit stage mapping")
    ap.add_argument("--force", action="store_true", help="re-use an --out directory this tool created earlier")
    a = ap.parse_args(argv)
    try:
        meta = prepare_dataset(a.path, a.out, a.config, adapter_name=a.adapter, split=a.split,
                               train_units=_csv(a.train_units), val_units=_csv(a.val_units),
                               test_units=_csv(a.test_units), max_rows_per_file=a.max_rows_per_file,
                               max_files=a.max_files, only_units=_csv(a.only_units), allow_experimental=a.allow_experimental,
                               allow_fallthrough=a.allow_fallthrough, force=a.force)
    except PrepareError as e:
        print(f"PREPARE FAILED: {e}", file=sys.stderr)
        return 2
    for w in meta["warnings"]:
        print(f"WARNING: {w}")
    print(f"OK: {meta['splits']} sequences; train with:\n  {meta['train_command']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
