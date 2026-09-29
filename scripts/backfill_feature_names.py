"""Audit W19/I1: write `feature_names` into checkpoints saved before that field existed.

`models/checkpoint_io.py::validate_feature_names` compares a caller's assembled feature list
against the list the checkpoint was trained on, by name and order -- but it deliberately skips
checkpoints that carry no `feature_names` key, so it was inert on every artefact produced before
W19 landed, including the two the demo loads. This backfills that key from each checkpoint's own
embedded training config, which is the authoritative record of what it was trained on.

Additive only: no tensor is touched. The script refuses to write if the derived list length
disagrees with the checkpoint's stored `n_features`, and verifies the file reloads afterwards.

    python -m scripts.backfill_feature_names            # report only
    python -m scripts.backfill_feature_names --write    # apply
"""
from __future__ import annotations

import argparse
import glob

import torch

from common.config import feature_columns


def backfill(path: str, write: bool) -> str:
    ckpt = torch.load(path, map_location="cpu", weights_only=False)
    if ckpt.get("feature_names"):
        return "already has it"
    config = ckpt.get("config")
    if not config:
        return "SKIP: no embedded config"
    try:
        names = feature_columns(config)
    except Exception as exc:  # a config shape this helper doesn't understand
        return f"SKIP: cannot derive features ({type(exc).__name__})"

    stored = ckpt.get("n_features")
    if stored is not None and stored != len(names):
        return f"REFUSED: n_features={stored} but config yields {len(names)}"
    if not write:
        return f"would write {len(names)} names"

    ckpt["feature_names"] = list(names)
    torch.save(ckpt, path)
    reloaded = torch.load(path, map_location="cpu", weights_only=False)
    if list(reloaded.get("feature_names") or []) != list(names):
        return "ERROR: did not persist"
    return f"wrote {len(names)} names"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="apply changes (default: report only)")
    parser.add_argument("--glob", default="checkpoints*/**/*.pt")
    args = parser.parse_args()

    paths = sorted(glob.glob(args.glob, recursive=True))
    counts: dict[str, int] = {}
    for p in paths:
        result = backfill(p, args.write)
        key = result.split(":")[0].split(" ")[0]
        counts[key] = counts.get(key, 0) + 1
        if not result.startswith("already"):
            print(f"  {result:34s} {p}")
    print(f"\n{len(paths)} checkpoints: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    if not args.write:
        print("report only -- re-run with --write to apply")


if __name__ == "__main__":
    main()
