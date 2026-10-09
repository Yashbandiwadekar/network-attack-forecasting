"""Validate a dataset folder/file against the adapter contract and the 41-feature schema.

    python -m scripts.validate_dataset <path> [--adapter NAME] [--sample-rows N] [--label-scan full|skip]
                                       [--report-dir DIR] [--no-embeddings] [--config YAML]

Exit code: 0 PASS, 1 WARN, 2 FAIL (3 = bad invocation). Reads only; the only files written are the
JSON + markdown reports (default data/adapter_reports/). CPU only.
"""
from __future__ import annotations

import os

os.environ.setdefault("CUDA_VISIBLE_DEVICES", "-1")  # GPU may be busy: never touch it

import argparse
import re
import sys
from pathlib import Path

from pipeline.adapters.validation import render_markdown, validate_dataset, write_report

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--adapter", default=None, help="force an adapter (default: auto-detect)")
    ap.add_argument("--sample-rows", type=int, default=300_000, help="total rows sampled (contiguous prefix per file)")
    ap.add_argument("--min-rows-per-file", type=int, default=20_000)
    ap.add_argument("--label-scan", choices=["full", "skip"], default="full",
                    help="full = stream every row's label column (exact counts, minutes for GB files)")
    ap.add_argument("--config", default="configs/default.yaml", help="supplies windowing + feature lists only")
    ap.add_argument("--report-dir", default=str(PROJECT_ROOT / "data" / "adapter_reports"))
    ap.add_argument("--name", default=None, help="report file stem (default derived from path)")
    ap.add_argument("--no-embeddings", action="store_true", help="skip the GraphSAGE embedding features (faster)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    if not Path(args.path).exists():
        print(f"path not found: {args.path}", file=sys.stderr)
        return 3
    report = validate_dataset(args.path, args.adapter, sample_rows=args.sample_rows,
                              min_rows_per_file=args.min_rows_per_file, label_scan=args.label_scan,
                              config_path=args.config, embeddings=not args.no_embeddings, progress=not args.quiet)
    stem = args.name or re.sub(r"[^A-Za-z0-9_.-]+", "_", Path(args.path).resolve().name or "dataset")
    jp, mp = write_report(report, args.report_dir, stem)
    print(render_markdown(report))
    print(f"report: {jp}\n        {mp}\nVERDICT: {report['verdict']}")
    return {"PASS": 0, "WARN": 1, "FAIL": 2}[report["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
