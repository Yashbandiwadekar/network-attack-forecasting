"""Build a self-contained model bundle (docs/09 A2, docs/10).

    python -m scripts.make_model_bundle --config configs/real_data_v2_converged_seed1.yaml \
        --out dist/models/seed1 [--name seed1] [--archive]

Copies exactly what inference needs (checkpoint, scaler.npz, metadata.json, the config), writes
MANIFEST.json (sizes, SHA256, feature schema, git commit, graph-encoder fingerprint) and verifies the
result. --archive also writes <out>.tar.gz next to it and prints its SHA256. Nothing is uploaded.
Weights are never committed: /dist/ is gitignored.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from common.bundle import BundleError, build_bundle, make_archive


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", required=True, help="configs/*.yaml of the model to bundle")
    ap.add_argument("--out", required=True, help="output directory, e.g. dist/models/seed1 (must not exist or be empty)")
    ap.add_argument("--name", default=None, help="model name recorded in the manifest (default: output folder name)")
    ap.add_argument("--archive", action="store_true", help="also write <out>.tar.gz")
    args = ap.parse_args()
    try:
        manifest = build_bundle(args.config, args.out, args.name)
    except BundleError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    out = Path(args.out)
    total = sum(f["size"] for f in manifest["files"])
    print(f"[+] bundle {manifest['model_name']} at {out.resolve()}")
    for f in manifest["files"]:
        print(f"    {f['path']:<36} {f['size']:>9,d} B  sha256 {f['sha256'][:16]}...")
    print(f"    total {total:,d} bytes ({total / 1024:.1f} KiB), {manifest['n_features']} features, "
          f"git {str(manifest['git_commit'])[:10]} dirty={manifest['git_dirty']}")
    if args.archive:
        arc = out.parent / (out.name + ".tar.gz")
        digest = make_archive(out, arc)
        print(f"[+] archive {arc.resolve()}  {arc.stat().st_size:,d} B  sha256 {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
