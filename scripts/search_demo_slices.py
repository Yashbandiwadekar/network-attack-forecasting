"""Search CIC-2018 for the slice of each attack family on which the served model alerts most strongly (docs/22).

    python -m scripts.search_demo_slices --out <dir>/search.jsonl [--shard 0 --shards 2]

The owner wants the best-performing examples as demos, so this is a deliberate SEARCH, not a fixed rule. The grid is
fixed in this file and every slice tried is logged (nothing is dropped from the log):

  * family       = one attack label (web brute force / XSS / SQL injection of one day count as one family)
  * span         = [first, last] row of the family's labels in its day file
  * lengths      = 5,000 / 20,000 / 40,000 rows
  * end rows     = 5 evenly spaced points across the span (first + k/5 * (last - first), k = 1..5)
  * slice        = rows [end - length, end), kept only if it holds >= MIN_ATTACK_ROWS rows of the family's labels,
                   is <= SIZE_CAP_MB as a CSV, and gives some host 12 windows
  * score        = in-process on the served bundle (dist/models/seed1), the same code path as POST /demo/load
  * best slice   = highest peak probability among hosts whose 12 SCORED windows contain observed, non-heuristic
                   attack stages (an alert on all-Benign windows never counts); must reach 0.40 to be used.

Selection is by measured model output on the exact slice, so the winners are optimistic examples by construction
(the search is the selection effect). scripts/build_demo_files.py --from-search rebuilds the winners and re-measures
them through the server; those re-measured numbers are the ones shown.
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scripts import build_demo_files as B  # noqa: E402

BUNDLE_CONFIG = PROJECT_ROOT / "dist" / "models" / "seed1" / "config.yaml"
LENGTHS = (5_000, 20_000, 40_000)
N_ENDS = 5
MIN_ATTACK_ROWS = 300
SEQ = 12


def families() -> list[dict]:
    fam: dict[tuple[str, str], dict] = {}
    for day, label, name, _ in B.LABELS:
        key = (day, name if name == "Web attacks" else label)
        f = fam.setdefault(key, dict(day=day, name=name, labels=[], file=B.DAYS[day]))
        f["labels"].append(label)
    return [dict(f, id=B._slug(f["name"] if f["name"] == "Web attacks" else f["labels"][0]) + "-" + f["day"].replace("-", ""))
            for f in fam.values()]


def label_span(path: Path, labels: list[str]) -> tuple[int, int]:
    lab = B._labels(path).astype(str)
    idx = lab.index[lab.isin(labels)]
    return int(idx.min()), int(idx.max())


def score_slice(src: Path, start: int, n: int, labels: list[str], tmp: Path, ctx) -> dict:
    from app import service
    from models.forecast import ForecastEngine
    config, model, scaler = ctx
    df = pd.read_csv(src, skiprows=range(1, start + 1) if start else None, nrows=n, low_memory=False)
    attack_rows = int(df["Label"].astype(str).isin(labels).sum())
    rec = dict(start=start, n=int(len(df)), attack_rows=attack_rows)
    if attack_rows < MIN_ATTACK_ROWS:
        return dict(rec, skipped=f"only {attack_rows} attack rows")
    out = tmp / "slice.csv"
    df.to_csv(out, index=False, lineterminator="\n")
    mb = out.stat().st_size / 1024 / 1024
    rec["size_mb"] = round(mb, 2)
    if mb > B.SIZE_CAP_MB:
        return dict(rec, skipped=f"{mb:.1f} MB over cap")
    flow_df, windows = service.process_uploads(out, None, config)
    seq_len = int(config["windowing"]["sequence_length"])
    batch = service.score_all_hosts(ForecastEngine(model, scaler, config), windows, service.feature_cols_for(config), seq_len)
    if batch is None:
        return dict(rec, skipped="no host with 12 windows")
    best = None
    peaks = []
    for i, host in enumerate(batch.host_ids):
        peak = float(np.max(batch.infiltration_probs[i]))
        peaks.append(peak)
        g = windows[windows["src_ip"] == host].sort_values("window_start").iloc[-seq_len:]
        stages = g["stage"].astype(str)
        in_view = bool(g["stage_observed"].all()) and bool((stages != "benign").any()) and not set(stages) <= {"benign", "reconnaissance"}
        if in_view and (best is None or peak > best["peak"]):
            best = dict(host=host, peak=round(peak, 4), stages=stages.value_counts().to_dict())
    return dict(rec, hosts=len(peaks), peak_max=round(max(peaks), 4), flagged_hosts=int(sum(p >= B.ALERT_THRESHOLD for p in peaks)),
                catch=best)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--ends", type=int, default=N_ENDS, help="end points across each family's span (pass 1: 5, pass 2: 12)")
    ap.add_argument("--shard", type=int, default=0)
    ap.add_argument("--shards", type=int, default=1)
    args = ap.parse_args()
    from app import service
    config, model, scaler, _ = service.load_backend(str(BUNDLE_CONFIG))
    ctx = (config, model, scaler)
    done = set()
    if args.out.exists():
        for line in args.out.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            done.add((r["family"], r["start"], r["n"]))
    fams = families()[args.shard::args.shards]
    with tempfile.TemporaryDirectory(prefix="demo_search_") as td:
        for fam in fams:
            src = B.RAW_CIC / fam["file"]
            first, last = label_span(src, fam["labels"])
            seen = set()
            # grid points, plus the slice the original fixed rule would have taken (2,000 rows of context, 40,000 rows)
            grid = [(max(0, first + int(round((last - first) * k / args.ends)) - L), L)
                    for L in LENGTHS for k in range(1, args.ends + 1)]
            grid.append((max(0, first - B.PRE_CONTEXT_ROWS), 40_000))
            if True:
                for start, L in grid:
                    if (start, L) in seen or (fam["id"], start, L) in done:
                        continue
                    seen.add((start, L))
                    t = time.time()
                    try:
                        rec = score_slice(src, start, L, fam["labels"], Path(td), ctx)
                    except Exception as exc:                                  # logged, never silently dropped
                        rec = dict(start=start, n=L, skipped=f"error: {exc}")
                    rec.update(family=fam["id"], day=fam["day"], file=fam["file"], labels=fam["labels"], span=[first, last],
                               seconds=round(time.time() - t, 1))
                    with args.out.open("a", encoding="utf-8") as fh:
                        fh.write(json.dumps(rec) + "\n")
                    print(fam["id"], start, L, rec.get("skipped") or (rec["peak_max"], rec["catch"] and rec["catch"]["peak"]), flush=True)


if __name__ == "__main__":
    main()
