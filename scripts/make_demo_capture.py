"""Build the demo capture used in the walkthrough video.

A 40,000-flow slice of CIC-IDS-2018 Friday 02-03-2018 (Bot day). Chosen because it is small
enough to upload on camera in a couple of seconds and still produces the full story: a host that
escalates from ~0 to 0.9997 infiltration probability across the 60-second horizon, with a
Command & Control -> Impact stage transition and a reportable CERT-In category.

The output is NOT committed -- it is 14 MB of redistributed CIC-IDS-2018 data, and the raw day
files are a licensed third-party download. This script regenerates it byte-identically from the
raw capture instead.

    python -m scripts.make_demo_capture
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC = PROJECT_ROOT / "data" / "raw" / "flows_real" / "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv"
OUT = PROJECT_ROOT / "demo" / "demo-capture-cicids2018-bot-02mar2018.csv"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=40000)
    parser.add_argument("--src", type=Path, default=SRC)
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args()

    if not args.src.exists():
        raise SystemExit(
            f"Raw capture not found: {args.src}\n"
            "Download CSE-CIC-IDS2018 Friday-02-03-2018 from the Canadian Institute for "
            "Cybersecurity and place it there."
        )

    df = pd.read_csv(args.src, nrows=args.rows, low_memory=False)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.out, index=False)

    mix = df["Label"].value_counts().to_dict() if "Label" in df else {}
    print(f"wrote {args.out.relative_to(PROJECT_ROOT)} "
          f"({args.out.stat().st_size / 1024 / 1024:.1f} MB, {len(df):,} flows)")
    print(f"label mix: {mix}")
    print("expected when uploaded: 1 host, peak ~0.9997 (critical), "
          "Command & Control -> Impact, CERT-In reportable (DDoS)")


if __name__ == "__main__":
    main()
