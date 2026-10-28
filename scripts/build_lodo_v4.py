"""Build the per-day cache used by the docs/18 leave-one-day-out protocol.

Reads data/processed_real_v2_converged/{train,val}.npz READ-ONLY (the sealed test.npz is never opened) and writes one
folder per calendar day under data/processed_adapter/lodo_v4/<YYYY-MM-DD>/<key>.npy (uncompressed, memory-mappable),
plus a manifest.json with row counts. Nothing under data/processed_real_v2_converged is modified, no scaler is fitted.

    python -m scripts.build_lodo_v4
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SRC = ROOT / "data" / "processed_real_v2_converged"
OUT = ROOT / "data" / "processed_adapter" / "lodo_v4"
SPLITS = ("train", "val")          # test.npz is deliberately not read here


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    parts: dict[str, dict[str, list]] = {}
    for split in SPLITS:
        z = np.load(SRC / f"{split}.npz", allow_pickle=False)
        day = z["window_end_time"].astype("datetime64[D]").astype(str)
        for d in np.unique(day):
            m = day == d
            for k in z.files:
                parts.setdefault(str(d), {}).setdefault(k, []).append(z[k][m])
            print(split, d, int(m.sum()), flush=True)
        del z
    manifest = {"source": str(SRC), "splits_read": list(SPLITS), "days": {}}
    for d, kv in parts.items():
        dd = OUT / d
        dd.mkdir(exist_ok=True)
        n = 0
        for k, lst in kv.items():
            a = np.concatenate(lst)
            np.save(dd / f"{k}.npy", a)
            n = len(a)
        manifest["days"][d] = {"n_sequences": int(n), "keys": sorted(kv)}
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    print("done", {d: v["n_sequences"] for d, v in manifest["days"].items()})


if __name__ == "__main__":
    main()
