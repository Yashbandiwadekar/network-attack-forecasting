"""Secondary window-label definitions (docs/16 action 5, docs/19 section 0.6): per-window attack-flow counts rebuilt from the RAW
CIC-2018 CSVs of the LODO days only, aligned to the cached sequences and VERIFIED against the primary label.

The primary label of a sequence is `infiltration[:, 0]` = "any attack flow in the next 10 s window". Here the same window is rebuilt from raw
rows (flows keyed by floor(timestamp, 10 s), the pipeline's key) so that the number of attack flows and of all flows in the target window
are known; `align_next_counts` asserts that `n_attack > 0` reproduces the primary label before any secondary rule is applied.
The sealed test days are refused (they are not on the allow-list and `eval.lodo_v4.assert_sealed` is called).
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from eval.lodo_v4 import assert_sealed

RAW_DIR = Path("V:/Datasets/CIC-IDS-2018-flows")
RAW_FILE = {   # LODO pseudo-host days only; 02-20 is per-host (7.9M rows) and keeps the primary label only
    "2018-02-14": "Wednesday-14-02-2018", "2018-02-15": "Thursday-15-02-2018", "2018-02-21": "Wednesday-21-02-2018",
    "2018-02-22": "Thursday-22-02-2018", "2018-02-28": "Wednesday-28-02-2018", "2018-03-02": "Friday-02-03-2018",
}
WINDOW = np.timedelta64(10, "s")


def window_counts(day: str, raw_dir: Path = RAW_DIR) -> pd.DataFrame:
    """DataFrame indexed by window start (datetime64) with n_flows and n_attack for the day (flows of that calendar date only)."""
    assert_sealed([day])
    if day not in RAW_FILE:
        raise ValueError(f"no raw file registered for {day}")
    p = raw_dir / f"{RAW_FILE[day]}_TrafficForML_CICFlowMeter.csv"
    df = pd.read_csv(p, usecols=["Timestamp", "Label", "Tot Fwd Pkts", "Tot Bwd Pkts"], low_memory=False)
    df = df[df["Label"] != "Label"]                                     # repeated header rows present in some files
    ts = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
    pk = pd.to_numeric(df["Tot Fwd Pkts"], errors="coerce") + pd.to_numeric(df["Tot Bwd Pkts"], errors="coerce")
    ok = ts.notna() & (pk > 0) & (ts.dt.strftime("%Y-%m-%d") == day)    # pipeline drops unparseable rows and zero-packet flows
    ts, lab = ts[ok], df["Label"][ok].astype(str).str.strip()
    att = lab.str.lower().ne("benign").to_numpy()
    g = pd.DataFrame({"w": ts.dt.floor("10s").to_numpy(), "a": att}).groupby("w")["a"].agg(["size", "sum"])
    g.columns = ["n_flows", "n_attack"]
    return g


def align_next_counts(window_end_time: np.ndarray, primary: np.ndarray, counts: pd.DataFrame, min_match: float = 0.99) -> dict:
    """For every sequence: n_attack / n_flows of the window that follows its last input window (end time + 10 s), plus the match rate of
    (n_attack > 0) against the primary label. Raises if the match is below `min_match`."""
    nxt = np.asarray(window_end_time).astype("datetime64[ns]") + WINDOW.astype("timedelta64[ns]")
    idx = pd.DatetimeIndex(nxt)
    na = counts["n_attack"].reindex(idx).fillna(0).to_numpy().astype(np.int64)
    nf = counts["n_flows"].reindex(idx).fillna(0).to_numpy().astype(np.int64)
    prim = np.asarray(primary) > 0
    match = float(((na > 0) == prim).mean())
    pos_recall = float((na[prim] > 0).mean()) if prim.any() else float("nan")
    if match < min_match:
        raise ValueError(f"raw-count window label disagrees with the primary label on {1 - match:.2%} of sequences (< {min_match:.0%} match)")
    return {"n_attack_next": na, "n_flows_next": nf, "match_rate": match, "primary_pos_recovered": pos_recall}


def secondary_labels(n_attack: np.ndarray, n_flows: np.ndarray, primary: np.ndarray, k: int, s: float) -> dict[str, np.ndarray]:
    """Boolean score masks per definition. `eval` rows exclude ambiguous windows (primary-positive but failing the rule), see docs/19 0.6.
    A: attack flows >= k and share >= s. Returns {'pos': bool, 'keep': bool}."""
    share = n_attack / np.maximum(n_flows, 1)
    pos = (n_attack >= k) & (share >= s)
    prim = np.asarray(primary) > 0
    return {"pos": pos, "keep": pos | ~prim}


def sustained_mask(primary_series: np.ndarray, run: int = 6) -> np.ndarray:
    """Windows of a single time-ordered unit that belong to a run of >= `run` consecutive positives (label definition (c) of docs/16)."""
    p = (np.asarray(primary_series) > 0).astype(np.int8)
    out = np.zeros(len(p), bool)
    i = 0
    while i < len(p):
        if p[i]:
            j = i
            while j < len(p) and p[j]:
                j += 1
            if j - i >= run:
                out[i:j] = True
            i = j
        else:
            i += 1
    return out
