"""QC-1: opt-in contiguous-window handling and gap statistics."""
import copy

import numpy as np
import pandas as pd

from models.forecast import (
    latest_sequence, latest_sequence_is_contiguous, latest_sequences_batch,
)
from pipeline.mitre_mapping import BENIGN
from pipeline.windowing import build_sequences, sequence_gap_stats

CONFIG = {"windowing": {"sequence_length": 2, "forecast_horizon": 2, "window_seconds": 10}}
T0 = pd.Timestamp("2026-01-01")


def _windows(offsets, ip="a"):
    return pd.DataFrame([
        {"src_ip": ip, "window_start": T0 + pd.Timedelta(seconds=10 * o), "flow_count": float(o), "stage": BENIGN}
        for o in offsets
    ])


def test_default_keeps_gapped_sequences():
    seqs = build_sequences(_windows([0, 1, 2, 5, 6, 7]), ["flow_count"], CONFIG)
    assert len(seqs["X"]) == 3  # 6 - 2 - 2 + 1, gap or not
    stats = sequence_gap_stats(seqs["window_times"], 10)
    # only the [2, 5] input pair has a gap; the default build keeps it (behaviour unchanged)
    assert stats["n_sequences"] == 3 and abs(stats["frac_with_gaps"] - 1 / 3) < 1e-9


def test_input_gap_is_reported():
    seqs = build_sequences(_windows([0, 1, 5, 6, 7, 8]), ["flow_count"], CONFIG)
    stats = sequence_gap_stats(seqs["window_times"], 10)
    assert stats["frac_with_gaps"] > 0 and stats["max_step_s"] == 40.0


def test_require_contiguous_drops_gapped_sequences():
    cfg = copy.deepcopy(CONFIG)
    cfg["windowing"]["require_contiguous_windows"] = True
    # slots 0,1,2,3 contiguous; gap; 8,9,10,11 contiguous -> 4-window runs yield 1 sample each
    seqs = build_sequences(_windows([0, 1, 2, 3, 8, 9, 10, 11]), ["flow_count"], cfg)
    assert len(seqs["X"]) == 2
    np.testing.assert_array_equal(sorted(seqs["X"][:, 0, 0]), [0.0, 8.0])
    assert sequence_gap_stats(seqs["window_times"], 10)["frac_with_gaps"] == 0.0
    # every aligned array was filtered consistently
    for k, v in seqs.items():
        assert len(v) == 2, k


def test_require_contiguous_all_dropped_returns_empty():
    cfg = copy.deepcopy(CONFIG)
    cfg["windowing"]["require_contiguous_windows"] = True
    seqs = build_sequences(_windows([0, 2, 4, 6, 8]), ["flow_count"], cfg)
    assert seqs["X"].shape[0] == 0


def test_gap_stats_empty():
    assert sequence_gap_stats(np.zeros((0, 3), dtype="datetime64[ns]"), 10)["n_sequences"] == 0


def test_forecast_helpers_flag_and_opt_in_filter():
    w = pd.concat([_windows([0, 1, 2], "ok"), _windows([0, 1, 5], "gap")], ignore_index=True)
    assert latest_sequence_is_contiguous(w, "ok", 3, 10) is True
    assert latest_sequence_is_contiguous(w, "gap", 3, 10) is False
    assert latest_sequence_is_contiguous(w, "ok", 9, 10) is None
    # default behaviour unchanged
    assert latest_sequence(w, ["flow_count"], "gap", 3) is not None
    assert latest_sequence(w, ["flow_count"], "gap", 3, window_seconds=10, require_contiguous=True) is None
    hosts, seqs = latest_sequences_batch(w, ["flow_count"], 3)
    assert sorted(hosts) == ["gap", "ok"] and seqs.shape == (2, 3, 1)
    flags: dict = {}
    hosts2, _ = latest_sequences_batch(w, ["flow_count"], 3, window_seconds=10, contiguous_out=flags)
    assert hosts2 == hosts and flags == {"ok": True, "gap": False}
    hosts3, seqs3 = latest_sequences_batch(w, ["flow_count"], 3, window_seconds=10, require_contiguous=True)
    assert hosts3 == ["ok"] and seqs3.shape == (1, 3, 1)
