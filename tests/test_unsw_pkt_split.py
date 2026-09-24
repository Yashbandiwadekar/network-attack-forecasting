import numpy as np
import pandas as pd

from pipeline.build_unsw_pkt_dataset import carve_val_block


def _train(n=200, pos_from=100):
    ends = pd.Timestamp("2015-01-22 12:00:00") + pd.to_timedelta(np.arange(n) * 10, unit="s")
    times = np.stack([(ends - pd.Timedelta(seconds=110) + pd.Timedelta(seconds=10 * i)).values for i in range(12)], axis=1)
    y = np.zeros((n, 6)); y[pos_from:, 0] = 1  # attacks only in the second half of the day
    return {"window_end_time": ends.values, "window_times": times, "infiltration": y,
            "X": np.arange(n).reshape(n, 1, 1).astype(np.float32)}


def test_val_block_has_positives_and_shares_no_window_with_train():
    splits = {"train": _train(), "val": {k: v[:0] for k, v in _train().items()}, "test": {}}
    out = carve_val_block(splits, positive_quantile=0.5, window_s=10, horizon=6)

    val_y = out["val"]["infiltration"][:, 0]
    assert len(out["val"]["X"]) > 0 and val_y.sum() > 0  # the whole point: val must contain attacks
    tr_times, va_times = out["train"]["window_times"], out["val"]["window_times"]
    # no window timestamp appears in both a train sequence and a val sequence
    assert not (set(np.unique(tr_times)) & set(np.unique(va_times)))
    # every original sequence is in exactly one place or dropped at the edges, never duplicated
    assert len(out["train"]["X"]) + len(out["val"]["X"]) <= 200
