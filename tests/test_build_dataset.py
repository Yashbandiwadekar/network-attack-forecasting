import numpy as np

from pipeline.build_dataset import _chronological_split

SPLIT_CONFIG = {"train_frac": 0.7, "val_frac": 0.15, "test_frac": 0.15}


def _sequences(src_ips: list[str], times: list[int]) -> dict:
    n = len(src_ips)
    return {
        "src_ip": np.array(src_ips),
        "window_end_time": np.array(times, dtype=np.int64),
        "X": np.arange(n).reshape(n, 1, 1).astype(np.float32),  # identity payload so splits are traceable
    }


def test_splits_within_each_group_not_globally():
    # group "a": 10 sequences, all EARLY in absolute time. group "b": 10 sequences, all LATE.
    # a naive global chronological split would put all of "a" in train and all of "b" in test —
    # this must instead give both groups their own 70/15/15 split.
    src_ips = ["a"] * 10 + ["b"] * 10
    times = list(range(10)) + list(range(1000, 1010))
    seqs = _sequences(src_ips, times)

    splits = _chronological_split(seqs, SPLIT_CONFIG)

    assert set(splits["train"]["src_ip"]) == {"a", "b"}
    assert set(splits["val"]["src_ip"]) == {"a", "b"}
    assert set(splits["test"]["src_ip"]) == {"a", "b"}
    # 7/1/2 split per group of 10 (70%, 15%, 15% rounded down)
    assert (splits["train"]["src_ip"] == "a").sum() == 7
    assert (splits["train"]["src_ip"] == "b").sum() == 7


def test_within_group_chronological_order_is_preserved_no_leakage():
    src_ips = ["a"] * 10
    times = list(range(10))
    seqs = _sequences(src_ips, times)

    splits = _chronological_split(seqs, SPLIT_CONFIG)

    max_train_time = splits["train"]["window_end_time"].max()
    min_val_time = splits["val"]["window_end_time"].min()
    min_test_time = splits["test"]["window_end_time"].min()
    assert max_train_time < min_val_time
    assert min_val_time < min_test_time


def test_every_row_assigned_to_exactly_one_split():
    src_ips = ["a"] * 13 + ["b"] * 7
    times = list(range(20))
    seqs = _sequences(src_ips, times)

    splits = _chronological_split(seqs, SPLIT_CONFIG)

    total = sum(len(s["src_ip"]) for s in splits.values())
    assert total == 20


def test_tiny_group_does_not_crash():
    # a group with only 1-2 sequences can't meaningfully split 3 ways — must not error
    seqs = _sequences(["a"], [0])
    splits = _chronological_split(seqs, SPLIT_CONFIG)
    total = sum(len(s["src_ip"]) for s in splits.values())
    assert total == 1
