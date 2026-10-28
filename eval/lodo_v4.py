"""Leave-one-day-out (LODO) validation logic for docs/18 (docs/16 action 2): fold construction, out-of-fold selection
metric, epoch selection (global and nested), and the day-balanced operating point.

Pure functions of numpy arrays: no file is read or written here, no model is trained, no checkpoint or scaler is touched.
The training/OOF driver is eval/lodo_v4_run.py; the baseline gate itself is eval.diagnostics.core.baseline_gate.

Protocol in one paragraph (full text and rationale in docs/18 section 0):
  * Units are the calendar days of the CIC-2018 TRAIN+VAL splits (02-14, 02-15, 02-20, 02-21, 02-22, 02-28, 03-02).
    The test days (02-16, 02-23, 03-01) never enter any function in this module as data; `assert_sealed` refuses them.
  * A day fold holds out one whole day: no row of that day is in the fold's training rows.
  * 02-20 is the only day with real source IPs (6,810 hosts, 10 attackers). It is split into `n_groups` host groups
    (no host in two groups; attackers spread over the groups). A host-group fold holds out one group's hosts of 02-20 and
    trains on the other six days plus the OTHER 02-20 groups. That is host-disjoint, NOT day-disjoint; folds say so.
  * Selection metric: mean over days of the OUT-OF-FOLD within-day AUROC (02-20's OOF scores are pooled over its groups
    so that it counts as one day). Never validation loss.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Mapping

import numpy as np

#: attack family of each CIC-2018 day (from the config comment of configs/real_data_v2_converged.yaml)
DAY_FAMILY: dict[str, str] = {
    "2018-02-14": "initial_access", "2018-02-15": "impact", "2018-02-16": "impact", "2018-02-20": "impact",
    "2018-02-21": "impact", "2018-02-22": "initial_access", "2018-02-23": "initial_access",
    "2018-02-28": "lateral_movement", "2018-03-01": "lateral_movement", "2018-03-02": "command_and_control",
}
SEALED_TEST_DAYS: tuple[str, ...] = ("2018-02-16", "2018-02-23", "2018-03-01")
LODO_DAYS: tuple[str, ...] = ("2018-02-14", "2018-02-15", "2018-02-20", "2018-02-21", "2018-02-22", "2018-02-28",
                              "2018-03-02")
HOST_SPLIT_DAY = "2018-02-20"


@dataclass(frozen=True)
class Fold:
    name: str
    day: str                 # the held-out day (or the day whose hosts are partly held out)
    group: int | None = None  # None = whole day held out; int = held-out host group of `day`

    @property
    def kind(self) -> str:
        return "day" if self.group is None else "host_group"


def assert_sealed(days) -> None:
    bad = sorted(set(map(str, days)) & set(SEALED_TEST_DAYS))
    if bad:
        raise ValueError(f"sealed test day(s) {bad} must not be used for validation, selection or training")


def assign_host_groups(hosts, positive_hosts, n_groups: int = 3, seed: int = 0) -> dict[str, int]:
    """Deterministic partition of `hosts` into `n_groups` groups with no host in two groups. Positive (attacking) hosts
    are dealt round-robin FIRST (so every group holds attackers whenever there are >= n_groups of them), benign hosts are
    then dealt round-robin in an order fixed by a seeded hash (stable across platforms, independent of input order)."""
    if n_groups < 2:
        raise ValueError("n_groups must be >= 2")
    hosts = sorted({str(h) for h in hosts})
    pos = {str(h) for h in positive_hosts}
    if not pos <= set(hosts):
        raise ValueError("positive_hosts must be a subset of hosts")

    def key(h: str) -> str:
        return hashlib.sha1(f"{seed}|{h}".encode()).hexdigest()

    out: dict[str, int] = {}
    pos_sorted = sorted(pos, key=key)
    for i, h in enumerate(pos_sorted):
        out[h] = i % n_groups
    # continue the deal from the group after the last attacker so group sizes stay within 1 host of each other
    start = len(pos_sorted) % n_groups
    for i, h in enumerate(sorted((h for h in hosts if h not in pos), key=key)):
        out[h] = (start + i) % n_groups
    return out


def build_folds(days=LODO_DAYS, host_split_day: str = HOST_SPLIT_DAY, n_groups: int = 3) -> list[Fold]:
    """One day fold per day, except `host_split_day`, which becomes `n_groups` host-group folds."""
    assert_sealed(days)
    folds: list[Fold] = []
    for d in sorted(days):
        if d == host_split_day:
            folds += [Fold(f"{d}#g{g}", d, g) for g in range(n_groups)]
        else:
            folds.append(Fold(d, d))
    return folds


def fold_masks(fold: Fold, day: np.ndarray, host: np.ndarray, host_group: Mapping[str, int] | None
               ) -> tuple[np.ndarray, np.ndarray]:
    """(train_mask, heldout_mask) over rows described by `day` (YYYY-MM-DD) and `host` (src_ip) arrays."""
    day = np.asarray(day).astype(str)
    host = np.asarray(host).astype(str)
    if fold.group is None:
        held = day == fold.day
    else:
        if host_group is None:
            raise ValueError("host_group mapping required for a host-group fold")
        g = np.array([host_group[h] for h in host]) if len(host) else np.zeros(0, int)
        held = (day == fold.day) & (g == fold.group)
    return ~held, held


def assert_no_leakage(fold: Fold, day, host, train_mask, held_mask, host_group=None) -> None:
    """Raises AssertionError on any leakage: overlapping rows; for a day fold, any held-out-day row in train; for a
    host-group fold, any host present in both train and held-out rows; any sealed day anywhere."""
    day = np.asarray(day).astype(str)
    host = np.asarray(host).astype(str)
    train_mask = np.asarray(train_mask, bool)
    held_mask = np.asarray(held_mask, bool)
    assert not (train_mask & held_mask).any(), "a row is both train and held out"
    assert held_mask.any(), "empty held-out set"
    assert_sealed(set(day[train_mask]) | set(day[held_mask]))
    if fold.group is None:
        assert not (day[train_mask] == fold.day).any(), f"held-out day {fold.day} leaks into train"
        assert set(day[held_mask]) == {fold.day}
    else:
        assert not (set(host[train_mask & (day == fold.day)]) & set(host[held_mask])), "a host is in both train and held out"


def family_coverage(fold: Fold, train_days) -> dict:
    """Family-awareness of a fold: is the held-out day's attack family still represented in training, and by which days?
    A fold whose family is absent from training measures transfer to an unseen family, not within-family generalisation."""
    fam = DAY_FAMILY[fold.day]
    same = sorted(d for d in set(map(str, train_days)) if DAY_FAMILY.get(d) == fam and d != fold.day)
    same_day_hosts = fold.group is not None            # other hosts of the same day remain in train
    return {"family": fam, "family_in_train": bool(same) or same_day_hosts,
            "family_in_train_other_days": bool(same), "other_days_same_family": same,
            "same_day_other_hosts_in_train": same_day_hosts,
            "day_disjoint": fold.group is None}


# ------------------------------------------------------------------ selection metric

def _auc(y, s):
    from sklearn.metrics import roc_auc_score
    y = np.asarray(y)
    if y.size == 0 or y.min() == y.max():
        return float("nan")
    return float(roc_auc_score(y, s))


def _ap(y, s):
    from sklearn.metrics import average_precision_score
    y = np.asarray(y)
    if y.size == 0 or y.max() == 0:
        return float("nan")
    return float(average_precision_score(y, s))


def oof_day_metrics(y: np.ndarray, score: np.ndarray, day: np.ndarray) -> dict[str, dict]:
    """Out-of-fold within-day AUROC/AUPRC per day (nan when a day has one class)."""
    day = np.asarray(day).astype(str)
    out = {}
    for d in sorted(set(day)):
        m = day == d
        out[d] = {"auroc": _auc(y[m], score[m]), "auprc": _ap(y[m], score[m]), "n": int(m.sum()), "pos": int(np.sum(y[m] > 0))}
    return out


def selection_metric(per_day_auroc: Mapping[str, float]) -> float:
    """The selection metric: unweighted mean over days of the within-day out-of-fold AUROC (days with one class skipped)."""
    v = [x for x in per_day_auroc.values() if x is not None and not np.isnan(x)]
    return float(np.mean(v)) if v else float("nan")


def select_epoch(curves: Mapping[str, np.ndarray]) -> tuple[int, np.ndarray]:
    """curves: {day: array over epochs of OOF within-day AUROC}. Returns (0-based epoch maximising the day-mean, that
    mean curve). Ties resolve to the EARLIER epoch (cheaper, less over-confident)."""
    mat = np.array([np.asarray(c, float) for c in curves.values()])
    mean = np.nanmean(mat, axis=0)
    best = int(np.flatnonzero(mean >= np.nanmax(mean) - 1e-12)[0])
    return best, mean


def nested_epoch_selection(curves: Mapping[str, np.ndarray]) -> dict[str, dict]:
    """Honest per-day number for a tuned epoch: for each day d the epoch is chosen from the OTHER days' mean curve, and
    d is read at that epoch. Averaging these removes the argmax optimism of reporting the same days that chose the epoch."""
    days = list(curves)
    out = {}
    for d in days:
        others = {k: curves[k] for k in days if k != d}
        e, _ = select_epoch(others)
        out[d] = {"epoch": e, "auroc": float(np.asarray(curves[d], float)[e])}
    return out


# ------------------------------------------------------------------ operating point

def day_balanced_threshold(y: np.ndarray, score: np.ndarray, day: np.ndarray, target_fpr: float) -> float:
    """Alert threshold from OUT-OF-FOLD scores: the smallest score s such that the day-balanced false-positive rate of
    `score >= s` over negatives is <= target_fpr, where each day's negatives carry total weight 1 (so 02-20's 1.2M
    sequences do not decide the threshold alone). Alert rule: score >= threshold."""
    y = np.asarray(y)
    score = np.asarray(score, float)
    day = np.asarray(day).astype(str)
    neg = y <= 0
    s, d = score[neg], day[neg]
    days, inv, cnt = np.unique(d, return_inverse=True, return_counts=True)
    w = 1.0 / cnt[inv]
    w = w / w.sum()
    order = np.argsort(-s, kind="stable")
    s_sorted, cw = s[order], np.cumsum(w[order])
    # a threshold equal to a score value alarms on every negative with score >= that value, so only the LAST index
    # of each run of tied scores gives a realisable (threshold, FPR) pair
    ends = np.flatnonzero(np.r_[s_sorted[1:] != s_sorted[:-1], True])
    ok = ends[cw[ends] <= target_fpr + 1e-12]
    if len(ok) == 0:
        return float(np.nextafter(s_sorted[0], np.inf))     # nothing can alarm within budget
    return float(s_sorted[ok[-1]])


def operating_point_by_day(y: np.ndarray, score: np.ndarray, day: np.ndarray, threshold: float) -> dict[str, dict]:
    """Per-day realised FPR, TPR (recall) and alarm rate at `threshold` (alarm = score >= threshold)."""
    y = np.asarray(y)
    day = np.asarray(day).astype(str)
    alarm = np.asarray(score, float) >= threshold
    out = {}
    for d in sorted(set(day)):
        m = day == d
        neg, pos = m & (y <= 0), m & (y > 0)
        out[d] = {"fpr": float(alarm[neg].mean()) if neg.any() else None,
                  "tpr": float(alarm[pos].mean()) if pos.any() else None,
                  "alarm_rate": float(alarm[m].mean()), "n_neg": int(neg.sum()), "n_pos": int(pos.sum())}
    return out
