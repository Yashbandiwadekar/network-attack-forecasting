"""docs/19 library: data pool, folds, nested (inner) leave-one-day-out tuning and the estimators of the classical baselines.

Reuses, unchanged, the docs/18 protocol: eval.lodo_v4 (folds, sealed-day guard, day-balanced threshold, operating point) and the 7 non-test
CIC-2018 days of data/processed_adapter/lodo_v4 (read only). New data only under data/processed_adapter/baselines_v5/ (feature caches), new
results only under checkpoints_baselines_v5/ and docs/lodo_v5/. The sealed test days are never read (assert_sealed in every fold builder; the
raw-CSV reader refuses them).

Inner loop (nested tuning, docs/19 section 0.4): for an outer fold the inner folds are the outer-TRAIN days, each held out whole, with the
02-20 training sample (70,000 rows minus any held-out host group) as ONE inner fold; a candidate configuration is scored by the mean over inner
folds of the within-fold AUROC; ties go to the earlier grid entry (the default is always first). The outer held-out day/group never enters.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common.config import feature_columns, load_config  # noqa: E402
from eval import lodo_v4 as L  # noqa: E402
from models import features_v5 as F5  # noqa: E402

SRC = ROOT / "data" / "processed_adapter" / "lodo_v4"
DATA = ROOT / "data" / "processed_adapter" / "baselines_v5"
CKPT = ROOT / "checkpoints_baselines_v5"
RES = ROOT / "docs" / "lodo_v5"
CONFIG_PATH = "configs/real_data_v2_converged_seed1.yaml"
NAMES = feature_columns(load_config(CONFIG_PATH))
N20 = 70_000
N_GROUPS = 3
PSEUDO_DAYS = tuple(d for d in L.LODO_DAYS if d != L.HOST_SPLIT_DAY)

# ----------------------------------------------------------------------------- default configurations (pre-registered, docs/19 0.3)
HGB_DEFAULT = dict(learning_rate=0.1, max_leaf_nodes=31, min_samples_leaf=20, l2_regularization=0.0, class_weight=None)


def hgb_grid() -> list[dict]:
    """Default first, then 12 configurations drawn without replacement (seed 0) from the 32-point full factorial of docs/19 0.3."""
    import itertools
    full = [dict(learning_rate=lr, max_leaf_nodes=ml, min_samples_leaf=ms, l2_regularization=l2, class_weight=cw)
            for lr, ml, ms, l2, cw in itertools.product([0.05, 0.15], [8, 31], [20, 300], [0.0, 10.0], [None, "balanced"])]
    rng = np.random.default_rng(0)
    pick = [full[i] for i in rng.permutation(len(full)) if full[i] != HGB_DEFAULT]
    return [HGB_DEFAULT] + pick[:12]


def tree_grid() -> list[dict]:
    return [dict(min_samples_leaf=m, class_weight=cw) for m in (5, 50) for cw in (None, "balanced_subsample")]


def lr_grid() -> list[dict]:
    return [dict(C=c, class_weight=cw) for c in (0.01, 0.1, 1.0) for cw in (None, "balanced")]


GRIDS = {"HGB": hgb_grid, "ET": tree_grid, "RF": tree_grid, "LR": lr_grid}


# ----------------------------------------------------------------------------- estimators
class Model:
    """fit(F, y) / score(F) wrapper: NaN-aware HGB, or median-imputed ET / RF / LR (LR additionally standardises and clips at +/-6)."""

    def __init__(self, family: str, cfg: dict, n_threads: int = 4):
        self.family, self.cfg, self.n_threads = family, dict(cfg), n_threads

    def fit(self, F: np.ndarray, y: np.ndarray) -> "Model":
        from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
        from sklearn.linear_model import LogisticRegression
        from threadpoolctl import threadpool_limits
        y = (np.asarray(y) > 0).astype(int)
        c = self.cfg
        with threadpool_limits(self.n_threads):
            if self.family == "HGB":
                self.est = HistGradientBoostingClassifier(max_iter=200, early_stopping=False, random_state=0, **c).fit(F, y)
                return self
            self.med = np.nanmedian(F, axis=0)
            self.med = np.where(np.isnan(self.med), 0.0, self.med)
            Fi = np.where(np.isnan(F), self.med, F)
            if self.family in ("ET", "RF"):
                cls = ExtraTreesClassifier if self.family == "ET" else RandomForestClassifier
                self.est = cls(n_estimators=150, max_features="sqrt", n_jobs=self.n_threads, random_state=0, **c).fit(Fi, y)
            elif self.family == "LR":
                self.mu, self.sd = Fi.mean(0), Fi.std(0) + 1e-6
                self.est = LogisticRegression(max_iter=500, **c).fit(np.clip((Fi - self.mu) / self.sd, -6, 6), y)
            else:
                raise ValueError(self.family)
        return self

    def score(self, F: np.ndarray, batch: int = 200_000) -> np.ndarray:
        from threadpoolctl import threadpool_limits
        out = []
        with threadpool_limits(self.n_threads):
            for i in range(0, len(F), batch):
                f = F[i:i + batch]
                if self.family != "HGB":
                    f = np.where(np.isnan(f), self.med, f)
                    if self.family == "LR":
                        f = np.clip((f - self.mu) / self.sd, -6, 6)
                out.append(self.est.predict_proba(f)[:, 1])
        return np.concatenate(out)


# ----------------------------------------------------------------------------- data: per-day feature caches
def _day_dir(day: str) -> Path:
    return DATA / day


def prep_context(day: str) -> None:
    """Causal rolling-baseline context for the FULL day (all hosts of 02-20), computed before any subsampling."""
    L.assert_sealed([day])
    out = _day_dir(day)
    out.mkdir(parents=True, exist_ok=True)
    if (out / "ctx.npz").exists():
        return
    X = np.load(SRC / day / "X.npy", mmap_mode="r")
    last = np.asarray(X[:, -1, :])
    unit = np.load(SRC / day / "src_ip.npy")
    t = np.load(SRC / day / "window_end_time.npy")
    mu, sd = F5.causal_context(F5.vol_last_log(last, NAMES), unit, t)
    np.savez(out / "ctx.npz", mu=mu.astype(np.float64), sd=sd.astype(np.float64))


def prep_variant(day: str, variant: str, chunk: int = 100_000, X_override=None, tag: str = "") -> None:
    L.assert_sealed([day])
    out = _day_dir(day)
    f = out / f"{variant}{tag}.npy"
    if f.exists():
        return
    prep_context(day)
    X = np.load(SRC / day / "X.npy", mmap_mode="r") if X_override is None else X_override
    T = np.load(SRC / day / "window_times.npy", mmap_mode="r")
    z = np.load(out / "ctx.npz")
    n = len(X)
    arr, names = None, None
    for i in range(0, n, chunk):
        sl = slice(i, min(n, i + chunk))
        Fc, names = F5.build_features(np.asarray(X[sl]), NAMES, variant, T=np.asarray(T[sl]), ctx=(z["mu"][sl], z["sd"][sl]))
        if arr is None:
            arr = np.lib.format.open_memmap(str(f) + ".tmp.npy", mode="w+", dtype=np.float32, shape=(n, Fc.shape[1]))
        arr[sl] = Fc
    arr.flush()
    del arr
    Path(str(f) + ".tmp.npy").replace(f)
    (out / f"{variant}{tag}.names.json").write_text(json.dumps(names), encoding="utf-8")


def feature_names(variant: str) -> list[str]:
    return json.loads((_day_dir(PSEUDO_DAYS[0]) / f"{variant}.names.json").read_text(encoding="utf-8"))


class Pool:
    """The docs/18 training pool (six pseudo-host days in full + the fixed 70,000-row sample of 02-20) for one feature variant, plus
    memory-mapped full 02-20 features for the held-out host groups. Row order is identical to eval.lodo_v4_run.load_pool."""

    def __init__(self, variant: str, n20: int = N20, seed: int = 0, features: bool = True):
        self.variant = variant
        F, y, day, host, time_ = [], [], [], [], []
        for d in L.LODO_DAYS:
            inf = np.load(SRC / d / "infiltration.npy", mmap_mode="r")
            src = np.load(SRC / d / "src_ip.npy")
            wt = np.load(SRC / d / "window_end_time.npy")
            if d == L.HOST_SPLIT_DAY:
                n = len(inf)
                self.idx20 = np.sort(np.random.default_rng(seed).choice(n, n20, replace=False))
                sel = self.idx20
                self.y20 = (np.asarray(inf[:, 0]) > 0)
                self.h20 = src.astype(str)
                self.t20 = wt
                self.F20 = np.load(_day_dir(d) / f"{variant}.npy", mmap_mode="r") if features else None
            else:
                sel = np.arange(len(inf))
            if features:
                Fd = np.load(_day_dir(d) / f"{variant}.npy", mmap_mode="r")
                F.append(np.asarray(Fd[sel]))
            y.append((np.asarray(inf[sel, 0]) > 0).astype(np.int8))
            day += [d] * len(sel)
            host += list(src[sel].astype(str))
            time_.append(wt[sel])
        self.F = np.concatenate(F) if features else None
        self.y = np.concatenate(y)
        self.day = np.array(day)
        self.host = np.array(host)
        self.time = np.concatenate(time_)
        self.host_group = L.assign_host_groups(set(self.h20), set(self.h20[self.y20]), N_GROUPS, seed=0)
        for h in set(self.host):
            self.host_group.setdefault(h, 0)

    def folds(self) -> list[L.Fold]:
        return L.build_folds(n_groups=N_GROUPS)

    def outer(self, fold: L.Fold) -> dict:
        """train mask over the pool and the held-out arrays of an outer fold (leakage assertions run here)."""
        tr, he = L.fold_masks(fold, self.day, self.host, self.host_group)
        L.assert_no_leakage(fold, self.day, self.host, tr, he, self.host_group)
        if fold.group is None:
            idx = np.flatnonzero(he)
            return {"train": tr, "idx": idx, "y": self.y[idx], "F": (self.F[idx] if self.F is not None else None),
                    "time": self.time[idx], "host": self.host[idx]}
        g = np.array([self.host_group[h] for h in self.h20])
        idx = np.flatnonzero(g == fold.group)
        return {"train": tr, "idx": idx, "y": self.y20[idx].astype(np.int8),
                "F": (np.asarray(self.F20[idx]) if self.F20 is not None else None), "time": self.t20[idx], "host": self.h20[idx]}


def inner_folds(pool: Pool, train: np.ndarray) -> list[tuple[str, np.ndarray]]:
    """[(name, boolean mask over pool rows that is held out)] for the outer-train rows: every pseudo-host day whole, plus the 02-20 sample."""
    out = []
    for d in L.LODO_DAYS:
        m = train & (pool.day == d)
        if m.any() and (pool.y[m].min() != pool.y[m].max()):
            out.append((d, m))
    return out


def auc(y, s):
    return L._auc(y, s)


# ----------------------------------------------------------------------------- tasks run in worker processes
def inner_task(F, y, train_idx, held_idx, family, cfg, n_threads=4):
    m = Model(family, cfg, n_threads).fit(F[train_idx], y[train_idx])
    return m.score(F[held_idx]).astype(np.float32)


def timer():
    t0 = time.time()
    return lambda: time.time() - t0
