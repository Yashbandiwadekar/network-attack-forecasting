"""Reusable, dependency-light diagnostic helpers used by docs/16-diagnosis-and-improvement-plan.md.

Everything here is a pure function of numpy arrays: no file is read or written, no checkpoint or scaler is
touched, so the functions are safe to call on any split.
"""
from __future__ import annotations

import numpy as np


def _auc(y: np.ndarray, s: np.ndarray) -> float | None:
    from sklearn.metrics import roc_auc_score
    y = np.asarray(y)
    if y.size == 0 or y.min() == y.max():
        return None
    return float(roc_auc_score(y, s))


def per_unit_auroc(y: np.ndarray, score: np.ndarray, unit: np.ndarray) -> dict:
    """AUROC pooled, within each unit (e.g. day), and with every score replaced by its unit's mean score.

    The 'unit_mean' AUROC measures how much of the pooled ranking is only the between-unit offset
    (units with a higher base rate also getting higher scores); 'within' is the ranking inside each unit.
    Units with a single class report None. 'mean_within' averages the defined within-unit AUROCs unweighted.
    """
    y = np.asarray(y).astype(float)
    score = np.asarray(score, dtype=float)
    unit = np.asarray(unit).astype(str)
    out: dict = {"pooled": _auc(y, score), "within": {}, "unit_rate": {}, "unit_mean_score": {}, "n": {}}
    mean_by = {}
    for u in np.unique(unit):
        m = unit == u
        out["within"][u] = _auc(y[m], score[m])
        out["unit_rate"][u] = float(y[m].mean())
        out["unit_mean_score"][u] = float(score[m].mean())
        out["n"][u] = int(m.sum())
        mean_by[u] = score[m].mean()
    out["unit_mean"] = _auc(y, np.array([mean_by[u] for u in unit]))
    vals = [v for v in out["within"].values() if v is not None]
    out["mean_within"] = float(np.mean(vals)) if vals else None
    return out


def univariate_auroc(X_last: np.ndarray, y: np.ndarray, names: list[str]) -> dict[str, float | None]:
    """AUROC of each raw feature (last input window) as a score for y. Constant features give 0.5."""
    out: dict[str, float | None] = {}
    for j, n in enumerate(names):
        col = X_last[:, j]
        out[n] = 0.5 if np.ptp(col) == 0 else _auc(y, col)
    return out


def clip_rates(X: np.ndarray, mean: np.ndarray, std: np.ndarray, clip_std: float = 6.0) -> np.ndarray:
    """Per-feature fraction of values (over all sequences and steps) whose standardized value exceeds +/-clip_std."""
    z = (X.reshape(-1, X.shape[-1]) - mean) / std
    return (np.abs(z) > clip_std).mean(axis=0)


def smd_and_ks(ref: np.ndarray, other: np.ndarray, mean: np.ndarray | None = None, std: np.ndarray | None = None,
               max_n: int = 200_000, seed: int = 0) -> dict[str, np.ndarray]:
    """Per-feature standardized mean difference ((other-ref)/ref_std, ref std floored like FeatureScaler) and KS statistic.
    ref/other: (N, F) or (N, L, F) arrays; rows are subsampled to max_n for the KS."""
    from scipy.stats import ks_2samp
    r = ref.reshape(-1, ref.shape[-1]).astype(np.float64)
    o = other.reshape(-1, other.shape[-1]).astype(np.float64)
    mu = r.mean(0) if mean is None else mean
    sd = r.std(0) if std is None else std
    sd = np.where(sd < 1e-6, 1.0, sd)
    smd = (o.mean(0) - mu) / sd
    rng = np.random.default_rng(seed)
    ri = r[rng.choice(len(r), min(max_n, len(r)), replace=False)]
    oi = o[rng.choice(len(o), min(max_n, len(o)), replace=False)]
    ks = np.array([ks_2samp(ri[:, j], oi[:, j]).statistic if (np.ptp(ri[:, j]) > 0 or np.ptp(oi[:, j]) > 0) else 0.0
                   for j in range(r.shape[1])])
    return {"smd": smd, "ks": ks}


def constant_features(X: np.ndarray, tol: float = 1e-9) -> np.ndarray:
    """Boolean mask of features whose std over all rows is <= tol."""
    return X.reshape(-1, X.shape[-1]).std(axis=0) <= tol


def high_corr_pairs(X: np.ndarray, names: list[str], thresh: float = 0.95) -> list[tuple[str, str, float]]:
    """Feature pairs with |Pearson r| >= thresh (constant features are skipped)."""
    flat = X.reshape(-1, X.shape[-1]).astype(np.float64)
    keep = np.where(flat.std(0) > 1e-9)[0]
    c = np.corrcoef(flat[:, keep], rowvar=False)
    out = []
    for a in range(len(keep)):
        for b in range(a + 1, len(keep)):
            if abs(c[a, b]) >= thresh:
                out.append((names[keep[a]], names[keep[b]], float(c[a, b])))
    return sorted(out, key=lambda t: -abs(t[2]))


def noisy_auroc(y_true: np.ndarray, score: np.ndarray, fn_rate: float, fp_rate: float, seed: int = 0, reps: int = 20) -> dict:
    """Simulation, NOT a measurement: how the AUROC measured against corrupted labels moves when the true
    labels are flipped at the assumed rates (a true positive recorded as 0 with prob fn_rate, a true negative
    recorded as 1 with prob fp_rate). `score` is held fixed. Returns mean/sd over reps.
    For a score that perfectly ranks y_true this is the ceiling the noise imposes."""
    rng = np.random.default_rng(seed)
    y_true = np.asarray(y_true).astype(int)
    vals = []
    for _ in range(reps):
        flip = np.where(y_true == 1, rng.random(len(y_true)) < fn_rate, rng.random(len(y_true)) < fp_rate)
        y_obs = np.where(flip, 1 - y_true, y_true)
        a = _auc(y_obs, score)
        if a is not None:
            vals.append(a)
    return {"mean": float(np.mean(vals)), "sd": float(np.std(vals))}


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    from scipy.stats import beta
    lo = 0.0 if k == 0 else float(beta.ppf(alpha / 2, k, n - k + 1))
    hi = 1.0 if k == n else float(beta.ppf(1 - alpha / 2, k + 1, n - k))
    return lo, hi


def n_for_rate_zero_events(p_alt: float, alpha: float = 0.05) -> int:
    """Smallest n such that, if the true event rate were p_alt, seeing 0 events in n independent units has
    probability < alpha (one-sided): (1-p_alt)^n < alpha."""
    return int(np.ceil(np.log(alpha) / np.log(1 - p_alt)))


def hanley_mcneil_se(auc: float, n_pos: int, n_neg: int) -> float:
    """Hanley-McNeil (1982) standard error of an AUROC with n_pos/n_neg INDEPENDENT cases."""
    q1 = auc / (2 - auc)
    q2 = 2 * auc ** 2 / (1 + auc)
    var = (auc * (1 - auc) + (n_pos - 1) * (q1 - auc ** 2) + (n_neg - 1) * (q2 - auc ** 2)) / (n_pos * n_neg)
    return float(np.sqrt(max(var, 0.0)))


def min_detectable_auroc(auc0: float, n_pos: int, n_neg: int, z_alpha: float = 1.96, z_power: float = 0.8416) -> float:
    """Approximate minimum AUROC gap above `auc0` (e.g. 0.5) detectable with 80% power at two-sided alpha 0.05
    when the AUROC is estimated from n_pos/n_neg independent cases (Hanley-McNeil SE evaluated at auc0).
    Returns the delta, an optimistic bound (it ignores the extra variance of comparing two estimated AUROCs)."""
    se = hanley_mcneil_se(auc0, n_pos, n_neg)
    return float((z_alpha + z_power) * se)


def unit_balanced_auroc(y: np.ndarray, score: np.ndarray, unit: np.ndarray) -> float | None:
    """AUROC in which every unit (e.g. host or host-scenario series) carries total weight 1, however many
    sequences it contributes. The ordinary sequence-level AUROC lets one long series dominate (CTU-13: one bot
    host contributes 67% of the positive sequences); comparing the two shows how much a number rests on a few units."""
    from sklearn.metrics import roc_auc_score
    y = np.asarray(y)
    if y.size == 0 or y.min() == y.max():
        return None
    unit = np.asarray(unit).astype(str)
    _, inv, counts = np.unique(unit, return_inverse=True, return_counts=True)
    return float(roc_auc_score(y, score, sample_weight=1.0 / counts[inv]))


def load(spec: str) -> dict[str, np.ndarray]:
    """Read-only loader. spec = 'dir:split1,split2' -> arrays of the listed .npz splits concatenated on axis 0
    (only keys present in every split are kept; allow_pickle=False, so no pickled code can run)."""
    from pathlib import Path
    d, _, splits = spec.rpartition(":")   # the split list never contains ':'; a Windows drive letter in d is fine
    parts = []
    for s in splits.split(","):
        z = np.load(Path(d) / f"{s}.npz", allow_pickle=False)
        parts.append({k: z[k] for k in z.files})
    keys = set(parts[0]).intersection(*[set(q) for q in parts[1:]])
    return {k: np.concatenate([q[k] for q in parts]) for k in keys}


def day_of(arr: dict) -> np.ndarray:
    """Calendar day (YYYY-MM-DD string) of each sequence's last input window, from `window_end_time`."""
    return arr["window_end_time"].astype("datetime64[D]").astype(str)
