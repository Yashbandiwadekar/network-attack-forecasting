"""Causal engineered features for the classical baselines of docs/19 (docs/16 action 4 + temporal / normalised features).

Pure numpy/pandas-free functions of arrays; no file is read or written. Input rows are the 12-window raw sequences already used by the
Transformer and by eval.baseline_gate (X: N x 12 x 41, T: N x 12 window start times), plus an optional per-unit "causal context".

CAUSALITY CONTRACT (tested in tests/test_features_v5.py)
  * The features of a row depend only on that row's own 12 windows (all <= its prediction time t) and, for the context block, on the
    LAST windows of EARLIER sequences of the SAME unit (host, or the pseudo-host of a day) with strictly smaller last-window time.
  * No label of any kind (current/past infiltration, stage) is an input. "time since last quiet window" is computed from flow_count.
  * Row order is irrelevant (context is computed after sorting by (unit, time)); deleting or replacing every row with a later time
    changes nothing for the rows at or before t.
  * Warm-up: a row with fewer than `min_periods` earlier windows in its unit gets NaN context features (HistGradientBoosting handles
    NaN natively; the LR path imputes the train median).

Variants (docs/19 section 0.2) are cumulative recipes; `VARIANTS[name]` documents each.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np

# --- feature groups (by name; see configs/real_data_v2_converged.yaml) ---
ZERO9 = ["mean_ttl", "var_ttl", "mean_window_size", "frag_ratio", "mean_payload_size", "std_payload_size", "port_scan_score",
         "retransmit_ratio", "has_packet_features"]
IDENT = ["has_ip_data", "unique_dst_ips", "graph_out_degree", "graph_fan_out_ratio", "graph_fan_in_ratio", "graph_component_size",
         "graph_dst_entropy"] + [f"graph_embed_{i}" for i in range(8)]
LOG_COLS = ["flow_count", "unique_dst_ports", "total_bytes", "total_packets", "mean_duration", "mean_iat", "var_iat", "max_iat"]
VOL = ["flow_count", "unique_dst_ports", "total_bytes", "total_packets", "mean_duration"]     # temporal / context base features
LEVEL_VOL = ["flow_count", "unique_dst_ports", "total_bytes", "total_packets", "bytes_per_flow", "packets_per_flow"]  # absolute volume levels
Z_FLOOR = 0.1               # log-domain floor for a standard deviation used as a denominator
CTX_WINDOW = 120            # previous sequences (10 s each on pseudo-host days = 20 min) in the rolling baseline
CTX_MIN = 12                # warm-up: fewer earlier windows -> NaN
STACK_BLOCKS = ("last", "mean", "std", "d1", "d6", "max")


@dataclass(frozen=True)
class Variant:
    name: str
    drop_zero9: bool = False
    drop_ident: bool = False
    log: bool = False
    ratio: bool = False
    temporal: bool = False
    ctx: bool = False
    relative_only: bool = False
    doc: str = ""


VARIANTS: dict[str, Variant] = {v.name: v for v in [
    Variant("S0_stacked41", doc="current HGB_stacked: all 41 raw features x 6 stack blocks (anchor, reproduces docs/18)"),
    Variant("S1_no_zero9", drop_zero9=True, doc="S0 without the 9 always-zero packet features"),
    Variant("S2_no_ident", drop_zero9=True, drop_ident=True,
            doc="S1 without has_ip_data, unique_dst_ips, 5 graph features, 8 graph_embed features (17 behavioural features)"),
    Variant("S3_log", drop_zero9=True, drop_ident=True, log=True, doc="S2 with log1p on count/volume/duration/IAT features before stacking"),
    Variant("S4_ratio", drop_zero9=True, drop_ident=True, log=True, ratio=True,
            doc="S3 + per-window ratio/rate features (bytes/packet, packets/flow, bytes/flow, ports/flow, syn-ack, rst+fin)"),
    Variant("S5_temporal", drop_zero9=True, drop_ident=True, log=True, ratio=True, temporal=True,
            doc="S4 + causal in-sequence features (z / jump / slope / burst vs the earlier 11 windows, spike count, seconds since quiet, gaps)"),
    Variant("S6_context", drop_zero9=True, drop_ident=True, log=True, ratio=True, temporal=True, ctx=True,
            doc="S5 + z / difference of the last window against the unit's rolling baseline of the previous 120 sequences (causal)"),
    Variant("S7_relative", drop_zero9=True, drop_ident=True, log=True, ratio=True, temporal=True, ctx=True, relative_only=True,
            doc="S6 without the absolute LEVEL blocks (last/mean/max) of the volume features: only relative / shape information about volume"),
]}


def _idx(names: list[str], cols: list[str]) -> list[int]:
    return [names.index(c) for c in cols]


def base_columns(names: list[str], v: Variant) -> list[str]:
    drop = set()
    if v.drop_zero9:
        drop |= set(ZERO9)
    if v.drop_ident:
        drop |= set(IDENT)
    return [n for n in names if n not in drop]


def window_matrix(X: np.ndarray, names: list[str], v: Variant) -> tuple[np.ndarray, list[str]]:
    """(N, L, F') per-window features of the variant: kept raw columns (log1p on LOG_COLS if v.log), then the ratio features."""
    cols = base_columns(names, v)
    A = (np.array(X, dtype=np.float32, order="C") if len(cols) == len(names)       # S0: identical bytes to eval.baseline_gate.stack_features
         else X[:, :, _idx(names, cols)].astype(np.float32, copy=True))
    if v.log:
        for k, c in enumerate(cols):
            if c in LOG_COLS:
                A[:, :, k] = np.log1p(np.maximum(A[:, :, k], 0.0))
    out_names = list(cols)
    if v.ratio:
        g = lambda c: X[:, :, names.index(c)].astype(np.float64)
        fc, pk, by, pt = g("flow_count"), g("total_packets"), g("total_bytes"), g("unique_dst_ports")
        eps = 1.0
        extra = {
            "bytes_per_packet": np.log1p(by / np.maximum(pk, eps)),
            "packets_per_flow": np.log1p(pk / np.maximum(fc, eps)),
            "bytes_per_flow": np.log1p(by / np.maximum(fc, eps)),
            "ports_per_flow": pt / np.maximum(fc, eps),
            "syn_minus_ack": g("syn_ratio") - g("ack_ratio"),
            "rst_plus_fin": g("rst_ratio") + g("fin_ratio"),
        }
        for k, a in extra.items():
            A = np.concatenate([A, a[:, :, None].astype(np.float32)], axis=2)
            out_names.append(k)
    return A, out_names


def stack_blocks(A: np.ndarray, cols: list[str], relative_only: bool = False) -> tuple[np.ndarray, list[str]]:
    """last, mean, std, d1 (last - previous), d6 (last - 6 back), max over the windows of every column (same recipe as
    eval.baseline_gate.stack_features). relative_only drops last/mean/max of the absolute volume LEVEL columns."""
    L = A.shape[1]
    back = min(6, L - 1)
    blocks = {"last": A[:, -1], "mean": A.mean(1), "std": A.std(1), "d1": A[:, -1] - A[:, -2], "d6": A[:, -1] - A[:, -1 - back], "max": A.max(1)}
    keep_cols = list(range(len(cols)))
    parts, names = [], []
    for b in STACK_BLOCKS:
        ks = keep_cols
        if relative_only and b in ("last", "mean", "max"):
            ks = [k for k in keep_cols if cols[k] not in LEVEL_VOL]
        parts.append(blocks[b][:, ks])
        names += [f"{b}:{cols[k]}" for k in ks]
    return np.concatenate(parts, axis=1), names


def temporal_block(A: np.ndarray, cols: list[str], T: np.ndarray | None) -> tuple[np.ndarray, list[str]]:
    """Causal in-sequence features from the (log-domain) VOL columns and the window times. Everything uses only the 12 windows of the
    row: 'prior' = windows 0..L-2, 'last' = window L-1."""
    N, L, _ = A.shape
    outs, names = [], []
    t_idx = np.arange(L, dtype=np.float64)
    tc = t_idx - t_idx.mean()
    for c in VOL:
        k = cols.index(c)
        a = A[:, :, k].astype(np.float64)
        prior, last = a[:, :-1], a[:, -1]
        mu, sd = prior.mean(1), prior.std(1)
        outs += [(last - mu) / np.maximum(sd, Z_FLOOR), last - np.median(prior, axis=1),
                 (a * tc).sum(1) / (tc ** 2).sum(),                      # OLS slope over the 12 windows
                 a[:, -3:].max(1) - a[:, :-3].mean(1)]                   # burst: max of last 3 minus mean of the earlier 9
        names += [f"tz:{c}", f"tjump:{c}", f"tslope:{c}", f"tburst:{c}"]
    k = cols.index("flow_count")
    fc = A[:, :, k].astype(np.float64)
    med = np.median(fc, axis=1, keepdims=True)
    outs.append((fc > med + np.log(3.0)).sum(1).astype(np.float64))      # windows with >3x the 12-window median flow_count
    names.append("spike_count")
    quiet = fc <= med                                                    # label-free "quiet" windows
    if T is not None:
        tsec = (np.asarray(T).astype("datetime64[s]").astype(np.int64)).astype(np.float64)
        span = tsec[:, -1] - tsec[:, 0]
        dt_last = tsec[:, -1] - tsec[:, -2]
        any_q = quiet.any(1)
        lastq = L - 1 - np.argmax(quiet[:, ::-1], axis=1)                # index of the latest quiet window
        since = np.where(any_q, tsec[:, -1] - tsec[np.arange(N), lastq], span + 10.0)
        outs += [since, dt_last, span]
        names += ["secs_since_quiet", "dt_last", "span"]
    else:
        any_q = quiet.any(1)
        lastq = L - 1 - np.argmax(quiet[:, ::-1], axis=1)
        outs.append(np.where(any_q, (L - 1 - lastq) * 10.0, L * 10.0))
        names.append("secs_since_quiet")
    return np.stack(outs, axis=1).astype(np.float32), names


# ------------------------------------------------------------------ causal per-unit context (rolling baseline)

def vol_last_log(X_last: np.ndarray, names: list[str]) -> np.ndarray:
    """(N, 5) log1p of the VOL features of the LAST window of each row."""
    return np.log1p(np.maximum(X_last[:, _idx(names, VOL)].astype(np.float64), 0.0))


def causal_context(vals: np.ndarray, unit: np.ndarray, time: np.ndarray, window: int = CTX_WINDOW, min_periods: int = CTX_MIN
                   ) -> tuple[np.ndarray, np.ndarray]:
    """Per-row mean / std (N, K) of the K columns of `vals` over the previous <= `window` rows of the same unit with STRICTLY
    smaller time (the row itself and equal-time rows are excluded), NaN when fewer than `min_periods` earlier rows exist.
    Order-invariant: rows are sorted by (unit, time, original index) internally. `vals` of a row is its last window, so a row sees
    only windows that ended before its own last window."""
    vals = np.asarray(vals, dtype=np.float64)
    N, K = vals.shape
    _, ucode = np.unique(np.asarray(unit).astype(str), return_inverse=True)
    tt = np.asarray(time).astype("datetime64[us]").astype(np.int64)
    order = np.lexsort((np.arange(N), tt, ucode))
    u, t, v = ucode[order], tt[order], vals[order]
    # position of each sorted row inside its unit, and the number of earlier rows with strictly smaller time
    starts = np.r_[0, np.flatnonzero(np.diff(u)) + 1]
    unit_start = np.repeat(starts, np.diff(np.r_[starts, N]))
    # first sorted index of each (unit, time) group: rows with equal time must not see each other
    key_change = np.r_[True, (u[1:] != u[:-1]) | (t[1:] != t[:-1])]
    grp_first = np.maximum.accumulate(np.where(key_change, np.arange(N), 0))
    n_prev = np.minimum(grp_first - unit_start, window)                   # earlier rows available (strictly earlier time)
    C = np.vstack([np.zeros((1, K)), np.cumsum(v, axis=0)])
    C2 = np.vstack([np.zeros((1, K)), np.cumsum(v * v, axis=0)])
    hi = grp_first                                                       # exclusive end index
    lo = hi - n_prev
    n = np.maximum(n_prev, 1)[:, None].astype(np.float64)
    s, s2 = C[hi] - C[lo], C2[hi] - C2[lo]
    mean = s / n
    var = np.maximum(s2 / n - mean ** 2, 0.0)
    bad = (n_prev < min_periods)[:, None]
    mean = np.where(bad, np.nan, mean)
    sd = np.where(bad, np.nan, np.sqrt(var))
    out_m, out_s = np.empty_like(mean), np.empty_like(sd)
    out_m[order], out_s[order] = mean, sd
    return out_m, out_s


def context_block(A: np.ndarray, cols: list[str], ctx: tuple[np.ndarray, np.ndarray]) -> tuple[np.ndarray, list[str]]:
    """z-score and difference of the last window of each VOL feature against the unit's rolling baseline (NaN in warm-up)."""
    mu, sd = ctx
    outs, names = [], []
    for j, c in enumerate(VOL):
        last = A[:, -1, cols.index(c)].astype(np.float64)
        outs += [(last - mu[:, j]) / np.maximum(sd[:, j], Z_FLOOR), last - mu[:, j]]
        names += [f"cz:{c}", f"crel:{c}"]
    return np.stack(outs, axis=1).astype(np.float32), names


def build_features(X: np.ndarray, names: list[str], variant: str | Variant, T: np.ndarray | None = None,
                   ctx: tuple[np.ndarray, np.ndarray] | None = None) -> tuple[np.ndarray, list[str]]:
    """Feature matrix (N, F) float32 and column names for `variant`. `ctx` = causal_context(vol_last_log(X[:, -1]), unit, time)
    is required for variants with ctx=True (compute it on the FULL unit series before chunking or subsampling)."""
    v = VARIANTS[variant] if isinstance(variant, str) else variant
    A, cols = window_matrix(X, names, v)
    if v.ctx and ctx is None:
        raise ValueError(f"variant {v.name} needs the causal context (see causal_context)")
    F, fn = stack_blocks(A, cols, v.relative_only)
    parts, out_names = [F], list(fn)
    if v.ratio and not v.log:
        raise ValueError("ratio features assume log=True")
    if v.temporal or v.ctx:
        # the temporal/context blocks need log-domain VOL columns even when v.log is False (not used by any registered variant)
        tb, tn = temporal_block(A, cols, T)
        parts.append(tb)
        out_names += tn
    if v.ctx:
        cb, cn = context_block(A, cols, ctx)
        parts.append(cb)
        out_names += cn
    return np.concatenate(parts, axis=1).astype(np.float32), out_names


def ablate_feature(X: np.ndarray, names: list[str], cols: list[str], values: np.ndarray) -> np.ndarray:
    """Copy of X with every window of the named raw columns replaced by `values` (e.g. the train mean). Derived features
    (log, ratios, rolling stats, z-scores, deltas, context) are rebuilt from the ablated X, so nothing derived from the feature survives
    except through other columns."""
    Y = np.array(X, copy=True)
    for c, val in zip(cols, np.atleast_1d(values)):
        Y[:, :, names.index(c)] = val
    return Y
