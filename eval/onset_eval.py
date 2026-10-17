"""Onset-only, episode-level evaluation (docs/09 B1, docs/05 R-2; definitions in docs/13).

Every future model change is meant to be measured against this, so the unit of analysis is the
*independent episode* (a host that goes benign -> attacked), not the 10-second window, and every
figure is printed with the number of episodes (and hosts) behind it.

Definitions (also stated, before any result, in docs/13-onset-evaluation.md)
---------------------------------------------------------------------------
* A *sequence* is one model input: L windows ending at the "current" window c, with K future labels.
* Per sequence, from the OBSERVED label of the current window and the K future labels:
    - already-attacking : current window is non-benign
    - onset             : current window benign AND some future window k=1..K is non-benign
    - benign-throughout : current window benign AND all K future windows benign
* An *onset window* p is a window that is non-benign while the previous window is benign. Every onset
  sequence has exactly one onset window (its first non-benign future window).
* An *episode* groups the onset windows of ONE host (key = scenario_id + src_ip) that belong together:
  a later onset window joins the previous episode when it has the same stage and fewer than
  `merge_gap` (default K) benign windows separate it from the end of the previous attack run.
  `merge_gap=0` gives the raw onset events. The episode's onset time T0 is the REAL start time of its
  first onset window.
* An alarm is `score >= threshold`, where score = max over the K rollout infiltration probabilities
  (the same quantity the server compares with ALERT_THRESHOLD). The alarm of a sequence is issued at
  `issue time = start of its current window + window_seconds` (the window is complete).
* Outcome of an episode = classification of its FIRST alarm among the sequences that can see the
  onset (benign origins up to K windows before it) or that follow it inside the episode:
    early    : issue time <  T0                       (lead = T0 - issue time, real seconds)
    on-time  : T0 <= issue time <= T0 + window_seconds
    late     : issue time >  T0 + window_seconds      (delay = issue time - T0)
    missed   : no alarm at all
  Episodes whose onset window lies beyond the last window with a known timestamp (the final K
  windows of a host's timeline, or a split cut) have no real T0 and are reported as `unresolved`.
* An episode is *contiguous* when every window step from the earliest eligible origin's first input
  window to the onset window is exactly `window_seconds`; otherwise it is *gapped* (QC-1).

Per-window timestamps of the K future windows are not stored in the .npz splits. They are
reconstructed from the overlap of consecutive sequences of one host (sequence j+1 shifts the window
times of sequence j by one), never from k * window_seconds.

CLI
---
    python -m eval.onset_eval --config configs/real_data_v2_converged_seed1.yaml
    python -m eval.onset_eval --config configs/real_data_v2_converged_seed1.yaml \
        --checkpoint checkpoints_real_v2_converged/seed2/world_model_best.pt --label seed2
    python -m eval.onset_eval --config configs/real_data_v2_converged_seed1.yaml \
        --data-dir data/processed_adapter/cic2017_zeroshot_60s --splits train,val,test --label cic2017_zeroshot

Inference only (CPU or GPU). No training, no checkpoint or data directory is modified; the only file
written is the JSON result under docs/onset_eval/.
"""
from __future__ import annotations

import argparse
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

NS = 10 ** 9
STAGE_NAMES = {-1: "impact", 0: "benign", 1: "reconnaissance", 2: "initial_access",
               3: "lateral_movement", 4: "command_and_control", 5: "exfiltration"}


# ---------------------------------------------------------------------------
# small statistics helpers
# ---------------------------------------------------------------------------

def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple[float | None, float | None]:
    """Exact binomial CI. (None, None) when n == 0."""
    if n <= 0:
        return None, None
    from scipy.stats import beta
    lo = 0.0 if k == 0 else float(beta.ppf(alpha / 2, k, n - k + 1))
    hi = 1.0 if k == n else float(beta.ppf(1 - alpha / 2, k + 1, n - k))
    return lo, hi


def _prop(k: int, n: int) -> dict[str, Any]:
    lo, hi = clopper_pearson(k, n)
    return {"k": int(k), "n": int(n), "rate": (k / n) if n else None, "ci95_exact": [lo, hi]}


def cluster_rate_ci(flags: np.ndarray, clusters: np.ndarray, B: int = 1000, seed: int = 0) -> dict[str, Any]:
    """Pooled rate of `flags` with a percentile CI from resampling whole clusters (overlapping
    sliding sequences of one stretch are not independent, so a plain binomial CI would be optimistic)."""
    flags = np.asarray(flags, dtype=float)
    n = len(flags)
    if n == 0:
        return {"k": 0, "n": 0, "n_clusters": 0, "rate": None, "ci95_cluster_bootstrap": [None, None]}
    uniq, inv = np.unique(clusters, return_inverse=True)
    m = len(uniq)
    cnt = np.bincount(inv, minlength=m).astype(float)
    pos = np.bincount(inv, weights=flags, minlength=m)
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, m, size=(B, m))
    rates = pos[idx].sum(1) / np.maximum(cnt[idx].sum(1), 1)
    lo, hi = np.percentile(rates, [2.5, 97.5])
    return {"k": int(flags.sum()), "n": int(n), "n_clusters": int(m), "rate": float(flags.sum() / n),
            "ci95_cluster_bootstrap": [float(lo), float(hi)]}


def _boot_median(values: np.ndarray, B: int = 2000, seed: int = 0) -> list[float | None]:
    if len(values) == 0:
        return [None, None]
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(values), size=(B, len(values)))
    med = np.median(values[idx], axis=1)
    lo, hi = np.percentile(med, [2.5, 97.5])
    return [float(lo), float(hi)]


def auroc_cluster_ci(pos: np.ndarray, pos_cl: np.ndarray, neg: np.ndarray, neg_cl: np.ndarray,
                     B: int = 300, seed: int = 0) -> dict[str, Any]:
    """AUROC of onset-origin scores (positives) vs benign-throughout scores (negatives), with a
    two-level cluster bootstrap (positives clustered by episode, negatives by benign stretch)."""
    from scipy.stats import rankdata
    out = {"n_pos": int(len(pos)), "n_pos_episodes": int(len(np.unique(pos_cl))) if len(pos) else 0,
           "n_neg": int(len(neg)), "n_neg_stretches": int(len(np.unique(neg_cl))) if len(neg) else 0,
           "auroc": None, "ci95_cluster_bootstrap": [None, None]}
    if len(pos) == 0 or len(neg) == 0:
        return out

    def _auc(p, q):
        r = rankdata(np.concatenate([p, q]))
        return float((r[:len(p)].sum() - len(p) * (len(p) + 1) / 2) / (len(p) * len(q)))

    out["auroc"] = _auc(pos, neg)
    up, ip = np.unique(pos_cl, return_inverse=True)
    un, in_ = np.unique(neg_cl, return_inverse=True)
    pos_groups = [np.flatnonzero(ip == i) for i in range(len(up))]
    neg_groups = [np.flatnonzero(in_ == i) for i in range(len(un))]
    rng = np.random.default_rng(seed)
    vals = []
    for _ in range(B):
        pi = np.concatenate([pos_groups[i] for i in rng.integers(0, len(up), len(up))])
        ni = np.concatenate([neg_groups[i] for i in rng.integers(0, len(un), len(un))])
        vals.append(_auc(pos[pi], neg[ni]))
    lo, hi = np.percentile(vals, [2.5, 97.5])
    out["ci95_cluster_bootstrap"] = [float(lo), float(hi)]
    return out


# ---------------------------------------------------------------------------
# timeline reconstruction
# ---------------------------------------------------------------------------

def _ns(a) -> np.ndarray:
    return np.asarray(a).astype("datetime64[ns]").astype(np.int64)


@dataclass
class Chain:
    """One host's maximal run of sequences whose windows overlap by L-1 (stride 1)."""
    key: str
    seq: np.ndarray            # global sequence indices, time order; origin c = L-1+i  <->  seq[i]
    t: np.ndarray              # int64 ns window starts for positions 0..last (last = L-1+n-1)
    y: np.ndarray              # int8 observed non-benign flag for positions 0..P-1 (-1 = unknown)
    st: np.ndarray             # int16 stage index per position (-2 = unknown, -1 = impact)
    L: int
    K: int

    @property
    def n(self) -> int:
        return len(self.seq)

    @property
    def last(self) -> int:
        return self.L - 1 + self.n - 1


def build_chains(arr: dict[str, np.ndarray], L: int, K: int) -> tuple[list[Chain], int]:
    """Returns (chains, n_label_mismatches). A mismatch is a sequence whose stored future label k
    disagrees with the label the reconstructed timeline holds for that window; it must be 0."""
    import pandas as pd
    if L < 2:
        raise ValueError("sequence length must be >= 2 to chain overlapping sequences")
    wt = _ns(arr["window_times"])
    n_all = wt.shape[0]
    cur = np.asarray(arr["current_infiltration"]).astype(np.int8)
    fut = np.asarray(arr["infiltration"]).astype(np.int8)
    cst = np.asarray(arr["current_stage"]).astype(np.int16)
    fst = np.asarray(arr["future_stages"]).astype(np.int16)
    src = np.asarray(arr["src_ip"]).astype(str) if "src_ip" in arr else np.full(n_all, "host")
    if "scenario_id" in arr and len(np.asarray(arr["scenario_id"])) == n_all:
        keys = np.char.add(np.char.add(np.asarray(arr["scenario_id"]).astype(str), "|"), src)
    else:
        keys = src
    codes, uniq = pd.factorize(keys)
    order = np.lexsort((wt[:, -1], codes))
    chains: list[Chain] = []
    mism = 0
    ocodes = codes[order]
    bounds = np.flatnonzero(np.diff(ocodes)) + 1
    for grp in np.split(order, bounds):
        if len(grp) == 0:
            continue
        link = (wt[grp[1:], :-1] == wt[grp[:-1], 1:]).all(axis=1)
        cuts = np.flatnonzero(~link) + 1
        for seg in np.split(grp, cuts):
            n = len(seg)
            P = L - 1 + n + K
            t = np.concatenate([wt[seg[0]], wt[seg[1:], -1]])
            y = np.full(P, -1, np.int8)
            st = np.full(P, -2, np.int16)
            y[L - 1:L - 1 + n] = cur[seg]
            st[L - 1:L - 1 + n] = cst[seg]
            y[L - 1 + n:] = fut[seg[-1], :K]
            st[L - 1 + n:] = fst[seg[-1], :K]
            base = L - 1 + np.arange(n)
            for k in range(1, K + 1):
                mism += int((y[base + k] != fut[seg, k - 1]).sum())
            chains.append(Chain(key=str(keys[seg[0]]), seq=seg, t=t, y=y, st=st, L=L, K=K))
    return chains, mism


# ---------------------------------------------------------------------------
# episodes
# ---------------------------------------------------------------------------

@dataclass
class Episode:
    chain: int
    key: str
    stage: int
    p0: int                       # position of the first onset window in the chain timeline
    n_raw: int
    T0_ns: int | None             # real start time of the first onset window (None = unresolved)
    early: list[tuple[int, int]]  # (global seq idx, issue_ns) of benign origins before p0, earliest first
    later: list[tuple[int, int]]  # (global seq idx, issue_ns) of origins from p0 to the end of the episode span
    contiguous: bool
    clean_history: bool = False   # earliest origin's L input windows are all KNOWN benign (no attack in its input history)
    raw_origins: list[tuple[int, int, int]] = field(default_factory=list)  # (global seq idx, raw onset p, k)


def _run_end(y: np.ndarray, p: int) -> int:
    q = p
    while q + 1 < len(y) and y[q + 1] == 1:
        q += 1
    return q


def find_episodes(chains: list[Chain], window_seconds: int, merge_gap: int | None = None
                  ) -> tuple[list[Episode], dict[int, int]]:
    """Episodes over all chains. Returns (episodes, seq_to_episode) where seq_to_episode maps the
    global index of every ONSET sequence to its episode index."""
    ws_ns = int(window_seconds) * NS
    episodes: list[Episode] = []
    seq_to_ep: dict[int, int] = {}
    for ci, ch in enumerate(chains):
        L, K, y, last = ch.L, ch.K, ch.y, ch.last
        mg = K if merge_gap is None else int(merge_gap)
        # step_bad[p] = 1 when the step INTO window p is not exactly window_seconds (unknown -> bad)
        P = len(y)
        bad = np.ones(P, np.int64)
        bad[0] = 0
        if last >= 1:
            bad[1:last + 1] = (np.diff(ch.t) != ws_ns).astype(np.int64)
        csum = np.concatenate([[0], np.cumsum(bad)])  # csum[i] = sum(bad[:i])

        raws: list[dict[str, Any]] = []
        for p in range(L, P):
            if y[p] == 1 and y[p - 1] == 0:
                origins = []
                c = p - 1
                while c >= max(p - K, L - 1) and y[c] == 0:
                    if c <= last:
                        origins.append(c)
                    c -= 1
                if origins:
                    raws.append({"p": p, "stage": int(ch.st[p]), "end": _run_end(y, p), "origins": origins})
        groups: list[list[dict[str, Any]]] = []
        for r in raws:
            if groups and groups[-1][0]["stage"] == r["stage"] and (r["p"] - groups[-1][-1]["end"] - 1) < mg:
                groups[-1].append(r)
            else:
                groups.append([r])
        for g in groups:
            p0 = g[0]["p"]
            early_c = sorted(g[0]["origins"])
            span_end = min(g[-1]["end"], last)
            later_c = [c for c in range(p0, span_end + 1) if c <= last]
            T0 = int(ch.t[p0]) if p0 <= last else None
            a = max(early_c[0] - (L - 1), 0)
            contiguous = bool(p0 <= last and (csum[p0 + 1] - csum[a + 1]) == 0)
            h0 = early_c[0] - (L - 1)
            clean = bool(h0 >= L - 1 and (y[h0:early_c[0] + 1] == 0).all())
            ep = Episode(
                chain=ci, key=ch.key, stage=g[0]["stage"], p0=p0, n_raw=len(g), T0_ns=T0,
                early=[(int(ch.seq[c - (L - 1)]), int(ch.t[c]) + ws_ns) for c in early_c],
                later=[(int(ch.seq[c - (L - 1)]), int(ch.t[c]) + ws_ns) for c in later_c],
                contiguous=contiguous, clean_history=clean,
            )
            ei = len(episodes)
            for r in g:
                for c in r["origins"]:
                    gi = int(ch.seq[c - (L - 1)])
                    ep.raw_origins.append((gi, r["p"], r["p"] - c))
                    seq_to_ep[gi] = ei
            episodes.append(ep)
    return episodes, seq_to_ep


def episode_outcome(ep: Episode, alarm: np.ndarray, window_seconds: int, horizon: int) -> dict[str, Any]:
    ws_ns = int(window_seconds) * NS
    n_early = len(ep.early)
    n_early_alarmed = int(sum(bool(alarm[i]) for i, _ in ep.early))
    base = {"key": ep.key, "stage": STAGE_NAMES.get(ep.stage, str(ep.stage)), "contiguous": ep.contiguous,
            "n_raw_onsets": ep.n_raw, "n_early_origins": n_early, "n_early_origins_alarmed": n_early_alarmed}
    if ep.T0_ns is None:
        return {**base, "outcome": "unresolved", "lead_s": None, "delay_s": None}
    first = None
    for gi, issue in sorted(ep.early + ep.later, key=lambda x: x[1]):
        if alarm[gi]:
            first = issue
            break
    if first is None:
        return {**base, "outcome": "missed", "lead_s": None, "delay_s": None}
    d = first - ep.T0_ns
    if d < 0:
        lead = -d / NS
        return {**base, "outcome": "early", "lead_s": lead, "delay_s": None,
                "lead_within_nominal_horizon": bool(lead <= horizon * window_seconds)}
    if d <= ws_ns:
        return {**base, "outcome": "on_time", "lead_s": None, "delay_s": d / NS}
    return {**base, "outcome": "late", "lead_s": None, "delay_s": d / NS}


def _summarise_outcomes(outs: list[dict[str, Any]], B: int = 2000) -> dict[str, Any]:
    res = [o for o in outs if o["outcome"] != "unresolved"]
    n = len(res)
    cnt = {k: sum(o["outcome"] == k for o in res) for k in ("early", "on_time", "late", "missed")}
    leads = np.array([o["lead_s"] for o in res if o["outcome"] == "early"], dtype=float)
    delays = np.array([o["delay_s"] for o in res if o["outcome"] in ("on_time", "late")], dtype=float)
    return {
        "n_episodes": len(outs), "n_unresolved_time": len(outs) - n, "n_scored": n,
        "n_hosts": len({o["key"] for o in outs}),
        "early": _prop(cnt["early"], n), "on_time": _prop(cnt["on_time"], n),
        "late": _prop(cnt["late"], n), "missed": _prop(cnt["missed"], n),
        "any_alarm_before_or_at_onset_window": _prop(cnt["early"] + cnt["on_time"], n),
        "detected_at_all": _prop(cnt["early"] + cnt["on_time"] + cnt["late"], n),
        "lead_s": {"n": int(len(leads)), "median": float(np.median(leads)) if len(leads) else None,
                   "mean": float(leads.mean()) if len(leads) else None,
                   "min": float(leads.min()) if len(leads) else None,
                   "max": float(leads.max()) if len(leads) else None,
                   "median_ci95_bootstrap": _boot_median(leads, B),
                   "n_within_nominal_horizon": int(sum(o.get("lead_within_nominal_horizon", False) for o in res))},
        "detection_delay_s_on_time_or_late": {"n": int(len(delays)),
                                              "median": float(np.median(delays)) if len(delays) else None},
        "frac_pre_onset_origins_alarmed": _prop(sum(o["n_early_origins_alarmed"] for o in outs),
                                                sum(o["n_early_origins"] for o in outs)),
    }


# ---------------------------------------------------------------------------
# per-sequence populations
# ---------------------------------------------------------------------------

def sequence_categories(arr: dict[str, np.ndarray]) -> np.ndarray:
    """0 = benign-throughout, 1 = onset, 2 = already-attacking (from observed labels only)."""
    cur = np.asarray(arr["current_infiltration"]) > 0.5
    fut_any = (np.asarray(arr["infiltration"]) > 0.5).any(axis=1)
    cat = np.zeros(len(cur), np.int8)
    cat[~cur & fut_any] = 1
    cat[cur] = 2
    return cat


def _stretch_ids(chains: list[Chain], mask: np.ndarray) -> np.ndarray:
    """Cluster id for each sequence in `mask`: maximal runs of consecutive (chain order) members."""
    ids = np.full(len(mask), -1, np.int64)
    nxt = 0
    for ch in chains:
        prev = False
        for g in ch.seq:
            if mask[g]:
                if not prev:
                    nxt += 1
                ids[g] = nxt
                prev = True
            else:
                prev = False
    return ids


def _seq_clean_history(chains: list[Chain], n_total: int) -> np.ndarray:
    """True when all L input windows of the sequence are KNOWN to be benign (labels of the first L-1
    windows of a chain are not stored, so the first L-1 sequences of a chain are never 'clean')."""
    out = np.zeros(n_total, bool)
    for ch in chains:
        L = ch.L
        bad = np.concatenate([[0], np.cumsum(ch.y != 0)])  # unknown (-1) counts as not benign
        c = L - 1 + np.arange(ch.n)
        out[ch.seq] = (bad[c + 1] - bad[c - (L - 1)]) == 0
    return out


def _seq_contiguous(chains: list[Chain], window_seconds: int, n_total: int) -> np.ndarray:
    """True when the sequence's L input windows and K target windows are all exactly window_seconds apart
    AND that is verifiable from stored timestamps (a target window past the last known time is unverifiable
    -> False)."""
    ws_ns = int(window_seconds) * NS
    out = np.zeros(n_total, bool)
    for ch in chains:
        L, K, last = ch.L, ch.K, ch.last
        P = len(ch.y)
        bad = np.ones(P, np.int64)
        bad[0] = 0
        if last >= 1:
            bad[1:last + 1] = (np.diff(ch.t) != ws_ns).astype(np.int64)
        cs = np.concatenate([[0], np.cumsum(bad)])
        c = L - 1 + np.arange(ch.n)
        out[ch.seq] = (cs[c + K + 1] - cs[c - (L - 1) + 1]) == 0
    return out


# ---------------------------------------------------------------------------
# main analysis (pure function over arrays)
# ---------------------------------------------------------------------------

def structure(arr: dict[str, np.ndarray], window_seconds: int, merge_gap: int | None = None) -> dict[str, Any]:
    """Everything that does not depend on the scores/threshold."""
    L = int(np.asarray(arr["window_times"]).shape[1])
    K = int(np.asarray(arr["infiltration"]).shape[1])
    n = len(np.asarray(arr["current_infiltration"]))
    chains, mism = build_chains(arr, L, K)
    episodes, seq_to_ep = find_episodes(chains, window_seconds, merge_gap)
    raw_eps, _ = find_episodes(chains, window_seconds, 0)
    cat = sequence_categories(arr)
    assert sum(len(c.seq) for c in chains) == n
    covered = np.zeros(n, bool)
    covered[list(seq_to_ep)] = True
    if not np.array_equal(covered, cat == 1):
        raise AssertionError("onset sequences and episode origins disagree "
                             f"({int((covered != (cat == 1)).sum())} sequences)")
    return {"L": L, "K": K, "n": n, "chains": chains, "mismatch": mism, "episodes": episodes,
            "raw_episodes": raw_eps, "seq_to_ep": seq_to_ep, "cat": cat,
            "seq_contig": _seq_contiguous(chains, window_seconds, n),
            "seq_clean": _seq_clean_history(chains, n),
            "stretch": _stretch_ids(chains, cat == 0)}


def _host_populations(S: dict[str, Any], arr: dict[str, np.ndarray]) -> dict[str, Any]:
    keys = {}
    for ch in S["chains"]:
        keys.setdefault(ch.key, []).append(ch)
    cat = S["cat"]
    ep_hosts = {e.key for e in S["episodes"]}
    only_benign = attack_first = 0
    for k, chs in keys.items():
        seqs = np.concatenate([c.seq for c in chs])
        if (cat[seqs] == 0).all():
            only_benign += 1
        first = min(chs, key=lambda c: c.t[0])
        if first.y[first.L - 1] == 1:
            attack_first += 1
    return {"n_hosts": len(keys), "n_hosts_with_onset_episode": len(ep_hosts),
            "n_hosts_benign_throughout_only": only_benign,
            "n_hosts_whose_first_observed_window_is_already_attacking": attack_first}


def analyse(arr: dict[str, np.ndarray], scores: np.ndarray, thresholds: dict[str, float],
            window_seconds: int, merge_gap: int | None = None, B: int = 1000, seed: int = 0,
            S: dict[str, Any] | None = None) -> dict[str, Any]:
    """Full report for one dataset and one set of alarm thresholds."""
    S = S or structure(arr, window_seconds, merge_gap)
    K, cat, chains = S["K"], S["cat"], S["chains"]
    scores = np.asarray(scores, dtype=float)
    n = S["n"]
    ep_tail = [e for e in S["episodes"] if e.T0_ns is None]
    result: dict[str, Any] = {
        "window_seconds": int(window_seconds), "L": S["L"], "K": K, "n_sequences": n,
        "timeline_label_mismatches": S["mismatch"], "merge_gap_windows": K if merge_gap is None else merge_gap,
        "sequences": {"benign_throughout": int((cat == 0).sum()), "onset": int((cat == 1).sum()),
                      "already_attacking": int((cat == 2).sum())},
        "hosts": _host_populations(S, arr),
        "episodes": {
            "n_episodes_merged": len(S["episodes"]), "n_raw_onset_events": len(S["raw_episodes"]),
            "n_unresolved_time": len(ep_tail),
            "n_clean_history": sum(e.clean_history for e in S["episodes"]),
            "n_contiguous": sum(e.contiguous for e in S["episodes"]),
            "n_gapped_or_unverifiable": sum(not e.contiguous for e in S["episodes"]),
            "n_hosts": len({e.key for e in S["episodes"]}),
            "by_stage": {STAGE_NAMES.get(s, str(s)): sum(e.stage == s for e in S["episodes"])
                         for s in sorted({e.stage for e in S["episodes"]})},
        },
        "thresholds": {},
    }
    # already-attacking runs (raw)
    runs = []
    for ci, ch in enumerate(chains):
        c = ch.L - 1
        while c <= ch.last:
            if ch.y[c] == 1:
                e = c
                while e + 1 <= ch.last and ch.y[e + 1] == 1:
                    e += 1
                runs.append((ci, c, e))
                c = e + 1
            else:
                c += 1
    result["already_attacking_runs"] = {
        "n_runs": len(runs),
        "n_left_censored_runs(first observed window already attacking)": int(sum(r[1] == chains[r[0]].L - 1 for r in runs)),
    }

    onset_mask, benign_mask, att_mask = cat == 1, cat == 0, cat == 2
    ep_hosts_set = {e.key for e in S["episodes"]}
    same_host_mask = np.zeros(n, bool)
    for ch in chains:
        if ch.key in ep_hosts_set:
            same_host_mask[ch.seq] = True
    seq_ep = np.full(n, -1, np.int64)
    for g, e in S["seq_to_ep"].items():
        seq_ep[g] = e
    k_to = np.zeros(n, np.int64)
    for e in S["episodes"]:
        for gi, _, k in e.raw_origins:
            k_to[gi] = k

    for name, thr in thresholds.items():
        alarm = scores >= thr
        outs = [episode_outcome(e, alarm, window_seconds, K) for e in S["episodes"]]
        for o, e in zip(outs, S["episodes"]):
            o["clean_history"] = e.clean_history
        clean_outs = [o for o in outs if o["clean_history"]]
        cont = [o for o in outs if o["contiguous"]]
        gap = [o for o in outs if not o["contiguous"]]
        fa_all = cluster_rate_ci(alarm[benign_mask], S["stretch"][benign_mask], B, seed)
        fa_c = cluster_rate_ci(alarm[benign_mask & S["seq_contig"]], S["stretch"][benign_mask & S["seq_contig"]], B, seed)
        fa_g = cluster_rate_ci(alarm[benign_mask & ~S["seq_contig"]], S["stretch"][benign_mask & ~S["seq_contig"]], B, seed)
        # alarm bursts on benign-throughout sequences: runs of consecutive alarming sequences in a chain
        bursts = 0
        for ch in chains:
            a = alarm[ch.seq] & benign_mask[ch.seq]
            bursts += int((a & ~np.concatenate([[False], a[:-1]])).sum())
        on_rate = cluster_rate_ci(alarm[onset_mask], seq_ep[onset_mask], B, seed)
        att_rate = cluster_rate_ci(alarm[att_mask], np.array([0] * int(att_mask.sum())), 1, seed)
        att_runs_alarmed = 0
        for ci, a, b in runs:
            ch = chains[ci]
            att_runs_alarmed += int(alarm[ch.seq[a - (ch.L - 1): b - (ch.L - 1) + 1]].any())
        auc = auroc_cluster_ci(scores[onset_mask], seq_ep[onset_mask], scores[benign_mask],
                               S["stretch"][benign_mask], B=min(B, 300), seed=seed)
        per_k = {}
        for k in range(1, K + 1):
            m = onset_mask & (k_to == k)
            per_k[str(k)] = {"n_sequences": int(m.sum()),
                             "n_episodes": int(len(np.unique(seq_ep[m]))) if m.any() else 0,
                             "alarm_rate": float(alarm[m].mean()) if m.any() else None}
        cl = S["seq_clean"]
        fa_same = cluster_rate_ci(alarm[benign_mask & same_host_mask], S["stretch"][benign_mask & same_host_mask], B, seed)
        fa_clean = cluster_rate_ci(alarm[benign_mask & cl], S["stretch"][benign_mask & cl], B, seed)
        result["thresholds"][name] = {
            "threshold": float(thr),
            "episodes_all": _summarise_outcomes(outs),
            "episodes_contiguous": _summarise_outcomes(cont),
            "episodes_clean_history": _summarise_outcomes(clean_outs),
            "episodes_gapped_or_unverifiable": _summarise_outcomes(gap),
            "false_alarm_benign_throughout_sequences": {
                "all": fa_all, "contiguous": fa_c, "gapped_or_unverifiable": fa_g,
                "clean_history": fa_clean, "same_hosts_as_episodes": fa_same, "n_alarm_bursts": bursts, "n_sequences": int(benign_mask.sum())},
            "alarm_rate_on_onset_sequences": on_rate,
            "alarm_rate_on_already_attacking_sequences": {k: att_rate[k] for k in ("k", "n", "rate")},
            "already_attacking_runs_with_any_alarm": {"k": att_runs_alarmed, "n": len(runs)},
            "alarm_rate_by_steps_to_onset": per_k,
            "per_episode": outs,
        }
    cl = S["seq_clean"]
    same_host = same_host_mask
    result["auroc_onset_vs_benign_throughout_same_hosts_only"] = auroc_cluster_ci(
        scores[onset_mask & same_host], seq_ep[onset_mask & same_host],
        scores[benign_mask & same_host], S["stretch"][benign_mask & same_host], B=min(B, 300), seed=seed)
    result["auroc_onset_vs_benign_throughout_clean_history"] = auroc_cluster_ci(
        scores[onset_mask & cl], seq_ep[onset_mask & cl], scores[benign_mask & cl], S["stretch"][benign_mask & cl],
        B=min(B, 300), seed=seed)
    result["auroc_onset_vs_benign_throughout"] = auroc_cluster_ci(
        scores[onset_mask], seq_ep[onset_mask], scores[benign_mask], S["stretch"][benign_mask], B=min(B, 300), seed=seed)
    return result


# ---------------------------------------------------------------------------
# thresholds
# ---------------------------------------------------------------------------

def threshold_for_false_alarm_rate(scores: np.ndarray, benign_mask: np.ndarray, max_rate: float) -> float:
    """Smallest threshold whose alarm rate on the benign-throughout sequences is <= max_rate (fit on
    VALIDATION data only). `score >= t` is the alarm rule."""
    s = np.sort(np.asarray(scores, float)[benign_mask])[::-1]
    if len(s) == 0:
        return float("nan")
    m = int(math.floor(max_rate * len(s)))
    if m >= len(s):
        return float(s[-1])
    return float(np.nextafter(s[m], np.inf))


# ---------------------------------------------------------------------------
# model scoring + CLI
# ---------------------------------------------------------------------------

def rollout_scores(model, scaler, X: np.ndarray, horizon: int, device) -> np.ndarray:
    """(N, K) rollout infiltration probabilities, identical to eval.benchmark / ForecastEngine."""
    import torch
    from eval.benchmark import _rollout_infiltration_probs
    Xs = torch.tensor(scaler.transform(X), dtype=torch.float32)
    return _rollout_infiltration_probs(model, Xs, horizon, device)


def _load_splits(d: Path, names: list[str]) -> dict[str, np.ndarray]:
    parts = []
    for nme in names:
        z = np.load(d / f"{nme}.npz", allow_pickle=False)
        parts.append({k: z[k] for k in z.files})
    keys = set(parts[0]).intersection(*[set(p) for p in parts[1:]])
    return {k: np.concatenate([p[k] for p in parts], axis=0) for k in keys}


def _fmt_prop(p: dict) -> str:
    if p["n"] == 0:
        return "n/a (0 episodes)"
    lo, hi = p["ci95_exact"]
    return f"{p['k']}/{p['n']} = {p['rate']:.0%} [{lo:.0%}-{hi:.0%}]"


def print_report(label: str, res: dict[str, Any]) -> None:
    print(f"\n=== {label} ===")
    s, e = res["sequences"], res["episodes"]
    print(f"sequences {res['n_sequences']}: benign-throughout {s['benign_throughout']}, onset {s['onset']}, "
          f"already-attacking {s['already_attacking']}; hosts {res['hosts']}")
    print(f"episodes (merge gap {res['merge_gap_windows']} windows): {e['n_episodes_merged']} merged over "
          f"{e['n_hosts']} host(s) [{e['n_raw_onset_events']} raw onset events]; contiguous {e['n_contiguous']}, "
          f"gapped/unverifiable {e['n_gapped_or_unverifiable']}, time-unresolved {e['n_unresolved_time']}; by stage {e['by_stage']}")
    print(f"timeline label mismatches: {res['timeline_label_mismatches']} (must be 0); "
          f"already-attacking runs {res['already_attacking_runs']}")
    a = res["auroc_onset_vs_benign_throughout"]
    print(f"AUROC onset-origin vs benign-throughout: {a['auroc']} CI {a['ci95_cluster_bootstrap']} "
          f"({a['n_pos_episodes']} episodes, {a['n_neg_stretches']} benign stretches)")
    a2 = res["auroc_onset_vs_benign_throughout_clean_history"]
    print(f"AUROC, clean input history only: {a2['auroc']} CI {a2['ci95_cluster_bootstrap']} "
          f"({a2['n_pos_episodes']} episodes, {a2['n_neg_stretches']} benign stretches); clean-history episodes: {e['n_clean_history']}")
    a3 = res["auroc_onset_vs_benign_throughout_same_hosts_only"]
    print(f"AUROC, negatives from the SAME hosts as the episodes only: {a3['auroc']} CI {a3['ci95_cluster_bootstrap']} "
          f"({a3['n_pos_episodes']} episodes, {a3['n_neg_stretches']} benign stretches)")
    for name, t in res["thresholds"].items():
        print(f"-- threshold {name} = {t['threshold']:.4f}")
        for grp in ("episodes_all", "episodes_contiguous", "episodes_gapped_or_unverifiable", "episodes_clean_history"):
            g = t[grp]
            print(f"   {grp:34s} n={g['n_episodes']} ({g['n_hosts']} host) scored={g['n_scored']}: "
                  f"early {_fmt_prop(g['early'])}; on-time {_fmt_prop(g['on_time'])}; "
                  f"late {_fmt_prop(g['late'])}; missed {_fmt_prop(g['missed'])}; "
                  f"median lead {g['lead_s']['median']} s (n={g['lead_s']['n']})")
        fa = t["false_alarm_benign_throughout_sequences"]
        for nm in ("all", "contiguous", "gapped_or_unverifiable", "clean_history", "same_hosts_as_episodes"):
            f = fa[nm]
            ci = f.get("ci95_cluster_bootstrap")
            print(f"   false alarm [{nm}]: {f['k']}/{f['n']} sequences"
                  + (f" = {f['rate']:.1%} CI {ci[0]:.1%}-{ci[1]:.1%} ({f['n_clusters']} stretches)" if f['rate'] is not None else ""))
        o = t["alarm_rate_on_onset_sequences"]
        print(f"   alarm rate on onset sequences: {o['k']}/{o['n']} = {o['rate']} CI {o['ci95_cluster_bootstrap']} ({o['n_clusters']} episodes)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", required=True, help="model config (checkpoint_dir, processed_dir = scaler + validation data)")
    ap.add_argument("--checkpoint", default=None, help="checkpoint .pt (default: <checkpoint_dir>/world_model_best.pt)")
    ap.add_argument("--data-dir", default=None, help="processed dir to evaluate (default: the config's processed_dir)")
    ap.add_argument("--splits", default="test", help="comma list of splits of --data-dir to concatenate")
    ap.add_argument("--label", default=None)
    ap.add_argument("--window-seconds", type=int, default=None, help="default: data-dir metadata, else config")
    ap.add_argument("--alert-threshold", type=float, default=None, help="default: app.service.ALERT_THRESHOLD (0.40)")
    ap.add_argument("--val-false-alarm", default="0.05,0.01", help="validation false-alarm budgets for the fixed thresholds")
    ap.add_argument("--merge-gap", type=int, default=None, help="windows (default K); 0 = raw onset events")
    ap.add_argument("--bootstrap", type=int, default=1000)
    ap.add_argument("--out", default=None, help="JSON path (default docs/onset_eval/<label>.json)")
    a = ap.parse_args(argv)

    import torch
    from common.config import load_config, resolve_path
    from models.dataset import FeatureScaler
    from models.forecast import load_world_model
    from eval.metrics import lead_time_metrics, threshold_at_fpr

    config = load_config(a.config)
    ckpt = Path(a.checkpoint) if a.checkpoint else resolve_path(config, "checkpoint_dir") / "world_model_best.pt"
    label = a.label or ckpt.parent.name
    src_dir = resolve_path(config, "processed_dir")
    data_dir = Path(a.data_dir) if a.data_dir else src_dir
    if a.alert_threshold is None:
        from app.service import ALERT_THRESHOLD as alert
    else:
        alert = a.alert_threshold
    ws = a.window_seconds
    if ws is None:
        mp = data_dir / "metadata.json"
        ws = int(json.loads(mp.read_text(encoding="utf-8")).get("window_seconds", config["windowing"]["window_seconds"])) \
            if mp.exists() else int(config["windowing"]["window_seconds"])

    model, _ = load_world_model(ckpt)
    device = next(model.parameters()).device
    scaler = FeatureScaler.load(src_dir / "scaler.npz")
    K = int(config["windowing"]["forecast_horizon"])

    val = _load_splits(src_dir, ["val"])
    val_probs = rollout_scores(model, scaler, val["X"], K, device)
    val_score = val_probs.max(axis=1)
    val_ws = int(config["windowing"]["window_seconds"])
    val_cat = sequence_categories(val)
    thresholds = {"served_0.40": float(alert)}
    for tok in a.val_false_alarm.split(","):
        r = float(tok)
        thresholds[f"val_fixed_fa{r:g}"] = threshold_for_false_alarm_rate(val_score, val_cat == 0, r)

    arr = _load_splits(data_dir, a.splits.split(","))
    probs = rollout_scores(model, scaler, arr["X"], K, device)
    score = probs.max(axis=1)
    res = analyse(arr, score, thresholds, ws, a.merge_gap, a.bootstrap)
    res["meta"] = {"label": label, "config": a.config, "checkpoint": str(ckpt), "data_dir": str(data_dir),
                   "splits": a.splits, "window_seconds_eval": ws, "window_seconds_training": val_ws,
                   "score": "max over K rollout infiltration probabilities",
                   "threshold_source": "served = app.service.ALERT_THRESHOLD; val_fixed = "
                                       f"fit on {src_dir} val split (benign-throughout sequences), never on the evaluated data",
                   "device": str(device)}
    res["validation_reference"] = {"n_val_sequences": int(len(val_score)), "val_sequences_by_category": {
        "benign_throughout": int((val_cat == 0).sum()), "onset": int((val_cat == 1).sum()),
        "already_attacking": int((val_cat == 2).sum())}}

    # QC-3 sequence-level lead time (eval.metrics.lead_time_metrics), at the benchmark's own threshold
    # (5% FPR on val single-step probs) and at the served threshold. Window-step based, kept only so the
    # README numbers can be re-run; the episode-level numbers above are the ones to use.
    val_t1 = val_probs[:, 0]
    bench_thr = threshold_at_fpr(np.asarray(val["infiltration"])[:, 0], val_t1, 0.05)
    legacy = {}
    for nm, thr in (("benchmark_val_5pct_fpr_t1", bench_thr), ("served_0.40", float(alert))):
        lt = lead_time_metrics(np.asarray(arr["infiltration"]), np.asarray(arr["current_infiltration"]), probs, thr, ws)
        legacy[nm] = {"threshold": float(thr), **(lt or {"n_transitions": 0})}
    res["legacy_qc3_lead_time_sequence_level"] = legacy

    print_report(label, res)
    out = Path(a.out) if a.out else Path(__file__).resolve().parents[1] / "docs" / "onset_eval" / f"{label}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=1, default=str), encoding="utf-8")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
