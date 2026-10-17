"""Markov next-stage forecaster over stage events (docs/14-stage-forecasting.md).

A continuous-time Markov chain on kill-chain stages, estimated by counting:

  * states      the stage of the entity's latest event (first order) or (previous stage, latest stage)
                (second order, interpolated with the first-order estimate = backoff);
  * outcomes    the next stage (any of the stages except the current one, because adjacent events of the same
                stage are collapsed) or END (the chain provably ended: nothing followed within `max_chain_gap_s`);
  * P(next = b | a) = (n_ab + alpha) / (n_a + alpha * |outcomes|)                Laplace smoothing
  * timing      GIVEN that a next stage happens, the onset-to-onset time is exponential with rate
                mu_a = (n_a + k) / (E_a + k / mu_pool): n_a followed events of state a, E_a their total
                onset-to-onset time PLUS the `observed_until - start` of events still open when the data ended
                (right-censored: their exposure counts, no transition does).  Chains that ended contribute
                nothing to mu: their END probability already sits in P(next = END), counting their silent
                `max_chain_gap_s` as exposure too would double-count it.  A Gamma(k, k/mu_pool) prior shrinks
                small states towards the pooled rate.  (Transitions longer than `max_chain_gap_s` cannot be
                seen, so mu is biased slightly high when gaps approach that limit.)
  * forecast    P(next stage = b within H) = P(next = b | a) * (1 - exp(-mu_a * H));  what is left,
                1 - sum_b, is "no further stage within H" (the chain ends, or the next stage comes later).
                Expected time to the next stage = 1 / mu_a, conditional on a next stage occurring at all.

`order=0` is the marginal-frequency baseline (state ignored): same output, same machinery, so any gain from
state is measured against it.  Everything serialises to JSON (`to_dict` / `from_dict` / `save` / `load`),
there is no pickle; the object is loadable in the server later.  Pure Python + math: no torch, no numpy.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from pipeline.stage_events import (
    DEFAULT_MAX_CHAIN_GAP_S, STAGES, Chain, _merge_events,
)

END = "<end>"
SCHEMA = "naf.stage_forecaster/1"


def _canon_events(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    evs = sorted((dict(e) for e in events), key=lambda e: (e["start_s"], e["end_s"]))
    out: list[dict[str, Any]] = []
    for e in evs:
        if out and out[-1]["stage"] == e["stage"]:
            out[-1] = _merge_events(out[-1], e)
        else:
            out.append(e)
    return out


@dataclass
class Forecast:
    entity: str
    view: str
    state: dict[str, Any]
    horizon_s: float
    p_next_within_horizon: dict[str, float]
    p_next: dict[str, float]                    # P(next = b), no horizon; includes END
    p_any_stage_within_horizon: float
    p_no_further_stage_within_horizon: float
    expected_time_to_next_s: float
    rate_per_s: float
    ranked_victims: list[dict[str, Any]]
    evidence: dict[str, Any]
    top_stage: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in (
            "entity", "view", "state", "horizon_s", "p_next_within_horizon", "p_next",
            "p_any_stage_within_horizon", "p_no_further_stage_within_horizon", "expected_time_to_next_s",
            "rate_per_s", "top_stage", "ranked_victims", "evidence")}


class StageForecaster:
    def __init__(self, order: int = 1, alpha: float = 1.0, beta: float = 2.0, min_support2: int = 2,
                 rate_prior_events: float = 1.0, max_chain_gap_s: float = DEFAULT_MAX_CHAIN_GAP_S,
                 stages: list[str] | None = None):
        if order not in (0, 1, 2):
            raise ValueError("order must be 0 (marginal baseline), 1 or 2")
        if alpha <= 0:
            raise ValueError("alpha must be > 0 (Laplace smoothing keeps unseen transitions possible)")
        self.order, self.alpha, self.beta, self.min_support2 = order, float(alpha), float(beta), int(min_support2)
        self.rate_prior_events = float(rate_prior_events)
        self.max_chain_gap_s = float(max_chain_gap_s)
        self.stages = list(stages or STAGES)
        self.counts1: dict[str, dict[str, int]] = {}      # state -> outcome -> n
        self.counts2: dict[str, dict[str, int]] = {}      # "prev|state" -> outcome -> n
        self.exposure: dict[str, float] = {}              # state -> total exposure seconds
        self.target = {"pairs": 0, "hits": 0}             # recon targets that were attacked next
        self.fit_info: dict[str, Any] = {"n_chains": 0, "n_events": 0, "n_transitions": 0, "n_end": 0, "n_censored": 0}

    # ------------------------------------------------------------------ fitting
    def _s1(self, stage: str) -> str:
        return "*" if self.order == 0 else stage

    def fit(self, chains: Iterable[Chain], observed_until: float | None = None, sign: int = 1) -> "StageForecaster":
        """Count transitions over `chains` (already collapsed by stage_events.link_chains).  Calling fit again
        ADDS to the counts; build a fresh object for a different training set.  `sign=-1` removes the
        contribution of chains that were added earlier with the SAME `observed_until` (exact leave-out)."""
        w = 1 if sign >= 0 else -1
        ch = list(chains)
        if observed_until is None:
            observed_until = max((e["end_s"] for c in ch for e in c.events), default=0.0)
        fi = self.fit_info
        for c in ch:
            fi["n_chains"] += w
            evs = _canon_events(c.events)
            for i, e in enumerate(evs):
                fi["n_events"] += w
                a = e["stage"]
                s1 = self._s1(a)
                prev = evs[i - 1]["stage"] if i > 0 else None
                if i + 1 < len(evs):
                    nxt = evs[i + 1]
                    out, expo = nxt["stage"], max(nxt["start_s"] - e["start_s"], 0.0)
                    fi["n_transitions"] += w
                    if self.order >= 1 and e["stage"] == RECON and nxt["stage"] != RECON and e["dsts"] and nxt["dsts"]:
                        self.target["pairs"] += w
                        self.target["hits"] += w * int(bool(set(e["dsts"]) & set(nxt["dsts"])))
                elif c.terminated:
                    out, expo = END, 0.0
                    fi["n_end"] += w
                else:
                    fi["n_censored"] += w
                    self.exposure[s1] = self.exposure.get(s1, 0.0) + w * max(observed_until - e["start_s"], 0.0)
                    continue
                self.counts1.setdefault(s1, {})
                self.counts1[s1][out] = self.counts1[s1].get(out, 0) + w
                self.exposure[s1] = self.exposure.get(s1, 0.0) + w * expo
                if self.order == 2 and prev is not None:
                    k2 = f"{prev}|{a}"
                    self.counts2.setdefault(k2, {})
                    self.counts2[k2][out] = self.counts2[k2].get(out, 0) + w
        return self

    def copy(self) -> "StageForecaster":
        return StageForecaster.from_dict(json.loads(json.dumps(self.to_dict())))

    # ------------------------------------------------------------------ estimates
    def outcomes(self, state_stage: str) -> list[str]:
        """Possible outcomes after `state_stage`: every other stage, plus END (same-stage repeats are collapsed
        into one event, so they are structurally impossible; order 0 has no state, all stages are possible)."""
        return [s for s in self.stages if self.order == 0 or s != state_stage] + [END]

    def _p1(self, state_stage: str) -> dict[str, float]:
        outs = self.outcomes(state_stage)
        row = self.counts1.get(self._s1(state_stage), {})
        n = sum(row.get(o, 0) for o in outs)
        den = n + self.alpha * len(outs)
        return {o: (row.get(o, 0) + self.alpha) / den for o in outs}

    def _pooled_rate(self) -> float:
        n = sum(v for r in self.counts1.values() for k, v in r.items() if k != END)
        e = sum(self.exposure.values())
        return (n / e) if n > 0 and e > 0 else 1.0 / self.max_chain_gap_s

    def rate(self, state_stage: str) -> float:
        pool = self._pooled_rate()
        row = self.counts1.get(self._s1(state_stage), {})
        n = sum(v for k, v in row.items() if k != END)
        e = self.exposure.get(self._s1(state_stage), 0.0)
        k = self.rate_prior_events
        return (n + k) / (e + k / pool)

    def next_distribution(self, state_stage: str, prev_stage: str | None = None) -> tuple[dict[str, float], int, dict[str, Any]]:
        """(P(next = outcome), order actually used, support info)."""
        p1 = self._p1(state_stage)
        info = {"n_from_state": sum(self.counts1.get(self._s1(state_stage), {}).values()),
                "counts": dict(self.counts1.get(self._s1(state_stage), {}))}
        if self.order == 2 and prev_stage is not None:
            row = self.counts2.get(f"{prev_stage}|{state_stage}", {})
            n2 = sum(row.values())
            info["n_from_state_given_prev"] = n2
            info["counts_given_prev"] = dict(row)
            if n2 >= self.min_support2:
                p = {o: (row.get(o, 0) + self.beta * p1[o]) / (n2 + self.beta) for o in p1}
                return p, 2, info
        return p1, (0 if self.order == 0 else 1), info

    # ------------------------------------------------------------------ prediction
    def predict(self, events: Iterable[dict[str, Any]], horizon_s: float, now: float | None = None,
                entity: str = "", view: str = "attacker", top_victims: int = 10) -> Forecast:
        """Forecast for one live entity from its events so far (raw events; adjacent same-stage events are
        collapsed here).  `now` defaults to the end of the latest event."""
        evs = _canon_events(events)
        if not evs:
            raise ValueError("predict needs at least one event")
        cur = evs[-1]
        prev = evs[-2] if len(evs) > 1 else None
        now = cur["end_s"] if now is None else float(now)
        a = cur["stage"]
        p, used, info = self.next_distribution(a, prev["stage"] if prev else None)
        lam = self.rate(a)
        within = 1.0 - math.exp(-lam * float(horizon_s))
        pw = {s: p[s] * within for s in p if s != END}
        p_any = sum(pw.values())
        top = max(pw, key=pw.get) if pw else None
        victims = self._rank_victims(evs, view, top_victims)
        evidence = {
            "order_used": used, "state": a, "previous_stage": prev["stage"] if prev else None,
            "support": info, "pooled_rate_per_s": self._pooled_rate(),
            "p_chain_ends": p[END],
            "current_event": {k: cur[k] for k in ("event_id", "start_s", "end_s", "n_flows", "source", "confidence") if k in cur},
            "recon_events_used": [e.get("event_id") for e in evs if e["stage"] == RECON],
            "p_next_victim_in_recon_targets": (self.target["hits"] + 1) / (self.target["pairs"] + 2),
            "target_stats": dict(self.target),
            "trained_on": dict(self.fit_info),
        }
        return Forecast(entity=entity, view=view,
                        state={"stage": a, "start_s": cur["start_s"], "end_s": cur["end_s"],
                               "elapsed_s": max(now - cur["start_s"], 0.0)},
                        horizon_s=float(horizon_s), p_next_within_horizon=pw, p_next=p,
                        p_any_stage_within_horizon=p_any, p_no_further_stage_within_horizon=1.0 - p_any,
                        expected_time_to_next_s=1.0 / lam, rate_per_s=lam, ranked_victims=victims,
                        evidence=evidence, top_stage=top)

    def _rank_victims(self, evs: list[dict[str, Any]], view: str, k: int) -> list[dict[str, Any]]:
        """Likely next victims = targets touched during reconnaissance, by share of recon flows.  Meaningful for
        the attacker and pair views only (in the victim/host view the entity IS the target)."""
        if view not in ("attacker", "pair"):
            return []
        tot: dict[str, int] = {}
        for e in evs:
            if e["stage"] == RECON:
                for ip, n in e["dsts"].items():
                    tot[ip] = tot.get(ip, 0) + n
        if not tot:
            return []
        hit_after = set()
        seen_recon = False
        for e in evs:
            if e["stage"] == RECON:
                seen_recon = True
            elif seen_recon:
                hit_after |= set(e["dsts"])
        s = sum(tot.values())
        rows = [{"ip": ip, "recon_flows": n, "score": n / s, "already_targeted_after_recon": ip in hit_after}
                for ip, n in sorted(tot.items(), key=lambda kv: (-kv[1], kv[0]))]
        return rows[:k]

    # ------------------------------------------------------------------ views for reporting
    def transition_table(self) -> dict[str, Any]:
        """Counts, smoothed probabilities and rates per state (first order), for the docs."""
        rows = {}
        for a in (self.stages if self.order else ["*"]):
            c = self.counts1.get(a, {})
            n = sum(c.values())
            p = self._p1(a) if self.order else self._p1(self.stages[0])
            rows[a] = {"n": n, "counts": c, "p_smoothed": {k: round(v, 4) for k, v in p.items()},
                       "exposure_s": self.exposure.get(a, 0.0), "rate_per_s": self.rate(a if self.order else self.stages[0]),
                       "mean_time_to_next_event_s": 1.0 / self.rate(a if self.order else self.stages[0])}
        return rows

    # ------------------------------------------------------------------ serialisation (JSON, no pickle)
    def to_dict(self) -> dict[str, Any]:
        return {"schema": SCHEMA, "order": self.order, "alpha": self.alpha, "beta": self.beta,
                "min_support2": self.min_support2, "rate_prior_events": self.rate_prior_events,
                "max_chain_gap_s": self.max_chain_gap_s, "stages": self.stages, "counts1": self.counts1,
                "counts2": self.counts2, "exposure": self.exposure, "target": self.target, "fit_info": self.fit_info}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "StageForecaster":
        if d.get("schema") != SCHEMA:
            raise ValueError(f"not a {SCHEMA} document (schema={d.get('schema')!r})")
        m = cls(d["order"], d["alpha"], d["beta"], d["min_support2"], d["rate_prior_events"], d["max_chain_gap_s"], d["stages"])
        m.counts1 = {k: {kk: int(vv) for kk, vv in v.items()} for k, v in d["counts1"].items()}
        m.counts2 = {k: {kk: int(vv) for kk, vv in v.items()} for k, v in d["counts2"].items()}
        m.exposure = {k: float(v) for k, v in d["exposure"].items()}
        m.target = {k: int(v) for k, v in d["target"].items()}
        m.fit_info = dict(d["fit_info"])
        return m

    def save(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(self.to_dict(), indent=1, sort_keys=True), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "StageForecaster":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


RECON = STAGES[0]
