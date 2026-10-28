"""FULLY SYNTHETIC campaign generator for tests and for the correctness check of the stage forecaster.

Every number it produces is a property of the generator's own parameters.  It is evidence that the
machinery (event building -> chain linking -> Markov estimate) recovers a KNOWN answer, and nothing else:
it says nothing about real attackers, and no result computed on it may be quoted as such.

A campaign (one attacker A, one victim V, distinct IPs per campaign, all separated in time by hours):

    reconnaissance      A -> V and `n_decoys` other targets          label PortScan
      p_ia   -> initial_access     A -> V                          label SSH-Bruteforce
        p_c2   -> command_and_control  V -> C2 server              label Bot            (direction flips!)
          p_exfil -> exfiltration       V -> drop server           label SYNTH-Exfiltration
      (otherwise the chain ENDS there)

The gap between consecutive stage onsets is exponential with `mean_gap_s[i]`, floored at `min_gap_s`.
Benign background flows (random host pairs, including some from the attacker/victim addresses) are added.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

BASE = pd.Timestamp("2026-01-05 00:00:00")


def synthetic_campaigns(n_campaigns: int = 400, p_ia: float = 0.7, p_c2: float = 0.6, p_exfil: float = 0.5,
                        mean_gap_s: tuple[float, float, float] = (420.0, 600.0, 480.0), min_gap_s: float = 30.0,
                        n_decoys: int = 3, stage_len_s: tuple[float, float] = (60.0, 200.0),
                        flows_per_event: tuple[int, int] = (15, 40), campaign_spacing_s: float = 6 * 3600.0,
                        background_per_campaign: int = 60, seed: int = 0) -> tuple[pd.DataFrame, dict]:
    """Returns (flows, truth).  flows: canonical-ish frame (timestamp, src_ip, dst_ip, dst_port, protocol, label,
    has_ip_data, unit).  truth: the generating parameters and the realised chains (for audit)."""
    rng = np.random.default_rng(seed)
    rows: list[tuple] = []
    realised = []
    gaps_seen: dict[str, list[float]] = {"recon->initial_access": [], "initial_access->command_and_control": [],
                                         "command_and_control->exfiltration": []}

    def emit(t0, dur, src, dsts, label, port_choices=(22, 80, 443)):
        n = int(rng.integers(flows_per_event[0], flows_per_event[1] + 1))
        ts = np.sort(rng.uniform(t0, t0 + dur, n))
        ds = rng.choice(dsts, n)
        for t, d in zip(ts, ds):
            rows.append((BASE + pd.to_timedelta(float(t), unit="s"), src, str(d), float(rng.choice(port_choices)), 6.0, label))

    for k in range(n_campaigns):
        a = f"172.20.{k // 250}.{k % 250 + 1}"
        v = f"10.{k // 250 + 1}.{k % 250 + 1}.10"
        decoys = [f"10.{k // 250 + 1}.{k % 250 + 1}.{20 + j}" for j in range(n_decoys)]
        c2 = f"203.0.{k // 250}.{k % 250 + 1}"
        drop = f"198.51.{k // 250}.{k % 250 + 1}"
        t = k * campaign_spacing_s + float(rng.uniform(0, 600))
        chain = ["reconnaissance"]
        dur = float(rng.uniform(*stage_len_s))
        emit(t, dur, a, [v] + decoys, "PortScan", tuple(range(1, 1024, 37)))
        onset = t
        end = t + dur
        for nxt, p, mg, gkey in (("initial_access", p_ia, mean_gap_s[0], "recon->initial_access"),
                                 ("command_and_control", p_c2, mean_gap_s[1], "initial_access->command_and_control"),
                                 ("exfiltration", p_exfil, mean_gap_s[2], "command_and_control->exfiltration")):
            if rng.random() >= p:
                break
            gap = max(float(rng.exponential(mg)), min_gap_s)
            gaps_seen[gkey].append(gap)
            onset = onset + gap
            dur = float(rng.uniform(*stage_len_s))
            if nxt == "initial_access":
                emit(onset, dur, a, [v], "SSH-Bruteforce", (22,))
            elif nxt == "command_and_control":
                emit(onset, dur, v, [c2], "Bot", (443, 6667))
            else:
                emit(onset, dur, v, [drop], "SYNTH-Exfiltration", (443,))
            chain.append(nxt)
            end = onset + dur
        realised.append({"attacker": a, "victim": v, "chain": chain, "start_s": t, "end_s": end})
    horizon = n_campaigns * campaign_spacing_s + 7200
    # benign background, including benign traffic from the attacker / victim addresses
    bg_hosts = [f"192.0.2.{i}" for i in range(1, 60)]
    for _ in range(background_per_campaign * n_campaigns):
        s_, d_ = rng.choice(bg_hosts, 2, replace=False)
        rows.append((BASE + pd.to_timedelta(float(rng.uniform(0, horizon)), unit="s"), str(s_), str(d_),
                     float(rng.choice((53, 80, 443))), 6.0, "BENIGN"))
    for r in realised[: max(n_campaigns // 4, 1)]:
        for who in (r["attacker"], r["victim"]):
            rows.append((BASE + pd.to_timedelta(float(r["start_s"] - 3 * 3600), unit="s"), who, bg_hosts[0], 443.0, 6.0, "BENIGN"))
    df = pd.DataFrame(rows, columns=["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "label"])
    df["has_ip_data"] = 1.0
    df["unit"] = "synthetic"
    df = df.sort_values("timestamp", kind="mergesort").reset_index(drop=True)
    truth = {
        "SYNTHETIC": True, "n_campaigns": n_campaigns, "n_decoys": n_decoys, "seed": seed,
        "p": {"reconnaissance->initial_access": p_ia, "initial_access->command_and_control": p_c2,
              "command_and_control->exfiltration": p_exfil},
        "mean_gap_s": {"reconnaissance->initial_access": mean_gap_s[0], "initial_access->command_and_control": mean_gap_s[1],
                       "command_and_control->exfiltration": mean_gap_s[2]},
        "realised_counts": {
            "recon": n_campaigns,
            "recon->ia": int(sum(len(r["chain"]) >= 2 for r in realised)),
            "ia->c2": int(sum(len(r["chain"]) >= 3 for r in realised)),
            "c2->exfil": int(sum(len(r["chain"]) >= 4 for r in realised)),
        },
        "campaigns": realised,
        "t_base": str(BASE),
    }
    return df, truth
