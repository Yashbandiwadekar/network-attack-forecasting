"""Deterministic scapy-written captures for the live-engine tests (no network, no real traffic)."""
from __future__ import annotations

import random
from pathlib import Path

from scapy.all import IP, TCP, UDP, Ether, wrpcap

BASE = 1_760_000_000 - (1_760_000_000 % 10)   # a 10 s boundary
LINK = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")


def dense_pcap(path: Path, seconds: int = 300, n_hosts: int = 6, seed: int = 7, base: int = BASE,
               port_offset: int = 0, long_flows: bool = False) -> Path:
    """`n_hosts` clients (10.0.0.x) talk to a few servers (10.0.1.x) for `seconds`: every host starts a short
    TCP flow (SYN, SYN-ACK, ACK, data both ways, FIN) most seconds plus an occasional UDP query, so every
    host has a flow in nearly every 10 s window (=> 12-window sequences exist). Flows last < 3 s."""
    rng = random.Random(seed)
    pkts = []
    sport = 20000 + port_offset
    for t in range(seconds):
        for h in range(1, n_hosts + 1):
            if rng.random() < 0.55:
                continue
            src, dst = f"10.0.0.{h}", f"10.0.1.{rng.randint(1, 3)}"
            sport += 1
            dport = rng.choice([22, 80, 443])
            t0 = base + t + rng.random() * 0.4
            seq = [(src, dst, sport, dport, "S", 0.0, 0), (dst, src, dport, sport, "SA", 0.02 + rng.random() * 0.05, 0),
                   (src, dst, sport, dport, "A", 0.08, 0)]
            for k in range(rng.randint(1, 4)):
                seq.append((src, dst, sport, dport, "PA", 0.2 + 0.31 * k, rng.randint(20, 400)))
                seq.append((dst, src, dport, sport, "PA", 0.3 + 0.31 * k, rng.randint(20, 900)))
            seq.append((src, dst, sport, dport, "FA", 1.9 + rng.random() * 0.5, 0))
            for a, b, sp, dp, fl, dt, ln in seq:
                p = LINK / IP(src=a, dst=b) / TCP(sport=sp, dport=dp, flags=fl) / (b"x" * ln)
                p.time = t0 + dt
                pkts.append(p)
            if rng.random() < 0.3:
                sport += 1
                p = LINK / IP(src=src, dst="10.0.1.9") / UDP(sport=sport, dport=53) / (b"q" * 30)
                p.time = t0 + 0.5
                pkts.append(p)
    if long_flows:
        # one connection per host that lives for the whole capture (a packet every 4 s): it crosses many
        # flow-timeout buckets and many windows, which is what the live engine's anchors exist for
        for h in range(1, n_hosts + 1):
            for k in range(0, seconds, 4):
                a, b, sp, dp = (f"10.0.0.{h}", "10.0.1.1", 44000 + h, 22) if k % 8 == 0 else ("10.0.1.1", f"10.0.0.{h}", 22, 44000 + h)
                p = LINK / IP(src=a, dst=b) / TCP(sport=sp, dport=dp, flags="PA") / (b"k" * 16)
                p.time = base + k + 0.05 * h
                pkts.append(p)
    pkts.sort(key=lambda p: float(p.time))
    wrpcap(str(path), pkts)
    return path
