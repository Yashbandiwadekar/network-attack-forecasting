"""F1 -- randomised lab-campaign recorder (docs/20 section 7, "Forecasting").

WHAT THIS IS. A driver that FABRICATES ATT&CK-style campaign captures for the owner's own isolated
forecasting research (SIH 2026). It synthesises packet captures (PCAP) and matching ground-truth
labels (a sidecar CSV in pipeline/adapters/sidecar.py format) for randomised kill-chains over benign
background. It does NOT attack, scan, or connect to any real host: every packet is written straight
into a .pcap file with scapy's wrpcap, so the output is a recording of traffic that never left the
process. The point is to produce many held-out, whole-campaign labelled episodes so the forecaster's
early-warning rate can be measured (docs/14 section 5; docs/20 F1). Nothing here is evidence about real
attackers -- it is a controlled stimulus with a known ground truth, exactly like eval/synthetic_campaigns.py
but emitted as PCAP+sidecar so it exercises the real pcap adapter and stage-event builder end to end.

RANDOMISATION (docs/20 F1: "randomised gaps, IPs, stage subsets and tools, plus negative chains"):
  * IPs           -- distinct per campaign (attacker, victim, decoys, c2 server, drop server);
  * gaps          -- exponential inter-stage onset gaps, randomised per stage;
  * stage subsets -- each campaign realises a prefix of the kill chain (it can stop after any stage),
                     plus optional lateral_movement and an impact (DoS/DDoS) finisher;
  * tools         -- each stage draws a label/port profile from a small menu (e.g. SSH vs FTP brute,
                     Bot over 443 vs 8080), so the model cannot memorise one script;
  * negative chains -- recon-only campaigns that go nowhere, and benign-only campaigns, so false alarms
                     on never-followed events are measurable (docs/14 section 5.2: 30/31 alarmed).

VOCABULARY. Labels are only the strings pipeline.mitre_mapping.label_to_stage understands (docs/14
section 6 table). An unknown label maps to `impact` silently, so the menus below are kept to known names.

OUTPUT (one folder, --out):
  <out>/pcap/campaign_XXXX.pcap   one capture per campaign (Ethernet / IPv4 / TCP|UDP)
  <out>/labels.csv               merged sidecar covering every campaign (src,dst,start,end,label,dst_port)
  <out>/campaign_log.jsonl       one line per scripted action, second-resolution timestamps (the "second
                                 timestamp log" of docs/20 F1) -- the ground truth independent of the PCAP
  <out>/manifest.json           per-campaign realised chain, IPs, negative flag, and train/holdout split
  <out>/RECORDER.txt            provenance: seed, parameters, git-less build stamp, the "not evidence" note

Then build events and evaluate (docs/14 section 7):
  python -m pipeline.stage_events --input <out>/pcap --adapter pcap --labels-sidecar <out>/labels.csv \
      --name lab_f1 --views host,attacker,pair --merge-gap 30 --min-flows 5
  python -m eval.stage_forecast_eval --events-dir data/processed_adapter/stage_events_lab_f1 \
      --view host --fold entity --horizon 600 --thresholds 0.25,0.5 --max-chain-gap 3600 --label lab_f1

Hold out WHOLE campaigns (manifest "split"=="holdout"): thresholds are frozen on the training campaigns.
"""
from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap

# --- stage menus: (label, ports, kind) -- label must be a name label_to_stage knows (docs/14 section 6) ---
RECON = [("PortScan", tuple(range(1, 1024, 37)), "scan")]
INITIAL_ACCESS = [
    ("SSH-Bruteforce", (22,), "brute"),
    ("FTP-BruteForce", (21,), "brute"),
    ("SSH-Patator", (22,), "brute"),
    ("FTP-Patator", (21,), "brute"),
    ("Brute Force -Web", (80, 443), "brute"),
    ("SQL Injection", (80, 443), "web"),
]
LATERAL = [("Infiltration", (445,), "lateral"), ("Infiltration", (3389,), "lateral")]
C2 = [("Bot", (443,), "beacon"), ("Bot", (8080,), "beacon"), ("Bot", (6667,), "beacon")]
EXFIL = [("SYNTH-Exfiltration", (443,), "bulk")]
IMPACT = [
    ("DDoS attacks-LOIC-HTTP", (80,), "flood"),
    ("DoS attacks-Hulk", (80,), "flood"),
    ("DoS attacks-GoldenEye", (80,), "flood"),
    ("DoS attacks-SlowHTTPTest", (80,), "slow"),
]

BENIGN_PORTS = (53, 80, 443, 123, 8443)
PROTO_TCP, PROTO_UDP = 6, 17

# fixed locally-administered MACs: pinning them stops scapy trying to ARP-resolve a route (no lab NIC here)
_MAC_A, _MAC_B = "02:00:00:00:00:01", "02:00:00:00:00:02"


def _eth() -> "Ether":
    return Ether(src=_MAC_A, dst=_MAC_B)


@dataclass
class Action:
    """One scripted stage: a labelled block of flows in one direction over [start_s, end_s]."""
    label: str
    src: str
    dst: str
    ports: tuple
    start_s: float
    end_s: float
    kind: str
    stage: str
    n_flows: int


@dataclass
class Campaign:
    idx: int
    attacker: str
    victim: str
    decoys: list
    c2: str
    drop: str
    lateral_target: str
    start_s: float
    actions: list = field(default_factory=list)
    chain: list = field(default_factory=list)
    negative: str = ""  # "", "recon_only", or "benign_only"


def _rand_ip(rng: random.Random, net: str) -> str:
    """A documentation-range address (RFC 5737 / RFC 1918); never a routable public host."""
    return f"{net}.{rng.randint(1, 254)}"


def _payload(rng: random.Random, kind: str) -> bytes:
    sizes = {
        "scan": (0, 40), "brute": (20, 120), "web": (120, 600), "lateral": (60, 400),
        "beacon": (16, 200), "bulk": (600, 1400), "flood": (40, 300), "slow": (0, 60),
        "benign": (40, 800),
    }[kind]
    n = rng.randint(*sizes)
    return bytes(rng.getrandbits(8) for _ in range(n)) if n else b""


def _emit_packets(pkts: list, act_or_bg, rng: random.Random, proto: int = PROTO_TCP):
    """Append scapy packets for one labelled block (or a benign block) spread over [start,end]."""
    src, dst, ports, t0, t1, kind, n = act_or_bg
    times = np.sort(rng_uniform(rng, t0, max(t1, t0 + 0.5), n))
    for t in times:
        dport = rng.choice(ports)
        sport = rng.randint(1024, 65535)
        pay = _payload(rng, kind)
        if proto == PROTO_TCP:
            # a tiny, plausible exchange: SYN, SYN/ACK-less PSH-ACK with payload, ACK
            base = _eth() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=rng.randint(0, 2**31))
            base.time = float(t)
            pkts.append(base)
            data = _eth() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA") / Raw(pay)
            data.time = float(t) + rng.uniform(0.001, 0.05)
            pkts.append(data)
            fin = _eth() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA")
            fin.time = float(t) + rng.uniform(0.05, 0.2)
            pkts.append(fin)
        else:
            p = _eth() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(pay)
            p.time = float(t)
            pkts.append(p)


def rng_uniform(rng: random.Random, lo: float, hi: float, n: int) -> list:
    return [rng.uniform(lo, hi) for _ in range(max(n, 1))]


def build_campaign(idx: int, rng: random.Random, t0: float, args) -> Campaign:
    attacker = _rand_ip(rng, f"172.20.{idx % 200}")
    victim = _rand_ip(rng, f"10.{idx % 200}.{(idx // 200) % 200}")
    decoys = [_rand_ip(rng, f"10.{idx % 200}.{(idx // 200) % 200}") for _ in range(rng.randint(2, 4))]
    c2 = _rand_ip(rng, f"203.0.{idx % 200}")
    drop = _rand_ip(rng, f"198.51.{idx % 200}")
    lat = _rand_ip(rng, f"10.{idx % 200}.{(idx // 200) % 200}")
    camp = Campaign(idx, attacker, victim, decoys, c2, drop, lat, t0)

    roll = rng.random()
    if roll < args.p_benign_only:
        camp.negative = "benign_only"
        return camp  # no attack actions at all; background only (added later)

    def dur() -> float:
        return rng.uniform(*args.stage_len_s)

    def gap() -> float:
        return max(rng.expovariate(1.0 / args.mean_gap_s), args.min_gap_s)

    t = t0
    # recon (attacker -> victim + decoys)
    label, ports, kind = rng.choice(RECON)
    d = dur()
    camp.actions.append(Action(label, attacker, victim, ports, t, t + d, kind, "reconnaissance",
                               rng.randint(*args.flows_recon)))
    for dec in camp.decoys:
        camp.actions.append(Action(label, attacker, dec, ports, t, t + d, kind, "reconnaissance",
                                   rng.randint(3, 10)))
    camp.chain.append("reconnaissance")

    if rng.random() < args.p_recon_only:
        camp.negative = "recon_only"
        return camp  # recon that is never followed -- a true negative for false-alarm counting

    # initial_access (attacker -> victim)
    if rng.random() >= args.p_ia:
        return camp
    t += gap()
    label, ports, kind = rng.choice(INITIAL_ACCESS)
    camp.actions.append(Action(label, attacker, victim, ports, t, t + dur(), kind, "initial_access",
                               rng.randint(*args.flows_stage)))
    camp.chain.append("initial_access")

    # optional lateral_movement (victim -> internal target) -- compromised host pivots
    if rng.random() < args.p_lateral:
        t += gap()
        label, ports, kind = rng.choice(LATERAL)
        camp.actions.append(Action(label, victim, camp.lateral_target, ports, t, t + dur(), kind,
                                   "lateral_movement", rng.randint(*args.flows_stage)))
        camp.chain.append("lateral_movement")

    # command_and_control (victim -> c2 server: direction flips)
    if rng.random() >= args.p_c2:
        return camp
    t += gap()
    label, ports, kind = rng.choice(C2)
    camp.actions.append(Action(label, victim, camp.c2, ports, t, t + dur(), kind,
                               "command_and_control", rng.randint(*args.flows_stage)))
    camp.chain.append("command_and_control")

    # finisher: either exfiltration (victim -> drop) or impact (attacker -> victim DoS/DDoS)
    if rng.random() < args.p_finish:
        t += gap()
        if rng.random() < args.p_impact_finish:
            label, ports, kind = rng.choice(IMPACT)
            camp.actions.append(Action(label, attacker, victim, ports, t, t + dur(), kind, "impact",
                                       rng.randint(*args.flows_impact)))
            camp.chain.append("impact")
        else:
            label, ports, kind = rng.choice(EXFIL)
            camp.actions.append(Action(label, victim, camp.drop, ports, t, t + dur(), kind,
                                       "exfiltration", rng.randint(*args.flows_stage)))
            camp.chain.append("exfiltration")
    return camp


def add_background(pkts: list, camp: Campaign, rng: random.Random, args, span_end_s: float):
    """Benign chatter from and around the campaign hosts, so attack flows are not the only traffic."""
    bg_hosts = [_rand_ip(rng, "192.0.2") for _ in range(rng.randint(6, 14))]
    pool = bg_hosts + [camp.attacker, camp.victim] + camp.decoys
    n = rng.randint(*args.background_flows)
    lo = camp.start_s - args.pre_background_s
    for _ in range(n):
        s, d = rng.sample(pool, 2)
        t = rng.uniform(lo, span_end_s)
        proto = PROTO_UDP if rng.random() < 0.3 else PROTO_TCP
        _emit_packets(pkts, (s, d, BENIGN_PORTS, t, t + rng.uniform(0.2, 3.0), "benign", 1), rng, proto)


def write_campaign_pcap(camp: Campaign, rng: random.Random, args, pcap_path: Path) -> float:
    pkts: list = []
    span_end = camp.start_s
    for a in camp.actions:
        span_end = max(span_end, a.end_s)
        proto = PROTO_UDP if a.kind == "beacon" and rng.random() < 0.25 else PROTO_TCP
        _emit_packets(pkts, (a.src, a.dst, a.ports, a.start_s, a.end_s, a.kind, a.n_flows), rng, proto)
    add_background(pkts, camp, rng, args, span_end + args.post_background_s)
    pkts.sort(key=lambda p: p.time)
    wrpcap(str(pcap_path), pkts)
    return span_end


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="F1 randomised lab-campaign recorder (PCAP + labels sidecar).")
    ap.add_argument("--out", required=True, help="output folder")
    ap.add_argument("--n", type=int, default=48, help="number of campaigns to record")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--holdout", type=int, default=30, help="whole campaigns reserved for the frozen test")
    ap.add_argument("--base-time", default=None, help="ISO start time (default: now, UTC)")
    ap.add_argument("--campaign-spacing-s", type=float, default=3 * 3600.0,
                    help="seconds between campaign starts (> max_chain_gap keeps them separate chains)")
    ap.add_argument("--mean-gap-s", type=float, default=240.0, help="mean inter-stage onset gap")
    ap.add_argument("--min-gap-s", type=float, default=20.0)
    ap.add_argument("--stage-len-s", type=float, nargs=2, default=(40.0, 180.0))
    ap.add_argument("--p-ia", type=float, default=0.75, help="P(initial_access | recon)")
    ap.add_argument("--p-lateral", type=float, default=0.35, help="P(lateral_movement | initial_access)")
    ap.add_argument("--p-c2", type=float, default=0.7, help="P(c2 | initial_access)")
    ap.add_argument("--p-finish", type=float, default=0.6, help="P(exfil or impact | c2)")
    ap.add_argument("--p-impact-finish", type=float, default=0.4, help="P(impact vs exfil | finishing)")
    ap.add_argument("--p-recon-only", type=float, default=0.15, help="negative: recon that goes nowhere")
    ap.add_argument("--p-benign-only", type=float, default=0.1, help="negative: no attack at all")
    ap.add_argument("--flows-recon", type=int, nargs=2, default=(20, 60))
    ap.add_argument("--flows-stage", type=int, nargs=2, default=(8, 30))
    ap.add_argument("--flows-impact", type=int, nargs=2, default=(60, 160))
    ap.add_argument("--background-flows", type=int, nargs=2, default=(15, 40))
    ap.add_argument("--pre-background-s", type=float, default=600.0)
    ap.add_argument("--post-background-s", type=float, default=300.0)
    a = ap.parse_args(argv)

    out = Path(a.out)
    (out / "pcap").mkdir(parents=True, exist_ok=True)
    rng = random.Random(a.seed)

    if a.base_time:
        base_dt = datetime.fromisoformat(a.base_time)
        if base_dt.tzinfo is None:
            base_dt = base_dt.replace(tzinfo=timezone.utc)
    else:
        base_dt = datetime.now(timezone.utc)
    base_epoch = base_dt.timestamp()

    sidecar_rows = []  # src_ip,dst_ip,start,end,label,dst_port
    log_lines = []
    manifest = []

    # whole-campaign holdout: pick indices up front, independent of content
    holdout_idx = set(rng.sample(range(a.n), min(a.holdout, a.n))) if a.holdout else set()

    for i in range(a.n):
        t0 = base_epoch + i * a.campaign_spacing_s + rng.uniform(0, 300)
        camp = build_campaign(i, rng, t0, a)
        pcap_path = out / "pcap" / f"campaign_{i:04d}.pcap"
        span_end = write_campaign_pcap(camp, rng, a, pcap_path)

        for act in camp.actions:
            s_iso = datetime.fromtimestamp(act.start_s, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            e_iso = datetime.fromtimestamp(act.end_s, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            # sidecar: one rule per scripted action (port pinned when the menu is single-port)
            port = act.ports[0] if len(act.ports) == 1 else ""
            sidecar_rows.append((act.src, act.dst, s_iso, e_iso, act.label, port))
            log_lines.append(json.dumps({
                "campaign": i, "stage": act.stage, "label": act.label, "src": act.src, "dst": act.dst,
                "ports": list(act.ports), "start_epoch": round(act.start_s, 3), "end_epoch": round(act.end_s, 3),
                "start_iso": s_iso, "n_flows": act.n_flows,
            }))

        manifest.append({
            "campaign": i, "pcap": f"pcap/campaign_{i:04d}.pcap",
            "attacker": camp.attacker, "victim": camp.victim, "decoys": camp.decoys,
            "c2": camp.c2, "drop": camp.drop, "lateral_target": camp.lateral_target,
            "chain": camp.chain, "negative": camp.negative or None,
            "start_epoch": round(camp.start_s, 3), "end_epoch": round(span_end, 3),
            "split": "holdout" if i in holdout_idx else "train",
        })
        if (i + 1) % 10 == 0 or i + 1 == a.n:
            print(f"recorded {i + 1}/{a.n} campaigns", flush=True)

    # merged sidecar (no header-less rules possible: every rule has IPs + a time range)
    import csv
    with (out / "labels.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["src_ip", "dst_ip", "start", "end", "label", "dst_port"])
        w.writerows(sidecar_rows)
    (out / "campaign_log.jsonl").write_text("\n".join(log_lines) + "\n")
    (out / "manifest.json").write_text(json.dumps({
        "SYNTHETIC": True, "generator": "scripts/record_lab_campaigns.py", "seed": a.seed,
        "n_campaigns": a.n, "n_holdout": len(holdout_idx),
        "base_time_utc": base_dt.isoformat(), "params": vars(a),
        "campaigns": manifest,
    }, indent=2))

    chains = [c["chain"] for c in manifest]
    n_pos = sum(1 for c in manifest if not c["negative"] and len(c["chain"]) > 1)
    n_neg = sum(1 for c in manifest if c["negative"])
    reached = {s: sum(1 for ch in chains if s in ch)
               for s in ("reconnaissance", "initial_access", "lateral_movement",
                         "command_and_control", "exfiltration", "impact")}
    (out / "RECORDER.txt").write_text(
        "FULLY SYNTHETIC lab-campaign recording (F1, docs/20). Fabricated PCAP+sidecar for the owner's own\n"
        "isolated forecasting research; NO real host was scanned, connected to, or attacked. Not evidence\n"
        "about real attackers -- a controlled stimulus with a known ground truth (see eval/synthetic_campaigns.py).\n"
        f"seed={a.seed}  n_campaigns={a.n}  holdout={len(holdout_idx)}  base={base_dt.isoformat()}\n"
        f"positives(chain>1)={n_pos}  negatives={n_neg}  stage reach={reached}\n"
    )

    print(f"\nwrote {a.n} PCAPs to {out/'pcap'}")
    print(f"labels.csv rules: {len(sidecar_rows)}  campaign_log.jsonl actions: {len(log_lines)}")
    print(f"positives(chain>1): {n_pos}  negatives: {n_neg}  holdout: {len(holdout_idx)}")
    print(f"stage reach: {reached}")
    print("\nnext:")
    print(f"  python -m pipeline.stage_events --input {out/'pcap'} --adapter pcap "
          f"--labels-sidecar {out/'labels.csv'} --name lab_f1 --views host,attacker,pair "
          f"--merge-gap 30 --min-flows 5")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
