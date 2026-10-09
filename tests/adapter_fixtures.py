"""Small synthetic fixtures for the dataset-adapter toolkit tests (no real data needed)."""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from pipeline.adapters.unsw_nb15 import RAW_COLUMNS


def cic_df(n: int = 300, start: str = "2018-02-14 08:00:00", step_s: float = 5.0, ip: bool = True,
           iat_scale: float = 1.0, reduced: bool = False, labels: list[str] | None = None,
           attack_block: tuple[int, int] = (150, 200), attack_label: str = "SSH-Bruteforce",
           dur_scale: float = 1.0, ts_fmt: str = "%d/%m/%Y %H:%M:%S", seed: int = 0, hosts: int = 2) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    fwd = rng.integers(2, 20, n)
    bwd = rng.integers(1, 15, n)
    pkts = fwd + bwd
    dur_us = rng.integers(100_000, 5_000_000, n).astype(float) * dur_scale
    iat = dur_us / (pkts - 1) * iat_scale
    ts = pd.Timestamp(start) + pd.to_timedelta(np.arange(n) * step_s, unit="s")
    lab = np.array(["Benign"] * n, dtype=object)
    lo, hi = attack_block
    lab[lo:hi] = attack_label
    if labels is not None:
        lab = np.array(labels, dtype=object)
    d: dict[str, object] = {}
    if ip:
        d["Src IP"] = [f"10.0.0.{1 + i % hosts}" for i in range(n)]
        d["Src Port"] = rng.integers(1024, 60000, n)
        d["Dst IP"] = [f"192.168.1.{1 + (i * 7) % 11}" for i in range(n)]
    d["Dst Port"] = rng.choice([22, 80, 443, 53], n)
    d["Protocol"] = rng.choice([6, 6, 6, 17], n)
    d["Timestamp"] = ts.strftime(ts_fmt)
    d["Flow Duration"] = dur_us.astype(np.int64)
    d["Tot Fwd Pkts"] = fwd
    d["Tot Bwd Pkts"] = bwd
    d["TotLen Fwd Pkts"] = fwd * 120
    d["TotLen Bwd Pkts"] = bwd * 300
    d["SYN Flag Cnt"] = rng.integers(0, 2, n)
    d["ACK Flag Cnt"] = np.minimum(rng.integers(0, 12, n), pkts)
    d["FIN Flag Cnt"] = rng.integers(0, 2, n)
    d["RST Flag Cnt"] = (rng.random(n) < 0.2).astype(int)
    d["PSH Flag Cnt"] = np.minimum(rng.integers(0, 6, n), pkts)
    d["URG Flag Cnt"] = (rng.random(n) < 0.1).astype(int)
    d["Flow IAT Mean"] = iat
    d["Flow IAT Std"] = iat * 0.5
    d["Flow IAT Max"] = iat * 3
    if not reduced:
        for i in range(25):
            d[f"Filler {i}"] = rng.random(n)
    d["Label"] = lab
    return pd.DataFrame(d)


def write_cic(path: Path, **kw) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    cic_df(**kw).to_csv(path, index=False)
    return path


def write_ctu(path: Path, n: int = 200, with_unknown: int = 0, seed: int = 0) -> Path:
    rng = np.random.default_rng(seed)
    path.parent.mkdir(parents=True, exist_ok=True)
    ts = pd.Timestamp("2011-08-18 10:00:00") + pd.to_timedelta(np.arange(n) * 4.0, unit="s")
    pkts = rng.integers(2, 30, n)
    src_bytes = pkts * 60
    rows = []
    for i in range(n):
        lab = "flow=Background-UDP-Established"
        if 80 <= i < 120:
            lab = "flow=From-Botnet-V44-TCP-CC-Custom-Encryption"
        if i < with_unknown:
            lab = "flow=Totally-New-Label"
        proto = "icmp" if i % 50 == 7 else ("udp" if i % 3 == 0 else "tcp")
        dport = "0x0303" if proto == "icmp" else str(int(rng.choice([80, 443, 53])))
        rows.append(f"{ts[i].strftime('%Y/%m/%d %H:%M:%S.%f')},{rng.random() * 5:.6f},{proto},147.32.84.{1 + i % 3},"
                    f"{1024 + i},   ->,10.1.1.{1 + i % 9},{dport},S_RA,0,0,{pkts[i]},{src_bytes[i] + 200},{src_bytes[i]},{lab}")
    path.write_text("StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label\n"
                    + "\n".join(rows) + "\n", encoding="utf-8")
    return path


def unsw_rows(n: int = 100, attack_cat_block: tuple[int, int, str] = (40, 60, "Reconnaissance"),
              arp_rows: int = 0, sintpkt_ms: float | None = None, seed: int = 0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(n):
        r = {c: 0 for c in RAW_COLUMNS}
        proto = "arp" if i < arp_rows else ("udp" if i % 4 == 0 else "tcp")
        dur = 0.5 + rng.random()
        r.update({
            "srcip": f"59.166.0.{1 + i % 3}", "sport": 1000 + i, "dstip": f"149.171.126.{1 + i % 5}", "dsport": 80,
            "proto": proto, "state": "FIN" if proto == "tcp" else "CON", "dur": dur,
            "sbytes": 200, "dbytes": 400, "spkts": 4, "dpkts": 6, "stime": 1421927414 + i * 3, "ltime": 1421927415 + i * 3,
            "sintpkt": sintpkt_ms if sintpkt_ms is not None else dur * 1000 / 3,
            "dintpkt": sintpkt_ms if sintpkt_ms is not None else dur * 1000 / 5, "synack": 0.01, "ackdat": 0.02,
            "attack_cat": None, "label": 0,
        })
        lo, hi, cat = attack_cat_block
        if lo <= i < hi:
            r["attack_cat"], r["label"] = cat, 1
        rows.append(r)
    return pd.DataFrame(rows)


def write_unsw(path: Path, **kw) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    unsw_rows(**kw).to_csv(path, header=False, index=False)
    return path
