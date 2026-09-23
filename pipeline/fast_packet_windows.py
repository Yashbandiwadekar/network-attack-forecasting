"""Fast, streaming, parallel PCAP -> per-(src_ip, window) packet-level features.

pipeline/packet_features.py::load_pcap fully dissects every packet with Scapy (~3,200 packets/s/core
measured) and returns one big DataFrame, which is fine for a demo upload but unusable for hundreds of
GB of captures: too slow, and it holds the whole file in RAM. This module computes the SAME eight
packet-level window features (mean_ttl, var_ttl, mean_window_size, frag_ratio, mean_payload_size,
std_payload_size, port_scan_score, retransmit_ratio) but

  * reads raw frames with Scapy's RawPcapReader (no dissection) and hand-parses just the IPv4/TCP/UDP
    header fields it needs with `struct` -- no new dependency;
  * aggregates in bounded chunks (only a small tail of the last, still-open window is carried over), so
    memory stays flat regardless of file size;
  * processes files in parallel (one file per worker).

It is checked against the Scapy path for parity (tests/test_fast_packet_windows.py and the real-capture
check recorded in BUILD_REPORT.md), so a feature here means the same thing as in the demo path.

Limits, stated honestly: IPv4 only (IPv6 frames are skipped, exactly as load_pcap skips non-IP); Ethernet
and Linux-cooked (SLL, link type 113 -- what the UNSW-NB15 captures use) link layers only; the first and
last window of each file are dropped because a file boundary can cut a window in half and the
unique-port / retransmit features are not additive across files.
"""
from __future__ import annotations

import struct
import time
from pathlib import Path

import numpy as np
import pandas as pd
from scapy.utils import RawPcapReader

LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113
_LINK_HEADER = {LINKTYPE_ETHERNET: 14, LINKTYPE_LINUX_SLL: 16}
_ETHERTYPE_OFFSET = {LINKTYPE_ETHERNET: 12, LINKTYPE_LINUX_SLL: 14}

PACKET_FEATURES = [
    "mean_ttl", "var_ttl", "mean_window_size", "frag_ratio",
    "mean_payload_size", "std_payload_size", "port_scan_score", "retransmit_ratio",
]

_U16 = struct.Struct(">H")
_U32 = struct.Struct(">I")


def _parse_chunk(frames: list[tuple[bytes, float]], link_off: int, ethertype_off: int) -> dict[str, np.ndarray]:
    """Hand-parse IPv4 + TCP/UDP header fields for a list of (raw_frame, timestamp)."""
    ts, src, dst, ttl, frag, pay, sport, dport, win, seq, is_tcp = ([] for _ in range(11))
    u16, u32 = _U16.unpack_from, _U32.unpack_from
    for data, t in frames:
        if len(data) < link_off + 20 or u16(data, ethertype_off)[0] != 0x0800:
            continue  # not IPv4 (load_pcap skips anything without an IP layer as well)
        ihl = (data[link_off] & 0x0F) * 4
        if data[link_off] >> 4 != 4 or ihl < 20:
            continue
        flags_frag = u16(data, link_off + 6)[0]
        proto = data[link_off + 9]
        ts.append(t)
        src.append(u32(data, link_off + 12)[0])
        dst.append(u32(data, link_off + 16)[0])
        ttl.append(data[link_off + 8])
        frag.append(bool(flags_frag & 0x2000) or (flags_frag & 0x1FFF) > 0)
        l4 = link_off + ihl
        pay.append(len(data) - l4)  # == len(bytes(ip.payload)) on the captured bytes
        sp = dp = w = sq = -1
        tcp = 0
        # Ports/flags exist only in the first fragment; later fragments carry no L4 header.
        if (flags_frag & 0x1FFF) == 0:
            if proto == 6 and len(data) >= l4 + 16:
                sp, dp = struct.unpack_from(">HH", data, l4)
                sq = u32(data, l4 + 4)[0]
                w = u16(data, l4 + 14)[0]
                tcp = 1
            elif proto == 17 and len(data) >= l4 + 4:
                sp, dp = struct.unpack_from(">HH", data, l4)
        sport.append(sp); dport.append(dp); win.append(w); seq.append(sq); is_tcp.append(tcp)
    return {
        "ts": np.asarray(ts, dtype=np.float64), "src": np.asarray(src, dtype=np.uint32),
        "dst": np.asarray(dst, dtype=np.uint32), "ttl": np.asarray(ttl, dtype=np.float64),
        "frag": np.asarray(frag, dtype=np.float64), "pay": np.asarray(pay, dtype=np.float64),
        "sport": np.asarray(sport, dtype=np.int64), "dport": np.asarray(dport, dtype=np.int64),
        "win": np.asarray(win, dtype=np.float64), "seq": np.asarray(seq, dtype=np.int64),
        "is_tcp": np.asarray(is_tcp, dtype=bool),
    }


def _aggregate(cols: dict[str, np.ndarray], window_seconds: int) -> pd.DataFrame:
    """Per-(src, window_start) features; same definitions as compute_packet_window_features."""
    if len(cols["ts"]) == 0:
        return pd.DataFrame(columns=["src", "window_start_s", *PACKET_FEATURES])
    df = pd.DataFrame(cols)
    df["ws"] = (np.floor(df["ts"] / window_seconds) * window_seconds).astype(np.int64)
    # window size only counts real TCP packets; ports only where an L4 header was present
    df["win"] = df["win"].where(df["is_tcp"])
    df["dport_f"] = df["dport"].where(df["dport"] >= 0)
    keys = ["src", "ws"]
    g = df.groupby(keys, sort=False)
    out = pd.DataFrame({
        "mean_ttl": g["ttl"].mean(),
        "var_ttl": g["ttl"].var(ddof=0),
        "mean_window_size": g["win"].mean().fillna(0.0),
        "frag_ratio": g["frag"].mean(),
        "mean_payload_size": g["pay"].mean(),
        "std_payload_size": g["pay"].std(ddof=0),
        "port_scan_score": (g["dport_f"].nunique() / g.size()).clip(0.0, 1.0),
    })
    tcp = df[df["is_tcp"]]
    dup = tcp.duplicated(subset=keys + ["dst", "sport", "dport", "seq"], keep="first")
    tcp_n = tcp.groupby(keys, sort=False).size()
    dup_n = dup.groupby([tcp["src"], tcp["ws"]], sort=False).sum()
    out["retransmit_ratio"] = (dup_n / tcp_n).reindex(out.index).fillna(0.0)
    out = out.reset_index().rename(columns={"ws": "window_start_s"})
    return out[["src", "window_start_s", *PACKET_FEATURES]]


def process_pcap(path: str | Path, window_seconds: int = 10, chunk_packets: int = 400_000, max_frames: int | None = None) -> tuple[pd.DataFrame, dict]:
    """Stream one capture file -> (window features, stats). Time-ordered captures are assumed (checked:
    every UNSW-NB15 file is); the still-open final window of each chunk is carried into the next chunk so
    no window is split across chunks. First and last window of the file are dropped (see module docstring)."""
    path = Path(path)
    t0 = time.time()
    parts: list[pd.DataFrame] = []
    carry: dict[str, np.ndarray] | None = None
    n_frames = n_ip = 0
    with RawPcapReader(str(path)) as reader:
        # Scapy picks the classic-pcap or pcapng reader from the file's magic bytes (UNSW-NB15 ships
        # both, all named .pcap). The two report timestamps / link types differently:
        #   classic: meta.sec + meta.usec, one link type for the whole file (reader.linktype)
        #   pcapng:  (meta.tshigh << 32 | meta.tslow) / meta.tsresol, link type per packet (meta.linktype)
        is_ng = type(reader).__name__ == "RawPcapNgReader"
        scale = 1e9 if getattr(reader, "nano", False) else 1e6
        link_off = eth_off = None
        buf: list[tuple[bytes, float]] = []

        def flush(final: bool) -> None:
            nonlocal buf, carry
            cols = _parse_chunk(buf, link_off or 14, eth_off or 12)
            buf = []
            if carry is not None and len(carry["ts"]):
                cols = {k: np.concatenate([carry[k], cols[k]]) for k in cols}
            carry = None
            if len(cols["ts"]) == 0:
                return
            last_ws = int(np.floor(cols["ts"].max() / window_seconds) * window_seconds)
            if final:
                parts.append(_aggregate(cols, window_seconds))
                return
            open_mask = np.floor(cols["ts"] / window_seconds) * window_seconds >= last_ws
            carry = {k: v[open_mask] for k, v in cols.items()}
            parts.append(_aggregate({k: v[~open_mask] for k, v in cols.items()}, window_seconds))

        for data, meta in reader:
            n_frames += 1
            if link_off is None:
                linktype = meta.linktype if is_ng else reader.linktype
                link_off = _LINK_HEADER.get(linktype)
                if link_off is None:
                    raise ValueError(f"{path.name}: unsupported link type {linktype}")
                eth_off = _ETHERTYPE_OFFSET[linktype]
                file_linktype = linktype
            elif is_ng and meta.linktype != file_linktype:
                raise ValueError(f"{path.name}: mixed link types in one pcapng file")
            t = ((meta.tshigh << 32) | meta.tslow) / meta.tsresol if is_ng else meta.sec + meta.usec / scale
            buf.append((data, t))
            if max_frames is not None and n_frames >= max_frames:
                break
            if len(buf) >= chunk_packets:
                flush(final=False)
        flush(final=True)

    parts = [p for p in parts if len(p)]
    feats = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame(columns=["src", "window_start_s", *PACKET_FEATURES])
    if len(feats):
        lo, hi = feats["window_start_s"].min(), feats["window_start_s"].max()
        feats = feats[(feats["window_start_s"] > lo) & (feats["window_start_s"] < hi)]  # drop boundary windows
    stats = {"file": path.name, "frames": n_frames, "windows": len(feats), "seconds": time.time() - t0,
             "frames_per_s": n_frames / max(time.time() - t0, 1e-9)}
    return feats.reset_index(drop=True), stats


def to_window_frame(feats: pd.DataFrame) -> pd.DataFrame:
    """Same shape compute_packet_window_features returns: src_ip (dotted string), window_start, 8 features."""
    if feats.empty:
        return pd.DataFrame(columns=["src_ip", "window_start", *PACKET_FEATURES])
    out = feats.copy()
    out["src_ip"] = out["src"].map(lambda v: ".".join(str((int(v) >> s) & 255) for s in (24, 16, 8, 0)))
    out["window_start"] = pd.to_datetime(out["window_start_s"], unit="s")
    return out[["src_ip", "window_start", *PACKET_FEATURES]]


def _worker(args: tuple[str, int, str]) -> dict:
    path, window_seconds, out_dir = args
    feats, stats = process_pcap(path, window_seconds)
    to_window_frame(feats).to_parquet(Path(out_dir) / (Path(path).parent.name.replace(" ", "_") + "__" + Path(path).stem + ".parquet"), index=False)
    return stats


def process_many(paths: list[str | Path], out_dir: str | Path, window_seconds: int = 10, workers: int = 16) -> list[dict]:
    """One file per worker process; writes one parquet per capture file into out_dir."""
    from multiprocessing import Pool

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    jobs = [(str(p), window_seconds, str(out_dir)) for p in paths]
    stats = []
    with Pool(workers) as pool:
        for s in pool.imap_unordered(_worker, jobs):
            print(f"{s['file']}: {s['frames']:,} frames, {s['windows']:,} windows, {s['frames_per_s']:,.0f} frames/s", flush=True)
            stats.append(s)
    return stats
