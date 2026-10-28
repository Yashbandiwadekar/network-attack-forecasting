"""In-process live / replay engine (docs/09 A3, design in docs/07 section 1.4, write-up in docs/11).

    packets (dumpcap ring files, or a replayed PCAP paced by its own timestamps)
      -> fast parser (pipeline/fast_packet_windows.read_all_frames_counted)
      -> LiveEngine.ingest():  filter -> rolling packet buffer -> assemble_flows -> 10 s event-time windows
                               -> the SAME feature assembly as app/service.process_uploads
                               -> per-host history (12-window warm-up) -> batched rollout
      -> publish() -> the dashboard STATE (atomic swap) -> the existing 5 s poll

Why this is not scripts/live_forecast.py. That script assembles flows per file with the Scapy path, so a
flow crossing a 10 s file boundary is split in two; it re-scores nothing provisional; it never touches the
dashboard. This module keeps one rolling packet buffer and re-assembles flows over it, so a flow is always
seen whole, and it emits a window to the history only once no flow that started in it can still change.

Window rules (the part that decides whether live features equal batch features)
  * A flow belongs to the window its FIRST packet falls in, keyed by the initiator's IP (group_by src_ip),
    floor(timestamp, 10 s): identical to pipeline.windowing.build_flow_windows.
  * Window W (start S) is FINAL once the watermark (newest packet time seen) >= S + window + flow_timeout +
    grace. Every flow that starts in W has ended or been cut by the flow timeout by then, so its record is
    complete and W's features equal the batch features. Nothing is re-emitted.
  * Windows after that are PROVISIONAL: scored from the flows seen so far, recomputed on every tick, never
    stored, flagged `provisional` so the UI can grey them.
  * Silent windows are not synthesised (training dropped them too). A host's sequence is its last 12
    non-empty windows; `input_contiguous` says whether they were also back-to-back in wall-clock time.

Deliberate deviations from training, all disclosed in docs/11: flow timeout defaults to 30 s (CICFlowMeter
used 120 s; a longer timeout delays finality), packet-level features are zero-filled (flow-only checkpoints
only), and a flow idle for more than the timeout starts a fresh timeout grid.

Safety: this module never opens a network interface and never starts dumpcap. It reads files.
"""
from __future__ import annotations

import ipaddress
import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import numpy as np
import pandas as pd

from app import service
from common.config import feature_columns
from models.forecast import ForecastEngine, latest_sequences_batch
from pipeline.fast_packet_windows import (
    assemble_flows, empty_anchors, flow_key_stats, ip_to_str, read_all_frames_counted,
)
from pipeline.graph_embedding_features import build_graph_embedding_window_features
from pipeline.graph_features import build_graph_window_features
from pipeline.windowing import (
    apply_reconnaissance_heuristic, build_flow_windows, merge_graph_embedding_features,
    merge_graph_features, merge_packet_features,
)

STALE_AFTER_S = 30.0
CAPTURE_SUFFIXES = (".pcap", ".pcapng")


class LiveConfigError(ValueError):
    """The engine cannot be started with this model or these settings."""


@dataclass
class LiveSettings:
    flow_timeout_s: float = 30.0       # docs/07: 30 s for live; 120 s is CICFlowMeter's value
    grace_s: float = 2.0               # extra wait after flow_timeout before a window is final
    alert_threshold: float = service.ALERT_THRESHOLD
    lab_cidrs: tuple[str, ...] = ()    # keep a packet only if BOTH endpoints are inside one of these
    ignore_ports: tuple[int, ...] = () # drop packets to/from these ports (the dashboard's own port)
    max_hosts: int = 5000              # LRU cap on hosts with history
    host_ttl_s: float = 600.0          # forget a host this long (event time) after its last window
    max_buffer_packets: int = 2_000_000
    max_flows_kept: int = 100_000      # flows retained for the dashboard's per-host flow counts
    keep_windows: int = 12             # history windows retained per host (>= sequence_length)
    stale_after_s: float = STALE_AFTER_S
    score_log: Path | None = None      # JSONL, one line per host per newly final window
    collect_final: bool = False        # tests: keep every final window row (unbounded; never in production)


@dataclass
class Snapshot:
    flow_df: pd.DataFrame
    windows: pd.DataFrame
    batch: Any                          # BatchForecastResult | None
    source_name: str
    ingested_flows: int
    host_meta: dict[str, dict[str, Any]] = field(default_factory=dict)


def _dotted(values: np.ndarray) -> list[str]:
    return list(ip_to_str(pd.Series(values, dtype=np.uint32)))


def _cidr_mask(ip: np.ndarray, nets: list[ipaddress.IPv4Network]) -> np.ndarray:
    m = np.zeros(len(ip), dtype=bool)
    for n in nets:
        m |= (ip.astype(np.uint64) & int(n.netmask)) == int(n.network_address)
    return m


def _iso(epoch_s: float | None) -> str | None:
    if epoch_s is None or not np.isfinite(epoch_s):
        return None
    return datetime.fromtimestamp(float(epoch_s), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class LiveEngine:
    def __init__(self, engine: ForecastEngine, config: dict[str, Any], settings: LiveSettings | None = None,
                 publish: Callable[[Snapshot], None] | None = None, source_name: str = "live",
                 mode: str = "REPLAY", clock: Callable[[], float] = time.time):
        self.engine = engine
        self.config = config
        self.s = settings or LiveSettings()
        if not service.is_flow_only_model(config):
            raise LiveConfigError(
                "The live engine zero-fills packet-level features, so it only serves flow-only checkpoints "
                "(processed/metadata.json must say flow_only). Serve a flow-only model (the default is).")
        self.window_s = int(config["windowing"]["window_seconds"])
        self.seq_len = int(config["windowing"]["sequence_length"])
        if self.s.keep_windows < self.seq_len:
            self.s.keep_windows = self.seq_len
        self.feature_cols = feature_columns(config)
        self.publish = publish
        self.source_name = source_name
        self.mode = mode
        self.clock = clock
        self._nets = [ipaddress.ip_network(c, strict=False) for c in self.s.lab_cidrs]
        for n in self._nets:
            if n.version != 4:
                raise LiveConfigError(f"lab CIDR {n} is not IPv4 (the parser is IPv4 only)")
        self._ignore_ports = np.asarray(sorted(set(self.s.ignore_ports)), dtype=np.int64)

        self._lock = threading.Lock()        # serialises ingest()
        self._stat_lock = threading.Lock()   # guards the counters status() reads
        self._cols: dict[str, np.ndarray] | None = None
        self._anchors = empty_anchors()
        self._cursor: float | None = None    # start (epoch s) of the oldest window that is not final yet
        self._wm: float = float("-inf")      # watermark: newest packet time seen
        self._hist: dict[str, deque] = {}    # host -> deque of final window rows (dict), oldest first
        self._host_seen: dict[str, float] = {}
        self._recent_flows: list[pd.DataFrame] = []
        self.clock_map: tuple[float, float, float] | None = None   # (event0, wall0, speed): replay only, for latency
        self.final_rows: list[dict] = []     # only filled when settings.collect_final
        self._logged_window: dict[str, float] = {}
        self._alert_state: dict[str, bool] = {}
        self.recent_alerts: deque = deque(maxlen=50)
        self.started_wall = clock()
        self._stopped = False
        self._rate: deque = deque(maxlen=128)  # (wall, packets_total, flows_total); first entry is the start baseline
        self._rate.append((self.started_wall, 0, 0))
        self._lat: deque = deque(maxlen=200)  # ingest compute seconds
        self._pkt_lat: deque = deque(maxlen=200)  # packet -> published, seconds
        self._final_delays: deque = deque(maxlen=200)  # window end (replay schedule) -> final, seconds
        self.c: dict[str, Any] = dict(
            frames=0, packets=0, packets_kept=0, unparsed=0, filtered_cidr=0, filtered_port=0, filtered_proto=0,
            late_dropped=0, buffer_dropped=0, hosts_evicted=0, flows_final=0, windows_final=0,
            ingests=0, files_ok=0, files_failed=0, last_data_wall=None, last_publish_wall=None,
            last_window_start=None, flows_provisional=0, windows_provisional=0, hosts_warming=0,
            hosts_scored=0, alerts_active=0, scoring_s_last=None, finished=False, error=None,
            final_delay_s_last=None, behind_schedule_s=0.0)

    # ------------------------------------------------------------------ feature assembly

    def _features(self, flows: pd.DataFrame) -> pd.DataFrame:
        """Exactly the flow-only sequence of app/service.process_uploads, on a set of whole windows."""
        w = build_flow_windows(flows, self.config)
        w = merge_packet_features(w, None, self.config)
        w = merge_graph_features(w, build_graph_window_features(flows, self.config), self.config)
        w = merge_graph_embedding_features(w, build_graph_embedding_window_features(flows, self.config), self.config)
        w = apply_reconnaissance_heuristic(w, self.config)
        w["stage_observed"] = False
        return w

    def _flows_frame(self, cols_flows: pd.DataFrame) -> pd.DataFrame:
        f = cols_flows
        out = f.drop(columns=["timestamp_s", "src_ip", "dst_ip"]).copy()
        out["timestamp"] = pd.to_datetime(f["timestamp_s"].to_numpy(), unit="s")
        out["src_ip"] = ip_to_str(f["src_ip"]).to_numpy()
        out["dst_ip"] = ip_to_str(f["dst_ip"]).to_numpy()
        out["label"] = "BENIGN"   # no ground truth in a capture; stage_observed=False says so
        out["wstart_s"] = np.floor(f["timestamp_s"].to_numpy() / self.window_s) * self.window_s
        return out

    # ------------------------------------------------------------------ ingest

    def ingest(self, cols: dict[str, np.ndarray], frames: int | None = None, sched_wall: float | None = None) -> None:
        """Feed parsed packets (any chunking: a ring file, a replay slice). `frames` is the number of raw
        frames the chunk came from (for the unparsed counter). `sched_wall` is when the first packet was
        due (replay) so packet-to-dashboard latency can be measured."""
        with self._lock:
            t_in = self.clock()
            t_cpu = time.perf_counter()
            n_in = len(cols["ts"])
            with self._stat_lock:
                self.c["frames"] += frames if frames is not None else n_in
                self.c["unparsed"] += max((frames or n_in) - n_in, 0)
            cols = self._filter(cols)
            n = len(cols["ts"])
            if n:
                first_pkt_ts = float(cols["ts"].min())
                self._wm = max(self._wm, float(cols["ts"].max()))
                if self._cursor is None:
                    self._cursor = np.floor(first_pkt_ts / self.window_s) * self.window_s
                late = cols["ts"] < self._cursor
                if late.any():
                    with self._stat_lock:
                        self.c["late_dropped"] += int(late.sum())
                    cols = {k: v[~late] for k, v in cols.items()}
                    n = len(cols["ts"])
            if n:
                self._cols = cols if self._cols is None else {k: np.concatenate([self._cols[k], cols[k]]) for k in cols}
                over = len(self._cols["ts"]) - self.s.max_buffer_packets
                if over > 0:
                    order = np.argsort(self._cols["ts"], kind="stable")[over:]
                    order.sort()
                    self._cols = {k: v[order] for k, v in self._cols.items()}
                    with self._stat_lock:
                        self.c["buffer_dropped"] += over
            with self._stat_lock:
                self.c["packets"] += n_in
                self.c["packets_kept"] += n
                if n_in or frames:
                    self.c["last_data_wall"] = t_in
            self._process()
            with self._stat_lock:
                if n and self._cols is not None:
                    self._lat.append(time.perf_counter() - t_cpu)
                    first = sched_wall if sched_wall is not None else (first_pkt_ts if self.mode == "LIVE" else None)
                    if first is not None:
                        self._pkt_lat.append(max(self.clock() - first, 0.0))
                self.c["ingests"] += 1
                self._rate.append((self.clock(), self.c["packets"], self.c["flows_final"]))

    def finish(self) -> None:
        """End of a replay: treat the watermark as infinite so every remaining window becomes final."""
        with self._lock:
            self._process(flush=True)
            with self._stat_lock:
                self.c["finished"] = True

    def _filter(self, cols: dict[str, np.ndarray]) -> dict[str, np.ndarray]:
        n = len(cols["ts"])
        if n == 0:
            return cols
        keep = np.isin(cols["proto"], (6, 17)) & (cols["sport"] >= 0)
        n_proto = int((~keep).sum())
        n_cidr = n_port = 0
        if self._nets:
            ok = _cidr_mask(cols["src"], self._nets) & _cidr_mask(cols["dst"], self._nets)
            n_cidr = int((keep & ~ok).sum())
            keep &= ok
        if len(self._ignore_ports):
            hit = np.isin(cols["sport"], self._ignore_ports) | np.isin(cols["dport"], self._ignore_ports)
            n_port = int((keep & hit).sum())
            keep &= ~hit
        with self._stat_lock:
            self.c["filtered_proto"] += n_proto
            self.c["filtered_cidr"] += n_cidr
            self.c["filtered_port"] += n_port
        return {k: v[keep] for k, v in cols.items()}

    # ------------------------------------------------------------------ the tick

    def _process(self, flush: bool = False) -> None:
        W, T, G = self.window_s, self.s.flow_timeout_s, self.s.grace_s
        if self._cols is None or self._cursor is None or len(self._cols["ts"]) == 0:
            self._publish_snapshot(pd.DataFrame(), flush)
            return
        wm = self._wm
        flows = assemble_flows(self._cols, timeout_s=T, anchors=self._anchors)
        fdf = self._flows_frame(flows) if len(flows) else pd.DataFrame()
        if len(fdf):
            fdf = fdf[fdf["wstart_s"] >= self._cursor]

        # windows whose start S satisfies S + W + T + G <= watermark are final
        if flush:
            last_final = float(fdf["wstart_s"].max()) if len(fdf) else self._cursor - W
        else:
            last_final = np.floor((wm - T - G - W) / W) * W
        if last_final >= self._cursor:
            if len(fdf):
                fin = fdf[fdf["wstart_s"] <= last_final]
                if len(fin):
                    self._absorb_final(fin, flush)
                    fdf = fdf[fdf["wstart_s"] > last_final]
            self._cursor = last_final + W
        prov = fdf
        # anchors from the whole buffer, then trim everything before the oldest non-final window
        parts = [self._anchors, flow_key_stats(self._cols)]
        trimmed = self._cols["ts"] < self._cursor
        if trimmed.any():
            tk = flow_key_stats({k: v[trimmed] for k, v in self._cols.items()})
            tk["tlast"] = tk["last"]
            parts.append(tk)
        if any(len(x) for x in parts[1:]):
            g = pd.concat(parts).groupby(level=[0, 1, 2], sort=False)
            self._anchors = pd.DataFrame({"first": g["first"].min(), "last": g["last"].max(), "tlast": g["tlast"].max()})
        # A key may be forgotten once its last packet is older than the buffer by a full timeout: nothing of
        # it is left in the buffer, and a returning packet is then a new flow (its old bucket grid is stale).
        self._anchors = self._anchors[self._anchors["last"] >= self._cursor - T]
        if len(self._anchors) > self.s.max_buffer_packets:
            self._anchors = self._anchors.nlargest(self.s.max_buffer_packets // 2, "last")
        keep = self._cols["ts"] >= self._cursor
        if not keep.all():
            self._cols = {k: v[keep] for k, v in self._cols.items()}
        self._publish_snapshot(prov, flush)

    def _absorb_final(self, fin: pd.DataFrame, flush: bool = False) -> None:
        wins = self._features(fin)
        with self._stat_lock:
            self.c["flows_final"] += len(fin)
            self.c["windows_final"] += len(wins)
        self._recent_flows.append(fin)
        horizon = fin["wstart_s"].max() - self.s.keep_windows * self.window_s
        self._recent_flows = [f for f in self._recent_flows if f["wstart_s"].max() >= horizon]
        while sum(len(f) for f in self._recent_flows) > self.s.max_flows_kept and len(self._recent_flows) > 1:
            self._recent_flows.pop(0)
        wins = wins.sort_values(["src_ip", "window_start"])
        for host, grp in wins.groupby("src_ip", sort=False):
            dq = self._hist.setdefault(host, deque(maxlen=self.s.keep_windows))
            for rec in grp.to_dict("records"):
                dq.append(rec)
                if self.s.collect_final:
                    self.final_rows.append(rec)
            self._host_seen[host] = max(self._host_seen.get(host, 0.0), grp["window_start"].max().timestamp())
        newest_end = float(wins["window_start"].max().timestamp()) + self.window_s
        with self._stat_lock:
            self.c["last_window_start"] = newest_end - self.window_s
            if self.clock_map is not None and self.clock_map[2] > 0 and not flush:
                ev0, wall0, speed = self.clock_map
                self.c["final_delay_s_last"] = round(self.clock() - (wall0 + (newest_end - ev0) / speed), 3)
                self._final_delays.append(self.c["final_delay_s_last"])

    def _evict(self) -> None:
        if not self._hist:
            return
        ref = max(self._host_seen.values())
        for h in [h for h, t in self._host_seen.items() if ref - t > self.s.host_ttl_s]:
            self._drop_host(h, count=False)
        over = len(self._hist) - self.s.max_hosts
        if over > 0:
            for h, _ in sorted(self._host_seen.items(), key=lambda kv: kv[1])[:over]:
                self._drop_host(h, count=True)

    def _drop_host(self, host: str, count: bool) -> None:
        self._hist.pop(host, None)
        self._host_seen.pop(host, None)
        self._logged_window.pop(host, None)
        self._alert_state.pop(host, None)
        if count:
            with self._stat_lock:
                self.c["hosts_evicted"] += 1

    # ------------------------------------------------------------------ scoring + publish

    def _publish_snapshot(self, prov_flows: pd.DataFrame, flush: bool) -> None:
        self._evict()
        t_score = time.perf_counter()
        prov_rows = pd.DataFrame()
        if len(prov_flows):
            prov_rows = self._features(prov_flows)
            prov_rows["provisional"] = True
        with self._stat_lock:
            self.c["flows_provisional"] = int(len(prov_flows))
            self.c["windows_provisional"] = int(len(prov_rows))
        recs = [r for dq in self._hist.values() for r in dq]
        fin_df = pd.DataFrame(recs)
        if len(fin_df):
            fin_df["provisional"] = False
        parts = [d for d in (fin_df, prov_rows) if len(d)]
        windows = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame()
        batch = None
        meta: dict[str, dict[str, Any]] = {}
        if len(windows):
            windows = windows.sort_values(["src_ip", "window_start"]).reset_index(drop=True)
            counts = windows.groupby("src_ip")["window_start"].size()
            contiguous: dict[str, bool] = {}
            hosts, seqs = latest_sequences_batch(
                windows, self.feature_cols, self.seq_len, window_seconds=self.window_s, contiguous_out=contiguous)
            last_prov = windows.groupby("src_ip")["provisional"].last()
            if hosts:
                batch = self.engine.rollout_batch(hosts, seqs)
            for h in hosts:
                meta[h] = {"input_contiguous": bool(contiguous.get(h, True)), "provisional": bool(last_prov[h]),
                           "windows_seen": int(counts[h])}
            with self._stat_lock:
                self.c["hosts_scored"] = len(hosts)
                self.c["hosts_warming"] = int((counts < self.seq_len).sum())
            if batch is not None:
                self._alerts_and_log(batch, windows, meta)
            else:
                with self._stat_lock:
                    self.c["alerts_active"] = 0
        else:
            with self._stat_lock:
                self.c["hosts_scored"] = 0
                self.c["hosts_warming"] = 0
        recent = pd.concat(self._recent_flows, ignore_index=True) if self._recent_flows else pd.DataFrame()
        if len(prov_flows):
            recent = pd.concat([recent, prov_flows], ignore_index=True) if len(recent) else prov_flows
        snap = Snapshot(flow_df=recent, windows=windows, batch=batch, source_name=self.source_name,
                        ingested_flows=int(self.c["flows_final"]), host_meta=meta)
        with self._stat_lock:
            self.c["scoring_s_last"] = round(time.perf_counter() - t_score, 4)
            self.c["last_publish_wall"] = self.clock()
        if self.publish is not None and not self._stopped:
            self.publish(snap)

    def _alerts_and_log(self, batch, windows: pd.DataFrame, meta: dict) -> None:
        thr = self.s.alert_threshold
        peaks = np.max(np.asarray(batch.infiltration_probs, dtype=float), axis=1)
        active = 0
        lines = []
        for i, h in enumerate(batch.host_ids):
            peak = float(peaks[i])
            is_alert = peak >= thr
            active += is_alert
            if is_alert and not self._alert_state.get(h, False):
                with self._stat_lock:
                    self.recent_alerts.append({
                        "host": h, "peak_prob": round(peak, 4),
                        "stage": str(batch.stage_predictions[i][int(np.argmax(batch.infiltration_probs[i]))]),
                        "provisional": meta[h]["provisional"], "wall": self.clock()})
            self._alert_state[h] = is_alert
            if self.s.score_log is not None and not meta[h]["provisional"]:
                ws = self._host_seen.get(h)
                if ws is not None and self._logged_window.get(h) != ws:
                    self._logged_window[h] = ws
                    lines.append({"as_of": _iso(ws), "host": h, "peak_prob": round(peak, 4), "alert": bool(is_alert),
                                  "input_contiguous": meta[h]["input_contiguous"]})
        with self._stat_lock:
            self.c["alerts_active"] = int(active)
        if lines and self.s.score_log is not None:
            p = Path(self.s.score_log)
            p.parent.mkdir(parents=True, exist_ok=True)
            if p.exists() and p.stat().st_size > 50 * 1024 * 1024:
                p.replace(p.with_suffix(".jsonl.1"))
            with p.open("a", encoding="utf-8") as fh:
                fh.write("".join(json.dumps(x) + "\n" for x in lines))

    # ------------------------------------------------------------------ status

    RATE_WINDOW_S = 60.0   # LIVE ingests once per 10 s ring file, so the window must span several of them

    def _rates(self) -> tuple[float, float]:
        """Packets/s and flows/s over the last RATE_WINDOW_S of wall time, measured between ingest samples
        (the start baseline counts as a sample, so one ingest already gives a rate). Reads 0 once the feed
        has been silent for the whole window."""
        now = self.clock()
        samples = list(self._rate)
        inwin = [r for r in samples if now - r[0] <= self.RATE_WINDOW_S]
        if not inwin:
            return 0.0, 0.0
        older = [r for r in samples if now - r[0] > self.RATE_WINDOW_S]
        base = older[-1] if older else samples[0]
        last = inwin[-1]
        if last is base or last[0] <= base[0]:
            return 0.0, 0.0
        dt = last[0] - base[0]
        return (last[1] - base[1]) / dt, (last[2] - base[2]) / dt

    def halt(self) -> None:
        """After this the engine never publishes again (a stopped session must not write into STATE)."""
        self._stopped = True

    def status(self) -> dict[str, Any]:
        with self._stat_lock:
            c = dict(self.c)
            pps, fps = self._rates()
            lat = sorted(self._lat)
            plat = sorted(self._pkt_lat)
            fdel = sorted(self._final_delays)
            alerts = list(self.recent_alerts)[-10:]
        now = self.clock()
        # "no data for > 30 s", counted from the last data, or from the session start before any has arrived
        since = now - (c["last_data_wall"] if c["last_data_wall"] is not None else self.started_wall)
        stale = (not c["finished"]) and since > self.s.stale_after_s
        state = "STALE" if stale else self.mode
        wm = None if not np.isfinite(self._wm) else self._wm
        lag = (now - wm) if (self.mode == "LIVE" and wm is not None) else c["behind_schedule_s"]

        def q(a, p):
            return None if not a else round(a[min(int(len(a) * p), len(a) - 1)], 4)
        return {
            "state": state, "mode": self.mode, "source": self.source_name, "finished": c["finished"],
            "stale_after_s": self.s.stale_after_s, "seconds_since_data": round(since, 1),
            "packets_per_s": round(pps, 1), "flows_per_s": round(fps, 1),
            "frames_total": c["frames"], "packets_total": c["packets"], "packets_kept": c["packets_kept"], "flows_total": c["flows_final"],
            "windows_processed": c["windows_final"], "windows_provisional": c["windows_provisional"],
            "hosts_warming_up": c["hosts_warming"], "hosts_scored": c["hosts_scored"],
            "sequence_length": self.seq_len, "window_seconds": self.window_s,
            "last_window_time": _iso(c["last_window_start"]), "watermark": _iso(wm),
            "lag_seconds": None if lag is None else round(float(lag), 2),
            "dropped": {"unparsed_frames": c["unparsed"], "filtered_non_tcp_udp": c["filtered_proto"],
                        "filtered_outside_lab_cidr": c["filtered_cidr"], "filtered_ignored_port": c["filtered_port"],
                        "late_packets": c["late_dropped"], "buffer_overflow_packets": c["buffer_dropped"],
                        "hosts_evicted": c["hosts_evicted"], "files_failed": c["files_failed"]},
            "caps": {"max_hosts": self.s.max_hosts, "max_buffer_packets": self.s.max_buffer_packets,
                     "buffer_packets_now": 0 if self._cols is None else int(len(self._cols["ts"])),
                     "hosts_now": len(self._hist), "anchors_now": int(len(self._anchors))},
            "alert_threshold": self.s.alert_threshold, "alerts_active": c["alerts_active"],
            "recent_alerts": alerts,
            "flow_timeout_s": self.s.flow_timeout_s, "grace_s": self.s.grace_s,
            "lab_cidrs": list(self.s.lab_cidrs), "ignored_ports": list(self.s.ignore_ports),
            "ingest_seconds_p50": q(lat, 0.5), "ingest_seconds_max": None if not lat else round(lat[-1], 4),
            "packet_to_dashboard_seconds_p50": q(plat, 0.5), "packet_to_dashboard_seconds_max": None if not plat else round(plat[-1], 4),
            "window_final_delay_s_last": c["final_delay_s_last"],
            "window_final_delay_s_p50": q(fdel, 0.5),
            "error": c["error"],
            "disclosure": "flow-only checkpoint; packet features zero-filled; thresholds uncalibrated on this network",
        }


# ---------------------------------------------------------------------------------------------- sources

def list_captures(path: Path) -> list[Path]:
    path = Path(path)
    if path.is_file():
        return [path]
    return sorted((p for p in path.iterdir() if p.suffix.lower() in CAPTURE_SUFFIXES and p.is_file()),
                  key=lambda p: (p.stat().st_mtime, p.name))


class ReplaySource(threading.Thread):
    """Replay a PCAP file (or a folder of them, in name order) paced by packet timestamps. speed 1 = real
    time, 10 = ten times faster, 0 = as fast as possible. `max_gap_s` shortens any capture gap longer than
    that (wall time only; event time is untouched)."""

    def __init__(self, live: LiveEngine, paths: list[Path], speed: float = 1.0, slice_s: float | None = None,
                 max_gap_s: float | None = None, clock: Callable[[], float] = time.time,
                 stop_event: threading.Event | None = None):
        super().__init__(daemon=True, name="naf-replay")
        self.live, self.paths, self.speed = live, list(paths), float(speed)
        self.slice_s = slice_s if slice_s is not None else (10.0 if speed <= 0 else 1.0 if speed <= 1 else min(float(speed), 10.0))
        self.max_gap_s, self.clock = max_gap_s, clock
        self.stop_event = stop_event or threading.Event()

    def run(self) -> None:
        live = self.live
        try:
            wall0 = event0 = None
            skipped = 0.0
            prev_end = None
            for path in self.paths:
                if self.stop_event.is_set():
                    return
                cols, n_frames = read_all_frames_counted(path)
                with live._stat_lock:
                    live.c["files_ok"] += 1
                n = len(cols["ts"])
                if n == 0:
                    continue
                if not (np.diff(cols["ts"]) >= 0).all():
                    order = np.argsort(cols["ts"], kind="stable")
                    cols = {k: v[order] for k, v in cols.items()}
                ts = cols["ts"]
                unparsed_left = n_frames - n
                a = 0
                while a < n and not self.stop_event.is_set():
                    start = float(ts[a])
                    b = int(np.searchsorted(ts, start + self.slice_s, side="left"))
                    b = max(b, a + 1)
                    if event0 is None:
                        event0, wall0 = start, self.clock()
                        if self.max_gap_s is None:
                            live.clock_map = (event0, wall0, self.speed)
                    if self.max_gap_s is not None and prev_end is not None and start - prev_end > self.max_gap_s:
                        skipped += (start - prev_end) - self.max_gap_s
                    if self.speed > 0 and wall0 is not None:
                        # catch-up: if a tick took longer than its slice, take everything that is due now in one go
                        # rather than falling further behind one slice at a time
                        now_event = event0 + skipped + (self.clock() - wall0) * self.speed
                        if now_event > start + 2 * self.slice_s:
                            b = max(b, int(np.searchsorted(ts, now_event, side="left")))
                    prev_end = float(ts[b - 1])
                    if self.speed > 0:
                        due = wall0 + (start - event0 - skipped) / self.speed
                        while not self.stop_event.is_set():
                            wait = due - self.clock()
                            if wait <= 0:
                                break
                            self.stop_event.wait(min(wait, 0.25))
                        with live._stat_lock:
                            live.c["behind_schedule_s"] = max(self.clock() - due, 0.0)
                    else:
                        due = self.clock()
                    piece = {k: v[a:b] for k, v in cols.items()}
                    live.ingest(piece, frames=(b - a) + unparsed_left, sched_wall=due)
                    unparsed_left = 0
                    a = b
            if not self.stop_event.is_set():
                live.finish()
        except Exception as exc:  # surfaced in /live/status; a bad capture must not kill the server
            with live._stat_lock:
                live.c["error"] = f"{type(exc).__name__}: {exc}"
                live.c["finished"] = True


class LiveDirSource(threading.Thread):
    """Tail a directory of rotating dumpcap files. Every file except the newest is closed and is read once;
    the newest is read only after it has not changed for `settle_newest_s` (dumpcap stopped). A file that
    vanishes (rotation) or fails to parse is counted, never fatal."""

    def __init__(self, live: LiveEngine, directory: Path, poll_s: float = 1.0, settle_newest_s: float = 20.0,
                 clock: Callable[[], float] = time.time, stop_event: threading.Event | None = None):
        super().__init__(daemon=True, name="naf-live-tail")
        self.live, self.dir, self.poll_s, self.settle = live, Path(directory), poll_s, settle_newest_s
        self.clock = clock
        self.stop_event = stop_event or threading.Event()
        self.done: set[str] = set()

    def poll_once(self) -> int:
        """Process every currently-closed new file; returns how many. (Separate so tests can drive it.)"""
        try:
            files = [p for p in self.dir.iterdir() if p.suffix.lower() in CAPTURE_SUFFIXES and p.is_file()]
        except OSError:
            return 0
        stats = {}
        for p in files:
            try:
                stats[p] = p.stat()
            except OSError:
                pass
        ordered = sorted(stats, key=lambda p: (stats[p].st_mtime, p.name))
        self.done &= {p.name for p in ordered}   # rotation deleted the old ones: forget them
        n = 0
        for i, p in enumerate(ordered):
            if p.name in self.done:
                continue
            newest = i == len(ordered) - 1
            if newest and self.clock() - stats[p].st_mtime < self.settle:
                continue
            self.done.add(p.name)
            try:
                cols, n_frames = read_all_frames_counted(p)
            except Exception:
                with self.live._stat_lock:
                    self.live.c["files_failed"] += 1
                continue
            with self.live._stat_lock:
                self.live.c["files_ok"] += 1
            if len(cols["ts"]) or n_frames:
                self.live.ingest(cols, frames=n_frames)
                n += 1
        return n

    def run(self) -> None:
        try:
            while not self.stop_event.is_set():
                if not self.poll_once():
                    self.stop_event.wait(self.poll_s)
        except Exception as exc:
            with self.live._stat_lock:
                self.live.c["error"] = f"{type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------------------------- controller

class LiveController:
    """Owns at most one running source. app/server.py holds one of these."""

    def __init__(self) -> None:
        self.live: LiveEngine | None = None
        self.source: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self.live is not None and self.source is not None and self.source.is_alive()

    def active(self) -> bool:
        """True while the engine owns the dashboard state (running, or a replay that has finished but not
        been stopped). Upload and dataset switching are refused while this is true."""
        return self.live is not None

    def start(self, live: LiveEngine, source_factory: Callable[[LiveEngine, threading.Event], threading.Thread]) -> None:
        with self._lock:
            if self.live is not None:
                raise RuntimeError("a live/replay session is already active; stop it first")
            self._stop = threading.Event()
            self.live = live
            self.source = source_factory(live, self._stop)
            self.source.start()

    def stop(self) -> bool:
        with self._lock:
            if self.live is None:
                return False
            self.live.halt()          # first: even if the thread is stuck in a read, it can no longer publish
            self._stop.set()
            if self.source is not None:
                self.source.join(timeout=10)
            self.live, self.source = None, None
            return True

    def status(self) -> dict[str, Any]:
        if self.live is None:
            return {"state": "OFF", "mode": "OFF", "source": None}
        return self.live.status()
