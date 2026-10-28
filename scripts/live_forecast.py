"""Run the trained world model against live network traffic (OFFLINE / JSONL tool).

SUPERSEDED for the dashboard by app/live.py (docs/11): that engine runs inside the server, uses the fast
parser, assembles flows over a rolling buffer instead of per file (this script splits every flow that
crosses a rotation boundary), and feeds the dashboard's STATE. This script is kept as a standalone way to
get a JSONL alert log without the server. It still uses the Scapy flow path, which is slow (about 3,200
packets/s on the dev PC) and has no flow timeout. Its alert threshold and default model now follow the
server (service.ALERT_THRESHOLD, the seed-1 v2 model). Merged from branch live-deployment-2026-10-10.

Replaces the row-count batching in `scripts/stream_consumer.py`, which had three defects that
made it unsuitable for a real deployment:

  * It batched every 100 ROWS. A 10-second window does not align to a row count, so a window got
    split across batches and was emitted twice, each time with only part of its flows. Windows
    here are closed on EVENT TIME: a window is emitted only once the watermark (newest flow
    timestamp seen) has passed its end, and flows belonging to a still-open window are carried
    over to the next chunk instead of being scored early.
  * It loaded the scaler straight from `processed_dir/scaler.npz`, which does not exist on a
    deployment box that has no `data/processed*` directory. This goes through
    `service.load_backend`, the same loader the dashboard uses.
  * It defaulted to `configs/default.yaml` -- the SYNTHETIC pipeline. The default here is the
    real converged checkpoint that every published number refers to.

It also POSTed to `/api/v1/alerts/ingest`, which does not exist in `app/server.py` (it was
written against the older `app/api.py`). Alerts are written to a JSONL file by default; `--post-to`
is opt-in and off unless a URL is given.

Where the flows come from
-------------------------
The 19 flow-level features include `mean_iat`/`var_iat`/`max_iat`, which are averages of each
flow's own INTRA-flow packet inter-arrival statistics (`pipeline/windowing.py` aggregates the
per-flow `iat_mean`/`iat_std`/`iat_max` columns). Zeek's conn.log does not carry those, so a
Zeek-only sensor cannot populate 3 of the 19 features and is not offered here. What does work:

  * ``--source pcap-dir``  -- the real live path. Point tcpdump at a directory and rotate every
    `window_seconds`, then this derives full flow records with genuine IATs using the project's
    own `pipeline/packet_features.build_flow_records` (effectively a CICFlowMeter stand-in):

        sudo tcpdump -i eth0 -G 10 -w /var/spool/naf/cap-%Y%m%d-%H%M%S.pcap -z gzip

    A file is only read once it has been untouched for `--settle-seconds`, so a pcap still being
    written is never parsed half-complete.
  * ``--source csv-replay`` -- replays a CICFlowMeter CSV in timestamp order. This drives the
    demo and exercises exactly the same windowing/buffering/scoring code as the live path, so
    the demo is not a separate codepath that can drift from production.

Deliberate non-features
-----------------------
Packet-level features stay ZERO-FILLED even when a PCAP is the source, because the shipped
checkpoint is flow-only (`service.is_flow_only_model`); feeding real packet features to it would
be off-distribution. Empty windows are NOT synthesised: training dropped windows with no flows,
so the per-host buffer holds the last `sequence_length` NON-EMPTY windows, matching it.

    python -m scripts.live_forecast --source pcap-dir --path /var/spool/naf
    python -m scripts.live_forecast --source csv-replay --path data/raw/flows_real/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv --speed 0
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import deque
from pathlib import Path

import numpy as np
import pandas as pd

from app import service
from common.config import feature_columns
from models.checkpoint_io import load_checkpoint, validate_feature_names
from models.forecast import ForecastEngine
from pipeline.flow_features import clean_and_normalize, load_flow_csv
from pipeline.graph_embedding_features import build_graph_embedding_window_features
from pipeline.graph_features import build_graph_window_features
from pipeline.packet_features import build_flow_records, load_pcap
from pipeline.windowing import (
    apply_reconnaissance_heuristic, build_flow_windows, merge_graph_embedding_features,
    merge_graph_features, merge_packet_features,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

CALIBRATION_WARNING = """
  !  These probabilities are NOT calibrated for this network.
     The model was fitted on the CIC-IDS-2018 lab capture. Live traffic differs in host mix,
     service profile and volume, so the absolute numbers carry no validated meaning here and the
     published AUROC does not transfer. Expect false positives. Treat output as a ranking signal
     for triage, not as a verdict, until it has been scored against ground truth on this network.
"""


class LiveForecaster:
    """Event-time windowing plus per-host sequence buffers over a stream of flow records."""

    def __init__(self, config: dict, engine: ForecastEngine, alert_threshold: float):
        self.config = config
        self.engine = engine
        self.alert_threshold = alert_threshold
        self.window_seconds = int(config["windowing"]["window_seconds"])
        self.seq_len = int(config["windowing"]["sequence_length"])
        self.feature_cols = feature_columns(config)
        # Last `seq_len` NON-EMPTY windows per host -- training dropped empty windows, so we do too.
        self.buffers: dict[str, deque] = {}
        self._carryover: pd.DataFrame | None = None
        self._seen_windows: dict[str, set] = {}

    def _assemble(self, flows: pd.DataFrame) -> pd.DataFrame:
        """Same feature-assembly order as app/service.py::process_uploads. Graph and
        graph-embedding features are computed over the whole chunk, which carries the cross-host
        context a graph needs; packet columns zero-fill (flow-only checkpoint)."""
        w = build_flow_windows(flows, self.config)
        w = merge_packet_features(w, None, self.config)
        w = merge_graph_features(w, build_graph_window_features(flows, self.config), self.config)
        w = merge_graph_embedding_features(
            w, build_graph_embedding_window_features(flows, self.config), self.config)
        return apply_reconnaissance_heuristic(w, self.config)

    def feed(self, flows: pd.DataFrame | None, final: bool = False) -> list[dict]:
        """Ingest a chunk of flow records; return forecasts for hosts with a full sequence.

        Flows in the still-open trailing window are held back until the next chunk, so a window
        is never scored on a partial view of itself.
        """
        parts = [p for p in (self._carryover, flows) if p is not None and len(p)]
        self._carryover = None
        if not parts:
            return []
        flows = parts[0] if len(parts) == 1 else pd.concat(parts, ignore_index=True)

        flows = flows.sort_values("timestamp")
        watermark = flows["timestamp"].max()

        if not final:
            # Hold back the trailing, still-open window.
            cutoff = watermark.floor(f"{self.window_seconds}s")
            open_rows = flows["timestamp"] >= cutoff
            self._carryover = flows[open_rows].copy()
            flows = flows[~open_rows]
            if flows.empty:
                return []

        windows = self._assemble(flows)
        if windows.empty:
            return []

        out = []
        for host, hw in windows.groupby("src_ip"):
            seen = self._seen_windows.setdefault(str(host), set())
            buf = self.buffers.setdefault(str(host), deque(maxlen=self.seq_len))
            for _, row in hw.sort_values("window_start").iterrows():
                key = row["window_start"]
                if key in seen:
                    continue  # never score the same window twice
                seen.add(key)
                buf.append(row)
            if len(buf) < self.seq_len:
                continue
            seq = np.stack([r[self.feature_cols].to_numpy(dtype=np.float32) for r in buf])
            res = self.engine.rollout(seq)
            probs = np.asarray(res.infiltration_probs, dtype=float)
            peak = int(np.argmax(probs))
            out.append({
                "host": str(host),
                "as_of": str(buf[-1]["window_start"]),
                "peak_prob": round(float(probs[peak]), 4),
                "peak_step": peak + 1,
                "peak_horizon_seconds": (peak + 1) * self.window_seconds,
                "trajectory": [round(float(p), 4) for p in probs],
                "predicted_stage": res.stage_predictions[peak],
                "alert": bool(probs[peak] >= self.alert_threshold),
            })
        return out


# --------------------------------------------------------------------------------------- sources

def source_pcap_dir(path: Path, settle_seconds: float, poll_seconds: float):
    """Yield flow records from completed rotated PCAPs, oldest first, each file read once."""
    done: set[str] = set()
    while True:
        ready = []
        for p in sorted(path.glob("*.pcap")) + sorted(path.glob("*.pcapng")):
            if p.name in done:
                continue
            if time.time() - p.stat().st_mtime < settle_seconds:
                continue  # still being written by tcpdump
            ready.append(p)
        for p in ready:
            done.add(p.name)
            try:
                packets = load_pcap(p)
                if len(packets):
                    yield build_flow_records(packets)
            except Exception as exc:  # a truncated rotation must not kill the daemon
                print(f"[warn] {p.name}: {exc}", file=sys.stderr)
        if not ready:
            time.sleep(poll_seconds)


def source_csv_replay(path: Path, window_seconds: int, speed: float):
    """Replay a CICFlowMeter CSV in timestamp order, one window-sized chunk at a time.

    `--speed 0` replays as fast as possible (for the demo); `--speed 1` paces it at real time.
    """
    df = clean_and_normalize(load_flow_csv(path, require_label=False)).sort_values("timestamp")
    for _, chunk in df.groupby(df["timestamp"].dt.floor(f"{window_seconds}s")):
        yield chunk
        if speed > 0:
            time.sleep(window_seconds / speed)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--config", default="configs/real_data_v2_converged_seed1.yaml",
                    help="The served seed-1 v2 model by default, NOT the synthetic configs/default.yaml.")
    ap.add_argument("--source", choices=("pcap-dir", "csv-replay"), required=True)
    ap.add_argument("--path", type=Path, required=True)
    ap.add_argument("--threshold", type=float, default=service.ALERT_THRESHOLD,
                    help="Alert threshold (the one shared server value). Uncalibrated on live traffic -- see startup warning.")
    ap.add_argument("--alert-log", type=Path, default=PROJECT_ROOT / "logs" / "live_alerts.jsonl")
    ap.add_argument("--post-to", default=None,
                    help="Optional URL to POST alerts to. Off by default; app/server.py has no "
                         "alert-ingest endpoint, so nothing is posted unless you supply one.")
    ap.add_argument("--speed", type=float, default=1.0, help="csv-replay only. 0 = as fast as possible.")
    ap.add_argument("--settle-seconds", type=float, default=2.0, help="pcap-dir only.")
    ap.add_argument("--poll-seconds", type=float, default=1.0, help="pcap-dir only.")
    args = ap.parse_args()

    config, model, scaler, _ = service.load_backend(args.config)
    if model is None:
        raise SystemExit(f"No checkpoint for {args.config}")
    engine = ForecastEngine(model, scaler, config)

    feature_cols = feature_columns(config)
    # Fail loudly on a schema mismatch at startup rather than with a silently-wrong forecast
    # later: checks column NAMES and ORDER, not just width (audit W19).
    from common.config import resolve_path
    validate_feature_names(
        load_checkpoint(resolve_path(config, "checkpoint_dir") / "world_model_best.pt"), feature_cols)

    fc = LiveForecaster(config, engine, args.threshold)
    print(f"[*] config {args.config} | {len(feature_cols)} features | "
          f"window {fc.window_seconds}s | sequence {fc.seq_len} "
          f"({fc.seq_len * fc.window_seconds}s of history needed before the first forecast)")
    if service.is_flow_only_model(config):
        print("[*] flow-only checkpoint: packet-level features are zero-filled by design.")
    print(CALIBRATION_WARNING)

    if args.source == "pcap-dir":
        if not args.path.is_dir():
            raise SystemExit(f"Not a directory: {args.path}")
        stream = source_pcap_dir(args.path, args.settle_seconds, args.poll_seconds)
    else:
        if not args.path.is_file():
            raise SystemExit(f"Not a file: {args.path}")
        stream = source_csv_replay(args.path, fc.window_seconds, args.speed)

    args.alert_log.parent.mkdir(parents=True, exist_ok=True)
    n_alerts = n_forecasts = 0
    session = None
    if args.post_to:
        import requests
        session = requests.Session()

    with args.alert_log.open("a", encoding="utf-8") as log:
        try:
            for chunk in stream:
                for r in fc.feed(chunk):
                    n_forecasts += 1
                    if not r["alert"]:
                        continue
                    n_alerts += 1
                    log.write(json.dumps(r) + "\n")
                    log.flush()
                    print(f"[ALERT] {r['host']:<24} p={r['peak_prob']:.3f} "
                          f"at +{r['peak_horizon_seconds']}s  stage={r['predicted_stage']}  "
                          f"as_of={r['as_of']}")
                    if session:
                        try:
                            session.post(args.post_to, json=r, timeout=5)
                        except Exception as exc:
                            print(f"[warn] POST failed: {exc}", file=sys.stderr)
        except KeyboardInterrupt:
            print("\n[*] stopped")
        finally:
            for r in fc.feed(None, final=True):
                n_forecasts += 1

    print(f"[*] {n_forecasts} forecasts, {n_alerts} alerts >= {args.threshold} -> {args.alert_log}")


if __name__ == "__main__":
    main()
