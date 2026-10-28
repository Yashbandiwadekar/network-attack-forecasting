"""docs/09 A3: app/live.py (replay + live-tail engine).

The parity tests are the point: the same packets must produce the same per-window features whether they
arrive in 10-second slices through the live engine or as one whole file through the batch path.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from app import live as live_mod
from app import service
from app.live import LiveEngine, LiveSettings, ReplaySource
from common.config import feature_columns
from models.forecast import ForecastEngine
from pipeline.fast_packet_windows import assemble_flows, ip_to_str, read_all_frames, read_all_frames_counted
from pipeline.windowing import (
    apply_reconnaissance_heuristic, build_flow_windows, merge_graph_embedding_features,
    merge_graph_features, merge_packet_features,
)
from pipeline.graph_embedding_features import build_graph_embedding_window_features
from pipeline.graph_features import build_graph_window_features
from tests.live_fixtures import BASE, LINK, dense_pcap

DEFAULT = "configs/real_data_v2_converged_seed1.yaml"


@pytest.fixture(scope="module")
def backend():
    service.clear_backend_cache()
    config, model, scaler, _ = service.load_backend(DEFAULT)
    if model is None:
        pytest.skip("served checkpoint not present")
    return config, ForecastEngine(model, scaler, config)


@pytest.fixture(scope="module")
def pcap(tmp_path_factory):
    return dense_pcap(tmp_path_factory.mktemp("live") / "dense.pcap")


@pytest.fixture(scope="module")
def pcap_long(tmp_path_factory):
    return dense_pcap(tmp_path_factory.mktemp("live_long") / "long.pcap", long_flows=True, seed=3)


def make_engine(backend, **kw):
    config, eng = backend
    snaps = []
    pub = kw.pop("publish", snaps.append)
    clock = kw.pop("clock", time.time)
    mode = kw.pop("mode", "REPLAY")
    settings = LiveSettings(**{"collect_final": True, **kw})
    return LiveEngine(eng, config, settings, publish=pub, mode=mode, clock=clock), snaps


def replay(le: LiveEngine, path: Path, speed: float = 0) -> None:
    ReplaySource(le, [path], speed=speed).run()
    assert le.c["error"] is None, le.c["error"]


def batch_windows(backend, path: Path, timeout_s: float) -> pd.DataFrame:
    """The batch path: whole file, one assemble_flows call, one feature assembly. Written out here
    (not via LiveEngine helpers) so the comparison is independent of the engine's own adapter."""
    config, _ = backend
    f = assemble_flows(read_all_frames(path), timeout_s=timeout_s)
    flows = f.drop(columns=["timestamp_s", "src_ip", "dst_ip"]).copy()
    flows["timestamp"] = pd.to_datetime(f["timestamp_s"].to_numpy(), unit="s")
    flows["src_ip"] = ip_to_str(f["src_ip"]).to_numpy()
    flows["dst_ip"] = ip_to_str(f["dst_ip"]).to_numpy()
    flows["label"] = "BENIGN"
    w = build_flow_windows(flows, config)
    w = merge_packet_features(w, None, config)
    w = merge_graph_features(w, build_graph_window_features(flows, config), config)
    w = merge_graph_embedding_features(w, build_graph_embedding_window_features(flows, config), config)
    return apply_reconnaissance_heuristic(w, config)


def assert_same_windows(live: pd.DataFrame, batch: pd.DataFrame, cols, tol=1e-6):
    key = ["src_ip", "window_start"]
    a = live.sort_values(key).reset_index(drop=True)
    b = batch.sort_values(key).reset_index(drop=True)
    assert not a.duplicated(key).any(), "duplicate (src_ip, window_start) rows"
    assert len(a) == len(b) and (a[key].values == b[key].values).all(), "different (host, window) sets"
    diff = max(float(np.abs(a[c].astype(float) - b[c].astype(float)).max()) for c in cols)
    assert diff < tol, f"max abs feature difference {diff}"


# ------------------------------------------------------------------------------------------ parity

def test_replay_equals_batch_for_every_final_window(backend, pcap):
    le, _ = make_engine(backend, flow_timeout_s=30.0)
    replay(le, pcap)
    live = pd.DataFrame(le.final_rows)
    cols = feature_columns(backend[0])
    assert len(live) > 150 and len(cols) == 41
    assert_same_windows(live, batch_windows(backend, pcap, 30.0), cols)


def test_long_flows_crossing_many_windows_still_match_batch(backend, pcap_long):
    """A connection that lives 300 s crosses ten timeout buckets and thirty windows. Without the
    anchors it would restart at every trimmed buffer edge and the features would differ."""
    le, _ = make_engine(backend, flow_timeout_s=30.0)
    replay(le, pcap_long)
    cols = feature_columns(backend[0])
    assert_same_windows(pd.DataFrame(le.final_rows), batch_windows(backend, pcap_long, 30.0), cols)


def test_slice_size_does_not_change_the_features(backend, pcap):
    cols = feature_columns(backend[0])
    outs = []
    for slice_s in (1.0, 7.0, 40.0):
        le, _ = make_engine(backend, flow_timeout_s=30.0)
        ReplaySource(le, [pcap], speed=0, slice_s=slice_s).run()
        outs.append(pd.DataFrame(le.final_rows))
    assert_same_windows(outs[0], outs[1], cols)
    assert_same_windows(outs[0], outs[2], cols)


def test_replay_matches_the_upload_path_including_iat_units(backend, pcap):
    """process_uploads (Scapy flows, no timeout) is the reference the dashboard's upload uses. Flows in the
    fixture last < 3 s, so the two must agree; the IAT columns need the same tolerance the existing
    fast-vs-Scapy test uses (timestamps round differently by about 1 microsecond)."""
    config, _ = backend
    le, _ = make_engine(backend, flow_timeout_s=120.0)
    replay(le, pcap)
    live = pd.DataFrame(le.final_rows)
    _, ref = service.process_uploads(None, pcap, config)
    key = ["src_ip", "window_start"]
    a = live.sort_values(key).reset_index(drop=True)
    b = ref.sort_values(key).reset_index(drop=True)
    assert len(a) == len(b) and (a[key].values == b[key].values).all()
    iat = {"mean_iat", "var_iat", "max_iat"}
    for c in feature_columns(config):
        x, y = a[c].astype(float).to_numpy(), b[c].astype(float).to_numpy()
        if c in iat:
            np.testing.assert_allclose(x, y, rtol=1e-3, atol=10.0, err_msg=c)
        else:
            np.testing.assert_allclose(x, y, rtol=1e-6, atol=1e-6, err_msg=c)
    # microseconds, not seconds: flows here have packet gaps of 0.1-0.5 s, i.e. about 1e5 us
    assert a["mean_iat"].median() > 1e4


# ------------------------------------------------------------------------------------------ gating

def _slice(cols, t0, t1):
    m = (cols["ts"] >= t0) & (cols["ts"] < t1)
    return {k: v[m] for k, v in cols.items()}


def test_warmup_gating_and_scoring(backend, pcap):
    cols = read_all_frames(pcap)
    le, snaps = make_engine(backend, flow_timeout_s=30.0)
    le.ingest(_slice(cols, BASE, BASE + 100))
    st = le.status()
    assert snaps[-1].batch is None and st["hosts_scored"] == 0 and st["hosts_warming_up"] >= 5
    le.ingest(_slice(cols, BASE + 100, BASE + 160))
    st = le.status()
    snap = snaps[-1]
    assert st["hosts_scored"] >= 5 and snap.batch is not None
    assert set(snap.batch.host_ids) == set(snap.host_meta)
    # every scored host really has 12 windows of history behind it
    assert all(m["windows_seen"] >= 12 for m in snap.host_meta.values())
    assert snap.windows["stage_observed"].eq(False).all()


def test_provisional_window_is_flagged_and_replaced_by_the_final_one(backend, pcap):
    cols = read_all_frames(pcap)
    le, snaps = make_engine(backend, flow_timeout_s=30.0)
    le.ingest(_slice(cols, BASE, BASE + 200))
    assert any(m["provisional"] for m in snaps[-1].host_meta.values())
    le.finish()
    assert not any(m["provisional"] for m in snaps[-1].host_meta.values())
    w = snaps[-1].windows
    assert not w.duplicated(["src_ip", "window_start"]).any()


def test_input_contiguous_flag(backend, pcap):
    cols = read_all_frames(pcap)
    hole = (cols["ts"] >= BASE + 230) & (cols["ts"] < BASE + 250)
    h1 = (cols["src"] == (10 << 24) + 1) | (cols["dst"] == (10 << 24) + 1)
    cols = {k: v[~(hole & h1)] for k, v in cols.items()}
    le, snaps = make_engine(backend, flow_timeout_s=30.0)
    le.ingest(_slice(cols, BASE, BASE + 290))
    meta = snaps[-1].host_meta
    assert meta["10.0.0.1"]["input_contiguous"] is False
    assert meta["10.0.0.2"]["input_contiguous"] is True


def test_stale_detection_uses_the_injected_clock(backend, pcap):
    now = [1000.0]
    cols = read_all_frames(pcap)
    le, _ = make_engine(backend, flow_timeout_s=30.0, clock=lambda: now[0])
    assert le.status()["state"] == "REPLAY"         # just started: not stale until 30 s have passed with no data
    now[0] += 31
    assert le.status()["state"] == "STALE"          # nothing ever arrived
    le.ingest(_slice(cols, BASE, BASE + 30))
    assert le.status()["state"] == "REPLAY"
    now[0] += 29
    assert le.status()["state"] == "REPLAY"
    now[0] += 2
    st = le.status()
    assert st["state"] == "STALE" and st["seconds_since_data"] > 30
    le.ingest(_slice(cols, BASE + 30, BASE + 40))
    assert le.status()["state"] == "REPLAY"
    le.finish()                                      # a finished replay is not stale, it is finished
    now[0] += 500
    st = le.status()
    assert st["state"] == "REPLAY" and st["finished"] is True


def test_live_mode_reports_live_and_lag(backend, pcap):
    cols = read_all_frames(pcap)
    t_end = BASE + 30
    now = [t_end + 4.0]
    le, _ = make_engine(backend, mode="LIVE", clock=lambda: now[0])
    le.ingest(_slice(cols, BASE, t_end))
    st = le.status()
    assert st["state"] == "LIVE" and 3.0 < st["lag_seconds"] < 5.0


def test_filters_and_late_packets_are_counted(backend, pcap):
    cols = read_all_frames(pcap)
    le, _ = make_engine(backend, flow_timeout_s=30.0, lab_cidrs=("10.0.0.0/24",), ignore_ports=(443,))
    le.ingest(_slice(cols, BASE, BASE + 120))
    st = le.status()["dropped"]
    # servers live in 10.0.1.0/24, outside the lab CIDR, so nothing between a client and a server is kept
    assert st["filtered_outside_lab_cidr"] > 0 and le.c["packets_kept"] == 0
    le2, _ = make_engine(backend, flow_timeout_s=30.0, ignore_ports=(443,))
    le2.ingest(_slice(cols, BASE, BASE + 120))
    assert le2.status()["dropped"]["filtered_ignored_port"] > 0
    assert not (le2._cols["sport"] == 443).any() and not (le2._cols["dport"] == 443).any()
    # a packet for a window that is already final is dropped, not silently merged
    le2.ingest(_slice(cols, BASE + 120, BASE + 200))
    before = le2.c["late_dropped"]
    le2.ingest(_slice(cols, BASE, BASE + 5))
    assert le2.c["late_dropped"] > before


def test_cidr_keeps_traffic_when_both_ends_are_inside(backend, pcap):
    cols = read_all_frames(pcap)
    le, _ = make_engine(backend, lab_cidrs=("10.0.0.0/16",))
    le.ingest(_slice(cols, BASE, BASE + 60))
    assert le.status()["dropped"]["filtered_outside_lab_cidr"] == 0 and le.c["packets_kept"] > 0


# ------------------------------------------------------------------------------------------ bounds

def test_memory_is_bounded(backend, pcap):
    cols = read_all_frames(pcap)
    total = len(cols["ts"])
    le, _ = make_engine(backend, flow_timeout_s=30.0, max_hosts=3, max_buffer_packets=400, max_flows_kept=50)
    ReplaySource(le, [pcap], speed=0, slice_s=5.0).run()
    st = le.status()
    assert st["caps"]["hosts_now"] <= 3 and st["dropped"]["hosts_evicted"] > 0
    assert all(len(dq) <= le.s.keep_windows for dq in le._hist.values())
    assert len(le._hist) <= 3
    assert sum(len(f) for f in le._recent_flows) <= 50 + 200   # one extra whole batch of flows at most
    assert st["caps"]["buffer_packets_now"] <= 400
    # and with a sane cap the buffer is a small fraction of the capture: it trims as windows finalise
    le2, _ = make_engine(backend, flow_timeout_s=30.0)
    ReplaySource(le2, [pcap], speed=0, slice_s=5.0).run()
    peak = max(le2._lat) if le2._lat else 0
    assert le2.status()["caps"]["anchors_now"] < total / 10
    assert le2.status()["caps"]["buffer_packets_now"] < total / 20
    assert peak >= 0


def test_buffer_trims_during_a_long_replay(backend, pcap):
    cols = read_all_frames(pcap)
    le, _ = make_engine(backend, flow_timeout_s=30.0)
    peak = 0
    for t in range(0, 300, 5):
        le.ingest(_slice(cols, BASE + t, BASE + t + 5))
        peak = max(peak, len(le._cols["ts"]) if le._cols is not None else 0)
    # about T + grace + one window + one slice (47 s) of a 300 s capture
    assert peak < len(cols["ts"]) * 0.30


def test_score_log_written_once_per_final_window(backend, pcap, tmp_path):
    log = tmp_path / "scores.jsonl"
    le, _ = make_engine(backend, flow_timeout_s=30.0, score_log=log)
    replay(le, pcap)
    lines = log.read_text().splitlines()
    assert lines and len({(__import__("json").loads(x)["host"], __import__("json").loads(x)["as_of"]) for x in lines}) == len(lines)


def test_packet_features_models_are_refused(backend, monkeypatch):
    config, eng = backend
    monkeypatch.setattr(service, "is_flow_only_model", lambda c: False)
    with pytest.raises(live_mod.LiveConfigError):
        LiveEngine(eng, config, LiveSettings())


# ------------------------------------------------------------------------------------------ live tail

def _split_files(cols, dirpath: Path, bounds):
    """Write slices of the capture as separate pcap files (mtime increasing) like dumpcap's ring."""
    from scapy.all import IP, TCP, UDP, Ether, wrpcap
    raw = []
    for a, b in zip(bounds[:-1], bounds[1:]):
        pkts = []
        for i in np.nonzero((cols["ts"] >= a) & (cols["ts"] < b))[0]:
            ip = lambda v: ".".join(str((int(v) >> s) & 255) for s in (24, 16, 8, 0))
            l4 = (TCP(sport=int(cols["sport"][i]), dport=int(cols["dport"][i]), flags=int(cols["flags"][i]))
                  if cols["is_tcp"][i] else UDP(sport=int(cols["sport"][i]), dport=int(cols["dport"][i])))
            p = LINK / IP(src=ip(cols["src"][i]), dst=ip(cols["dst"][i])) / l4 / (b"x" * int(cols["l4pay"][i]))
            p.time = float(cols["ts"][i])
            pkts.append(p)
        raw.append(pkts)
    paths = []
    for n, pkts in enumerate(raw):
        p = dirpath / f"ring_{n:05d}.pcap"
        wrpcap(str(p), pkts)
        paths.append(p)
    return paths


def test_live_tail_reads_closed_files_once_and_skips_the_open_one(backend, pcap, tmp_path):
    cols = read_all_frames(pcap)
    files = _split_files(cols, tmp_path, [BASE, BASE + 60, BASE + 120, BASE + 180])
    for i, f in enumerate(files):
        os.utime(f, (1000 + 10 * i, 1000 + 10 * i))
    now = [1000 + 25.0]
    le, snaps = make_engine(backend, mode="LIVE", flow_timeout_s=30.0, clock=lambda: now[0])
    src = live_mod.LiveDirSource(le, tmp_path, settle_newest_s=20.0, clock=lambda: now[0])
    assert src.poll_once() == 2          # files 0 and 1 are closed; file 2 (newest, mtime 1020) is "open"
    assert src.poll_once() == 0          # nothing new, nothing re-read
    now[0] += 30                         # dumpcap stopped: the newest file settles
    assert src.poll_once() == 1
    assert le.c["files_ok"] == 3
    # a rotated-away file is forgotten, a corrupt one is counted and does not stop the tail
    files[0].unlink()
    bad = tmp_path / "ring_00009.pcap"
    bad.write_bytes(b"not a pcap at all")
    os.utime(bad, (now[0] - 100, now[0] - 100))
    src.poll_once()
    assert le.c["files_failed"] == 1 and files[0].name not in src.done
    # the packets from the three files equal a single replay of the same data
    ref, _ = make_engine(backend, flow_timeout_s=30.0)
    ref.ingest(_slice(cols, BASE, BASE + 180))
    ref.finish()
    le.finish()
    assert le.c["flows_final"] == ref.c["flows_final"]


def test_replay_speed_paces_by_packet_time(backend, pcap):
    """speed=60: 40 s of capture takes roughly 0.7 s of wall time, not 40 s and not 0."""
    cols = read_all_frames(pcap)
    cut = _slice(cols, BASE, BASE + 40)
    wall = [0.0]
    sleeps = []

    class FakeStop:
        def is_set(self): return False
        def wait(self, t): sleeps.append(t); wall[0] += t

    le, _ = make_engine(backend, flow_timeout_s=30.0, clock=lambda: wall[0])
    src = ReplaySource(le, [pcap], speed=60.0, slice_s=1.0, clock=lambda: wall[0], stop_event=FakeStop())
    # feed the shortened capture through the same pacing code by pointing at a temp file
    import tempfile
    from scapy.all import wrpcap
    with tempfile.TemporaryDirectory() as d:
        p = _split_files(cut, Path(d), [BASE, BASE + 40])[0]
        src.paths = [p]
        src.run()
    assert 0.5 < sum(sleeps) < 0.9


# ------------------------------------------------------------------------------------------ thresholds

def test_there_is_one_alert_threshold():
    assert service.ALERT_THRESHOLD == 0.40
    assert service.severity_for(service.ALERT_THRESHOLD) == "serious"          # the "high risk" tier starts here
    assert service.severity_for(service.ALERT_THRESHOLD - 1e-6) == "warning"
    assert LiveSettings().alert_threshold == service.ALERT_THRESHOLD
    assert [t for t, _ in service.SEVERITY_LEVELS] == [0.70, 0.40, 0.15]


def test_alerts_fire_once_per_crossing_and_use_the_shared_threshold(backend, pcap, monkeypatch):
    from models.forecast import BatchForecastResult
    le, _ = make_engine(backend, flow_timeout_s=30.0)
    hot = [True]

    def fake(host_ids, seqs, batch_size=2048):
        k = int(backend[0]["windowing"]["forecast_horizon"])
        p = 0.9 if hot[0] else 0.1
        return BatchForecastResult(host_ids=host_ids, infiltration_probs=np.full((len(host_ids), k), p),
                                   stage_predictions=[["impact"] * k for _ in host_ids],
                                   stage_is_heuristic=[[False] * k for _ in host_ids])
    monkeypatch.setattr(le.engine, "rollout_batch", fake)
    cols = read_all_frames(pcap)
    le.ingest(_slice(cols, BASE, BASE + 150))
    st = le.status()
    assert st["alerts_active"] == st["hosts_scored"] > 0 and len(le.recent_alerts) == st["hosts_scored"]
    le.ingest(_slice(cols, BASE + 150, BASE + 170))          # still hot: no duplicate alert events
    assert len(le.recent_alerts) == st["hosts_scored"]
    hot[0] = False
    le.ingest(_slice(cols, BASE + 170, BASE + 190))
    assert le.status()["alerts_active"] == 0
    hot[0] = True
    le.ingest(_slice(cols, BASE + 190, BASE + 210))          # crosses again: new events
    assert len(le.recent_alerts) == 2 * st["hosts_scored"]


def test_live_rates_are_non_zero_between_ring_files(backend, pcap):
    """LIVE ingests once per 10 s file. A rate computed over only the last 10 s would read 0 at almost every
    5-second poll."""
    cols = read_all_frames(pcap)
    now = [5000.0]
    le, _ = make_engine(backend, mode="LIVE", clock=lambda: now[0])
    le.ingest(_slice(cols, BASE, BASE + 10))
    now[0] += 10
    le.ingest(_slice(cols, BASE + 10, BASE + 20))
    now[0] += 5                                         # a dashboard poll halfway between two files
    st = le.status()
    assert st["packets_per_s"] > 0 and st["state"] == "LIVE"
    one = make_engine(backend, mode="LIVE", clock=lambda: now[0])[0]
    now[0] += 3
    one.ingest(_slice(cols, BASE, BASE + 10))
    now[0] += 4
    assert one.status()["packets_per_s"] > 0            # a single ingest is already enough
    now[0] += 120
    assert le.status()["packets_per_s"] == 0.0          # silent for the whole window


def test_halted_engine_never_publishes_again(backend, pcap):
    cols = read_all_frames(pcap)
    le, snaps = make_engine(backend)
    le.ingest(_slice(cols, BASE, BASE + 20))
    n = len(snaps)
    assert n >= 1
    le.halt()
    le.ingest(_slice(cols, BASE + 20, BASE + 60))
    assert len(snaps) == n
