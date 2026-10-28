"""NetFlow-v2, PCAP, generic CICFlowMeter, labels sidecar, the two drop-bug regressions, multi-unit equivalence."""
from __future__ import annotations

import os

os.environ.setdefault("CUDA_VISIBLE_DEVICES", "-1")

import numpy as np
import pandas as pd
import pytest
import yaml
from scapy.all import IP, TCP, UDP, Ether, wrpcap

from common.config import PROJECT_ROOT, load_config
from models.dataset import build_datasets, load_split
from pipeline.adapters import ctu13 as base_ctu
from pipeline.adapters import prepare as P
from pipeline.adapters import validation as V
from pipeline.adapters import unsw_nb15 as base_unsw
from pipeline.adapters.base import check_canonical_frame
from pipeline.adapters.registry import detect_dataset, get_adapter
from pipeline.adapters.sidecar import LabelSidecar
from pipeline.graph_builder import load_window_graphs
from pipeline.mitre_mapping import label_to_stage, nf_classify
from tests.adapter_fixtures import cic_df, unsw_rows, write_cic, write_ctu

CFG = "configs/default.yaml"


def _quiet(*_a, **_k):
    return None


# ---- NetFlow v2 -------------------------------------------------------------------------------------
def nf_df(n=200, attack=("Exploits", 100, 140), seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(n):
        inp, outp = int(rng.integers(2, 10)), int(rng.integers(2, 8))
        dur = float(rng.integers(500, 5000))
        a = attack[0] if attack and attack[1] <= i < attack[2] else "Benign"
        rows.append({
            "IPV4_SRC_ADDR": f"10.0.0.{1 + i % 3}", "L4_SRC_PORT": 40000 + i, "IPV4_DST_ADDR": f"10.9.9.{1 + i % 7}",
            "L4_DST_PORT": 80, "PROTOCOL": 6 if i % 4 else 17, "L7_PROTO": 7.0, "IN_BYTES": inp * 100, "OUT_BYTES": outp * 300,
            "IN_PKTS": inp, "OUT_PKTS": outp, "TCP_FLAGS": 0x1B if i % 4 else 0,   # FIN|SYN|PSH|ACK
            "FLOW_DURATION_MILLISECONDS": dur, "FLOW_START_MILLISECONDS": 1_700_000_000_000 + i * 3000,
            "SRC_TO_DST_IAT_AVG": dur / max(inp - 1, 1), "DST_TO_SRC_IAT_AVG": dur / max(outp - 1, 1),
            "SRC_TO_DST_IAT_STDDEV": 5.0, "DST_TO_SRC_IAT_STDDEV": 7.0, "SRC_TO_DST_IAT_MAX": dur / 2, "DST_TO_SRC_IAT_MAX": dur / 3,
            "Label": int(a != "Benign"), "Attack": a,
        })
    return pd.DataFrame(rows)


def test_netflow_v2_detection_units_flags_and_labels(tmp_path):
    p = tmp_path / "NF-UNSW-NB15-v2.csv"
    nf_df().to_csv(p, index=False)
    assert detect_dataset(p).adapter == "netflow_v2"
    a = get_adapter("netflow_v2")
    df = a.read_flows(p)
    assert check_canonical_frame(df) == [] and len(df) == 200
    raw = nf_df().sort_values("FLOW_START_MILLISECONDS").iloc[0]
    r = df.sort_values("timestamp").iloc[0]
    assert r["duration_s"] == pytest.approx(raw["FLOW_DURATION_MILLISECONDS"] / 1000)            # ms -> s
    assert r["timestamp"] == pd.Timestamp("2023-11-14 22:13:20")
    tcp = df[df["protocol"] == 6].iloc[0]
    assert (tcp["fin_cnt"], tcp["syn_cnt"], tcp["psh_cnt"], tcp["ack_cnt"], tcp["rst_cnt"], tcp["urg_cnt"]) == (1, 1, 1, 1, 0, 0)
    assert (df.loc[df["protocol"] == 17, ["syn_cnt", "ack_cnt"]] == 0).all().all()               # flags only for tcp
    assert (df["iat_mean"] > 1000).all()                                                         # ms x1000 -> us
    assert set(df["label"]) == {"nf=Benign", "nf=Exploits"}
    assert a.label_status("nf=Exploits") == ("initial_access", "mapped")
    assert a.label_status("nf=Benign") == ("benign", "mapped")
    assert a.label_status("nf=DDoS") == ("impact", "impact_by_design")
    assert a.label_status("nf=Quantum-Attack") == ("impact", "unknown_fallthrough")


def test_netflow_v2_validates_with_consistent_iat_and_rejects_missing_timestamp(tmp_path):
    p = tmp_path / "nf.csv"
    nf_df(n=900).to_csv(p, index=False)
    rep = V.validate_dataset(p, progress=False, embeddings=False, sample_rows=2000, min_rows_per_file=200)
    assert rep["adapter"]["name"] == "netflow_v2" and "iat_units" not in {i["code"] for i in rep["findings"]}
    assert "adapter_experimental" in {i["code"] for i in rep["findings"]}
    q = tmp_path / "nots.csv"
    nf_df().drop(columns=["FLOW_START_MILLISECONDS"]).to_csv(q, index=False)
    rep2 = V.validate_dataset(q, progress=False, embeddings=False)
    assert rep2["verdict"] == "FAIL" and "FLOW_START_MILLISECONDS" in rep2["findings"][0]["message"]


def test_nf_classify_keywords():
    assert nf_classify("nf=Benign") == ("benign", True)
    assert nf_classify("nf=Backdoor")[0] == "initial_access"
    assert nf_classify("nf=Reconnaissance")[0] == "reconnaissance" and nf_classify("nf=scanning")[0] == "reconnaissance"
    assert nf_classify("nf=Theft")[0] == "exfiltration" and nf_classify("nf=Bot")[0] == "command_and_control"
    assert nf_classify("nf=password") == ("initial_access", True)
    assert nf_classify("nf=Zzz") == ("impact", False)
    assert label_to_stage("nf=Worms") == "lateral_movement"


# ---- PCAP -------------------------------------------------------------------------------------------
BASE = 1_700_000_000 - (1_700_000_000 % 10)


def write_pcap(path, n_flows=30):
    pkts = []
    link = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
    for f in range(n_flows):
        cl = f"10.0.0.{1 + f % 3}"
        srv = "10.0.1.5"
        t0 = BASE + f * 4.0
        for k, (a, b, sp, dp, fl, dt, ln) in enumerate([
                (cl, srv, 40000 + f, 80, "S", 0.0, 0), (srv, cl, 80, 40000 + f, "SA", 0.05, 0), (cl, srv, 40000 + f, 80, "A", 0.10, 0),
                (cl, srv, 40000 + f, 80, "PA", 0.60, 100), (srv, cl, 80, 40000 + f, "PA", 1.10, 400), (cl, srv, 40000 + f, 80, "FA", 1.50, 0)]):
            p = link / IP(src=a, dst=b) / TCP(sport=sp, dport=dp, flags=fl) / (b"x" * ln)
            p.time = t0 + dt
            pkts.append(p)
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), pkts)
    return path


def test_pcap_adapter_units_detection_and_default_label(tmp_path):
    p = write_pcap(tmp_path / "lab" / "demo.pcap")
    d = detect_dataset(tmp_path / "lab")
    assert d.adapter == "pcap" and d.confidence > 0.9
    a = get_adapter("pcap")
    df = a.read_flows(p)
    assert len(df) == 30 and check_canonical_frame(df) == []
    f = df.iloc[0]
    assert f["total_pkts"] == 6 and f["total_bytes"] == 500 and f["duration_s"] == pytest.approx(1.5)
    gaps = np.diff([0.0, 0.05, 0.10, 0.60, 1.10, 1.50]) * 1e6
    assert f["iat_mean"] == pytest.approx(gaps.mean(), rel=1e-6) and f["iat_max"] == pytest.approx(gaps.max(), rel=1e-6)   # microseconds
    assert (df["label"] == "BENIGN").all() and (df["has_ip_data"] == 1).all()
    assert f["syn_cnt"] == 2 and f["fin_cnt"] == 1


def test_pcap_sidecar_labels_attacker_flows_in_time_range(tmp_path):
    p = write_pcap(tmp_path / "demo.pcap")
    side = tmp_path / "labels.csv"
    t0 = pd.Timestamp(BASE, unit="s")
    side.write_text("attacker_ip,victim_ip,start_time,end_time,label\n"
                    f"10.0.0.1,10.0.1.5,{t0 + pd.Timedelta(seconds=40)},{t0 + pd.Timedelta(seconds=80)},SSH-Bruteforce\n")
    a = get_adapter("pcap").with_sidecar(side)
    df = a.read_flows(p)
    hit = df[df["label"] == "SSH-Bruteforce"]
    assert len(hit) > 0 and set(hit["src_ip"]) == {"10.0.0.1"}
    assert hit["timestamp"].min() >= t0 + pd.Timedelta(seconds=40) and hit["timestamp"].max() <= t0 + pd.Timedelta(seconds=80)
    assert (df[df["src_ip"] != "10.0.0.1"]["label"] == "BENIGN").all()
    rep = V.validate_dataset(p, "pcap", progress=False, embeddings=False, sample_rows=1000, min_rows_per_file=10)
    assert rep["labels"]["rows"][0]["label"] == "BENIGN"        # no sidecar -> single class
    assert not [i for i in rep["findings"] if i["code"] == "adapter_error"]


def test_sidecar_rules_wildcards_order_epoch_and_errors(tmp_path):
    fl = pd.DataFrame({"timestamp": pd.to_datetime([1000, 1010, 1020, 1030], unit="s"),
                       "src_ip": ["a", "b", "a", "c"], "dst_ip": ["v", "a", "w", "v"], "dst_port": [22, 22, 80, 22], "label": "x"})
    side = tmp_path / "s.csv"
    side.write_text("src_ip,dst_ip,start,end,label,dst_port\n"
                    "a,,1000,1025,Bot,\n"           # a as source OR destination, wildcard victim
                    "a,w,1015,1025,Infilteration,\n"  # later rule overrides for flow 3
                    ",v,,,SSH-Bruteforce,22\n")
    out = LabelSidecar.load(side).apply(fl, "BENIGN")["label"].tolist()
    assert out == ["SSH-Bruteforce", "Bot", "Infilteration", "SSH-Bruteforce"]
    strict = LabelSidecar.load(side, bidirectional=False).apply(fl, "BENIGN")["label"].tolist()
    assert strict[1] == "BENIGN"
    bad = tmp_path / "bad.csv"
    bad.write_text("src_ip,dst_ip,start,end,label\n,,,,Bot\n")
    with pytest.raises(ValueError, match="unconstrained"):
        LabelSidecar.load(bad)
    bad.write_text("src_ip,dst_ip,start,end\na,b,1,2\n")
    with pytest.raises(ValueError, match="label"):
        LabelSidecar.load(bad)
    bad.write_text("src_ip,dst_ip,start,end,label\na,b,notatime,2,Bot\n")
    with pytest.raises(ValueError, match="unparsable"):
        LabelSidecar.load(bad)


def test_sidecar_on_csv_adapter_changes_labels_and_label_scan_agrees(tmp_path):
    p = write_cic(tmp_path / "Tuesday.csv", n=300, ip=True, attack_block=(0, 0))
    side = tmp_path / "side.csv"
    side.write_text("src_ip,dst_ip,start,end,label\n10.0.0.1,,2018-02-14 08:05:00,2018-02-14 08:10:00,Bot\n")
    a = get_adapter("cicids2018").with_sidecar(side)
    df = a.read_flows(p)
    n_bot = int((df["label"] == "Bot").sum())
    assert n_bot > 0
    scan = V.scan_labels(a, [p], progress=False)
    assert scan["counts"].get("Bot") == n_bot and scan["rows"] == 300


# ---- generic CICFlowMeter ------------------------------------------------------------------------------
def generic_df(n=200, label=False, fmt="%Y-%m-%d %H:%M:%S"):
    d = cic_df(n=n, ip=True, ts_fmt=fmt, reduced=True)
    d = d.rename(columns={"Src IP": "src_ip", "Src Port": "src_port", "Dst IP": "dst_ip", "Dst Port": "dst_port",
                          "Protocol": "protocol", "Timestamp": "timestamp", "Flow Duration": "flow_duration",
                          "Tot Fwd Pkts": "tot_fwd_pkts", "Tot Bwd Pkts": "tot_bwd_pkts", "TotLen Fwd Pkts": "totlen_fwd_pkts",
                          "TotLen Bwd Pkts": "totlen_bwd_pkts", "SYN Flag Cnt": "syn_flag_cnt", "ACK Flag Cnt": "ack_flag_cnt",
                          "FIN Flag Cnt": "fin_flag_cnt", "RST Flag Cnt": "rst_flag_cnt", "PSH Flag Cnt": "psh_flag_cnt",
                          "URG Flag Cnt": "urg_flag_cnt", "Flow IAT Mean": "flow_iat_mean", "Flow IAT Std": "flow_iat_std",
                          "Flow IAT Max": "flow_iat_max"})
    return d if label else d.drop(columns=["Label"])


def test_generic_adapter_detects_unlabelled_snake_case_and_uses_default_or_sidecar(tmp_path):
    p = tmp_path / "lab_flows.csv"
    generic_df().to_csv(p, index=False)
    d = detect_dataset(p)
    assert d.adapter == "cicflowmeter_generic" and 0.5 < d.confidence < 0.9
    a = get_adapter("cicflowmeter_generic")
    df = a.read_flows(p)
    assert len(df) == 200 and (df["label"] == "BENIGN").all() and check_canonical_frame(df) == []
    assert df["duration_s"].max() < 10 and (df["has_ip_data"] == 1).all()
    side = tmp_path / "s.csv"
    side.write_text("src_ip,dst_ip,start,end,label\n10.0.0.1,,,,Bot\n")
    df2 = get_adapter("cicflowmeter_generic").with_sidecar(side).read_flows(p)
    assert set(df2["label"]) == {"BENIGN", "Bot"}


def test_generic_adapter_timestamp_formats(tmp_path):
    from pipeline.adapters.generic_cicflowmeter_adapter import parse_any_timestamp
    assert parse_any_timestamp(pd.Series(["25/12/2018 10:00:00"])).iloc[0] == pd.Timestamp("2018-12-25 10:00:00")
    assert parse_any_timestamp(pd.Series(["12/25/2018 10:00:00"])).iloc[0] == pd.Timestamp("2018-12-25 10:00:00")
    assert parse_any_timestamp(pd.Series(["1700000000", "1700000001"])).iloc[0] == pd.Timestamp("2023-11-14 22:13:20")
    assert parse_any_timestamp(pd.Series(["1700000000000"])).iloc[0] == pd.Timestamp("2023-11-14 22:13:20")


def test_dedicated_adapters_still_beat_the_generic_one(tmp_path):
    p = write_cic(tmp_path / "Tuesday-20-02-2018.csv", ip=True)
    assert detect_dataset(p).adapter == "cicids2018"


# ---- the two drop bugs (regressions; before/after numbers are in docs/08) -------------------------------
def test_ctu_icmp_hex_port_rows_are_kept_with_port_zero_but_bad_tcp_ports_still_dropped():
    raw = pd.DataFrame({
        "StartTime": ["2011/08/18 10:00:00.1"] * 3, "Dur": [1.0] * 3, "Proto": ["icmp", "tcp", "tcp"],
        "SrcAddr": ["1.1.1.1"] * 3, "Sport": ["0x0303", "1234", "1234"], "Dir": ["->"] * 3, "DstAddr": ["2.2.2.2"] * 3,
        "Dport": ["0x8104", "80", ""], "State": ["URP", "S_RA", "S_RA"], "sTos": [0] * 3, "dTos": [0] * 3, "TotPkts": [2, 2, 2],
        "TotBytes": [200] * 3, "SrcBytes": [100] * 3, "Label": ["flow=From-Botnet-V51-1-ICMP", "flow=Background", "flow=Background"]})
    out = base_ctu._normalize_columns(raw)
    assert len(out) == 2 and (out.loc[out["protocol"] == 1, "dst_port"] == 0).all()
    assert "flow=From-Botnet-V51-1-ICMP" in out["label"].tolist()


def test_unsw_other_protocols_are_kept_as_255_without_tcp_udp_flags():
    rows = unsw_rows(n=4)
    rows["proto"] = ["unas", "arp", "ospf", "tcp"]
    out = base_unsw._normalize_columns(rows)
    assert len(out) == 4
    assert out["protocol"].tolist() == [255, 255, 255, 6]
    assert out["is_tcp"].tolist() == [0, 0, 0, 1] and out["is_udp"].sum() == 0
    assert (out.loc[:2, ["syn_cnt", "ack_cnt", "fin_cnt", "rst_cnt"]] == 0).all().all()


# ---- loader smoke + multi-unit equivalence ---------------------------------------------------------------
def test_prepared_output_feeds_the_real_training_loader(tmp_path, monkeypatch):
    for k in ("PHOENIX_PROCESSED_DIR", "PHOENIX_DATA_DIR", "PHOENIX_RAW_FLOW_DIR"):
        monkeypatch.delenv(k, raising=False)
    src = write_cic(tmp_path / "raw" / "s.csv", n=500, reduced=True, step_s=7)
    out = tmp_path / "out"
    P.prepare_dataset(src.parent, out, CFG, log=_quiet)
    train, val, test, scaler = build_datasets(load_config(out / "config.yaml"))
    assert len(train) > 0 and len(val) > 0 and len(test) > 0 and (out / "scaler.npz").exists()
    x = train[0]
    assert x is not None and scaler.mean.shape[0] == 41


def test_multi_day_by_day_prepare_equals_pipeline_build_dataset(tmp_path, monkeypatch):
    from pipeline.build_dataset import build_dataset
    raw = tmp_path / "raw"
    days = ["2018-02-14", "2018-02-15", "2018-02-16"]
    for i, d in enumerate(days):
        write_cic(raw / f"day{i}.csv", n=900, ip=False, step_s=4, start=f"{d} 08:00:00", attack_block=(300, 500), seed=i)
    cfg = load_config(CFG)
    cfg["split"] = {**cfg["split"], "mode": "by_day", "train_days": ["02-14"], "val_days": ["02-15"], "test_days": ["02-16"]}
    cfg_path = tmp_path / "byday.yaml"
    cfg_path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    ref = tmp_path / "ref"
    monkeypatch.setenv("PHOENIX_PROCESSED_DIR", str(ref))
    monkeypatch.setenv("PHOENIX_RAW_FLOW_DIR", str(raw))
    monkeypatch.delenv("PHOENIX_DATA_DIR", raising=False)
    build_dataset(str(cfg_path))
    out = tmp_path / "mine"
    meta = P.prepare_dataset(raw, out, str(cfg_path), log=_quiet)
    assert meta["split_mode"] == "by_day" and meta["split_mode_source"] == "config.split.mode"
    for s in ("train", "val", "test"):
        a, b = load_split(ref, s), load_split(out, s)
        assert a.keys() == b.keys() and len(a["X"]) > 0
        for k in a:
            assert np.array_equal(a[k], b[k]), (s, k)
    assert set(load_window_graphs(ref / "window_graphs.pkl")) == set(load_window_graphs(out / "window_graphs.pkl"))
