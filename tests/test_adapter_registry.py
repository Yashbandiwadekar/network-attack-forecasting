"""Dataset-adapter registry: detection, unit conversion, label mapping, schema completeness, wrapping."""
from __future__ import annotations

import os

os.environ.setdefault("CUDA_VISIBLE_DEVICES", "-1")

import numpy as np
import pandas as pd
import pytest

from common.config import feature_columns, load_config
from pipeline import flow_features as ff
from pipeline.adapters import unsw_nb15 as base_unsw
from pipeline.adapters.base import CANONICAL_COLUMNS, ReadStats, check_canonical_frame, detect_file_adapter
from pipeline.adapters.registry import detect_dataset, get_adapter, list_adapters
from tests.adapter_fixtures import cic_df, write_cic, write_ctu, write_unsw


# ---- registry -------------------------------------------------------------------------------
def test_registry_contains_all_adapters():
    names = set(list_adapters())
    assert {"cicids2018", "synthetic", "ctu13", "unsw_nb15", "cicids2017", "netflow_v2", "ciciot2023",
            "unsw_nb15_split_sets", "cicids2017_mlcve"} <= names
    with pytest.raises(KeyError):
        get_adapter("nope")


# ---- detection --------------------------------------------------------------------------------
def test_detect_cic_full_schema_with_and_without_ip(tmp_path):
    a = write_cic(tmp_path / "ip" / "Tuesday-20-02-2018.csv", ip=True)
    b = write_cic(tmp_path / "noip" / "Friday-02-03-2018.csv", ip=False)
    assert detect_dataset(a).adapter == "cicids2018"
    assert detect_dataset(b).adapter == "cicids2018"
    name, _, evidence = detect_file_adapter(b)
    assert name == "cicids2018" and any("NO Src IP" in e for e in evidence)


def test_detect_reduced_schema_and_synthetic_filename_is_synthetic(tmp_path):
    a = write_cic(tmp_path / "x.csv", reduced=True)
    b = write_cic(tmp_path / "Synthetic-BenignHighVolume_TrafficForML.csv", reduced=True)
    assert detect_dataset(a).adapter == "synthetic"
    assert detect_dataset(b).adapter == "synthetic"


def test_detect_ctu_unsw_and_2017(tmp_path):
    assert detect_dataset(write_ctu(tmp_path / "11" / "capture.binetflow")).adapter == "ctu13"
    assert detect_dataset(write_unsw(tmp_path / "UNSW-NB15_1.csv")).adapter == "unsw_nb15"
    p = tmp_path / "Tuesday-WorkingHours.pcap_ISCX.csv"
    p.write_text("Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Flow Duration,"
                 " Total Fwd Packets, Total Backward Packets, Flow IAT Mean, Label\n1,a,1,b,2,6,4/7/2017 8:54,1,1,1,1,BENIGN\n")
    assert detect_dataset(p).adapter == "cicids2017"


def test_detect_unsupported_formats_and_garbage(tmp_path):
    p = tmp_path / "UNSW_NB15_training-set.csv"
    p.write_text("id,dur,proto,service,state,spkts,dpkts,sbytes,dbytes,attack_cat,label\n1,0.1,tcp,-,FIN,2,2,10,10,Normal,0\n")
    assert detect_dataset(p).adapter == "unsw_nb15_split_sets"
    q = tmp_path / "ciciot.csv"
    q.write_text("flow_duration,Header_Length,Protocol Type,Rate,Srate,label\n1,2,3,4,5,x\n")
    assert detect_dataset(q).adapter == "ciciot2023"
    nf = tmp_path / "nf.csv"
    nf.write_text("IPV4_SRC_ADDR,L4_SRC_PORT,IPV4_DST_ADDR,L4_DST_PORT,PROTOCOL,IN_BYTES,IN_PKTS,Label,Attack\na,1,b,2,6,1,1,0,Benign\n")
    assert detect_dataset(nf).adapter == "netflow_v2"
    g = tmp_path / "g.csv"
    g.write_text("a,b\nhello,world\n")
    assert detect_dataset(g).adapter is None
    assert detect_dataset(tmp_path / "missing").adapter is None


def test_detect_folder_flags_mixed(tmp_path):
    write_cic(tmp_path / "Tuesday.csv", ip=True)
    write_cic(tmp_path / "Synthetic-X.csv", reduced=True)
    d = detect_dataset(tmp_path)
    assert d.adapter == "cicids2018" and d.mixed
    files, skipped = get_adapter("cicids2018").discover_files(tmp_path)
    assert [f.name for f in files] == ["Tuesday.csv"] and "synthetic" in skipped[0][1]


# ---- unit conversion + schema completeness ------------------------------------------------------
def test_cic_units_pseudo_host_and_contract(tmp_path):
    p = write_cic(tmp_path / "Friday-02-03-2018.csv", n=50, ip=False, start="2018-03-02 08:00:00")
    raw = pd.read_csv(p)
    a = get_adapter("cicids2018")
    df = a.read_flows(p)
    assert check_canonical_frame(df) == []
    assert set(CANONICAL_COLUMNS) <= set(df.columns)
    # duration microseconds -> seconds, IAT stays microseconds
    first = raw.sort_values("Timestamp").iloc[0]
    row = df.iloc[0]
    assert row["duration_s"] == pytest.approx(first["Flow Duration"] / 1e6)
    assert row["iat_mean"] == pytest.approx(first["Flow IAT Mean"])
    # no IPs -> one pseudo-host per day, has_ip_data = 0
    assert (df["has_ip_data"] == 0).all() and df["src_ip"].str.startswith("NETWORK-2018-03-02").all()
    assert (df["dst_ip"] == "UNKNOWN").all()


def test_cic_chunked_equals_whole_file_and_wraps_flow_features(tmp_path):
    p = write_cic(tmp_path / "Tuesday.csv", n=120, ip=True)
    a = get_adapter("cicids2018")
    big = a.read_flows(p, chunksize=10_000)
    small = a.read_flows(p, chunksize=7)
    pd.testing.assert_frame_equal(big, small)
    ref = ff.clean_and_normalize(ff.load_flow_csv(p)).sort_values("timestamp").reset_index(drop=True)
    for c in ("timestamp", "src_ip", "dst_port", "duration_s", "total_pkts", "total_bytes", "iat_mean", "bidir_ratio", "label"):
        assert big[c].tolist() == ref[c].tolist(), c


def test_unsw_units_wrap_and_drop_accounting(tmp_path):
    p = write_unsw(tmp_path / "UNSW-NB15_1.csv", n=60, arp_rows=6, sintpkt_ms=2.0)
    a = get_adapter("unsw_nb15")
    st = ReadStats()
    df = a.read_flows(p, stats=st)
    assert st.rows_read == 60 and st.rows_dropped == 6          # arp is not in the protocol map -> dropped
    assert (df["iat_mean"] == 2000.0).all()                     # ms -> microseconds
    assert (df["iat_std"] == 0).all() and (df["psh_cnt"] == 0).all()
    assert df["label"].str.startswith("unsw=").all()
    ref = base_unsw._normalize_columns(pd.read_csv(p, header=None, names=base_unsw.RAW_COLUMNS))
    assert sorted(ref["src_bytes"].tolist()) == sorted(df["fwd_bytes"].tolist())
    assert check_canonical_frame(df) == []


def test_ctu_units_bidir_scenario_and_icmp_drop(tmp_path):
    p = write_ctu(tmp_path / "11" / "capture20110818-2.binetflow", n=120)
    a = get_adapter("ctu13")
    st = ReadStats()
    df = a.read_flows(p, stats=st)
    assert (df["scenario_id"] == 11).all()
    assert st.rows_dropped > 0                                  # ICMP rows have hex Dport -> NaN -> dropped (existing behaviour)
    assert (df["iat_mean"] == 0).all() and (df["syn_cnt"] == 0).all()
    assert df["bidir_ratio"].max() > 0                          # add_ctu13_features applied (adapter alone leaves 0.0)
    assert (df["has_ip_data"] == 1.0).all() and check_canonical_frame(df) == []


def test_feature_status_table_covers_exactly_the_41_features():
    cfg = load_config("configs/default.yaml")
    feats = feature_columns(cfg)
    assert len(feats) == 41
    for name in ("cicids2018", "ctu13", "unsw_nb15", "synthetic"):
        exp = get_adapter(name).expected_feature_status(1.0)
        assert set(exp) == set(feats), name


def test_feature_status_declares_ctu_and_unsw_gaps():
    ctu = get_adapter("ctu13").expected_feature_status(1.0)
    assert all(ctu[f][0] == "zero_filled" for f in ("syn_ratio", "psh_ratio", "mean_iat", "var_iat", "max_iat"))
    unsw = get_adapter("unsw_nb15").expected_feature_status(1.0)
    assert unsw["mean_iat"][0] == "derived" and unsw["psh_ratio"][0] == "zero_filled" and unsw["syn_ratio"][0] == "approximated"
    cic_noip = get_adapter("cicids2018").expected_feature_status(0.0)
    assert cic_noip["graph_out_degree"][0] == "zero_filled" and cic_noip["unique_dst_ips"][0] == "zero_filled"
    assert cic_noip["syn_ratio"][0] == "native"


# ---- label mapping ---------------------------------------------------------------------------------
@pytest.mark.parametrize("adapter,label,stage,status", [
    ("cicids2018", "Benign", "benign", "mapped"),
    ("cicids2018", "BENIGN", "benign", "mapped"),
    ("cicids2018", "SSH-Bruteforce", "initial_access", "mapped"),
    ("cicids2018", "Infilteration", "lateral_movement", "mapped"),
    ("cicids2018", "Bot", "command_and_control", "mapped"),
    ("cicids2018", "DDOS attack-HOIC", "impact", "impact_by_design"),
    ("cicids2018", "DoS attacks-Hulk", "impact", "impact_by_design"),
    ("cicids2018", "Label", "impact", "ignorable"),
    ("cicids2018", "Mystery-Attack", "impact", "unknown_fallthrough"),
    ("synthetic", "SYNTH-Exfiltration", "exfiltration", "mapped"),
    ("ctu13", "flow=Background-UDP-Established", "benign", "mapped"),
    ("ctu13", "flow=To-Background-UDP-CVUT-DNS-Server", "benign", "mapped"),
    ("ctu13", "flow=From-Normal-V44-Stribrek", "benign", "mapped"),
    ("ctu13", "flow=From-Botnet-V44-TCP-CC-Custom-Encryption", "command_and_control", "mapped"),
    ("ctu13", "flow=Brand-New-Thing", "impact", "unknown_fallthrough"),
    ("unsw_nb15", "unsw=Normal", "benign", "mapped"),
    ("unsw_nb15", "unsw=Reconnaissance", "reconnaissance", "mapped"),
    ("unsw_nb15", "unsw=Exploits", "initial_access", "mapped"),
    ("unsw_nb15", "unsw=Worms", "lateral_movement", "mapped"),
    ("unsw_nb15", "unsw=Generic", "impact", "impact_by_design"),
    ("unsw_nb15", "unsw=Fuzzers", "impact", "impact_by_design"),
    ("unsw_nb15", "unsw=Brand-New", "impact", "unknown_fallthrough"),
    ("cicids2017", "FTP-Patator", "impact", "unknown_fallthrough"),   # owner decision pending
    ("cicids2017", "PortScan", "impact", "unknown_fallthrough"),
    ("cicids2017", "DoS Hulk", "impact", "impact_by_design"),
    ("cicids2017", "BENIGN", "benign", "mapped"),
])
def test_label_status(adapter, label, stage, status):
    assert get_adapter(adapter).label_status(label) == (stage, status)


def test_every_known_label_in_the_mitre_tables_is_classified_not_fallthrough():
    from pipeline.mitre_mapping import CIC_LABEL_TO_STAGE, UNSW_LABEL_TO_STAGE
    cic = get_adapter("cicids2018")
    assert all(cic.label_status(k)[1] != "unknown_fallthrough" for k in CIC_LABEL_TO_STAGE)
    unsw = get_adapter("unsw_nb15")
    assert all(unsw.label_status("unsw=" + k.title())[1] != "unknown_fallthrough" for k in UNSW_LABEL_TO_STAGE)


# ---- stubs ---------------------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["netflow_v2", "ciciot2023", "unsw_nb15_split_sets", "cicids2017_mlcve"])
def test_stub_and_unsupported_adapters_refuse_to_read_with_a_howto(name, tmp_path):
    a = get_adapter(name)
    assert a.status in ("stub", "unsupported") and a.howto
    with pytest.raises(NotImplementedError, match=name):
        list(a.iter_flows(tmp_path / "x.csv"))


def test_cic2017_timestamp_rename_and_label_encoding(tmp_path):
    p = tmp_path / "Tuesday-WorkingHours.pcap_ISCX.csv"
    hdr = ("Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Flow Duration,"
           " Total Fwd Packets, Total Backward Packets,Total Length of Fwd Packets, Total Length of Bwd Packets,"
           "Flow IAT Mean, Flow IAT Std, Flow IAT Max,FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count,"
           " ACK Flag Count, URG Flag Count, Label\n")
    rows = ["1,10.0.0.1,5,10.0.0.2,80,6,4/7/2017 8:54,1000000,5,5,100,200,100000,5,300000,0,1,0,0,1,0,BENIGN",
            "2,10.0.0.1,5,10.0.0.2,80,6,4/7/2017 1:05,1000000,5,5,100,200,100000,5,300000,0,1,0,0,1,0,Web Attack \u2013 Brute Force"]
    p.write_bytes((hdr + "\n".join(rows) + "\n").encode("cp1252"))
    df = get_adapter("cicids2017").read_flows(p)
    assert len(df) == 2
    assert df["timestamp"].min() == pd.Timestamp("2017-07-04 08:54:00")
    assert "Web Attack \u2013 Brute Force" in df["label"].tolist()
    assert df["timestamp"].max() == pd.Timestamp("2017-07-04 13:05:00")   # 1:05 -> +12h heuristic
    assert (df["duration_s"] == 1.0).all()
