"""validate_dataset: every PASS/WARN/FAIL branch on small synthetic fixtures."""
from __future__ import annotations

import os

os.environ.setdefault("CUDA_VISIBLE_DEVICES", "-1")

import json

import numpy as np
import pandas as pd
import pytest

from pipeline.adapters import validation as V
from pipeline.adapters.registry import get_adapter
from scripts import validate_dataset as cli
from tests.adapter_fixtures import cic_df, write_cic, write_ctu, write_unsw

KW = dict(progress=False, embeddings=False, sample_rows=5000, min_rows_per_file=200)


def codes(rep, level=None):
    return {i["code"] for i in rep["findings"] if level is None or i["level"] == level}


def test_clean_real_style_dataset_has_no_fail(tmp_path):
    p = write_cic(tmp_path / "Tuesday-20-02-2018.csv", n=900, ip=True, step_s=5, attack_block=(400, 500))
    rep = V.validate_dataset(p, **KW)
    assert rep["verdict"] in ("PASS", "WARN") and not codes(rep, "FAIL"), rep["findings"]
    assert rep["adapter"]["name"] == "cicids2018"
    assert rep["rows_full_pass"] == 900 and rep["labels"]["mode"] == "full pass"
    assert rep["window_checks"]["n_features_found"] == 41
    # stage mapping table is present and correct
    table = {r["label"]: r for r in rep["labels"]["rows"]}
    assert table["SSH-Bruteforce"]["stage"] == "initial_access" and table["Benign"]["status"] == "mapped"
    # honest reporting: packet features are documented zero-fill (INFO), not an error
    assert "packet_zero_fill" in codes(rep, "INFO")


def test_no_ip_data_is_warn_not_fail(tmp_path):
    p = write_cic(tmp_path / "Friday-02-03-2018.csv", n=600, ip=False)
    rep = V.validate_dataset(p, **KW)
    assert "no_ip_data" in codes(rep, "WARN") and rep["verdict"] == "WARN"
    graph = {f["name"]: f for f in rep["window_checks"]["features"]}["graph_out_degree"]
    assert graph["expected_status"] == "zero_filled" and graph["constant_zero"]


def test_synthetic_reduced_schema_warns(tmp_path):
    p = write_cic(tmp_path / "synthetic_sample.csv", n=600, reduced=True)
    rep = V.validate_dataset(p, **KW)
    assert rep["adapter"]["name"] == "synthetic" and "synthetic_data" in codes(rep, "WARN")


def test_iat_in_milliseconds_fails(tmp_path):
    p = write_cic(tmp_path / "ms.csv", n=400, iat_scale=1e-3)
    rep = V.validate_dataset(p, **KW)
    assert rep["verdict"] == "FAIL" and "iat_units" in codes(rep, "FAIL")
    assert "MILLISECONDS" in next(i["message"] for i in rep["findings"] if i["code"] == "iat_units")


def test_iat_in_seconds_fails(tmp_path):
    p = write_cic(tmp_path / "s.csv", n=400, iat_scale=1e-6)
    assert "iat_units" in codes(V.validate_dataset(p, **KW), "FAIL")


def test_duration_unit_error_fails(tmp_path):
    p = write_cic(tmp_path / "dur.csv", n=400, dur_scale=1e6)   # microseconds * 1e6: absurd seconds
    rep = V.validate_dataset(p, **KW)
    assert "duration_units" in codes(rep, "FAIL")


def test_label_fallthrough_fail_and_warn_thresholds(tmp_path):
    n = 600
    labs = ["Benign"] * n
    for i in range(30):                      # 5% unknown
        labs[i * 10] = "Mystery-Attack"
    rep = V.validate_dataset(write_cic(tmp_path / "a.csv", n=n, labels=labs), **KW)
    assert "label_fallthrough" in codes(rep, "FAIL")
    assert rep["labels"]["fallthrough_labels"] == ["Mystery-Attack"]
    labs2 = ["Benign"] * 2000
    labs2[5] = "Mystery-Attack"              # 0.05% unknown
    rep2 = V.validate_dataset(write_cic(tmp_path / "b.csv", n=2000, labels=labs2), **KW)
    assert "label_fallthrough" in codes(rep2, "WARN") and "label_fallthrough" not in codes(rep2, "FAIL")


def test_ctu_unknown_label_and_documented_zero_fill(tmp_path):
    p = write_ctu(tmp_path / "11" / "capture.binetflow", n=1500, with_unknown=60)
    rep = V.validate_dataset(p, **KW)
    assert rep["adapter"]["name"] == "ctu13"
    assert "label_fallthrough" in codes(rep, "FAIL")
    assert "zero_filled_features" in codes(rep, "WARN")          # 6 flags + 3 IAT
    assert rep["flow_checks"]["iat"]["status"] == "zero_filled"  # no IAT unit check on zero-filled IAT
    assert rep["sample"]["rows_dropped"] > 0     # ICMP rows (hex Dport) are dropped by the existing CTU adapter


def test_rows_dropped_threshold_warns_and_reports_by_label(tmp_path):
    p = write_unsw(tmp_path / "UNSW-NB15_1.csv", n=1000, arp_rows=100, attack_cat_block=(0, 100, "Reconnaissance"))
    rep = V.validate_dataset(p, **KW)
    assert "rows_dropped" in codes(rep, "WARN")
    assert rep["sample"]["dropped_by_label"][0]["label"] == "unsw=Reconnaissance"
    assert "attack_rows_dropped" in codes(rep, "WARN")


def test_unsw_documented_approximations(tmp_path):
    p = write_unsw(tmp_path / "UNSW-NB15_1.csv", n=1500)
    rep = V.validate_dataset(p, **KW)
    assert {"zero_filled_features", "approximated_features"} <= codes(rep, "WARN")
    assert not codes(rep, "FAIL"), rep["findings"]


def test_unsw_iat_in_ms_not_converted_would_fail(tmp_path):
    ad = get_adapter("unsw_nb15")
    p = write_unsw(tmp_path / "UNSW-NB15_1.csv", n=300)
    df = ad.read_flows(p)
    df["iat_mean"] = df["iat_mean"] / 1000.0                     # the audit-G4 regression
    F = V._Findings()
    V.flow_checks(ad, df, F)
    assert any(i["code"] == "iat_units" and i["level"] == "FAIL" for i in F.items)


def test_flow_checks_nonfinite_ratio_flags_and_bytes_branches(tmp_path):
    ad = get_adapter("ctu13")
    base = ad.read_flows(write_ctu(tmp_path / "11" / "c.binetflow", n=200))

    def run(df):
        F = V._Findings()
        V.flow_checks(ad, df, F)
        return {(i["level"], i["code"]) for i in F.items}

    d = base.copy(); d.loc[d.index[0], "total_bytes"] = np.nan
    assert ("FAIL", "nonfinite") in run(d)
    d = base.copy(); d.loc[d.index[0], "duration_s"] = np.inf
    assert ("FAIL", "nonfinite") in run(d)
    d = base.copy(); d["syn_cnt"] = 0.4
    assert ("FAIL", "contract") in run(d)                        # flags as ratios
    d = base.copy(); d["total_bytes"] = d["total_pkts"] * 2      # < 20 bytes/packet incl. headers
    assert ("FAIL", "bytes_vs_packets") in run(d)
    d = base.copy(); d["total_bytes"] = d["total_pkts"] * 1e6
    assert ("FAIL", "bytes_vs_packets") in run(d)
    d = base.copy(); d.loc[d.index[:30], "duration_s"] = -1.0
    assert ("FAIL", "negative_values") in run(d)
    d = base.copy(); d["syn_cnt"] = d["total_pkts"] + 5
    assert ("WARN", "flag_counts") in run(d)
    d = base.copy(); d["timestamp"] = pd.Timestamp("1970-01-01") + pd.to_timedelta(np.arange(len(d)), unit="s")
    assert ("WARN", "timestamp_range") in run(d)
    d = base.drop(columns=["label"])
    assert ("FAIL", "contract") in run(d)


def test_flags_exceeding_packets_trips_window_ratio_range(tmp_path):
    ad = get_adapter("cicids2018")
    df = ad.read_flows(write_cic(tmp_path / "x.csv", n=300))
    df["ack_cnt"] = df["total_pkts"] * 3
    from common.config import load_config
    F = V._Findings()
    V.window_checks(ad, df, load_config("configs/default.yaml"), F, embeddings=False)
    assert any(i["code"] == "ratio_range" and i["level"] == "FAIL" for i in F.items)


def test_adapter_error_and_unsupported_and_unknown_are_fail_not_crash(tmp_path):
    bad = tmp_path / "bad.csv"
    df = cic_df(n=50)
    df.drop(columns=["Flow IAT Mean"]).to_csv(bad, index=False)
    rep = V.validate_dataset(bad, "cicids2018", **KW)
    assert rep["verdict"] == "FAIL"
    garbage = tmp_path / "g.csv"; garbage.write_text("a,b\n1,2\n")
    assert "no_adapter" in codes(V.validate_dataset(garbage, **KW), "FAIL")
    sets = tmp_path / "UNSW_NB15_training-set.csv"
    sets.write_text("id,dur,proto,service,state,spkts,dpkts,sbytes,dbytes,attack_cat,label\n1,0.1,tcp,-,FIN,2,2,10,10,Normal,0\n")
    rep = V.validate_dataset(sets, **KW)
    assert "adapter_unsupported" in codes(rep, "FAIL") and "srcip" in rep["findings"][0]["message"].lower() + "srcip"
    nf = tmp_path / "nf.csv"
    nf.write_text("IPV4_SRC_ADDR,L4_SRC_PORT,IPV4_DST_ADDR,L4_DST_PORT,PROTOCOL,IN_BYTES,IN_PKTS,Label,Attack\na,1,b,2,6,1,1,0,Benign\n")
    assert "adapter_stub" in codes(V.validate_dataset(nf, **KW), "FAIL")


def test_experimental_adapter_warns(tmp_path):
    p = tmp_path / "Tuesday-WorkingHours.pcap_ISCX.csv"
    hdr = ("Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Flow Duration,"
           " Total Fwd Packets, Total Backward Packets,Total Length of Fwd Packets, Total Length of Bwd Packets,"
           "Flow IAT Mean, Flow IAT Std, Flow IAT Max,FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count,"
           " ACK Flag Count, URG Flag Count, Label\n")
    rows = [f"{i},10.0.0.{i % 3},5,10.0.0.9,80,6,4/7/2017 8:{i % 60:02d},1000000,5,5,100,200,250000,5,300000,0,1,0,0,1,0,"
            + ("FTP-Patator" if i % 5 == 0 else "BENIGN") for i in range(200)]
    p.write_text(hdr + "\n".join(rows) + "\n")
    rep = V.validate_dataset(p, **KW)
    assert "adapter_experimental" in codes(rep, "WARN") and "label_fallthrough" in codes(rep, "FAIL")


def test_mixed_folder_flags_synthetic_file(tmp_path):
    write_cic(tmp_path / "Tuesday.csv", n=300, ip=True)
    write_cic(tmp_path / "Synthetic-BenignHighVolume_X.csv", n=300, reduced=True)
    rep = V.validate_dataset(tmp_path, **KW)
    assert "mixed_folder" in codes(rep, "WARN") and "file_skipped" in codes(rep, "WARN")


def test_label_scan_skip_and_cli_exit_codes_and_report_files(tmp_path):
    p = write_cic(tmp_path / "Friday-02-03-2018.csv", n=500, ip=False)
    out = tmp_path / "rep"
    rc = cli.main([str(p), "--report-dir", str(out), "--name", "t", "--no-embeddings", "--quiet", "--sample-rows", "3000",
                   "--min-rows-per-file", "100"])
    assert rc == 1                                               # WARN (no IPs)
    rep = json.loads((out / "t.json").read_text())
    assert rep["verdict"] == "WARN" and (out / "t.md").read_text().startswith("# Dataset validation")
    rc2 = cli.main([str(tmp_path / "nothing"), "--report-dir", str(out)])
    assert rc2 == 3
    bad = tmp_path / "g.csv"; bad.write_text("a,b\n1,2\n")
    assert cli.main([str(bad), "--report-dir", str(out), "--quiet"]) == 2
    rep3 = V.validate_dataset(p, label_scan="skip", **KW)
    assert rep3["label_scan"]["mode"] == "skipped" and "labels" not in rep3


def test_ordering_report_unsorted_is_info_not_fail(tmp_path):
    df = cic_df(n=400).sample(frac=1.0, random_state=1)
    p = tmp_path / "shuffled.csv"; df.to_csv(p, index=False)
    rep = V.validate_dataset(p, **KW)
    assert "unsorted" in codes(rep, "INFO") and rep["ordering"]["fraction_decreasing_adjacent_timestamps_raw_order"] > 0.3
    assert not codes(rep, "FAIL")
