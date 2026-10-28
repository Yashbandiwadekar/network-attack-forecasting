"""Stage-event builder (pipeline/stage_events.py): merge gap, entity keying, recon target sets, IP-less refusal,
detector input, chains, persistence, and the lab-recording label vocabulary."""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from pipeline.mitre_mapping import label_to_stage
from pipeline.stage_events import (
    STAGES, ctu13_icmp_flood_as_impact, events_from_detections, events_from_flows, link_chains, load_events,
    save_events,
)

T0 = pd.Timestamp("2026-03-01 10:00:00")


def flows(rows, unit="u"):
    """rows: (t_seconds, src, dst, label)"""
    df = pd.DataFrame(rows, columns=["t", "src_ip", "dst_ip", "label"])
    df["timestamp"] = T0 + pd.to_timedelta(df.pop("t"), unit="s")
    df["has_ip_data"] = 1.0
    df["unit"] = unit
    return df


# ------------------------------------------------------------------ merge gap / filters
def test_merge_gap_splits_and_joins_runs():
    f = flows([(0, "A", "V", "PortScan"), (100, "A", "V", "PortScan"), (200, "A", "V", "PortScan")])
    ev, rep = events_from_flows(f, "attacker", merge_gap_s=150)
    assert len(ev) == 1 and ev.n_flows[0] == 3 and ev.duration_s[0] == 200
    ev, _ = events_from_flows(f, "attacker", merge_gap_s=50)
    assert len(ev) == 3
    ev, _ = events_from_flows(f, "attacker", merge_gap_s=100)       # gap == merge gap joins (<=)
    assert len(ev) == 1


def test_min_duration_and_min_flows_drop_runs_and_are_counted():
    f = flows([(0, "A", "V", "PortScan"), (5, "A", "V", "PortScan"),            # 5 s, 2 flows
               (1000, "A", "V", "SSH-Bruteforce"), (1100, "A", "V", "SSH-Bruteforce"), (1200, "A", "V", "SSH-Bruteforce")])
    ev, rep = events_from_flows(f, "attacker", merge_gap_s=150, min_duration_s=30)
    assert list(ev.stage) == ["initial_access"] and rep.n_runs_dropped_filter == 1 and rep.n_runs_before_filter == 2
    ev, rep = events_from_flows(f, "attacker", merge_gap_s=150, min_flows=3)
    assert list(ev.stage) == ["initial_access"] and rep.n_runs_dropped_filter == 1


def test_benign_is_not_an_event_and_stage_changes_split_runs():
    f = flows([(0, "A", "V", "BENIGN"), (10, "A", "V", "PortScan"), (20, "A", "V", "SSH-Bruteforce"), (30, "A", "V", "BENIGN")])
    ev, rep = events_from_flows(f, "attacker", merge_gap_s=1000)
    assert list(ev.stage) == ["reconnaissance", "initial_access"] and rep.n_rows_benign == 2


# ------------------------------------------------------------------ entity keying
def _campaign():
    return flows([(0, "A", "V", "PortScan"), (5, "A", "D1", "PortScan"), (6, "A", "D1", "PortScan"),
                  (300, "A", "V", "SSH-Bruteforce"),
                  (600, "V", "C2", "Bot"), (610, "V", "C2", "Bot")])


def test_entity_keys_for_each_view():
    f = _campaign()
    att, _ = events_from_flows(f, "attacker")
    assert set(zip(att.entity, att.stage)) == {("A", "reconnaissance"), ("A", "initial_access"), ("V", "command_and_control")}
    vic, _ = events_from_flows(f, "victim")
    assert set(zip(vic.entity, vic.stage)) == {("V", "reconnaissance"), ("D1", "reconnaissance"), ("V", "initial_access"),
                                               ("C2", "command_and_control")}
    pair, _ = events_from_flows(f, "pair")
    assert {"A->V", "A->D1", "V->C2"} == set(pair.entity)
    host, _ = events_from_flows(f, "host")
    # the compromised host V: recon + initial access are done TO it (dst), command and control BY it (src)
    v = host[host.entity == "V"].sort_values("start_s")
    assert list(v.stage) == ["reconnaissance", "initial_access", "command_and_control"]
    with pytest.raises(ValueError):
        events_from_flows(f, "nonsense")


def test_host_view_links_a_direction_flipping_chain_attacker_view_does_not():
    f = _campaign()
    att = link_chains(events_from_flows(f, "attacker")[0], 7200)
    host = link_chains(events_from_flows(f, "host")[0], 7200)
    assert max(len(c.events) for c in att) == 2
    assert [c.stages for c in host if c.entity == "V"] == [["reconnaissance", "initial_access", "command_and_control"]]


def test_unit_scoped_entities_keep_scenarios_apart():
    f = pd.concat([flows([(0, "B", "X", "PortScan")], unit="s1"), flows([(10, "B", "X", "PortScan")], unit="s2")], ignore_index=True)
    ev, _ = events_from_flows(f, "attacker", merge_gap_s=1000, unit_scoped=True)
    assert len(ev) == 2 and set(ev.entity) == {"s1|B", "s2|B"}
    ev, _ = events_from_flows(f, "attacker", merge_gap_s=1000)
    assert len(ev) == 1


# ------------------------------------------------------------------ recon target sets
def test_recon_event_records_targets_touched_with_counts():
    f = _campaign()
    ev, _ = events_from_flows(f, "attacker")
    r = ev[(ev.entity == "A") & (ev.stage == "reconnaissance")].iloc[0]
    assert r.dsts == {"V": 1, "D1": 2} and r.n_dst == 2 and r.srcs == {"A": 3}
    ia = ev[(ev.entity == "A") & (ev.stage == "initial_access")].iloc[0]
    assert ia.dsts == {"V": 1}


def test_dst_set_is_truncated_but_true_distinct_count_is_kept():
    rows = [(i, "A", f"10.0.{i // 250}.{i % 250}", "PortScan") for i in range(400)]
    ev, _ = events_from_flows(flows(rows), "attacker", merge_gap_s=10)
    assert ev.n_dst[0] == 400 and len(ev.dsts[0]) == 50


# ------------------------------------------------------------------ IP-less refusal
def test_ipless_dataset_is_reported_unusable_and_no_entity_is_invented():
    f = pd.DataFrame({"timestamp": T0 + pd.to_timedelta(np.arange(6), unit="s"),
                      "src_ip": ["NETWORK-2018-02-16"] * 6, "dst_ip": ["UNKNOWN"] * 6,
                      "label": ["DoS attacks-Hulk"] * 3 + ["Benign"] * 3, "has_ip_data": 0.0, "unit": "Friday-16-02-2018"})
    for view in ("attacker", "victim", "pair", "host"):
        ev, rep = events_from_flows(f, view)
        assert ev.empty and rep.usable is False and "cannot be used for entity tracking" in rep.reason
        assert rep.units["Friday-16-02-2018"]["usable"] is False and rep.units["Friday-16-02-2018"]["usable_ip_fraction"] == 0.0


def test_refusal_is_per_unit_not_per_dataset():
    good = flows([(0, "A", "V", "PortScan"), (1, "A", "V", "PortScan")], unit="with-ips")
    bad = pd.DataFrame({"timestamp": [T0, T0 + pd.Timedelta(seconds=1)], "src_ip": ["NETWORK-x"] * 2, "dst_ip": ["UNKNOWN"] * 2,
                        "label": ["Bot", "Bot"], "has_ip_data": 0.0, "unit": "pseudo-day"})
    ev, rep = events_from_flows(pd.concat([good, bad], ignore_index=True), "attacker")
    assert rep.usable and list(ev.entity) == ["A"] and set(ev.unit) == {"with-ips"}
    assert rep.units["pseudo-day"]["usable"] is False and rep.units["with-ips"]["usable"] is True
    assert rep.n_rows_dropped_pseudo == 2


def test_single_pseudo_rows_inside_a_real_unit_are_dropped_and_counted():
    f = flows([(0, "A", "V", "PortScan"), (1, "A", "UNKNOWN", "PortScan"), (2, "A", "V", "PortScan")])
    ev, rep = events_from_flows(f, "attacker", merge_gap_s=10)
    assert ev.n_flows[0] == 2 and rep.n_rows_dropped_pseudo == 1


# ------------------------------------------------------------------ detector input
def _det(rows):
    return pd.DataFrame(rows, columns=["host", "window_start", "stage", "confidence"])


def test_detector_windows_merge_into_events_with_confidence():
    d = _det([("H", T0, "reconnaissance", 0.8), ("H", T0 + pd.Timedelta(seconds=10), "reconnaissance", 0.6),
              ("H", T0 + pd.Timedelta(seconds=20), "benign", 0.0),
              ("H", T0 + pd.Timedelta(seconds=900), "initial_access", 0.9)])
    ev, rep = events_from_detections(d, "attacker", window_s=10, merge_gap_s=30)
    assert list(ev.stage) == ["reconnaissance", "initial_access"] and rep.source == "detector"
    r = ev.iloc[0]
    assert r.n_flows == 2 and r.duration_s == 20 and abs(r.confidence - 0.7) < 1e-9 and r.source == "detector"
    ev2, rep2 = events_from_detections(d, "attacker", window_s=10, merge_gap_s=30, min_confidence=0.7)
    assert list(ev2.stage) == ["reconnaissance", "initial_access"] and ev2.n_flows[0] == 1 and rep2.n_rows_dropped_low_confidence == 1


def test_detector_unknown_stage_and_missing_destinations_are_reported_not_invented():
    d = _det([("H", T0, "reconnaissance", 1.0), ("H", T0 + pd.Timedelta(seconds=10), "persistence", 1.0)])
    ev, rep = events_from_detections(d, "attacker", window_s=10)
    assert rep.n_rows_dropped_unknown_stage == 1 and len(ev) == 1
    ev, rep = events_from_detections(d, "victim", window_s=10)           # no destination column -> nothing to key on
    assert ev.empty and rep.n_rows_dropped_no_dst == 1
    d["dst_ips"] = ["V1;V2", "V1"]
    ev, _ = events_from_detections(d, "victim", window_s=10)
    assert set(ev.entity) == {"V1", "V2"}


def test_detector_fan_out_does_not_inflate_window_counts_or_confidence():
    d = _det([("H", T0, "reconnaissance", 0.9), ("H", T0 + pd.Timedelta(seconds=10), "reconnaissance", 0.3)])
    d["dst_ips"] = ["V1;V2;V3;V4", "V1"]
    ev, _ = events_from_detections(d, "attacker", window_s=10, merge_gap_s=30)
    assert len(ev) == 1 and ev.n_flows[0] == 2 and abs(ev.confidence[0] - 0.6) < 1e-9      # 2 windows, not 5 rows
    assert ev.dsts[0] == {"V1": 2, "V2": 1, "V3": 1, "V4": 1} and ev.n_dst[0] == 4
    ev, rep = events_from_detections(d, "attacker", window_s=10, merge_gap_s=30, min_windows=3)
    assert ev.empty and rep.n_runs_dropped_filter == 1                                    # min windows counts windows


def test_detector_pseudo_hosts_are_refused():
    d = _det([("NETWORK-2018-02-16", T0, "reconnaissance", 1.0)])
    ev, rep = events_from_detections(d, "attacker", window_s=10)
    assert ev.empty and rep.usable is False


# ------------------------------------------------------------------ chains
def test_chain_gap_collapse_and_censoring():
    f = flows([(0, "A", "V", "PortScan"), (1000, "A", "V", "PortScan"),              # same stage, 1000 s apart
               (2000, "A", "V", "SSH-Bruteforce"),
               (50_000, "A", "V", "SSH-Bruteforce")])                                  # new chain, after 13 h
    ev, _ = events_from_flows(f, "attacker", merge_gap_s=100)
    assert len(ev) == 4
    ch = link_chains(ev, max_chain_gap_s=7200, observed_until=T0.timestamp() + 50_060)
    assert [c.stages for c in ch] == [["reconnaissance", "initial_access"], ["initial_access"]]   # recon collapsed
    assert ch[0].events[0]["n_flows"] == 2 and ch[0].events[0]["collapsed"] == 2
    assert ch[0].terminated is True and ch[1].terminated is False      # the last chain is still open at the end of the data
    ch = link_chains(ev, 7200, observed_until=T0.timestamp() + 50_060, collapse_same_stage=False)
    assert ch[0].stages == ["reconnaissance", "reconnaissance", "initial_access"]


def test_overlapping_events_are_ordered_by_start():
    f = flows([(0, "A", "V", "PortScan"), (400, "A", "V", "PortScan"), (100, "A", "V", "Bot"), (200, "A", "V", "Bot")])
    ev, _ = events_from_flows(f, "attacker", merge_gap_s=500)
    c = link_chains(ev, 7200, collapse_same_stage=False)[0]
    assert c.stages == ["reconnaissance", "command_and_control"]       # recon (start 0) first although it ends last
    assert c.events[0]["end_s"] > c.events[1]["start_s"]               # the overlap stays visible


def test_events_csv_round_trip(tmp_path):
    ev, _ = events_from_flows(_campaign(), "attacker")
    save_events(ev, tmp_path / "e.csv")
    back = load_events(tmp_path / "e.csv")
    assert list(back.entity) == list(ev.entity) and back.dsts.tolist() == ev.dsts.tolist()
    assert np.allclose(back.start_s, ev.start_s)


# ------------------------------------------------------------------ vocabulary of lab recordings
LAB_LABELS = {  # what to write into a labels sidecar for each stage (docs/14 section 6)
    "reconnaissance": ["PortScan"],
    "initial_access": ["SSH-Bruteforce", "FTP-BruteForce", "Brute Force -Web", "SQL Injection", "FTP-Patator", "SSH-Patator"],
    "lateral_movement": ["Infiltration", "Infilteration"],
    "command_and_control": ["Bot"],
    "exfiltration": ["SYNTH-Exfiltration"],
    "impact": ["DDoS attacks-LOIC-HTTP", "DoS attacks-Hulk"],
}


@pytest.mark.parametrize("stage", sorted(LAB_LABELS))
def test_every_documented_sidecar_label_maps_to_its_stage(stage):
    assert stage in STAGES
    for lab in LAB_LABELS[stage]:
        assert label_to_stage(lab) == stage, lab


def test_an_unlisted_label_silently_becomes_impact():
    # why docs/14 prints the table: a typo does not fail, it turns into 'impact'
    assert label_to_stage("Exfiltration") == "impact" and label_to_stage("exfil") == "impact"


def test_labels_sidecar_to_events_end_to_end(tmp_path):
    from pipeline.adapters.sidecar import LabelSidecar
    sc = tmp_path / "labels.csv"
    sc.write_text("src_ip,dst_ip,start,end,label\n"
                  "10.0.0.66,10.0.0.5,2026-03-01 10:00:00,2026-03-01 10:01:00,PortScan\n"
                  "10.0.0.66,10.0.0.5,2026-03-01 10:10:00,2026-03-01 10:12:00,SSH-Bruteforce\n"
                  "10.0.0.5,203.0.113.9,2026-03-01 10:30:00,2026-03-01 10:31:00,Bot\n", encoding="utf-8")
    pcap_like = flows([(s, a, b, "BENIGN") for s, a, b in
                       [(5, "10.0.0.66", "10.0.0.5"), (30, "10.0.0.66", "10.0.0.5"), (650, "10.0.0.66", "10.0.0.5"),
                        (1850, "10.0.0.5", "203.0.113.9"), (1860, "10.0.0.7", "10.0.0.8")]])
    labelled = LabelSidecar.load(sc).apply(pcap_like, "BENIGN")
    ev, rep = events_from_flows(labelled, "host", merge_gap_s=60)
    h = ev[ev.entity == "10.0.0.5"].sort_values("start_s")
    assert list(h.stage) == ["reconnaissance", "initial_access", "command_and_control"]
    assert ev.entity.isin(["10.0.0.7", "10.0.0.8"]).sum() == 0


# ------------------------------------------------------------------ evaluation-only relabel
def test_ctu13_icmp_relabel_is_scoped_and_leaves_the_mapping_alone():
    df = pd.DataFrame({"label": ["flow=From-Botnet-V51-1-ICMP", "flow=From-Botnet-V51-1-ICMP", "flow=From-Botnet-V51-1-UDP-DNS",
                                 "flow=Background-UDP"],
                       "protocol": [1.0, 1.0, 17.0, 17.0], "unit": ["10", "2", "10", "10"]})
    st = ctu13_icmp_flood_as_impact(df)
    assert list(st) == ["impact", "command_and_control", "command_and_control", "benign"]    # scenario 2 is not relabelled
    assert label_to_stage("flow=From-Botnet-V51-1-ICMP") == "command_and_control"           # mapping untouched


# ------------------------------------------------------------------ lab recording path (PCAP adapter + sidecar + CLI)
def test_cli_pcap_plus_sidecar_end_to_end(tmp_path):
    from pipeline import stage_events
    from tests.live_fixtures import BASE, dense_pcap
    cap = tmp_path / "cap" / "lab.pcap"
    cap.parent.mkdir()
    dense_pcap(cap, seconds=240, n_hosts=4)
    side = tmp_path / "labels.csv"
    side.write_text("src_ip,dst_ip,start,end,label\n"                       # epoch seconds are accepted
                    f"10.0.0.1,,{BASE},{BASE + 60},PortScan\n"
                    f"10.0.0.1,,{BASE + 120},{BASE + 200},SSH-Bruteforce\n", encoding="utf-8")
    out = tmp_path / "events"
    rc = stage_events.main(["--input", str(cap.parent), "--adapter", "pcap", "--labels-sidecar", str(side), "--name", "lab",
                            "--views", "attacker,host", "--merge-gap", "30", "--out-dir", str(out), "--show", "0"])
    assert rc == 0
    ev = load_events(out / "events_attacker.csv")
    a = ev[ev.entity == "10.0.0.1"].sort_values("start_s")
    assert list(a.stage)[:2] == ["reconnaissance", "initial_access"] and (out / "report.json").exists()
    assert set(ev.source) == {"label"}


def test_cli_refuses_ipless_input_with_exit_code_2(tmp_path):
    from pipeline import stage_events
    p = tmp_path / "d.csv"
    pd.DataFrame({"timestamp": ["2026-03-01 10:00:00"], "src_ip": ["NETWORK-2018-02-16"], "dst_ip": ["UNKNOWN"]}).to_csv(p, index=False)
    det = tmp_path / "det.csv"
    pd.DataFrame({"host": ["NETWORK-2018-02-16"], "window_start": ["2026-03-01 10:00:00"], "stage": ["reconnaissance"],
                  "confidence": [0.9]}).to_csv(det, index=False)
    rc = stage_events.main(["--detections", str(det), "--name", "x", "--views", "attacker", "--out-dir", str(tmp_path / "o"), "--show", "0"])
    assert rc == 2 and not (tmp_path / "o" / "events_attacker.csv").exists()
