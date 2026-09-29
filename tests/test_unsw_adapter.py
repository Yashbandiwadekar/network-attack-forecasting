import pandas as pd

from pipeline.adapters.unsw_nb15 import RAW_COLUMNS, _normalize_columns
from pipeline.mitre_mapping import label_to_stage


def _raw_row(**overrides) -> dict:
    row = {c: 0 for c in RAW_COLUMNS}
    row.update({
        "srcip": "10.0.0.1", "dstip": "10.0.0.2", "sport": 1234, "dsport": 80,
        "proto": "tcp", "state": "CON", "dur": 0.5, "sbytes": 100, "dbytes": 200,
        "spkts": 2, "dpkts": 3, "stime": 1421927414, "ltime": 1421927415,
        "attack_cat": None, "label": 0,
    })
    row.update(overrides)
    return row


def test_normal_row_maps_to_benign_with_real_ip_and_timestamp():
    df = pd.DataFrame([_raw_row()])
    out = _normalize_columns(df)
    assert out.loc[0, "src_ip"] == "10.0.0.1"
    assert out.loc[0, "has_ip_data"] == 1.0
    assert out.loc[0, "label"] == "unsw=Normal"
    assert label_to_stage(out.loc[0, "label"]) == "benign"
    assert pd.notna(out.loc[0, "timestamp"])


def test_reconnaissance_attack_cat_maps_to_reconnaissance_stage():
    df = pd.DataFrame([_raw_row(attack_cat=" Reconnaissance ", label=1)])
    out = _normalize_columns(df)
    assert out.loc[0, "label"] == "unsw=Reconnaissance"
    assert label_to_stage(out.loc[0, "label"]) == "reconnaissance"


def test_worms_maps_to_lateral_movement_and_generic_to_impact():
    df = pd.DataFrame([_raw_row(attack_cat="Worms", label=1), _raw_row(attack_cat="Generic", label=1)])
    out = _normalize_columns(df)
    stages = out["label"].map(label_to_stage).tolist()
    assert stages == ["lateral_movement", "impact"]


def test_protocol_mapped_to_numeric_and_udp_flag_set():
    df = pd.DataFrame([_raw_row(proto="udp")])
    out = _normalize_columns(df)
    assert out.loc[0, "protocol"] == 17
    assert out.loc[0, "is_udp"] == 1.0
    assert out.loc[0, "is_tcp"] == 0.0


def test_flags_derived_honestly_from_state_and_handshake_timers():
    # Audit G4/W5: completed handshake (synack>0, ackdat>0) on a TCP row seen closing (FIN state).
    df = pd.DataFrame([_raw_row(proto="tcp", state="FIN", synack=0.01, ackdat=0.02)])
    out = _normalize_columns(df)
    assert out.loc[0, "syn_cnt"] == 1.0
    assert out.loc[0, "ack_cnt"] == 1.0
    assert out.loc[0, "fin_cnt"] == 1.0
    assert out.loc[0, "rst_cnt"] == 0.0
    # PSH/URG have no derivable UNSW signal anywhere -- always zero, not invented.
    assert out.loc[0, "psh_cnt"] == 0.0
    assert out.loc[0, "urg_cnt"] == 0.0


def test_no_handshake_timers_means_no_syn_or_ack_derived():
    df = pd.DataFrame([_raw_row(proto="tcp", state="INT", synack=0.0, ackdat=0.0)])
    out = _normalize_columns(df)
    assert out.loc[0, "syn_cnt"] == 0.0
    assert out.loc[0, "ack_cnt"] == 0.0


def test_rst_state_sets_rst_flag():
    df = pd.DataFrame([_raw_row(proto="tcp", state="RST", synack=0.0, ackdat=0.0)])
    out = _normalize_columns(df)
    assert out.loc[0, "rst_cnt"] == 1.0


def test_flags_never_set_for_non_tcp_rows():
    df = pd.DataFrame([_raw_row(proto="udp", state="FIN", synack=0.01, ackdat=0.02)])
    out = _normalize_columns(df)
    assert out.loc[0, "syn_cnt"] == 0.0 and out.loc[0, "fin_cnt"] == 0.0


def test_iat_mean_converted_ms_to_microseconds():
    # sintpkt/dintpkt in ms; average of 2ms and 4ms -> 3ms -> 3000us.
    df = pd.DataFrame([_raw_row(sintpkt=2.0, dintpkt=4.0)])
    out = _normalize_columns(df)
    assert out.loc[0, "iat_mean"] == 3000.0
