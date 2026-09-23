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
