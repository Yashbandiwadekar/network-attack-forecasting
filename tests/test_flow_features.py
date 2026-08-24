import pandas as pd

from pipeline.flow_features import _parse_timestamp, clean_and_normalize, load_flow_csv


def test_parse_timestamp_handles_real_dayfirst_and_synthetic_iso():
    parsed = _parse_timestamp(pd.Series([
        "14/02/2018 08:31:01",       # real CIC-IDS-2018, unambiguously day-first (no 14th month)
        "01/03/2018 08:17:11",       # real CIC-IDS-2018, AMBIGUOUS — must be 1 March, not 3 January
        "2026-01-02 00:00:05",       # synthetic sample, ISO — must stay 2 January, not 1 February
        "2026-01-01 00:00:00.000",   # synthetic sample's actual on-disk format (has milliseconds)
        "not a timestamp",
    ]))
    assert parsed[0] == pd.Timestamp("2018-02-14 08:31:01")
    assert parsed[1] == pd.Timestamp("2018-03-01 08:17:11")
    assert parsed[2] == pd.Timestamp("2026-01-02 00:00:05")
    assert parsed[3] == pd.Timestamp("2026-01-01 00:00:00")
    assert pd.isna(parsed[4])

RAW_ROWS = [
    {
        "Src IP": "10.0.0.9", "Src Port": 40000, "Dst IP": "10.0.0.50", "Dst Port": 22,
        "Protocol": 6, "Timestamp": "2026-01-01 00:00:00", "Flow Duration": 2_000_000,
        "Tot Fwd Pkts": 4, "Tot Bwd Pkts": 2, "TotLen Fwd Pkts": 400, "TotLen Bwd Pkts": 200,
        "SYN Flag Cnt": 1, "ACK Flag Cnt": 3, "FIN Flag Cnt": 0, "RST Flag Cnt": 0,
        "PSH Flag Cnt": 1, "URG Flag Cnt": 0, "Flow IAT Mean": 1000.0, "Flow IAT Std": 100.0,
        "Flow IAT Max": 5000.0, "Label": "SSH-Bruteforce",
    },
    {
        # inf rate feature + a zero-packet flow, both of which real CICFlowMeter output can contain
        "Src IP": "10.0.0.5", "Src Port": 51000, "Dst IP": "93.184.216.34", "Dst Port": 443,
        "Protocol": 6, "Timestamp": "2026-01-01 00:00:05", "Flow Duration": 0,
        "Tot Fwd Pkts": 0, "Tot Bwd Pkts": 0, "TotLen Fwd Pkts": 0, "TotLen Bwd Pkts": 0,
        "SYN Flag Cnt": 0, "ACK Flag Cnt": 0, "FIN Flag Cnt": 0, "RST Flag Cnt": 0,
        "PSH Flag Cnt": 0, "URG Flag Cnt": 0, "Flow IAT Mean": 0.0, "Flow IAT Std": 0.0,
        "Flow IAT Max": 0.0, "Label": "BENIGN",
    },
]


def test_load_and_clean(tmp_path):
    csv_path = tmp_path / "sample.csv"
    pd.DataFrame(RAW_ROWS).to_csv(csv_path, index=False)

    raw = load_flow_csv(csv_path)
    df = clean_and_normalize(raw)

    # the zero-packet flow must be dropped — total_pkts > 0 is required downstream
    assert len(df) == 1
    row = df.iloc[0]
    assert row["src_ip"] == "10.0.0.9"
    assert row["total_pkts"] == 6
    assert row["total_bytes"] == 600
    assert row["is_tcp"] == 1.0
    assert row["is_udp"] == 0.0
    assert row["label"] == "SSH-Bruteforce"
    assert row["has_ip_data"] == 1.0  # real Src IP was present in this CSV


def test_missing_required_column_raises(tmp_path):
    # "Dst Port" is strictly required — unlike Src/Dst IP (see test below), there's no fallback
    csv_path = tmp_path / "bad.csv"
    bad_row = {k: v for k, v in RAW_ROWS[0].items() if k != "Dst Port"}
    pd.DataFrame([bad_row]).to_csv(csv_path, index=False)
    try:
        load_flow_csv(csv_path)
        assert False, "expected ValueError for missing column"
    except ValueError as e:
        assert "dst_port" in str(e)


def test_missing_ip_columns_synthesizes_per_day_pseudo_host(tmp_path):
    # Several real CIC-IDS-2018 CSV releases drop Src IP/Dst IP/Src Port entirely — this must not
    # raise; it should fall back to one pseudo-host per calendar day instead (see
    # pipeline/flow_features.py::_fill_missing_ip_columns).
    csv_path = tmp_path / "no_ip.csv"
    rows = []
    for row, day in zip(RAW_ROWS, ["2026-01-01 00:00:00", "2026-01-02 00:00:05"]):
        r = {k: v for k, v in row.items() if k not in ("Src IP", "Dst IP", "Src Port")}
        r["Timestamp"] = day
        r["Tot Fwd Pkts"] = 4  # keep both rows non-zero-packet so neither gets dropped
        rows.append(r)
    pd.DataFrame(rows).to_csv(csv_path, index=False)

    raw = load_flow_csv(csv_path)
    df = clean_and_normalize(raw)

    assert len(df) == 2
    assert (df["has_ip_data"] == 0.0).all()
    assert (df["dst_ip"] == "UNKNOWN").all()
    assert (df["src_port"] == 0).all()
    # different calendar days -> different pseudo-hosts, so sequences never span the day boundary
    assert df["src_ip"].nunique() == 2
    assert set(df["src_ip"]) == {"NETWORK-2026-01-01", "NETWORK-2026-01-02"}
