import pandas as pd

from pipeline.flow_features import clean_and_normalize, load_flow_csv

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


def test_missing_required_column_raises(tmp_path):
    csv_path = tmp_path / "bad.csv"
    bad_row = {k: v for k, v in RAW_ROWS[0].items() if k != "Src IP"}
    pd.DataFrame([bad_row]).to_csv(csv_path, index=False)
    try:
        load_flow_csv(csv_path)
        assert False, "expected ValueError for missing column"
    except ValueError as e:
        assert "src_ip" in str(e)
