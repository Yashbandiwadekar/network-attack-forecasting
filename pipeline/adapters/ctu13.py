from pathlib import Path

import pandas as pd


COLUMN_MAP = {
    "StartTime": "timestamp",
    "#StartTime": "timestamp",
    "Dur": "duration_s",
    "Proto": "protocol",
    "SrcAddr": "src_ip",
    "Sport": "src_port",
    "Dir": "direction",
    "DstAddr": "dst_ip",
    "Dport": "dst_port",
    "State": "state",
    "sTos": "src_tos",
    "dTos": "dst_tos",
    "TotPkts": "total_pkts",
    "TotBytes": "total_bytes",
    "SrcBytes": "src_bytes",
    "Label": "label",
}


EXPECTED_COLUMNS = [
    "timestamp",
    "duration_s",
    "protocol",
    "src_ip",
    "src_port",
    "direction",
    "dst_ip",
    "dst_port",
    "state",
    "src_tos",
    "dst_tos",
    "total_pkts",
    "total_bytes",
    "src_bytes",
    "label",
]


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize one CTU-13 .binetflow DataFrame."""

    df = df.copy()

    df = df.rename(columns=COLUMN_MAP)

    for column in EXPECTED_COLUMNS:
        if column not in df.columns:
            df[column] = pd.NA

    # Preserve original CTU-13 label
    df["original_label"] = (
        df["label"]
        .astype("string")
        .str.strip()
    )

    # CTU-13 botnet traffic
    df["attack_label"] = (
        df["original_label"]
        .str.contains(
            "From-Botnet",
            case=False,
            na=False,
        )
        .map({
            True: "attack",
            False: "benign",
        })
    )

    # Numeric fields
    numeric_columns = [
        "duration_s",
        "src_port",
        "dst_port",
        "src_tos",
        "dst_tos",
        "total_pkts",
        "total_bytes",
        "src_bytes",
    ]

    for column in numeric_columns:
        df[column] = pd.to_numeric(
            df[column],
            errors="coerce",
        )

    # CTU-13 protocol is text: tcp / udp / icmp
    df["protocol"] = (
        df["protocol"]
        .astype("string")
        .str.strip()
        .str.lower()
    )

    protocol_map = {
        "tcp": 6,
        "udp": 17,
        "icmp": 1,
    }

    df["protocol"] = df["protocol"].map(protocol_map)

    # Parse CTU-13 timestamps
    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce",
    )

    # Remove unusable rows
    df = df.dropna(
        subset=[
            "timestamp",
            "protocol",
            "dst_port",
            "total_pkts",
            "total_bytes",
        ]
    )

    df = df[df["total_pkts"] > 0]

    # ---------------------------------------------------------
    # Fields expected by existing flow/window pipeline
    # ---------------------------------------------------------

    df["fwd_pkts"] = df["total_pkts"]
    df["bwd_pkts"] = 0.0

    df["fwd_bytes"] = df["src_bytes"]

    df["bwd_bytes"] = (
        df["total_bytes"] - df["src_bytes"]
    ).clip(lower=0)

    # CTU-13 .binetflow does not contain TCP flag counts.
    df["syn_cnt"] = 0.0
    df["ack_cnt"] = 0.0
    df["fin_cnt"] = 0.0
    df["rst_cnt"] = 0.0
    df["psh_cnt"] = 0.0
    df["urg_cnt"] = 0.0

    # CTU-13 .binetflow does not contain CICFlowMeter IAT fields.
    df["iat_mean"] = 0.0
    df["iat_std"] = 0.0
    df["iat_max"] = 0.0

    df["is_tcp"] = (
        df["protocol"] == 6
    ).astype(float)

    df["is_udp"] = (
        df["protocol"] == 17
    ).astype(float)

    df["bidir_ratio"] = 0.0

    return df.reset_index(drop=True)


def load_ctu13_file(path: str | Path) -> pd.DataFrame:
    """Load and normalize one CTU-13 .binetflow file."""

    path = Path(path)

    df = pd.read_csv(
        path,
        low_memory=False,
    )

    df = _normalize_columns(df)

    # Add scenario metadata.
    #
    # Example:
    # data/raw/ctu13/1/capture20110810.binetflow
    #                         -> scenario_id = 1
    #
    # This is required so forecasting windows never
    # cross from one CTU-13 scenario into another.
    try:
        scenario_id = int(path.parent.name)
    except ValueError:
        scenario_id = path.parent.name

    df["scenario_id"] = scenario_id
    df["source_file"] = path.name

    return df


def load_ctu13_directory(directory: str | Path) -> pd.DataFrame:
    """Load and normalize all CTU-13 .binetflow files recursively."""

    directory = Path(directory)

    files = sorted(
        directory.rglob("*.binetflow")
    )

    if not files:
        raise FileNotFoundError(
            f"No .binetflow files found in {directory}"
        )

    frames = []

    for path in files:
        print(f"Loading: {path}")

        try:
            df = load_ctu13_file(path)

            frames.append(df)

            print(
                f"  Scenario: {df['scenario_id'].iloc[0]}"
            )

            print(
                f"  Rows: {len(df)}"
            )

        except Exception as exc:
            print(
                f"  ERROR: {exc}"
            )

    if not frames:
        raise RuntimeError(
            "No CTU-13 files could be loaded."
        )

    result = pd.concat(
        frames,
        ignore_index=True,
    )

    return (
        result
        .sort_values(
            ["scenario_id", "timestamp"]
        )
        .reset_index(drop=True)
    )
