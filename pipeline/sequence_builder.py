from __future__ import annotations

from pathlib import Path

import json
import numpy as np
import pandas as pd


INPUT_FILE = Path(
    "data/processed/ctu13_10s_windows.csv"
)

OUTPUT_DIR = Path(
    "data/processed/sequences"
)

SEQUENCE_LENGTH = 12
HORIZON_WINDOWS = 6


FEATURE_COLUMNS = [
    "flow_count",
    "attack_count",
    "total_bytes",
    "total_packets",
    "src_bytes",
    "duration_mean",
    "duration_max",
    "src_flow_count_mean",
    "dst_flow_count_mean",
    "src_unique_dst_ips_mean",
    "dst_unique_src_ips_mean",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "urg_count",
    "tcp_count",
    "udp_count",
    "iat_mean",
    "iat_std",
    "iat_max",
    "bidir_ratio_mean",
    "attack_rate",
    "bytes_per_flow",
    "packets_per_flow",
]


def build_sequences():

    print("=== LOADING WINDOW DATASET ===")

    df = pd.read_csv(INPUT_FILE)

    df["window_start"] = pd.to_datetime(
        df["window_start"],
        errors="coerce",
    )

    df = (
        df.dropna(subset=["window_start"])
        .sort_values("window_start")
        .reset_index(drop=True)
    )

    print("Windows:", len(df))
    print("Features:", len(FEATURE_COLUMNS))

    # ---------------------------------------------------------
    # CHECK REQUIRED COLUMNS
    # ---------------------------------------------------------

    required = set(FEATURE_COLUMNS) | {
        "window_start",
        "forecast_attack_next_60s",
    }

    missing = required - set(df.columns)

    if missing:
        raise ValueError(
            f"Missing columns: {sorted(missing)}"
        )

    # ---------------------------------------------------------
    # FEATURE MATRIX
    # ---------------------------------------------------------

    X_all = (
        df[FEATURE_COLUMNS]
        .replace(
            [np.inf, -np.inf],
            np.nan,
        )
        .fillna(0)
        .to_numpy(dtype=np.float32)
    )

    y_all = (
        df["forecast_attack_next_60s"]
        .to_numpy(dtype=np.int8)
    )

    timestamps = df["window_start"].to_numpy()

    # ---------------------------------------------------------
    # CREATE SEQUENCES
    # ---------------------------------------------------------

    print("\n=== CREATING SEQUENCES ===")

    X_sequences = []
    y_sequences = []
    sequence_times = []

    max_start = (
        len(df)
        - SEQUENCE_LENGTH
    )

    for start in range(max_start):

        end = (
            start
            + SEQUENCE_LENGTH
        )

        target_index = end - 1

        X_sequences.append(
            X_all[start:end]
        )

        y_sequences.append(
            y_all[target_index]
        )

        sequence_times.append(
            timestamps[target_index]
        )

    X = np.asarray(
        X_sequences,
        dtype=np.float32,
    )

    y = np.asarray(
        y_sequences,
        dtype=np.int8,
    )

    sequence_times = np.asarray(
        sequence_times
    )

    print("X shape:", X.shape)
    print("y shape:", y.shape)

    # ---------------------------------------------------------
    # SAVE
    # ---------------------------------------------------------

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    np.save(
        OUTPUT_DIR / "X.npy",
        X,
    )

    np.save(
        OUTPUT_DIR / "y.npy",
        y,
    )

    np.save(
        OUTPUT_DIR / "timestamps.npy",
        sequence_times,
    )

    metadata = {
        "source": "CTU-13",
        "input_file": str(INPUT_FILE),
        "window_size_seconds": 10,
        "sequence_length": SEQUENCE_LENGTH,
        "history_seconds": SEQUENCE_LENGTH * 10,
        "horizon_windows": HORIZON_WINDOWS,
        "horizon_seconds": HORIZON_WINDOWS * 10,
        "num_sequences": int(len(X)),
        "num_features": int(len(FEATURE_COLUMNS)),
        "feature_columns": FEATURE_COLUMNS,
        "target": "forecast_attack_next_60s",
        "target_values": {
            "0": "no attack in next 60 seconds",
            "1": "attack in next 60 seconds",
        },
        "X_shape": list(X.shape),
        "y_shape": list(y.shape),
    }

    with open(
        OUTPUT_DIR / "metadata.json",
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            metadata,
            f,
            indent=2,
        )

    print("\n=== SEQUENCE DATASET ===")

    print(
        "Sequences:",
        len(X),
    )

    print(
        "Sequence shape:",
        X.shape,
    )

    print(
        "Target counts:"
    )

    print(
        pd.Series(y)
        .value_counts()
        .sort_index()
    )

    print("\nSaved files:")

    print(
        OUTPUT_DIR / "X.npy"
    )

    print(
        OUTPUT_DIR / "y.npy"
    )

    print(
        OUTPUT_DIR / "timestamps.npy"
    )

    print(
        OUTPUT_DIR / "metadata.json"
    )


if __name__ == "__main__":
    build_sequences()
