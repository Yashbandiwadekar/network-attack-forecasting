from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd


INPUT_FILE = Path(
    "data/processed/ctu13_forecasting.csv"
)

OUTPUT_FILE = Path(
    "data/processed/ctu13_10s_windows.csv"
)


def build_10s_windows() -> pd.DataFrame:

    print("=== LOADING PROCESSED DATASET ===")

    df = pd.read_csv(INPUT_FILE)

    print("Rows:", len(df))
    print("Columns:", len(df.columns))

    # ---------------------------------------------------------
    # TIMESTAMP
    # ---------------------------------------------------------

    print("\n=== PREPARING TIMESTAMP ===")

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce",
    )

    df = df.dropna(
        subset=["timestamp"]
    )

    df = df.sort_values(
        "timestamp"
    ).reset_index(drop=True)

    # ---------------------------------------------------------
    # ATTACK INDICATOR
    # ---------------------------------------------------------

    df["_is_attack"] = (
        df["attack_label"]
        .astype(str)
        .str.lower()
        .eq("attack")
        .astype("int8")
    )

    # ---------------------------------------------------------
    # 10 SECOND WINDOWS
    # ---------------------------------------------------------

    print("\n=== CREATING 10-SECOND WINDOWS ===")

    df["window_start"] = (
        df["timestamp"]
        .dt.floor("10s")
    )

    grouped = df.groupby(
        "window_start",
        sort=True,
    )

    windows = grouped.agg(
        flow_count=(
            "timestamp",
            "size",
        ),

        attack_count=(
            "_is_attack",
            "sum",
        ),

        total_bytes=(
            "total_bytes",
            "sum",
        ),

        total_packets=(
            "total_pkts",
            "sum",
        ),

        src_bytes=(
            "src_bytes",
            "sum",
        ),

        duration_mean=(
            "duration_s",
            "mean",
        ),

        duration_max=(
            "duration_s",
            "max",
        ),

        src_flow_count_mean=(
            "src_flow_count",
            "mean",
        ),

        dst_flow_count_mean=(
            "dst_flow_count",
            "mean",
        ),

        src_unique_dst_ips_mean=(
            "src_unique_dst_ips",
            "mean",
        ),

        dst_unique_src_ips_mean=(
            "dst_unique_src_ips",
            "mean",
        ),

        syn_count=(
            "syn_cnt",
            "sum",
        ),

        ack_count=(
            "ack_cnt",
            "sum",
        ),

        fin_count=(
            "fin_cnt",
            "sum",
        ),

        rst_count=(
            "rst_cnt",
            "sum",
        ),

        psh_count=(
            "psh_cnt",
            "sum",
        ),

        urg_count=(
            "urg_cnt",
            "sum",
        ),

        tcp_count=(
            "is_tcp",
            "sum",
        ),

        udp_count=(
            "is_udp",
            "sum",
        ),

        iat_mean=(
            "iat_mean",
            "mean",
        ),

        iat_std=(
            "iat_std",
            "mean",
        ),

        iat_max=(
            "iat_max",
            "max",
        ),

        bidir_ratio_mean=(
            "bidir_ratio",
            "mean",
        ),
    ).reset_index()

    # ---------------------------------------------------------
    # DERIVED FEATURES
    # ---------------------------------------------------------

    print("\n=== ADDING DERIVED FEATURES ===")

    windows["attack_rate"] = (
        windows["attack_count"]
        / windows["flow_count"].replace(0, np.nan)
    ).fillna(0.0)

    windows["bytes_per_flow"] = (
        windows["total_bytes"]
        / windows["flow_count"].replace(0, np.nan)
    ).fillna(0.0)

    windows["packets_per_flow"] = (
        windows["total_packets"]
        / windows["flow_count"].replace(0, np.nan)
    ).fillna(0.0)

    # ---------------------------------------------------------
    # FUTURE 60 SECOND TARGET
    # ---------------------------------------------------------

    print("\n=== CREATING 60-SECOND FORECAST TARGET ===")

    # Six future 10-second windows.
    #
    # Current window:
    #       t
    #
    # Future:
    #       t+1 ... t+6
    #
    # Target = 1 if ANY attack occurs in those
    # six future windows.

    attack_values = (
        windows["attack_count"]
        .to_numpy(
            dtype=np.int64
        )
    )

    n = len(windows)

    future_attack = np.zeros(
        n,
        dtype=np.int64,
    )

    for i in range(n):

        end = min(
            i + 7,
            n,
        )

        if i + 1 < end:

            future_attack[i] = int(
                attack_values[
                    i + 1:end
                ].sum() > 0
            )

    windows[
        "forecast_attack_next_60s"
    ] = future_attack.astype("int8")

    # ---------------------------------------------------------
    # REMOVE INCOMPLETE FINAL WINDOWS
    # ---------------------------------------------------------

    # The final six windows cannot have a complete
    # 60-second future horizon.

    if n > 6:

        windows = windows.iloc[
            :-6
        ].reset_index(
            drop=True
        )

    # ---------------------------------------------------------
    # CLEAN NUMERIC VALUES
    # ---------------------------------------------------------

    numeric_columns = windows.select_dtypes(
        include=[np.number]
    ).columns

    windows[numeric_columns] = (
        windows[numeric_columns]
        .replace(
            [np.inf, -np.inf],
            np.nan,
        )
        .fillna(0)
    )

    # ---------------------------------------------------------
    # SAVE
    # ---------------------------------------------------------

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    windows.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    # ---------------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------------

    print("\n=== 10-SECOND WINDOW DATASET ===")

    print(
        "Windows:",
        len(windows),
    )

    print(
        "Columns:",
        len(windows.columns),
    )

    print(
        "Saved:",
        OUTPUT_FILE,
    )

    print("\n=== CURRENT ATTACK WINDOWS ===")

    print(
        (windows["attack_count"] > 0)
        .value_counts()
    )

    print("\n=== FORECAST TARGET ===")

    print(
        windows[
            "forecast_attack_next_60s"
        ].value_counts()
    )

    print("\n=== FORECAST TARGET % ===")

    print(
        windows[
            "forecast_attack_next_60s"
        ]
        .value_counts(
            normalize=True
        )
        .mul(100)
        .round(3)
    )

    print("\n=== FIRST WINDOWS ===")

    print(
        windows.head(10)
        .to_string(index=False)
    )

    return windows


if __name__ == "__main__":
    build_10s_windows()
