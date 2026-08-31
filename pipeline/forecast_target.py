from __future__ import annotations

import numpy as np
import pandas as pd


def add_forecast_target(
    df: pd.DataFrame,
    horizon_seconds: int = 60,
) -> pd.DataFrame:
    """Add a binary target for attacks occurring in the next time window."""

    df = df.copy()

    required = {"timestamp", "attack_label"}

    missing = required - set(df.columns)
    if missing:
        raise ValueError(
            f"Missing required columns: {sorted(missing)}"
        )

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce",
    )

    if df["timestamp"].isna().any():
        raise ValueError("Invalid timestamps found.")

    df = df.sort_values("timestamp").reset_index(drop=True)

    attack = (
        df["attack_label"]
        .astype(str)
        .str.lower()
        .eq("attack")
        .to_numpy(dtype=np.int8)
    )

    timestamps = df["timestamp"].astype("int64").to_numpy()

    horizon_ns = horizon_seconds * 1_000_000_000

    future_start = np.searchsorted(
        timestamps,
        timestamps,
        side="right",
    )

    future_end = np.searchsorted(
        timestamps,
        timestamps + horizon_ns,
        side="right",
    )

    prefix = np.concatenate(
        ([0], np.cumsum(attack, dtype=np.int64))
    )

    future_attack_count = (
        prefix[future_end] - prefix[future_start]
    )

    df["forecast_attack_next_60s"] = (
        future_attack_count > 0
    ).astype("int8")

    return df
