from __future__ import annotations

import pandas as pd


def add_temporal_features(
    df: pd.DataFrame,
    windows: tuple[int, ...] = (10, 30, 60),
) -> pd.DataFrame:
    """Add time-based historical network traffic features.

    All rolling features use only information available before
    the current flow to avoid target leakage.
    """

    df = df.copy()

    if "timestamp" not in df.columns:
        raise ValueError("Required column 'timestamp' is missing.")

    if "attack_label" not in df.columns:
        raise ValueError("Required column 'attack_label' is missing.")

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    if df["timestamp"].isna().all():
        raise ValueError("No valid timestamps found.")

    # Preserve chronological order.
    df = df.sort_values("timestamp").reset_index(drop=True)

    # Numeric attack indicator.
    df["_is_attack"] = (
        df["attack_label"].astype(str).str.lower().eq("attack").astype(int)
    )

    # Use timestamp as the rolling-time index.
    time_index = pd.DatetimeIndex(df["timestamp"])

    attack_series = pd.Series(
        df["_is_attack"].to_numpy(),
        index=time_index,
    )

    flow_series = pd.Series(
        1,
        index=time_index,
    )

    for seconds in windows:
        window = f"{seconds}s"

        # Shift by one flow so the current flow is NOT included.
        df[f"flows_prev_{seconds}s"] = (
            flow_series
            .rolling(window, closed="left")
            .sum()
            .to_numpy()
        )

        df[f"attacks_prev_{seconds}s"] = (
            attack_series
            .rolling(window, closed="left")
            .sum()
            .to_numpy()
        )

    # Historical attack rate.
    for seconds in windows:
        flows_col = f"flows_prev_{seconds}s"
        attacks_col = f"attacks_prev_{seconds}s"

        df[f"attack_rate_prev_{seconds}s"] = (
            df[attacks_col] /
            df[flows_col].replace(0, pd.NA)
        ).fillna(0.0)

    df = df.drop(columns=["_is_attack"])

    return df
