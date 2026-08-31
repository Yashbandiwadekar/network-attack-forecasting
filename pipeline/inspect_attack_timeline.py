import pandas as pd

path = "data/processed/ctu13_10s_windows.csv"

df = pd.read_csv(path)
df["window_start"] = pd.to_datetime(df["window_start"])

df["is_attack_window"] = (
    df["attack_count"] > 0
).astype(int)

print("=== ATTACK TIMELINE ===")

groups = (
    df["is_attack_window"]
    .ne(df["is_attack_window"].shift())
    .cumsum()
)

periods = (
    df.groupby(groups)
    .agg(
        start=("window_start", "min"),
        end=("window_start", "max"),
        attack=("is_attack_window", "first"),
        windows=("window_start", "size"),
    )
    .reset_index(drop=True)
)

print(periods.to_string(index=False))

print("\n=== CLASS COUNTS BY HOUR ===")

df["hour"] = df["window_start"].dt.floor("1h")

hourly = (
    df.groupby("hour")
    .agg(
        windows=("window_start", "size"),
        attack_windows=("is_attack_window", "sum"),
    )
)

hourly["benign_windows"] = (
    hourly["windows"] -
    hourly["attack_windows"]
)

print(hourly.to_string())

print("\n=== FORECAST TARGET BY HOUR ===")

target_hourly = (
    df.groupby("hour")["forecast_attack_next_60s"]
    .agg(["count", "sum"])
)

target_hourly["no_attack"] = (
    target_hourly["count"] -
    target_hourly["sum"]
)

print(target_hourly.to_string())
