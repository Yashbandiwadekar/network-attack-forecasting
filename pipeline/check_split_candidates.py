import pandas as pd

path = "data/processed/ctu13_10s_windows.csv"

df = pd.read_csv(path)

df["window_start"] = pd.to_datetime(
    df["window_start"]
)

df["target"] = df[
    "forecast_attack_next_60s"
].astype(int)

# Candidate chronological boundaries
splits = [
    (
        "Candidate A",
        "2011-08-10 09:46:50",
        "2011-08-10 12:00:00",
        "2011-08-10 14:00:00",
        "2011-08-10 15:53:00",
    ),
    (
        "Candidate B",
        "2011-08-10 09:46:50",
        "2011-08-10 13:00:00",
        "2011-08-10 14:30:00",
        "2011-08-10 15:53:00",
    ),
]

for name, start, train_end, val_end, test_end in splits:

    start = pd.Timestamp(start)
    train_end = pd.Timestamp(train_end)
    val_end = pd.Timestamp(val_end)
    test_end = pd.Timestamp(test_end)

    train = df[
        (df["window_start"] >= start)
        & (df["window_start"] < train_end)
    ]

    val = df[
        (df["window_start"] >= train_end)
        & (df["window_start"] < val_end)
    ]

    test = df[
        (df["window_start"] >= val_end)
        & (df["window_start"] <= test_end)
    ]

    print("\n==============================")
    print(name)
    print("==============================")

    for label, data in [
        ("TRAIN", train),
        ("VALIDATION", val),
        ("TEST", test),
    ]:

        counts = data["target"].value_counts()

        print(f"\n{label}")
        print("Windows:", len(data))
        print("Class 0:", int(counts.get(0, 0)))
        print("Class 1:", int(counts.get(1, 0)))

        if len(data):
            print(
                "Range:",
                data["window_start"].min(),
                "->",
                data["window_start"].max(),
            )
