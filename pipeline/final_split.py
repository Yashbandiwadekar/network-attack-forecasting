import numpy as np
from pathlib import Path

X = np.load(
    "data/processed/sequences/X.npy"
)

y = np.load(
    "data/processed/sequences/y.npy"
)

timestamps = np.load(
    "data/processed/sequences/timestamps.npy"
)

timestamps = timestamps.astype("datetime64[ns]")

print("=== ORIGINAL SEQUENCES ===")
print("X:", X.shape)
print("y:", y.shape)
print("timestamps:", timestamps.shape)

# ---------------------------------------------------------
# CHRONOLOGICAL BOUNDARIES
# ---------------------------------------------------------

train_end = np.datetime64(
    "2011-08-10T14:00:00"
)

val_end = np.datetime64(
    "2011-08-10T15:00:00"
)

# ---------------------------------------------------------
# MASKS
# ---------------------------------------------------------

train_mask = timestamps < train_end

val_mask = (
    (timestamps >= train_end)
    & (timestamps < val_end)
)

test_mask = timestamps >= val_end

X_train = X[train_mask]
y_train = y[train_mask]
t_train = timestamps[train_mask]

X_val = X[val_mask]
y_val = y[val_mask]
t_val = timestamps[val_mask]

X_test = X[test_mask]
y_test = y[test_mask]
t_test = timestamps[test_mask]

# ---------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------

print("\n=== FINAL CHRONOLOGICAL SPLIT ===")

for name, X_part, y_part, t_part in [
    ("TRAIN", X_train, y_train, t_train),
    ("VALIDATION", X_val, y_val, t_val),
    ("TEST", X_test, y_test, t_test),
]:

    print(f"\n{name}")

    print("X shape:", X_part.shape)
    print("y shape:", y_part.shape)

    print(
        "Class 0:",
        int((y_part == 0).sum())
    )

    print(
        "Class 1:",
        int((y_part == 1).sum())
    )

    if len(t_part) > 0:
        print(
            "Time:",
            t_part[0],
            "->",
            t_part[-1]
        )

# ---------------------------------------------------------
# SAVE
# ---------------------------------------------------------

OUTPUT_DIR = Path(
    "data/processed/final_splits"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

np.save(
    OUTPUT_DIR / "X_train.npy",
    X_train
)

np.save(
    OUTPUT_DIR / "y_train.npy",
    y_train
)

np.save(
    OUTPUT_DIR / "timestamps_train.npy",
    t_train
)

np.save(
    OUTPUT_DIR / "X_val.npy",
    X_val
)

np.save(
    OUTPUT_DIR / "y_val.npy",
    y_val
)

np.save(
    OUTPUT_DIR / "timestamps_val.npy",
    t_val
)

np.save(
    OUTPUT_DIR / "X_test.npy",
    X_test
)

np.save(
    OUTPUT_DIR / "y_test.npy",
    y_test
)

np.save(
    OUTPUT_DIR / "timestamps_test.npy",
    t_test
)

print("\n=== SAVED ===")
print(OUTPUT_DIR)
