import numpy as np
from pathlib import Path

X_PATH = Path("data/processed/sequences/X.npy")
Y_PATH = Path("data/processed/sequences/y.npy")
T_PATH = Path("data/processed/sequences/timestamps.npy")

X = np.load(X_PATH)
y = np.load(Y_PATH)
timestamps = np.load(T_PATH)

print("=== SEQUENCE DATASET CHECK ===")
print("X shape:", X.shape)
print("y shape:", y.shape)
print("timestamps shape:", timestamps.shape)

print("\n=== TARGET DISTRIBUTION ===")
print("0:", int((y == 0).sum()))
print("1:", int((y == 1).sum()))

# ---------------------------------------------------------
# CHRONOLOGICAL SPLIT
# ---------------------------------------------------------

n = len(X)

train_end = int(n * 0.70)
val_end = int(n * 0.85)

X_train = X[:train_end]
y_train = y[:train_end]
t_train = timestamps[:train_end]

X_val = X[train_end:val_end]
y_val = y[train_end:val_end]
t_val = timestamps[train_end:val_end]

X_test = X[val_end:]
y_test = y[val_end:]
t_test = timestamps[val_end:]

print("\n=== CHRONOLOGICAL SPLIT ===")

print("Train:")
print("  X:", X_train.shape)
print("  y:", y_train.shape)

print("Validation:")
print("  X:", X_val.shape)
print("  y:", y_val.shape)

print("Test:")
print("  X:", X_test.shape)
print("  y:", y_test.shape)

print("\n=== TARGET DISTRIBUTION ===")

print("Train:")
print("  0:", int((y_train == 0).sum()))
print("  1:", int((y_train == 1).sum()))

print("Validation:")
print("  0:", int((y_val == 0).sum()))
print("  1:", int((y_val == 1).sum()))

print("Test:")
print("  0:", int((y_test == 0).sum()))
print("  1:", int((y_test == 1).sum()))

print("\n=== TIME RANGES ===")

print(
    "Train:",
    t_train[0],
    "->",
    t_train[-1],
)

print(
    "Validation:",
    t_val[0],
    "->",
    t_val[-1],
)

print(
    "Test:",
    t_test[0],
    "->",
    t_test[-1],
)

# ---------------------------------------------------------
# SAVE SPLITS
# ---------------------------------------------------------

OUTPUT_DIR = Path("data/processed/splits")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

np.save(OUTPUT_DIR / "X_train.npy", X_train)
np.save(OUTPUT_DIR / "y_train.npy", y_train)
np.save(OUTPUT_DIR / "timestamps_train.npy", t_train)

np.save(OUTPUT_DIR / "X_val.npy", X_val)
np.save(OUTPUT_DIR / "y_val.npy", y_val)
np.save(OUTPUT_DIR / "timestamps_val.npy", t_val)

np.save(OUTPUT_DIR / "X_test.npy", X_test)
np.save(OUTPUT_DIR / "y_test.npy", y_test)
np.save(OUTPUT_DIR / "timestamps_test.npy", t_test)

print("\n=== SAVED ===")
print(OUTPUT_DIR)
