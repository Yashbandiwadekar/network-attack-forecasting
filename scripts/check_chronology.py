import numpy as np
from pathlib import Path

p = Path("data/processed/ctu13/_scenario_splits")

print("=== CHRONOLOGICAL ORDER CHECK ===")
print()

for scenario in sorted(
    p.glob("scenario_*"),
    key=lambda x: int(x.name.split("_")[1])
):
    print(f"{scenario.name}")

    for split in ["train", "val", "test"]:
        path = scenario / f"{split}.npz"

        with np.load(path, allow_pickle=False) as data:
            times = data["window_end_time"].astype(np.int64)

            if len(times) <= 1:
                ordered = True
            else:
                ordered = bool(np.all(times[1:] >= times[:-1]))

            print(
                f"  {split:5} | "
                f"ordered={ordered} | "
                f"first={times[0]} | "
                f"last={times[-1]}"
            )

    print()
