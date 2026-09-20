import numpy as np
from pathlib import Path

p = Path("data/processed/ctu13/_scenario_splits")

print("=== TRUE TIME RANGE BY SCENARIO ===")
print()

for scenario in sorted(
    p.glob("scenario_*"),
    key=lambda x: int(x.name.split("_")[1])
):
    all_times = []

    for split in ["train", "val", "test"]:
        with np.load(
            scenario / f"{split}.npz",
            allow_pickle=True
        ) as data:
            all_times.append(
                data["window_end_time"].astype(np.int64)
            )

    times = np.concatenate(all_times)

    print(
        f"{scenario.name:12} | "
        f"min={times.min()} | "
        f"max={times.max()} | "
        f"total={len(times):,}"
    )

print()
print("=== ATTACK TIME RANGE FROM ALL EXISTING SEQUENCES ===")
print()

for scenario in sorted(
    p.glob("scenario_*"),
    key=lambda x: int(x.name.split("_")[1])
):
    attack_times = []

    for split in ["train", "val", "test"]:
        with np.load(
            scenario / f"{split}.npz",
            allow_pickle=True
        ) as data:

            current = data["current_stage"]
            times = data["window_end_time"].astype(np.int64)

            mask = current > 0

            if mask.any():
                attack_times.append(times[mask])

    if attack_times:
        attack_times = np.concatenate(attack_times)

        print(
            f"{scenario.name:12} | "
            f"first_attack={attack_times.min()} | "
            f"last_attack={attack_times.max()} | "
            f"attack_sequences={len(attack_times):,}"
        )
    else:
        print(
            f"{scenario.name:12} | "
            f"NO CURRENT ATTACK SEQUENCES"
        )
