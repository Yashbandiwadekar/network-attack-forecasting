import numpy as np
from pathlib import Path

p = Path("data/processed/ctu13/_scenario_splits")

print("=== ATTACK LOCATION BY SCENARIO ===")
print()

for scenario in sorted(
    p.glob("scenario_*"),
    key=lambda x: int(x.name.split("_")[1])
):
    print("=" * 70)
    print(scenario.name)

    for split in ["train", "val", "test"]:
        path = scenario / f"{split}.npz"

        with np.load(path, allow_pickle=False) as data:
            current = data["current_stage"]
            future = data["future_stages"]
            times = data["window_end_time"]

            attack_current = np.where(current > 0)[0]
            attack_future = np.where(future > 0)[0]

            print(f"\n{split.upper()}")
            print(f"  sequences: {len(current):,}")

            if len(attack_current):
                print(
                    f"  current attacks: {len(attack_current):,}"
                )
                print(
                    f"  first current attack index: "
                    f"{attack_current[0]:,}"
                )
                print(
                    f"  last current attack index: "
                    f"{attack_current[-1]:,}"
                )
                print(
                    f"  first attack time: "
                    f"{times[attack_current[0]]}"
                )
                print(
                    f"  last attack time: "
                    f"{times[attack_current[-1]]}"
                )
            else:
                print("  current attacks: 0")

            if len(attack_future):
                print(
                    f"  future attack windows: "
                    f"{len(attack_future):,}"
                )
            else:
                print("  future attack windows: 0")
