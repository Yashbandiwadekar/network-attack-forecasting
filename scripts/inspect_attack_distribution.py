import numpy as np
from pathlib import Path

p = Path("data/processed/ctu13/_scenario_splits")

print("=== ATTACK DISTRIBUTION BY SCENARIO ===")
print(
    "Scenario | Split | Total | Non-benign current | "
    "Non-benign future | Infiltration"
)
print("-" * 90)

scenarios = sorted(
    p.glob("scenario_*"),
    key=lambda x: int(x.name.split("_")[1])
)

for scenario in scenarios:
    for split in ["train", "val", "test"]:

        path = scenario / f"{split}.npz"

        with np.load(path, allow_pickle=False) as data:

            current = data["current_stage"]
            future = data["future_stages"]
            infiltration = data["infiltration"]

            print(
                f"{scenario.name:10} | "
                f"{split:5} | "
                f"{len(current):7,} | "
                f"{int((current > 0).sum()):19,} | "
                f"{int((future > 0).sum()):18,} | "
                f"{int((infiltration > 0).sum()):11,}"
            )
