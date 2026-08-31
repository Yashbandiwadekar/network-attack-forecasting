from pathlib import Path

path = Path("pipeline/windowing.py")
text = path.read_text()

old = '''    if "scenario_id" in windows_df.columns:
        result["scenario_id"] = np.concatenate(
            scenario_id_parts,
            axis=0,
        )

    return result
'''

new = '''    if "scenario_id" in windows_df.columns:
        result["scenario_id"] = np.concatenate(
            scenario_id_parts,
            axis=0,
        )

    # --------------------------------------------------------------
    # IMPORTANT:
    # Sequences are created group-by-group (scenario_id, src_ip).
    # Therefore concatenation order is NOT chronological.
    # Sort every sequence-related array using the same timestamp
    # order before the dataset is split into train/val/test.
    # --------------------------------------------------------------

    order = np.argsort(
        result["window_end_time"],
        kind="stable",
    )

    for key in result:
        result[key] = result[key][order]

    return result
'''

if old not in text:
    raise SystemExit("Target block was not found. No changes made.")

path.write_text(text.replace(old, new))

print("SUCCESS: chronological sequence sorting added to build_sequences().")
