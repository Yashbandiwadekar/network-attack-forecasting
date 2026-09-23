"""Build a memory-safe windowed CTU-13 sequence dataset.

CTU-13 scenarios are split at the scenario level so that no scenario appears
in more than one of train/validation/test.

This is preferable here to splitting chronologically inside each scenario,
because CTU-13 attack activity is concentrated in particular periods. A
strict within-scenario chronological split can therefore produce a test set
containing almost no attack examples, making infiltration metrics meaningless.

The temporal order inside every individual scenario is preserved.
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import numpy as np

from common.config import feature_columns, load_config, resolve_path
from pipeline.adapters.ctu13 import load_ctu13_directory
from pipeline.adapters.ctu13_features import add_ctu13_features
from pipeline.graph_builder import build_window_graphs, load_window_graphs, save_window_graphs
from pipeline.graph_embedding_features import build_graph_embedding_window_features
from pipeline.graph_features import build_graph_window_features
from pipeline.windowing import (
    apply_reconnaissance_heuristic,
    build_flow_windows,
    build_sequences,
    merge_graph_embedding_features,
    merge_graph_features,
    merge_packet_features,
)


def process_scenario(
    scenario_id: int,
    config: dict,
    feature_cols: list[str],
    output_dir: Path,
) -> dict[str, int]:
    """Process one CTU-13 scenario and save its complete sequences."""

    scenario_path = f"data/raw/ctu13/{scenario_id}"

    print("\n" + "=" * 60)
    print(f"PROCESSING SCENARIO {scenario_id}")
    print("=" * 60)

    print("Loading flows...")
    df = load_ctu13_directory(scenario_path)

    print(f"Flows: {len(df):,}")

    print("Adding CTU-13 features...")
    df = add_ctu13_features(df)

    print("Building flow windows...")
    windows = build_flow_windows(df, config)

    print(f"Windows: {len(windows):,}")

    # ------------------------------------------------------------------ #
    # Graph features — CTU-13 always has real IPs, so all five graph      #
    # features carry genuine signal here (unlike most CIC-IDS-2018 days). #
    # ------------------------------------------------------------------ #

    print("Building graph features...")
    graph_windows = build_graph_window_features(df, config)
    windows = merge_graph_features(windows, graph_windows, config)

    print("Building graph embedding features...")
    window_graphs = build_window_graphs(df, config)
    embedding_windows = build_graph_embedding_window_features(df, config, graphs=window_graphs)
    windows = merge_graph_embedding_features(windows, embedding_windows, config)

    print("Adding packet features...")

    windows = merge_packet_features(
        windows,
        None,
        config,
    )

    windows = apply_reconnaissance_heuristic(
        windows,
        config,
    )

    print("\nStage distribution:")
    print(windows["stage"].value_counts())

    print("\nBuilding sequences...")

    sequences = build_sequences(
        windows,
        feature_cols,
        config,
    )

    n = len(sequences["X"])

    print(f"Sequences: {n:,}")

    if n == 0:
        print("WARNING: scenario produced no sequences.")
        return {
            "scenario_id": scenario_id,
            "sequences": 0,
        }

    scenario_dir = output_dir / f"scenario_{scenario_id}"
    scenario_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Persisted for joint GNN training (models/world_model_joint.py) -- see
    # pipeline/build_dataset.py's equivalent step for why.
    save_window_graphs(window_graphs, scenario_dir / "window_graphs.pkl")

    path = scenario_dir / "all.npz"

    np.savez(
        path,
        X=sequences["X"],
        next_state=sequences["next_state"],
        future_stages=sequences["future_stages"],
        infiltration=sequences["infiltration"],
        current_stage=sequences["current_stage"],
        current_infiltration=sequences["current_infiltration"],
        window_end_time=(
            sequences["window_end_time"]
            .astype("datetime64[ns]")
            .astype(np.int64)
        ),
        window_times=(
            sequences["window_times"]
            .astype("datetime64[ns]")
            .astype(np.int64)
        ),
        src_ip=sequences["src_ip"],
        scenario_id=sequences["scenario_id"],
    )

    print(f"Saved: {path}")

    infiltration = sequences["infiltration"][:, 0]

    print(
        f"  Positive sequences: "
        f"{int((infiltration > 0.5).sum()):,}"
    )

    print(
        f"  Negative sequences: "
        f"{int((infiltration <= 0.5).sum()):,}"
    )

    del sequences
    del windows
    del df

    return {
        "scenario_id": scenario_id,
        "sequences": n,
    }


def combine_scenarios(
    temporary_dir: Path,
    final_dir: Path,
    split_name: str,
    scenario_ids: list[int],
) -> int:
    """Combine complete scenario datasets into one split."""

    output_path = final_dir / f"{split_name}.npz"

    print("\n" + "-" * 60)
    print(f"BUILDING {split_name.upper()} SPLIT")
    print("-" * 60)

    arrays = {
        "X": [],
        "next_state": [],
        "future_stages": [],
        "infiltration": [],
        "current_stage": [],
        "current_infiltration": [],
        "window_end_time": [],
        "window_times": [],
        "src_ip": [],
        "scenario_id": [],
    }

    total = 0
    positives = 0

    for scenario_id in scenario_ids:
        path = (
            temporary_dir
            / f"scenario_{scenario_id}"
            / "all.npz"
        )

        if not path.exists():
            print(f"WARNING: missing {path}")
            continue

        print(f"Reading scenario {scenario_id}...")

        with np.load(
            path,
            allow_pickle=False,
        ) as data:

            for key in arrays:
                arrays[key].append(data[key])

            y = data["infiltration"][:, 0]

            total += len(y)
            positives += int((y > 0.5).sum())

    if total == 0:
        raise RuntimeError(
            f"No sequences found for split: {split_name}"
        )

    print(f"Sequences: {total:,}")
    print(f"Positive:  {positives:,}")
    print(
        f"Positive %: "
        f"{100.0 * positives / total:.4f}%"
    )

    np.savez(
        output_path,
        X=np.concatenate(arrays["X"], axis=0),
        next_state=np.concatenate(
            arrays["next_state"],
            axis=0,
        ),
        future_stages=np.concatenate(
            arrays["future_stages"],
            axis=0,
        ),
        infiltration=np.concatenate(
            arrays["infiltration"],
            axis=0,
        ),
        current_stage=np.concatenate(
            arrays["current_stage"],
            axis=0,
        ),
        current_infiltration=np.concatenate(
            arrays["current_infiltration"],
            axis=0,
        ),
        window_end_time=np.concatenate(
            arrays["window_end_time"],
            axis=0,
        ),
        window_times=np.concatenate(
            arrays["window_times"],
            axis=0,
        ),
        src_ip=np.concatenate(
            arrays["src_ip"],
            axis=0,
        ),
        scenario_id=np.concatenate(
            arrays["scenario_id"],
            axis=0,
        ),
    )

    print(f"Saved: {output_path}")

    del arrays

    return total


def main(
    config_path: str = "configs/default.yaml",
) -> None:

    config = load_config(config_path)

    # IMPORTANT:
    # config paths.processed_dir must be data/processed.
    processed_dir = resolve_path(
        config,
        "processed_dir",
    )

    ctu13_dir = processed_dir / "ctu13"

    temporary_dir = (
        ctu13_dir
        / "_scenario_sequences"
    )

    final_dir = (
        ctu13_dir
        / "splits"
    )

    if temporary_dir.exists():
        shutil.rmtree(temporary_dir)

    if final_dir.exists():
        shutil.rmtree(final_dir)

    temporary_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    final_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    feature_cols = feature_columns(config)

    print("=" * 60)
    print("CTU-13 SCENARIO-DISJOINT DATASET BUILD")
    print("=" * 60)

    print(
        f"Features: {len(feature_cols)}"
    )

    print(
        f"Sequence length: "
        f"{config['windowing']['sequence_length']}"
    )

    print(
        f"Forecast horizon: "
        f"{config['windowing']['forecast_horizon']}"
    )

    # ---------------------------------------------------------
    # CTU-13 scenario split
    #
    # 13 scenarios:
    #   Train: 1-9
    #   Validation: 10-11
    #   Test: 12-13
    #
    # The exact temporal order inside each scenario remains intact.
    # No scenario is shared between train/val/test.
    # ---------------------------------------------------------

    train_scenarios = list(range(1, 10))
    val_scenarios = [10, 11]
    test_scenarios = [12, 13]

    print("\nScenario split:")
    print(f"  Train: {train_scenarios}")
    print(f"  Val:   {val_scenarios}")
    print(f"  Test:  {test_scenarios}")

    scenario_info = {}

    for scenario_id in range(1, 14):

        info = process_scenario(
            scenario_id,
            config,
            feature_cols,
            temporary_dir,
        )

        scenario_info[str(scenario_id)] = info

    train_count = combine_scenarios(
        temporary_dir,
        final_dir,
        "train",
        train_scenarios,
    )

    val_count = combine_scenarios(
        temporary_dir,
        final_dir,
        "val",
        val_scenarios,
    )

    test_count = combine_scenarios(
        temporary_dir,
        final_dir,
        "test",
        test_scenarios,
    )

    totals = {
        "train": train_count,
        "val": val_count,
        "test": test_count,
    }

    # Merge the per-scenario window graphs into the single window_graphs.pkl joint GNN training
    # expects next to train/val/test.npz. Keys already carry scenario_id, so they can't collide.
    merged_graphs = {}
    for scenario_id in range(1, 14):
        path = temporary_dir / f"scenario_{scenario_id}" / "window_graphs.pkl"
        if path.exists():
            merged_graphs.update(load_window_graphs(path))
    save_window_graphs(merged_graphs, final_dir / "window_graphs.pkl")
    print(f"Merged {len(merged_graphs):,} window graphs -> {final_dir / 'window_graphs.pkl'}")
    del merged_graphs

    # ---------------------------------------------------------
    # Metadata
    # ---------------------------------------------------------

    metadata = {
        "dataset": "CTU-13",
        "feature_cols": feature_cols,
        "n_features": len(feature_cols),
        "window_seconds": config[
            "windowing"
        ]["window_seconds"],
        "sequence_length": config[
            "windowing"
        ]["sequence_length"],
        "forecast_horizon": config[
            "windowing"
        ]["forecast_horizon"],
        "stage_labels": config[
            "mitre_stages"
        ],

        "split_strategy": (
            "scenario-disjoint CTU-13 split; "
            "temporal order preserved within each scenario"
        ),

        "train_scenarios": train_scenarios,
        "val_scenarios": val_scenarios,
        "test_scenarios": test_scenarios,

        "scenario_count": 13,

        "sequence_counts": totals,

        "scenario_info": scenario_info,
    }

    with open(
        ctu13_dir / "metadata.json",
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            metadata,
            f,
            indent=2,
        )

    # ---------------------------------------------------------
    # Final report
    # ---------------------------------------------------------

    print("\n" + "=" * 60)
    print("CTU-13 DATASET BUILD COMPLETE")
    print("=" * 60)

    print(
        f"Train sequences: "
        f"{train_count:,}"
    )

    print(
        f"Validation sequences: "
        f"{val_count:,}"
    )

    print(
        f"Test sequences: "
        f"{test_count:,}"
    )

    print(
        f"\nOutput: {final_dir}"
    )

    print(
        f"Metadata: "
        f"{ctu13_dir / 'metadata.json'}"
    )

    print("\nScenario-disjoint split:")
    print(
        f"  Train scenarios: {train_scenarios}"
    )
    print(
        f"  Val scenarios:   {val_scenarios}"
    )
    print(
        f"  Test scenarios:  {test_scenarios}"
    )


if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--config",
        default="configs/default.yaml",
    )

    args = parser.parse_args()

    main(args.config)