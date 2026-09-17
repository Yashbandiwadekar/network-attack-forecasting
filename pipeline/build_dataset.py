from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np

from common.config import (
    load_config,
    resolve_path,
    feature_columns,
)

from pipeline.flow_features import load_flow_dir
from pipeline.graph_embedding_features import build_graph_embedding_window_features
from pipeline.graph_features import build_graph_window_features
from pipeline.windowing import (
    build_flow_windows,
    merge_graph_embedding_features,
    merge_graph_features,
    merge_packet_features,
    apply_reconnaissance_heuristic,
    build_sequences,
)


def chronological_split(
    sequences: dict[str, np.ndarray],
    split_config: dict[str, Any],
) -> dict[str, dict[str, np.ndarray]]:
    """
    Split sequences chronologically within each source IP.

    Each source gets its own train/validation/test split so that
    sources with different time ranges do not accidentally end up
    entirely in different splits.
    """

    src_ips = np.asarray(
        sequences["src_ip"]
    )

    train_frac = float(
        split_config["train_frac"]
    )

    val_frac = float(
        split_config["val_frac"]
    )

    if train_frac < 0 or val_frac < 0:
        raise ValueError(
            "Split fractions must be non-negative."
        )

    if train_frac + val_frac > 1:
        raise ValueError(
            "train_frac + val_frac must be <= 1."
        )

    # ---------------------------------------------------------
    # Group sequences by source IP
    # ---------------------------------------------------------

    groups: dict[str, list[int]] = {}

    for index, src_ip in enumerate(src_ips):
        groups.setdefault(
            str(src_ip),
            []
        ).append(index)

    split_indices = {
        "train": [],
        "val": [],
        "test": [],
    }

    # ---------------------------------------------------------
    # Split each source chronologically
    # ---------------------------------------------------------

    for indices in groups.values():

        indices = sorted(
            indices,
            key=lambda i:
                sequences["window_end_time"][i],
        )

        n = len(indices)

        # Very small groups cannot be meaningfully split.
        if n == 1:
            split_indices["train"].extend(
                indices
            )
            continue

        train_end = int(
            n * train_frac
        )

        val_end = (
            train_end
            + int(n * val_frac)
        )

        # Make sure training is not empty.
        if train_end == 0:
            train_end = 1

        train_end = min(
            train_end,
            n,
        )

        val_end = min(
            max(
                val_end,
                train_end,
            ),
            n,
        )

        split_indices["train"].extend(
            indices[:train_end]
        )

        split_indices["val"].extend(
            indices[
                train_end:val_end
            ]
        )

        split_indices["test"].extend(
            indices[val_end:]
        )

    # ---------------------------------------------------------
    # Create split dictionaries
    # ---------------------------------------------------------

    result = {}

    for split_name, indices in split_indices.items():

        indices = np.asarray(
            indices,
            dtype=np.int64,
        )

        # Keep each split chronologically ordered.
        if len(indices) > 0:

            indices = indices[
                np.argsort(
                    sequences[
                        "window_end_time"
                    ][indices],
                    kind="stable",
                )
            ]

        result[split_name] = {
            key: np.asarray(value)[indices]
            for key, value in sequences.items()
        }

    return result


def save_splits(
    splits: dict[str, dict[str, np.ndarray]],
    processed_dir: Path,
) -> None:
    """
    Save train/validation/test sequence tensors.
    """

    processed_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    for split_name, data in splits.items():

        output_file = (
            processed_dir
            / f"{split_name}.npz"
        )

        np.savez_compressed(
            output_file,
            **data,
        )

        print(
            f"Saved {split_name}: "
            f"{len(data['X'])} sequences"
        )


def build_dataset(config_path: str = "configs/default.yaml") -> dict[str, dict[str, np.ndarray]]:
    """
    Build the CIC-IDS-2018 sequence dataset.

    Flow CSVs are loaded from the directory configured by paths.raw_flow_dir in
    `config_path` — pass e.g. "configs/real_data.yaml" to build the real CIC-IDS-2018
    download instead of the default synthetic sample; both share this same script since
    they're the same CICFlowMeter-shaped data, just different sources (see
    configs/real_data.yaml's header comment).

    The pipeline performs:

        1. Load CIC-IDS-2018 flow CSVs
        2. Build time-windowed flow features
        3. Add packet-level placeholders when PCAP is unavailable
        4. Apply reconnaissance heuristic
        5. Build temporal sequences
        6. Perform chronological train/val/test split
        7. Save NPZ files and metadata
    """

    print(
        "=================================================="
    )
    print(
        " CIC-IDS-2018 DATASET BUILD"
    )
    print(
        "=================================================="
    )

    # ---------------------------------------------------------
    # Load configuration
    # ---------------------------------------------------------

    config = load_config(config_path)

    raw_flow_dir = resolve_path(
        config,
        "raw_flow_dir",
    )

    processed_dir = resolve_path(
        config,
        "processed_dir",
    )

    print(
        "\nConfiguration:"
    )

    print(
        "Raw flow directory:",
        raw_flow_dir,
    )

    print(
        "Processed directory:",
        processed_dir,
    )

    # ---------------------------------------------------------
    # STEP 1
    # ---------------------------------------------------------

    print(
        "\n=== STEP 1: Loading CIC-IDS-2018 flows ==="
    )

    print(
        "Input:",
        raw_flow_dir,
    )

    flow_df = load_flow_dir(
        raw_flow_dir
    )

    print(
        "Loaded rows:",
        len(flow_df),
    )

    print(
        "Loaded columns:",
        len(flow_df.columns),
    )

    # ---------------------------------------------------------
    # LABEL DISTRIBUTION
    # ---------------------------------------------------------

    print(
        "\n=== LABEL DISTRIBUTION ==="
    )

    print(
        flow_df["label"]
        .value_counts()
        .head(30)
    )

    # ---------------------------------------------------------
    # STEP 2
    # ---------------------------------------------------------

    print(
        "\n=== STEP 2: Building flow windows ==="
    )

    windows = build_flow_windows(
        flow_df,
        config,
    )

    print(
        "Flow windows:",
        len(windows),
    )

    # ---------------------------------------------------------
    # STEP 2b — Graph features
    #
    # Build the per-window host-interaction graph from the raw
    # flow DataFrame (not the already-aggregated windows) and
    # merge onto the windows DataFrame.
    #
    # CIC-IDS-2018: 9 of 10 days have no real IPs → graph
    # features are zero-filled via merge_graph_features().
    # The one day with real IPs contributes genuine signal.
    # ---------------------------------------------------------

    print(
        "\n=== STEP 2b: Building graph features ==="
    )

    graph_windows = build_graph_window_features(
        flow_df,
        config,
    )

    windows = merge_graph_features(
        windows,
        graph_windows,
        config,
    )

    print(
        "Graph features merged."
    )

    # ---------------------------------------------------------
    # STEP 2c — Learned graph-embedding features (GraphSAGE, frozen at
    # fixed random init -- see pipeline/graph_embedding_features.py
    # for the scope caveat on why it's not jointly trained yet).
    # ---------------------------------------------------------

    print(
        "\n=== STEP 2c: Building graph embedding features ==="
    )

    embedding_windows = build_graph_embedding_window_features(
        flow_df,
        config,
    )

    windows = merge_graph_embedding_features(
        windows,
        embedding_windows,
        config,
    )

    print(
        "Graph embedding features merged."
    )

    # ---------------------------------------------------------
    # STEP 3
    # ---------------------------------------------------------

    print(
        "\n=== STEP 3: Packet features ==="
    )

    # PCAP files are optional.
    #
    # We currently have CIC-IDS-2018 flow CSV data only,
    # so packet-level features are zero-filled.
    #
    # has_packet_features = 0 tells the model that packet
    # telemetry was not available.

    windows = merge_packet_features(
        windows,
        None,
        config,
    )

    print(
        "Packet features added as zero-filled."
    )

    print(
        "has_packet_features = 0"
    )

    # ---------------------------------------------------------
    # STEP 4
    # ---------------------------------------------------------

    print(
        "\n=== STEP 4: Reconnaissance heuristic ==="
    )

    windows = apply_reconnaissance_heuristic(
        windows,
        config,
    )

    print(
        "Reconnaissance heuristic applied."
    )

    # ---------------------------------------------------------
    # STAGE DISTRIBUTION
    # ---------------------------------------------------------

    print(
        "\n=== STAGE DISTRIBUTION ==="
    )

    print(
        windows["stage"]
        .value_counts()
    )

    # ---------------------------------------------------------
    # STEP 5
    # ---------------------------------------------------------

    print(
        "\n=== STEP 5: Building sequences ==="
    )

    # Use the project's single source of truth
    # for feature ordering.
    feature_cols = feature_columns(
        config
    )

    print(
        "Number of features:",
        len(feature_cols),
    )

    print(
        "Features:"
    )

    for i, feature in enumerate(
        feature_cols,
        1,
    ):
        print(
            f"{i:02d}. {feature}"
        )

    # ---------------------------------------------------------
    # Build sequences
    # ---------------------------------------------------------

    sequences = build_sequences(
        windows,
        feature_cols,
        config,
    )

    num_sequences = len(
        sequences["X"]
    )

    print(
        "\nSequences created:",
        num_sequences,
    )

    if num_sequences == 0:

        raise RuntimeError(
            "No sequences were created. "
            "Check the amount of data, "
            "sequence_length, "
            "forecast_horizon, "
            "and source grouping."
        )

    # ---------------------------------------------------------
    # Sequence shapes
    # ---------------------------------------------------------

    print(
        "X shape:",
        sequences["X"].shape,
    )

    print(
        "next_state shape:",
        sequences[
            "next_state"
        ].shape,
    )

    print(
        "future_stages shape:",
        sequences[
            "future_stages"
        ].shape,
    )

    print(
        "infiltration shape:",
        sequences[
            "infiltration"
        ].shape,
    )

    print(
        "current_stage shape:",
        sequences[
            "current_stage"
        ].shape,
    )

    # ---------------------------------------------------------
    # STEP 6
    # ---------------------------------------------------------

    print(
        "\n=== STEP 6: Chronological split ==="
    )

    splits = chronological_split(
        sequences,
        config["split"],
    )

    # ---------------------------------------------------------
    # Split sizes
    # ---------------------------------------------------------

    print(
        "\n=== SPLIT SIZES ==="
    )

    for split_name, data in splits.items():

        print(
            f"{split_name}: "
            f"{len(data['X'])} sequences"
        )

    # ---------------------------------------------------------
    # STEP 7
    # ---------------------------------------------------------

    print(
        "\n=== STEP 7: Saving processed dataset ==="
    )

    save_splits(
        splits,
        processed_dir,
    )

    # ---------------------------------------------------------
    # Metadata
    # ---------------------------------------------------------

    metadata = {
        "dataset": "CIC-IDS-2018",

        "source_directory": str(
            raw_flow_dir
        ),

        "feature_columns": feature_cols,

        "sequence_length": int(
            config["windowing"][
                "sequence_length"
            ]
        ),

        "forecast_horizon": int(
            config["windowing"][
                "forecast_horizon"
            ]
        ),

        "window_seconds": int(
            config["windowing"][
                "window_seconds"
            ]
        ),

        "flow_only": True,

        "packet_features_available": False,

        "num_windows": int(
            len(windows)
        ),

        "num_sequences": int(
            num_sequences
        ),

        "splits": {
            name: int(
                len(data["X"])
            )
            for name, data in splits.items()
        },
    }

    metadata_file = (
        processed_dir
        / "metadata.json"
    )

    with open(
        metadata_file,
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            metadata,
            f,
            indent=2,
        )

    print(
        "Saved:",
        metadata_file,
    )

    # ---------------------------------------------------------
    # FINAL SUMMARY
    # ---------------------------------------------------------

    print(
        "\n=================================================="
    )

    print(
        " DATASET BUILD COMPLETE"
    )

    print(
        "=================================================="
    )

    print(
        "\nProcessed directory:"
    )

    print(
        processed_dir
    )

    print(
        "\nGenerated files:"
    )

    print(
        "  train.npz"
    )

    print(
        "  val.npz"
    )

    print(
        "  test.npz"
    )

    print(
        "  metadata.json"
    )

    return splits


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/default.yaml")
    args = parser.parse_args()
    build_dataset(args.config)