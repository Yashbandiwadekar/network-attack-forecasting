"""Train JointWorldModel: the world model's Transformer with a genuinely trainable GraphSAGE
encoder (Phase 4 of the GNN work -- see models/world_model_joint.py's docstring for the
architecture, models/graph_batch.py for why batching the per-step graph lookups is necessary).

Separate script from models/train.py rather than a third --arch option there, because the data
loading path is fundamentally different: models.dataset.SequenceDataset's tensors are batchable
by a plain DataLoader, but the raw pipeline.graph_builder.WindowGraph objects backing every
(sample, step) pair are not tensors at all -- looking them up needs window_times/src_ip/
scenario_id (SequenceDataset's non-tensor whole-dataset arrays) plus the on-disk window graph
dict pipeline/build_dataset.py now persists (window_graphs.pkl). A custom index-based batch
iterator replaces the DataLoader here for that reason, not because anything about the loss or
optimization differs from models/train.py's own loop.

Loss is intentionally identical to models/train.py::_step_loss (same three terms: next-state MSE,
masked stage cross-entropy, infiltration BCE) -- the only difference this script is testing is
whether a trainable graph encoder changes the result, not a different training objective.

Usage:
    python -m models.train_joint --config configs/real_data.yaml
"""
from __future__ import annotations

import argparse

import numpy as np
import torch
import torch.nn as nn
from tqdm import tqdm

from common.config import feature_columns, load_config, resolve_path
from models.dataset import FeatureScaler, SequenceDataset, load_split
from models.graph_encoder import GraphSAGEEncoder
from models.world_model_joint import JointWorldModel
from pipeline.graph_builder import EDGE_FEATURE_COLS, WindowGraph, load_window_graphs, window_graph_key
from pipeline.graph_embedding_features import EMBED_DIM, GRAPH_EMBEDDING_FEATURE_NAMES

_EMPTY_GRAPH = WindowGraph(
    window_key=None, node_ids=[], node_index={},
    edge_index=np.zeros((2, 0), dtype=np.int64), edge_attr=np.zeros((0, len(EDGE_FEATURE_COLS)), dtype=np.float32),
)


def _device(config: dict) -> torch.device:
    want_cuda = config["model"]["device"] == "cuda"
    return torch.device("cuda" if want_cuda and torch.cuda.is_available() else "cpu")


def _base_feature_mask(config: dict) -> np.ndarray:
    """Boolean mask over feature_columns(config), True for every column EXCEPT the frozen
    `graph_embed_*` block Phase 3 precomputes -- JointWorldModel replaces those with a live
    computation instead of consuming them as static input."""
    cols = feature_columns(config)
    embed_set = set(GRAPH_EMBEDDING_FEATURE_NAMES)
    return np.array([c not in embed_set for c in cols], dtype=bool)


def _load_datasets(config: dict) -> tuple[SequenceDataset, SequenceDataset, SequenceDataset]:
    processed_dir = resolve_path(config, "processed_dir")
    scaler = FeatureScaler.load(processed_dir / "scaler.npz")
    return (
        SequenceDataset(load_split(processed_dir, "train"), scaler),
        SequenceDataset(load_split(processed_dir, "val"), scaler),
        SequenceDataset(load_split(processed_dir, "test"), scaler),
    )


def _build_graph_items(
    ds: SequenceDataset, indices: torch.Tensor, graphs: dict,
) -> list[tuple[WindowGraph, str]]:
    """Flat, row-major (sample, step) list matching JointWorldModel.forward's expected order --
    see that method's docstring. Falls back to an empty graph (zero embedding, per
    models/graph_batch.py's missing-host handling) if a window key is somehow absent from
    `graphs` -- defensive, since window_graphs.pkl is built from the SAME flow_df build_sequences
    windowed, so every key should exist; a mismatch would indicate a build_dataset.py bug, not an
    expected runtime case, hence falling back rather than crashing mid-training-run.
    """
    if ds.window_times is None:
        raise RuntimeError(
            "This dataset has no window_times field -- rebuild it with the current "
            "pipeline/build_dataset.py (joint training needs the schema added in commit 315921c).",
        )
    seq_len = ds.window_times.shape[1]
    items: list[tuple[WindowGraph, str]] = []
    for i in indices.tolist():
        host = str(ds.src_ip[i])
        # .item() keeps the native type (CTU-13 scenario ids are ints) -- stringifying it would
        # never match the (scenario_id, Timestamp) keys build_window_graphs produced.
        scenario_id = ds.scenario_id[i].item() if ds.scenario_id is not None else None
        for t in range(seq_len):
            key = window_graph_key(ds.window_times[i, t], scenario_id=scenario_id)
            items.append((graphs.get(key, _EMPTY_GRAPH), host))
    return items


def _step_loss(
    model: JointWorldModel, ds: SequenceDataset, indices: torch.Tensor, graphs: dict,
    base_mask: np.ndarray, device: torch.device,
) -> torch.Tensor:
    X = ds.X[indices][:, :, base_mask].to(device)
    next_state = ds.next_state[indices][:, base_mask].to(device)
    future_stages = ds.future_stages[indices].to(device)
    infiltration = ds.infiltration[indices].to(device)

    items = _build_graph_items(ds, indices, graphs)
    pred_next_state, stage_logits, infiltration_logit = model(X, items)

    # The Transformer's next-state head predicts its full input width (base + live embedding), but
    # the learned embedding part has no ground-truth target -- supervise only the base slice.
    mse = nn.functional.mse_loss(pred_next_state[:, :next_state.shape[1]], next_state)

    stage_target = future_stages[:, 0]
    mask = stage_target != -1
    ce = (nn.functional.cross_entropy(stage_logits[mask], stage_target[mask])
          if mask.any() else torch.tensor(0.0, device=device))

    bce = nn.functional.binary_cross_entropy_with_logits(infiltration_logit, infiltration[:, 0])
    return mse + ce + bce


def _iterate_batches(n: int, batch_size: int, shuffle: bool) -> list[torch.Tensor]:
    idx = torch.randperm(n) if shuffle else torch.arange(n)
    return [idx[start:start + batch_size] for start in range(0, n, batch_size)]


def train(config_path: str = "configs/real_data.yaml") -> None:
    config = load_config(config_path)
    device = _device(config)
    print(f"Training on device: {device} (arch: transformer_joint_gnn)")

    processed_dir = resolve_path(config, "processed_dir")
    graphs_path = processed_dir / "window_graphs.pkl"
    if not graphs_path.exists():
        raise FileNotFoundError(
            f"{graphs_path} not found -- rebuild the dataset with the current "
            "pipeline/build_dataset.py (or build_ctu13_dataset.py) first.",
        )
    print(f"Loading window graphs from {graphs_path} ...")
    graphs = load_window_graphs(graphs_path)
    print(f"  {len(graphs):,} window graphs loaded.")

    train_ds, val_ds, _ = _load_datasets(config)
    base_mask = _base_feature_mask(config)
    n_base_features = int(base_mask.sum())
    n_stage_classes = len(config["mitre_stages"])
    edge_dim = len(EDGE_FEATURE_COLS)

    model = JointWorldModel(
        n_base_features, n_stage_classes, config, edge_dim=edge_dim, embed_dim=EMBED_DIM,
    ).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=config["model"]["lr"])

    checkpoint_dir = resolve_path(config, "checkpoint_dir")
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    best_val_loss = float("inf")
    batch_size = config["model"]["batch_size"]

    for epoch in range(config["model"]["epochs"]):
        model.train()
        train_losses = []
        batches = _iterate_batches(len(train_ds), batch_size, shuffle=True)
        for indices in tqdm(batches, desc=f"epoch {epoch + 1}", leave=False):
            optimizer.zero_grad()
            loss = _step_loss(model, train_ds, indices, graphs, base_mask, device)
            loss.backward()
            optimizer.step()
            train_losses.append(loss.item())

        model.eval()
        val_losses = []
        with torch.no_grad():
            for indices in _iterate_batches(len(val_ds), batch_size, shuffle=False):
                val_losses.append(_step_loss(model, val_ds, indices, graphs, base_mask, device).item())

        train_loss = sum(train_losses) / len(train_losses)
        val_loss = sum(val_losses) / len(val_losses) if val_losses else float("nan")
        print(f"epoch {epoch + 1}/{config['model']['epochs']}  train_loss={train_loss:.4f}  val_loss={val_loss:.4f}")

        checkpoint = {
            "model_state": model.state_dict(),
            "n_base_features": n_base_features,
            "n_stage_classes": n_stage_classes,
            "edge_dim": edge_dim,
            "embed_dim": EMBED_DIM,
            "base_mask": base_mask,
            "config": config,
        }
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            torch.save(checkpoint, checkpoint_dir / "joint_gnn_world_model_best.pt")

    torch.save(checkpoint, checkpoint_dir / "joint_gnn_world_model_final.pt")
    print(f"Best val loss: {best_val_loss:.4f}. Checkpoints saved to {checkpoint_dir}")


def load_joint_world_model(
    checkpoint_path: str, device: torch.device | None = None,
) -> tuple[JointWorldModel, dict]:
    device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
    checkpoint = torch.load(checkpoint_path, map_location=device, weights_only=False)
    model = JointWorldModel(
        checkpoint["n_base_features"], checkpoint["n_stage_classes"], checkpoint["config"],
        edge_dim=checkpoint["edge_dim"], embed_dim=checkpoint["embed_dim"],
    )
    model.load_state_dict(checkpoint["model_state"])
    model.to(device).eval()
    return model, checkpoint["config"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/real_data.yaml")
    args = parser.parse_args()
    train(args.config)
