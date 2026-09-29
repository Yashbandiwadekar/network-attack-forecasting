"""Train the world model on the windowed sequences produced by pipeline/build_dataset.py.

Multi-task loss, all on the immediate next step (t+1):
  - MSE on the predicted next state vector          (the actual world-model dynamics objective)
  - cross-entropy on the predicted MITRE stage       (masked where the target is `impact`, see
                                                       pipeline/mitre_mapping.py)
  - BCE on the predicted infiltration probability

K-step forecasting is evaluated separately in eval/benchmark.py via models/forecast.py's
autoregressive rollout — this script only trains the single-step model those rollouts are built from.

Usage:
    python -m models.train --config configs/default.yaml
"""
from __future__ import annotations

import argparse

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from tqdm import tqdm

from common.config import feature_columns, load_config, resolve_path
from models.checkpoint_io import with_config_json
from models.dataset import build_datasets
from models.lstm_model import LSTMWorldModel
from models.world_model import WorldModel

ARCH_CHECKPOINT_STEM = {"transformer": "world_model", "lstm": "lstm_baseline"}


def _device(config: dict) -> torch.device:
    want_cuda = config["model"]["device"] == "cuda"
    return torch.device("cuda" if want_cuda and torch.cuda.is_available() else "cpu")


def _build_model(arch: str, n_features: int, n_stage_classes: int, config: dict) -> nn.Module:
    if arch == "lstm":
        return LSTMWorldModel(n_features, n_stage_classes, config)
    return WorldModel(n_features, n_stage_classes, config)


def _step_loss(model: nn.Module, batch, device: torch.device) -> tuple[torch.Tensor, dict[str, float]]:
    non_blocking = device.type == "cuda"
    X, next_state, future_stages, infiltration = [t.to(device, non_blocking=non_blocking) for t in batch]
    pred_next_state, stage_logits, infiltration_logit = model(X)

    mse = nn.functional.mse_loss(pred_next_state, next_state)

    stage_target = future_stages[:, 0]
    mask = stage_target != -1
    if mask.any():
        ce = nn.functional.cross_entropy(stage_logits[mask], stage_target[mask])
    else:
        ce = torch.tensor(0.0, device=device)

    bce = nn.functional.binary_cross_entropy_with_logits(infiltration_logit, infiltration[:, 0])

    total = mse + ce + bce
    return total, {"mse": mse.item(), "ce": ce.item(), "bce": bce.item(), "total": total.item()}


def train(config_path: str = "configs/default.yaml", arch: str = "transformer", seed: int | None = None) -> None:
    config = load_config(config_path)
    device = _device(config)
    print(f"Training on device: {device} (arch: {arch})")
    if seed is not None:
        # Optional, opt-in (audit E10). Seeded BEFORE the model is built and the DataLoader created, so both
        # weight init and shuffling are reproducible. Omitting --seed leaves the original unseeded behaviour.
        torch.manual_seed(seed)
        np.random.seed(seed)

    train_ds, val_ds, _, scaler = build_datasets(config)
    n_features = train_ds.X.shape[-1]
    n_stage_classes = len(config["mitre_stages"])
    # Audit W19: saved alongside n_features so a loader can check COLUMN IDENTITY, not just count
    # -- see models/checkpoint_io.py::validate_feature_names. None for configs with no `features`
    # section (the minimal test configs), same fallback ForecastEngine already uses.
    try:
        feature_names = feature_columns(config)
    except KeyError:
        feature_names = None

    # pin_memory + non_blocking .to() (in _step_loss) overlap the host->device copy with the
    # previous step's GPU compute instead of stalling on it -- num_workers is deliberately left at
    # its default of 0: SequenceDataset already holds everything as in-memory tensors, so
    # __getitem__ is pure indexing with no I/O for worker processes to parallelize, and spawning
    # them would only add IPC overhead. See models/dataset.py::SequenceDataset.
    pin_memory = device.type == "cuda"
    train_loader = DataLoader(train_ds, batch_size=config["model"]["batch_size"], shuffle=True,
                               pin_memory=pin_memory)
    val_loader = DataLoader(val_ds, batch_size=config["model"]["batch_size"], shuffle=False,
                             pin_memory=pin_memory)

    model = _build_model(arch, n_features, n_stage_classes, config).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=config["model"]["lr"])

    checkpoint_dir = resolve_path(config, "checkpoint_dir")
    if seed is not None:
        checkpoint_dir = checkpoint_dir / f"seed{seed}"  # each seed keeps its own checkpoints
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_stem = ARCH_CHECKPOINT_STEM[arch]
    best_val_loss = float("inf")

    for epoch in range(config["model"]["epochs"]):
        model.train()
        train_losses = []
        for batch in tqdm(train_loader, desc=f"epoch {epoch + 1}", leave=False):
            optimizer.zero_grad()
            loss, _ = _step_loss(model, batch, device)
            loss.backward()
            optimizer.step()
            train_losses.append(loss.item())

        model.eval()
        val_losses = []
        with torch.no_grad():
            for batch in val_loader:
                loss, _ = _step_loss(model, batch, device)
                val_losses.append(loss.item())

        train_loss = sum(train_losses) / len(train_losses)
        val_loss = sum(val_losses) / len(val_losses) if val_losses else float("nan")
        print(f"epoch {epoch + 1}/{config['model']['epochs']}  train_loss={train_loss:.4f}  val_loss={val_loss:.4f}")

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            torch.save(with_config_json({
                "model_state": model.state_dict(),
                "n_features": n_features,
                "n_stage_classes": n_stage_classes,
                "feature_names": feature_names,
                "config": config,
            }), checkpoint_dir / f"{checkpoint_stem}_best.pt")

    torch.save(with_config_json({
        "model_state": model.state_dict(),
        "n_features": n_features,
        "n_stage_classes": n_stage_classes,
        "feature_names": feature_names,
        "config": config,
    }), checkpoint_dir / f"{checkpoint_stem}_final.pt")
    print(f"Best val loss: {best_val_loss:.4f}. Checkpoints saved to {checkpoint_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--arch", default="transformer", choices=["transformer", "lstm"],
                         help="Sequence encoder to train: the world model's Transformer (default) "
                              "or the LSTM baseline (see docs/05-related-work-and-competitive-landscape.md).")
    parser.add_argument("--seed", type=int, default=None,
                        help="Seed the RNGs and save checkpoints under checkpoint_dir/seed<N> (audit E10). Default: unseeded, as before.")
    args = parser.parse_args()
    train(args.config, args.arch, args.seed)
