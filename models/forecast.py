"""K-step forward simulation: the "world model" behaviour the problem statement asks for.

models/train.py only ever trains a single-step (t -> t+1) predictor. This module is what turns
that into a rollout: feed the current L-window history in, get back a predicted next state, drop
the oldest window and append the prediction, repeat K times. Each step also yields the
infiltration probability, predicted MITRE stage, and the attention pattern over the window that
produced it — so a caller gets a full K-step trajectory, not just a single score.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import torch

from models.dataset import FeatureScaler
from models.world_model import WorldModel


@dataclass
class ForecastResult:
    infiltration_probs: np.ndarray   # (K,) probability of attack at each future step
    stage_predictions: list[str]     # (K,) argmax MITRE stage per step
    stage_probs: np.ndarray          # (K, n_stage_classes) full distribution per step
    attentions: np.ndarray           # (K, L) attention the model paid to each input window per step


def load_world_model(checkpoint_path: str | Path, device: torch.device | None = None) -> tuple[WorldModel, dict[str, Any]]:
    device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
    checkpoint = torch.load(checkpoint_path, map_location=device, weights_only=False)
    model = WorldModel(checkpoint["n_features"], checkpoint["n_stage_classes"], checkpoint["config"])
    model.load_state_dict(checkpoint["model_state"])
    model.to(device).eval()
    return model, checkpoint["config"]


class ForecastEngine:
    def __init__(self, model: WorldModel, scaler: FeatureScaler, config: dict[str, Any]):
        self.model = model
        self.scaler = scaler
        self.config = config
        self.stage_labels = config["mitre_stages"]
        self.device = next(model.parameters()).device

    def rollout(self, raw_sequence: np.ndarray) -> ForecastResult:
        """raw_sequence: (L, n_features) unscaled, most recent L windows in chronological order."""
        horizon = self.config["windowing"]["forecast_horizon"]
        seq = self.scaler.transform(raw_sequence).astype(np.float32)
        seq_t = torch.tensor(seq, device=self.device).unsqueeze(0)  # (1, L, F)

        infiltration_probs, stage_predictions, stage_probs_list, attentions = [], [], [], []

        with torch.no_grad():
            for _ in range(horizon):
                next_state, stage_logits, infiltration_logit, attn = self.model(seq_t, return_attention=True)

                inf_prob = torch.sigmoid(infiltration_logit).item()
                stage_prob = torch.softmax(stage_logits, dim=-1).squeeze(0).cpu().numpy()

                infiltration_probs.append(inf_prob)
                stage_predictions.append(self.stage_labels[int(stage_prob.argmax())])
                stage_probs_list.append(stage_prob)
                attentions.append(attn.squeeze(0).cpu().numpy())

                seq_t = torch.cat([seq_t[:, 1:, :], next_state.unsqueeze(1)], dim=1)

        return ForecastResult(
            infiltration_probs=np.array(infiltration_probs),
            stage_predictions=stage_predictions,
            stage_probs=np.stack(stage_probs_list),
            attentions=np.stack(attentions),
        )


def latest_sequence(windows_df, feature_cols: list[str], src_ip: str, sequence_length: int) -> np.ndarray | None:
    """Pull the most recent `sequence_length` windows for one source IP out of a windows
    DataFrame (as produced by pipeline/windowing.py), ready for ForecastEngine.rollout. Returns
    None if that source IP doesn't have enough history yet."""
    group = windows_df[windows_df["src_ip"] == src_ip].sort_values("window_start")
    if len(group) < sequence_length:
        return None
    return group[feature_cols].to_numpy(dtype=np.float32)[-sequence_length:]
