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
    transition_magnitude: np.ndarray  # (K,) scaled-feature L2 norm of each predicted state jump —
    #  how much the model believes conditions are about to shift. NOT a ground-truth reconstruction
    #  error: during a live K-step forecast there is no observed future to compare against yet, so
    #  this measures the size of the model's own predicted transition, not its accuracy. For a
    #  genuine (ground-truth) anomaly signal on already-observed traffic, see one_step_reconstruction_error().
    state_deltas: np.ndarray          # (K, F) predicted feature deltas per step, in raw (unscaled) units


@dataclass
class UncertaintyForecastResult:
    """MC-dropout estimate of forecast uncertainty: `n_samples` stochastic rollouts with dropout
    left active, summarized as a 10th/50th/90th percentile band per step. `ForecastEngine.rollout`
    (dropout off, deterministic) stays the primary path for training/benchmark reproducibility —
    this is for the demo's uncertainty band only.
    """
    infiltration_p10: np.ndarray  # (K,)
    infiltration_p50: np.ndarray  # (K,)
    infiltration_p90: np.ndarray  # (K,)
    stage_predictions: list[str]  # (K,) argmax of the mean stage distribution across samples


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
        """raw_sequence: (L, n_features) unscaled, most recent L windows in chronological order.
        Deterministic (dropout follows whatever mode the model is already in — eval by default
        after load_world_model) — this is the primary path used for training/benchmark
        reproducibility. For an uncertainty band, use rollout_with_uncertainty instead.

        Every call is a pure function of `raw_sequence`: no ground-truth future is ever read, by
        construction (the method signature has no such parameter) — calling this twice with the
        same input is guaranteed to produce the same trajectory, see
        tests/test_forecast_rollout.py::test_rollout_is_deterministic_in_eval_mode.
        """
        horizon = self.config["windowing"]["forecast_horizon"]
        seq = self.scaler.transform(raw_sequence).astype(np.float32)
        seq_t = torch.tensor(seq, device=self.device).unsqueeze(0)  # (1, L, F)

        infiltration_probs, stage_predictions, stage_probs_list = [], [], []
        attentions, transition_magnitude, state_deltas = [], [], []

        with torch.no_grad():
            for _ in range(horizon):
                next_state, stage_logits, infiltration_logit, attn = self.model(seq_t, return_attention=True)

                inf_prob = torch.sigmoid(infiltration_logit).item()
                stage_prob = torch.softmax(stage_logits, dim=-1).squeeze(0).cpu().numpy()

                last_scaled = seq_t[:, -1, :]
                jump = torch.linalg.norm(next_state - last_scaled).item()
                delta_raw = self.scaler.inverse_transform(next_state.squeeze(0).cpu().numpy()) - \
                    self.scaler.inverse_transform(last_scaled.squeeze(0).cpu().numpy())

                infiltration_probs.append(inf_prob)
                stage_predictions.append(self.stage_labels[int(stage_prob.argmax())])
                stage_probs_list.append(stage_prob)
                attentions.append(attn.squeeze(0).cpu().numpy())
                transition_magnitude.append(jump)
                state_deltas.append(delta_raw)

                seq_t = torch.cat([seq_t[:, 1:, :], next_state.unsqueeze(1)], dim=1)

        return ForecastResult(
            infiltration_probs=np.array(infiltration_probs),
            stage_predictions=stage_predictions,
            stage_probs=np.stack(stage_probs_list),
            attentions=np.stack(attentions),
            transition_magnitude=np.array(transition_magnitude),
            state_deltas=np.stack(state_deltas),
        )

    def rollout_with_uncertainty(self, raw_sequence: np.ndarray, n_samples: int = 20) -> UncertaintyForecastResult:
        """MC-dropout: re-run `rollout` `n_samples` times with dropout forced on, and summarize
        the spread. Restores whatever train/eval mode the model was in before returning."""
        was_training = self.model.training
        self.model.train()
        try:
            infiltration_samples = []
            stage_prob_samples = []
            for _ in range(n_samples):
                result = self.rollout(raw_sequence)
                infiltration_samples.append(result.infiltration_probs)
                stage_prob_samples.append(result.stage_probs)
        finally:
            self.model.train(was_training)

        infiltration_samples = np.stack(infiltration_samples)  # (n_samples, K)
        p10, p50, p90 = np.percentile(infiltration_samples, [10, 50, 90], axis=0)

        mean_stage_probs = np.stack(stage_prob_samples).mean(axis=0)  # (K, n_stage_classes)
        stage_predictions = [self.stage_labels[int(p.argmax())] for p in mean_stage_probs]

        return UncertaintyForecastResult(
            infiltration_p10=p10, infiltration_p50=p50, infiltration_p90=p90,
            stage_predictions=stage_predictions,
        )


def one_step_reconstruction_error(
    model: WorldModel, scaler: FeatureScaler, prior_sequence: np.ndarray, actual_next_state: np.ndarray
) -> float:
    """Genuine (ground-truth) unsupervised anomaly signal, distinct from ForecastResult's
    transition_magnitude: how far the model's next-state prediction from `prior_sequence` (the L
    real windows before the window being checked) is from what `actual_next_state` really was.
    Useful for flagging traffic whose actual behaviour didn't match learned dynamics at all,
    independent of the supervised infiltration/stage labels — apply it to the most recent fully
    observed transition, not to an imagined future step (which has no ground truth to check against).
    """
    device = next(model.parameters()).device
    scaled_prior = scaler.transform(prior_sequence).astype(np.float32)
    scaled_actual = scaler.transform(actual_next_state[None, :]).astype(np.float32)[0]

    with torch.no_grad():
        x = torch.tensor(scaled_prior, device=device).unsqueeze(0)
        predicted_next, _, _ = model(x)

    return float(np.linalg.norm(predicted_next.squeeze(0).cpu().numpy() - scaled_actual))


def latest_sequence(windows_df, feature_cols: list[str], src_ip: str, sequence_length: int) -> np.ndarray | None:
    """Pull the most recent `sequence_length` windows for one source IP out of a windows
    DataFrame (as produced by pipeline/windowing.py), ready for ForecastEngine.rollout. Returns
    None if that source IP doesn't have enough history yet."""
    group = windows_df[windows_df["src_ip"] == src_ip].sort_values("window_start")
    if len(group) < sequence_length:
        return None
    return group[feature_cols].to_numpy(dtype=np.float32)[-sequence_length:]


def previous_sequence_and_actual(
    windows_df, feature_cols: list[str], src_ip: str, sequence_length: int
) -> tuple[np.ndarray, np.ndarray] | None:
    """The (L windows, actual next window) pair one step further back than latest_sequence — the
    L windows before the most recent one, and the most recent one itself as ground truth. Feeds
    one_step_reconstruction_error. Returns None without at least sequence_length + 1 windows."""
    group = windows_df[windows_df["src_ip"] == src_ip].sort_values("window_start")
    if len(group) < sequence_length + 1:
        return None
    values = group[feature_cols].to_numpy(dtype=np.float32)
    return values[-sequence_length - 1:-1], values[-1]
