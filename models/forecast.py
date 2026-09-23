"""K-step forward simulation: the "world model" behaviour the problem statement asks for.

models/train.py only ever trains a single-step (t -> t+1) predictor. This module is what turns
that into a rollout: feed the current L-window history in, get back a predicted next state, drop
the oldest window and append the prediction, repeat K times. Each step also yields the
infiltration probability, predicted MITRE stage, and the attention pattern over the window that
produced it — so a caller gets a full K-step trajectory, not just a single score.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import torch

from common.config import feature_columns
from models.dataset import FeatureScaler
from models.world_model import WorldModel
from pipeline.mitre_mapping import IMPACT, RECONNAISSANCE


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
    stage_is_heuristic: list[bool] = field(default_factory=list)  # (K,) see _heuristic_stage_override


@dataclass
class BatchForecastResult:
    """Same K-step rollout as ForecastResult, computed for many hosts at once via batched tensor
    ops instead of a Python loop calling ForecastEngine.rollout per host. Built for the alert
    dashboard, which needs a peak infiltration score for every monitored host (thousands on real
    data) fast enough to feel live — one batched forward pass per K step regardless of host count,
    instead of host_count x K individual ones. No attention/SHAP here (those stay per-host,
    computed lazily only for whichever host an analyst drills into) — just the score used to
    decide which hosts are even worth drilling into.
    """
    host_ids: list[str]
    infiltration_probs: np.ndarray   # (N, K)
    stage_predictions: list[list[str]]  # (N, K)
    stage_is_heuristic: list[list[bool]] = field(default_factory=list)  # (N, K)


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


def _heuristic_stage_override(
    raw_features: np.ndarray,
    feature_index: dict[str, int],
    scaler: FeatureScaler,
    config: dict[str, Any],
    predicted_stage: str,
) -> tuple[str, bool]:
    """Audit S6/S7: the trained stage classifier has never seen a single real Reconnaissance
    example (no CIC-IDS-2018 label maps to it) and every DoS/DDoS ("impact") window is masked out
    of the stage classification loss entirely (see pipeline/mitre_mapping.py, docs/03-mitre-mapping.md).
    Its raw softmax over the 6 trained classes therefore has no informed answer for either case —
    measured on real data, DoS/DDoS windows come out as command_and_control 570/684 times (S7).

    This applies the SAME kind of feature-derived signal already used to build reconnaissance
    TRAINING labels (pipeline/windowing.py::apply_reconnaissance_heuristic) at INFERENCE time
    instead, so what's displayed matches an observable signal in the traffic rather than a class
    the network was never taught. It is a heuristic, not a trained prediction, and the caller
    (ForecastEngine) reports that distinction back via `stage_is_heuristic` rather than blending it
    in silently — "never invent labels, say so wherever shown."

    Thresholds are z-scores against the SAME scaler.mean/std already fit on this checkpoint's own
    training data (no new calibration artifact, no arbitrary constant) — `impact_volume_zscore`
    (default 4.0) and the existing `recon_port_scan_threshold` (already a per-window raw feature,
    0-1, no z-score needed) are both configurable under `windowing:` like the recon threshold.
    """
    def z(name: str) -> float:
        i = feature_index.get(name)
        if i is None:
            return 0.0
        std = scaler.std[i] if scaler.std[i] > 1e-9 else 1.0
        return float((raw_features[i] - scaler.mean[i]) / std)

    # DoS/DDoS: extreme flow/packet/byte volume from one host concentrated on very few
    # destinations -- a flood, not a scan. This is the flow-level signature the audit itself uses
    # to describe DDoS throughout (S7, E7): one source, sustained high volume, low destination
    # diversity (the opposite of a port scan, which is low volume per destination but many of them).
    volume_z_threshold = config["windowing"].get("impact_volume_zscore", 4.0)
    volume_z = max(z("flow_count"), z("total_packets"), z("total_bytes"))
    if volume_z > volume_z_threshold and z("unique_dst_ips") < volume_z_threshold / 2:
        return IMPACT, True

    # Reconnaissance: same raw signal apply_reconnaissance_heuristic uses for training labels
    # (port_scan_score >= recon_port_scan_threshold), applied here to the model's own prediction
    # instead of a training target. Zero-filled (and so never fires) when no PCAP is available for
    # this capture, same documented limitation as the training-time heuristic.
    port_scan_threshold = config["windowing"].get("recon_port_scan_threshold", 0.5)
    port_scan_idx = feature_index.get("port_scan_score")
    if port_scan_idx is not None and raw_features[port_scan_idx] >= port_scan_threshold:
        return RECONNAISSANCE, True

    return predicted_stage, False


from models.checkpoint_io import load_checkpoint  # noqa: E402


def load_world_model(checkpoint_path: str | Path, device: torch.device | None = None) -> tuple[WorldModel, dict[str, Any]]:
    device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
    checkpoint = load_checkpoint(checkpoint_path, device)
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

        # Audit S6/S7: feature-index lookup for _heuristic_stage_override, built once. None (and
        # the heuristic silently skipped) for configs that don't define a `features` section at
        # all -- keeps this engine usable with the minimal test configs already in
        # tests/test_forecast_rollout.py, which predate this and only exercise generic tensor
        # shapes, not real named features.
        try:
            self._feature_index = {name: i for i, name in enumerate(feature_columns(config))}
        except KeyError:
            self._feature_index = None

    def _override_stage(self, raw_features_row: np.ndarray, predicted_stage: str) -> tuple[str, bool]:
        if self._feature_index is None:
            return predicted_stage, False
        return _heuristic_stage_override(raw_features_row, self._feature_index, self.scaler, self.config, predicted_stage)

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
        attentions, transition_magnitude, state_deltas, stage_is_heuristic = [], [], [], []

        with torch.no_grad():
            for _ in range(horizon):
                next_state, stage_logits, infiltration_logit, attn = self.model(seq_t, return_attention=True)

                inf_prob = torch.sigmoid(infiltration_logit).item()
                stage_prob = torch.softmax(stage_logits, dim=-1).squeeze(0).cpu().numpy()

                last_scaled = seq_t[:, -1, :]
                jump = torch.linalg.norm(next_state - last_scaled).item()
                next_state_raw = self.scaler.inverse_transform(next_state.squeeze(0).cpu().numpy())
                delta_raw = next_state_raw - self.scaler.inverse_transform(last_scaled.squeeze(0).cpu().numpy())

                raw_stage = self.stage_labels[int(stage_prob.argmax())]
                final_stage, was_heuristic = self._override_stage(next_state_raw, raw_stage)

                infiltration_probs.append(inf_prob)
                stage_predictions.append(final_stage)
                stage_is_heuristic.append(was_heuristic)
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
            stage_is_heuristic=stage_is_heuristic,
        )

    def rollout_batch(self, host_ids: list[str], raw_sequences: np.ndarray, batch_size: int = 2048) -> BatchForecastResult:
        """raw_sequences: (N, L, F) unscaled, one row per host. Chunked into `batch_size`-sized
        pieces so an arbitrarily large host count doesn't try to allocate one giant tensor at once;
        each chunk is still a single batched forward pass per K step, not one per host."""
        horizon = self.config["windowing"]["forecast_horizon"]
        n = raw_sequences.shape[0]
        all_probs, all_stage_preds, all_heuristic_flags = [], [], []

        with torch.no_grad():
            for start in range(0, n, batch_size):
                chunk = raw_sequences[start:start + batch_size]
                seq = self.scaler.transform(chunk).astype(np.float32)
                seq_t = torch.tensor(seq, device=self.device)  # (b, L, F)

                probs_steps, stage_steps, heuristic_steps = [], [], []
                for _ in range(horizon):
                    next_state, stage_logits, infiltration_logit = self.model(seq_t)
                    probs_steps.append(torch.sigmoid(infiltration_logit).cpu().numpy())
                    raw_idx = torch.softmax(stage_logits, dim=-1).argmax(dim=-1).cpu().numpy()  # (b,)

                    # Audit S6/S7: same per-window heuristic override as rollout(), applied over
                    # the batch. A Python loop over the batch here is cheap relative to the
                    # forward pass it follows; see _heuristic_stage_override's docstring.
                    if self._feature_index is not None:
                        next_state_raw = self.scaler.inverse_transform(next_state.cpu().numpy())  # (b, F)
                        overridden, flags = [], []
                        for i, idx in enumerate(raw_idx):
                            stage, was_heuristic = self._override_stage(next_state_raw[i], self.stage_labels[int(idx)])
                            overridden.append(stage)
                            flags.append(was_heuristic)
                        stage_steps.append(overridden)
                        heuristic_steps.append(flags)
                    else:
                        stage_steps.append([self.stage_labels[int(i)] for i in raw_idx])
                        heuristic_steps.append([False] * len(raw_idx))

                    seq_t = torch.cat([seq_t[:, 1:, :], next_state.unsqueeze(1)], dim=1)

                all_probs.append(np.stack(probs_steps, axis=1))  # (b, K)
                all_stage_preds.append(np.array(stage_steps, dtype=object).T)  # (b, K)
                all_heuristic_flags.append(np.array(heuristic_steps, dtype=bool).T)  # (b, K)

        infiltration_probs = np.concatenate(all_probs, axis=0) if all_probs else np.zeros((0, horizon))
        stage_predictions = (
            np.concatenate(all_stage_preds, axis=0).tolist() if all_stage_preds else []
        )
        stage_is_heuristic = (
            np.concatenate(all_heuristic_flags, axis=0).tolist() if all_heuristic_flags else []
        )

        return BatchForecastResult(
            host_ids=host_ids, infiltration_probs=infiltration_probs, stage_predictions=stage_predictions,
            stage_is_heuristic=stage_is_heuristic,
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


def latest_sequences_batch(
    windows_df, feature_cols: list[str], sequence_length: int
) -> tuple[list[str], np.ndarray]:
    """The batched counterpart to latest_sequence: every eligible host's most recent
    `sequence_length` windows, stacked into one (N, L, F) array. One groupby pass over
    `windows_df` rather than one filter per host — needed for the alert dashboard to stay fast
    when scoring thousands of hosts (real CIC-IDS-2018 has ~9,150 of them).
    """
    host_ids: list[str] = []
    sequences: list[np.ndarray] = []
    for host, group in windows_df.groupby("src_ip", sort=False):
        if len(group) < sequence_length:
            continue
        group = group.sort_values("window_start")
        sequences.append(group[feature_cols].to_numpy(dtype=np.float32)[-sequence_length:])
        host_ids.append(host)

    if not sequences:
        return [], np.zeros((0, sequence_length, len(feature_cols)), dtype=np.float32)
    return host_ids, np.stack(sequences)


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
