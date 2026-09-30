"""Explainability required by the problem statement: "Black-box outputs without interpretability
are not acceptable." Three complementary views, all wired into the forecast output:

  - attention (from models/world_model.py / models/forecast.py): which PAST TIME WINDOWS the
    model relied on most for a given prediction — temporal explanation, free from the architecture.
  - gradient x input (this module): which FEATURES in the current snapshot are driving the
    infiltration probability, from a single backward pass — instant, an approximation.
  - SHAP (this module): the same "which features" question, sampling-based rather than a local
    linear approximation — slower but doesn't share gradient x input's blind spots (e.g. saturated
    sigmoid regions where the true gradient is near zero but the feature still matters).
"""
from __future__ import annotations

import numpy as np
import shap
import torch

from models.world_model import WorldModel


def summarize_attention(attention_row: np.ndarray, sequence_length: int) -> list[tuple[str, float]]:
    """attention_row: (L,) attention weights over the L input windows for one prediction step.
    Returns [(window_label, weight), ...] sorted by weight descending, most-recent window last
    in the raw sequence labelled "t-0" (most recent) down to "t-(L-1)" (oldest)."""
    labels = [f"t-{sequence_length - 1 - i}" for i in range(sequence_length)]
    pairs = list(zip(labels, attention_row.tolist()))
    return sorted(pairs, key=lambda p: -p[1])


def gradient_input_attribution(
    model: WorldModel, scaled_sequence: np.ndarray, feature_names: list[str], target: str = "probability",
) -> dict:
    """Gradient x input attribution for the infiltration head, w.r.t. the most recent
    window's features only (same "what about the current snapshot" framing as ShapExplainer, held
    to the same last-window scope for a fair side-by-side). One forward + one backward pass —
    orders of magnitude cheaper than SHAP's sampling, at the cost of being a local linear
    approximation rather than a sampled attribution.

    scaled_sequence: (L, F) already feature-scaled (same scaler used for training/rollout).

    target: "probability" (default, what ShapExplainer explains) or "logit". When the model is
    saturated (probability near 0 or 1) the sigmoid's gradient vanishes, so every probability
    attribution collapses to ~1e-4 and a UI showing it reads 0.0% for every feature. The
    probability gradient is the logit gradient times the per-sample constant p(1-p), so the two
    give the SAME ranking and the same relative shares; "logit" simply avoids the underflow.
    """
    if target not in ("probability", "logit"):
        raise ValueError(f"target must be 'probability' or 'logit', got {target!r}")
    device = next(model.parameters()).device
    was_training = model.training
    model.eval()
    try:
        x = torch.tensor(scaled_sequence, dtype=torch.float32, device=device).unsqueeze(0)
        x.requires_grad_(True)
        _, _, infiltration_logit = model(x)
        output = infiltration_logit if target == "logit" else torch.sigmoid(infiltration_logit)
        model.zero_grad(set_to_none=True)
        output.sum().backward()
    finally:
        model.train(was_training)

    last_window_grad = x.grad.squeeze(0)[-1, :]
    last_window_value = x.detach().squeeze(0)[-1, :]
    attribution = (last_window_grad * last_window_value).cpu().numpy()

    order = np.argsort(-np.abs(attribution))
    return {
        "feature_names": feature_names,
        "attribution": attribution,
        "top_features": [(feature_names[i], float(attribution[i])) for i in order[:5]],
    }


class ShapExplainer:
    """SHAP attribution for the infiltration-probability head, varying only the most recent
    window's features while holding the preceding L-1 windows of history fixed at their observed
    values — this isolates "what about the current snapshot is driving the score" rather than
    conflating it with the trajectory that led here.
    """

    def __init__(self, model: WorldModel, background_last_windows_scaled: np.ndarray, n_background: int = 20):
        self.model = model
        self.device = next(model.parameters()).device
        rng = np.random.default_rng(0)
        n = min(n_background, len(background_last_windows_scaled))
        idx = rng.choice(len(background_last_windows_scaled), n, replace=False)
        self.background = background_last_windows_scaled[idx]
        self._context: np.ndarray | None = None  # (L-1, F), set per explain() call

    def _predict_infiltration_prob(self, last_windows: np.ndarray) -> np.ndarray:
        n = last_windows.shape[0]
        context = np.tile(self._context[None, :, :], (n, 1, 1))
        full_seq = np.concatenate([context, last_windows[:, None, :]], axis=1)
        x = torch.tensor(full_seq, dtype=torch.float32, device=self.device)
        with torch.no_grad():
            _, _, infiltration_logit = self.model(x)
        return torch.sigmoid(infiltration_logit).cpu().numpy()

    def explain(self, scaled_sequence: np.ndarray, feature_names: list[str], nsamples: int = 100) -> dict:
        """scaled_sequence: (L, F) already feature-scaled (same scaler used for training/rollout)."""
        self._context = scaled_sequence[:-1]
        last_window = scaled_sequence[-1]

        explainer = shap.KernelExplainer(self._predict_infiltration_prob, self.background)
        raw = explainer.shap_values(last_window[None, :], nsamples=nsamples, silent=True)
        shap_values = np.asarray(raw).reshape(-1)

        order = np.argsort(-np.abs(shap_values))
        return {
            "feature_names": feature_names,
            "shap_values": shap_values,
            "top_features": [(feature_names[i], float(shap_values[i])) for i in order[:5]],
        }
