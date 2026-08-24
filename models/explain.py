"""Explainability required by the problem statement: "Black-box outputs without interpretability
are not acceptable." Two complementary views, both wired into the forecast output:

  - attention (from models/world_model.py / models/forecast.py): which PAST TIME WINDOWS the
    model relied on most for a given prediction — temporal explanation, free from the architecture.
  - SHAP (this module): which FEATURES in the current snapshot (which flags, ports, flow stats)
    are driving the infiltration probability up or down — feature-level explanation.
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
