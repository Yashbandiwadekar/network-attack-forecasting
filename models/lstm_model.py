"""LSTM sequence model: the second leg of the Markov/LSTM/Transformer architecture comparison
(see docs/05-related-work-and-competitive-landscape.md Section 4).

Deliberately mirrors WorldModel's (models/world_model.py) forward signature and multi-task head
layout exactly -- same next-state regression / stage classification / infiltration heads, same
(next_state, stage_logits, infiltration_logit) return tuple -- so it trains under the identical
loss function (models/train.py::_step_loss) and is scored under the identical benchmark harness
(eval/benchmark.py). The only thing that differs is the sequence encoder itself: a recurrent LSTM
in place of self-attention. This isolates the question the Transformer-vs-stacked-LR baseline
can't answer on its own: is self-attention specifically responsible for any gap over the
baselines, or would any sequential/recurrent architecture do just as well?
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import torch
import torch.nn as nn


class LSTMWorldModel(nn.Module):
    def __init__(self, n_features: int, n_stage_classes: int, config: dict[str, Any]):
        super().__init__()
        m = config["model"]
        d_model = m["d_model"]
        n_layers = m["n_layers"]
        dropout = m["dropout"] if n_layers > 1 else 0.0  # nn.LSTM warns/no-ops dropout on 1 layer

        self.lstm = nn.LSTM(
            input_size=n_features, hidden_size=d_model, num_layers=n_layers,
            batch_first=True, dropout=dropout,
        )
        self.next_state_head = nn.Linear(d_model, n_features)
        self.stage_head = nn.Linear(d_model, n_stage_classes)
        self.infiltration_head = nn.Linear(d_model, 1)

    def forward(self, x: torch.Tensor):
        """x: (batch, L, n_features) -> next_state (batch, n_features), stage_logits
        (batch, n_stage_classes), infiltration_logit (batch,) -- same shapes as
        WorldModel.forward (minus the attention-weights return, which has no LSTM equivalent)."""
        h_seq, _ = self.lstm(x)
        last_step = h_seq[:, -1, :]  # final hidden state, analogous to WorldModel's last_step
        next_state = self.next_state_head(last_step)
        stage_logits = self.stage_head(last_step)
        infiltration_logit = self.infiltration_head(last_step).squeeze(-1)
        return next_state, stage_logits, infiltration_logit


def load_lstm_baseline(
    checkpoint_path: str | Path, device: torch.device | None = None,
) -> tuple[LSTMWorldModel, dict[str, Any]]:
    """Mirrors models.forecast.load_world_model exactly, for the LSTM checkpoint models/train.py
    --arch lstm produces. No K-step rollout wrapper -- this baseline is only ever scored on the
    immediate next-step task in eval/benchmark.py, the same as the Markov/LR baselines."""
    device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
    checkpoint = torch.load(checkpoint_path, map_location=device, weights_only=False)
    model = LSTMWorldModel(checkpoint["n_features"], checkpoint["n_stage_classes"], checkpoint["config"])
    model.load_state_dict(checkpoint["model_state"])
    model.to(device).eval()
    return model, checkpoint["config"]
