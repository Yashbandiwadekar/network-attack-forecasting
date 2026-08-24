"""The world model: a Transformer that learns P(S_t+1 | S_t-L..S_t) over windowed network-state
sequences, with two prediction heads attached to the same learned representation:
  - next-state regression (the actual "world model" dynamics head)
  - MITRE-stage classification + infiltration probability for the immediate next step

K-step forecasting is NOT a separate head — models/forecast.py rolls this single-step model
forward autoregressively, feeding each predicted state back in as the newest input step. That
autoregressive rollout is what makes this a world model rather than a one-shot classifier.

Self-attention weights from the final layer are exposed for explainability: which past time
windows most influenced the prediction (see models/explain.py).
"""
from __future__ import annotations

import math
from typing import Any

import torch
import torch.nn as nn


class PositionalEncoding(nn.Module):
    def __init__(self, d_model: int, max_len: int = 64):
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float32).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        self.register_buffer("pe", pe.unsqueeze(0))  # (1, max_len, d_model)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return x + self.pe[:, : x.size(1)]


class EncoderLayer(nn.Module):
    """A standard post-norm Transformer encoder layer, implemented explicitly (rather than
    nn.TransformerEncoderLayer) so its self-attention weights can be returned for explainability."""

    def __init__(self, d_model: int, n_heads: int, d_ff: int, dropout: float):
        super().__init__()
        self.self_attn = nn.MultiheadAttention(d_model, n_heads, dropout=dropout, batch_first=True)
        self.ffn = nn.Sequential(nn.Linear(d_model, d_ff), nn.ReLU(), nn.Linear(d_ff, d_model))
        self.norm1 = nn.LayerNorm(d_model)
        self.norm2 = nn.LayerNorm(d_model)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        attn_out, attn_weights = self.self_attn(x, x, x, need_weights=True, average_attn_weights=True)
        x = self.norm1(x + self.dropout(attn_out))
        x = self.norm2(x + self.dropout(self.ffn(x)))
        return x, attn_weights  # attn_weights: (batch, L, L)


class WorldModel(nn.Module):
    def __init__(self, n_features: int, n_stage_classes: int, config: dict[str, Any]):
        super().__init__()
        m = config["model"]
        d_model = m["d_model"]

        self.input_proj = nn.Linear(n_features, d_model)
        self.pos_encoding = PositionalEncoding(d_model, max_len=config["windowing"]["sequence_length"] + 1)
        self.layers = nn.ModuleList([
            EncoderLayer(d_model, m["n_heads"], m["d_ff"], m["dropout"]) for _ in range(m["n_layers"])
        ])

        self.next_state_head = nn.Linear(d_model, n_features)
        self.stage_head = nn.Linear(d_model, n_stage_classes)
        self.infiltration_head = nn.Linear(d_model, 1)

    def forward(self, x: torch.Tensor, return_attention: bool = False):
        """x: (batch, L, n_features) -> next_state (batch, n_features), stage_logits
        (batch, n_stage_classes), infiltration_logit (batch,), and optionally the final layer's
        attention weights for the last time step's query (batch, L)."""
        h = self.input_proj(x)
        h = self.pos_encoding(h)

        attn_weights = None
        for layer in self.layers:
            h, attn_weights = layer(h)

        last_step = h[:, -1, :]  # representation after attending over the whole window
        next_state = self.next_state_head(last_step)
        stage_logits = self.stage_head(last_step)
        infiltration_logit = self.infiltration_head(last_step).squeeze(-1)

        if return_attention:
            # attention the last position paid to every position in the window, avg over heads
            last_step_attention = attn_weights[:, -1, :]  # (batch, L)
            return next_state, stage_logits, infiltration_logit, last_step_attention
        return next_state, stage_logits, infiltration_logit
