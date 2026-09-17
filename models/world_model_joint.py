"""JointWorldModel: the world model's Transformer with a GENUINELY TRAINABLE GraphSAGE encoder,
as opposed to the frozen-random-init one pipeline/graph_embedding_features.py precomputes as
static input columns (Phase 3).

Composition, not a rewrite: this wraps the existing models.world_model.WorldModel unchanged --
only the input it receives differs. At forward time, JointWorldModel computes a live per-step
graph embedding via models.graph_encoder.GraphSAGEEncoder (batched across every (sample, step)
pair via models.graph_batch.embed_batch, per Phase 4's B1 batching utility) and concatenates it
onto the *base* feature vector (flow + scalar graph_level + packet features -- explicitly
excluding the static `graph_embed_*` columns Phase 3 already computes, since those get replaced
by this live computation instead). The concatenated vector is what WorldModel actually sees, so
its Transformer architecture, multi-task heads, and K-step rollout (models/forecast.py) are
completely unchanged -- only the encoder producing part of the input is now part of the same
optimizer step as the Transformer, so gradients from the multi-task loss
(models/train_joint.py's loss, identical to models/train.py::_step_loss) flow into the GraphSAGE
encoder's weights too.
"""
from __future__ import annotations

from typing import Any

import torch
import torch.nn as nn

from models.graph_batch import embed_batch
from models.graph_encoder import GraphSAGEEncoder
from models.world_model import WorldModel
from pipeline.graph_builder import WindowGraph


class JointWorldModel(nn.Module):
    def __init__(
        self, n_base_features: int, n_stage_classes: int, config: dict[str, Any],
        edge_dim: int, embed_dim: int = 8, encoder_hidden_dim: int = 16,
    ):
        super().__init__()
        self.edge_dim = edge_dim
        self.embed_dim = embed_dim
        self.graph_encoder = GraphSAGEEncoder(edge_dim, hidden_dim=encoder_hidden_dim, out_dim=embed_dim)
        self.world_model = WorldModel(n_base_features + embed_dim, n_stage_classes, config)

    def forward(
        self,
        x_base: torch.Tensor,
        graph_items: list[tuple[WindowGraph, str]],
        return_attention: bool = False,
    ):
        """x_base: (batch, L, n_base_features), already on the target device.
        graph_items: flat, row-major list of (WindowGraph, host_ip) of length batch*L -- the
        graph backing every (sample, step) pair in x_base, in the same order x_base.reshape(-1, ...)
        would iterate (sample 0 step 0, sample 0 step 1, ..., sample 0 step L-1, sample 1 step 0, ...).
        Building this list is the caller's job (models/train_joint.py), since it requires looking
        up pipeline.graph_builder.window_graph_key per step from data SequenceDataset itself
        doesn't tensor-batch (window_times/src_ip/scenario_id) -- see that module's docstring.
        """
        batch, seq_len, _ = x_base.shape
        expected = batch * seq_len
        if len(graph_items) != expected:
            raise ValueError(
                f"graph_items must have batch*seq_len={expected} entries (got {len(graph_items)})",
            )

        live_embed = embed_batch(self.graph_encoder, graph_items, self.edge_dim, device=x_base.device)
        live_embed = live_embed.view(batch, seq_len, self.embed_dim)

        x = torch.cat([x_base, live_embed], dim=-1)
        return self.world_model(x, return_attention=return_attention)
