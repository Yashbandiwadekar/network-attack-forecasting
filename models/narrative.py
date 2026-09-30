"""Template-based, fully offline "attack story" generation from the forecast's own outputs.

No LLM call — this project runs with zero cloud API calls by design (see README, "What this
system does not do", and app/server.py's module docstring), and a templated narrative built directly from the model's own numeric outputs
(infiltration curve, predicted stage per step, attention weights, predicted state deltas) stays
exactly as trustworthy/explainable as those outputs already are. This turns "the model says 87%"
into a short paragraph a non-ML analyst can read directly, then pairs it with a recommended first
response action (see models/response.py).
"""
from __future__ import annotations

import numpy as np

from models.explain import summarize_attention
from models.forecast import ForecastResult
from models.response import recommended_action
from pipeline.mitre_mapping import BENIGN

_STAGE_PHRASING = {
    "reconnaissance": "beginning to probe the network (scanning behaviour)",
    "initial_access": "attempting to gain an initial foothold",
    "lateral_movement": "pivoting toward other internal hosts",
    "command_and_control": "establishing a command-and-control channel",
    "exfiltration": "moving data out of the network",
    "impact": "generating high-volume, disruptive traffic",
    "benign": "behaving consistently with normal traffic",
}


def generate_attack_narrative(
    src_ip: str,
    result: ForecastResult,
    feature_cols: list[str],
    window_seconds: int,
    current_stage: str | None = None,
) -> str:
    """A short, deterministic paragraph summarizing one host's K-step forecast, ending with a
    recommended first response action. Every claim traces back to a specific ForecastResult field
    — nothing here is invented or sampled."""
    horizon = len(result.infiltration_probs)
    peak_step = int(np.argmax(result.infiltration_probs))
    peak_prob = float(result.infiltration_probs[peak_step])
    peak_stage = result.stage_predictions[peak_step]
    first_prob = float(result.infiltration_probs[0])

    if result.infiltration_probs[-1] > first_prob + 0.05:
        trend = "rising"
    elif result.infiltration_probs[-1] < first_prob - 0.05:
        trend = "falling"
    else:
        trend = "holding steady"

    attn_pairs = summarize_attention(result.attentions[0], result.attentions.shape[1])
    top_window, top_weight = attn_pairs[0]

    delta_order = np.argsort(-np.abs(result.state_deltas[0]))[:3]
    top_delta_features = ", ".join(feature_cols[i] for i in delta_order)

    action = recommended_action(peak_stage)

    if current_stage and current_stage != BENIGN:
        opening = f"<b>{src_ip}</b> is currently classified as <b>{current_stage.replace('_', ' ')}</b>."
    else:
        opening = f"<b>{src_ip}</b>'s traffic is currently within normal bounds."

    forecast_line = (
        f"Over the next {horizon * window_seconds}s the forecast is <b>{trend}</b>: infiltration probability "
        f"starts at {first_prob:.0%} and peaks at {peak_prob:.0%} around t+{(peak_step + 1) * window_seconds}s, "
        f"where the model expects the host to be {_STAGE_PHRASING.get(peak_stage, peak_stage)}."
    )
    driver_line = (
        f"This forecast is driven most by activity in window <b>{top_window}</b> ({top_weight:.0%} attention "
        f"weight), with the largest expected shifts in <b>{top_delta_features}</b>."
    )
    action_line = f"<b>Recommended action:</b> {action['action']}."

    return " ".join([opening, forecast_line, driver_line, action_line])
