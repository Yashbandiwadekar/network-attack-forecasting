"""Benchmark: world model vs logistic-regression baseline on the immediate next-step prediction
task (both models are compared on exactly the same target — the baseline has no rollout to speak
of, so this is the fair apples-to-apples comparison the problem statement asks for; the world
model's K-step rollout is a separate capability the baseline simply doesn't have, demonstrated by
the Streamlit demo instead).

Usage:
    python -m eval.benchmark --config configs/default.yaml
"""
from __future__ import annotations

import argparse

import numpy as np
import torch

from common.config import load_config, resolve_path
from eval.metrics import binary_metrics, stage_metrics
from models.baseline_lr import BaselineModel
from models.dataset import build_datasets
from models.forecast import load_world_model


def _world_model_predictions(model, test_ds, device):
    with torch.no_grad():
        X = test_ds.X.to(device)
        _, stage_logits, infiltration_logit = model(X)
        infiltration_prob = torch.sigmoid(infiltration_logit).cpu().numpy()
        stage_pred = torch.softmax(stage_logits, dim=-1).argmax(dim=-1).cpu().numpy()
    return infiltration_prob, stage_pred


def run(config_path: str = "configs/default.yaml") -> str:
    config = load_config(config_path)
    train_ds, val_ds, test_ds, scaler = build_datasets(config)

    checkpoint_dir = resolve_path(config, "checkpoint_dir")
    model, _ = load_world_model(checkpoint_dir / "world_model_best.pt")
    device = next(model.parameters()).device

    infiltration_target = test_ds.infiltration[:, 0].numpy()
    stage_target = test_ds.future_stages[:, 0].numpy()
    stage_valid_mask = stage_target != -1

    wm_infiltration_prob, wm_stage_pred = _world_model_predictions(model, test_ds, device)
    wm_binary = binary_metrics(infiltration_target, wm_infiltration_prob)
    wm_stage = stage_metrics(stage_target, wm_stage_pred, stage_valid_mask)

    baseline = BaselineModel(config).fit(train_ds)
    last_window = test_ds.X[:, -1, :].numpy()
    bl_infiltration_prob, bl_stage_probs = baseline.predict(last_window)
    bl_stage_pred = bl_stage_probs.argmax(axis=-1)
    bl_binary = binary_metrics(infiltration_target, bl_infiltration_prob)
    bl_stage = stage_metrics(stage_target, bl_stage_pred, stage_valid_mask)

    report = _format_report(config, len(test_ds), wm_binary, wm_stage, bl_binary, bl_stage)

    report_path = resolve_path(config, "eval_report")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report, encoding="utf-8")
    print(report)
    print(f"\nWritten to {report_path}")
    return report


def _format_report(config, n_test, wm_binary, wm_stage, bl_binary, bl_stage) -> str:
    def row(name, m):
        return f"| {name} | {m['f1']:.3f} | {m['precision']:.3f} | {m['recall']:.3f} | {m['false_positive_rate']:.3f} |"

    def stage_row(name, m):
        return f"| {name} | {m['f1_macro']:.3f} | {m['precision_macro']:.3f} | {m['recall_macro']:.3f} |"

    return f"""# Evaluation: World Model vs Logistic Regression Baseline

Test set: {n_test} sequences. Both models predict the immediate next window (t+1); the world
model additionally supports K-step autoregressive rollout (see models/forecast.py), which the
baseline has no equivalent of and is demonstrated in the Streamlit app instead of benchmarked here.

## Infiltration probability (binary: attack in next window?)

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
{row("World Model (Transformer)", wm_binary)}
{row("Baseline (Logistic Regression)", bl_binary)}

## MITRE stage classification (5-way, `impact`-mapped windows excluded)

| Model | F1 (macro) | Precision (macro) | Recall (macro) |
|---|---|---|---|
{stage_row("World Model (Transformer)", wm_stage)}
{stage_row("Baseline (Logistic Regression)", bl_stage)}

## Interpretation

The baseline sees only the current window's feature vector, with no temporal context. The world
model sees the last {config['windowing']['sequence_length']} windows and is trained on the same
next-step targets. A gap in favour of the world model here is evidence that the extra temporal
context (attack progression patterns like the SYN-ratio ramp, port-scan-then-bruteforce sequencing)
is actually being used, not just memorized from the single most recent window.
"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/default.yaml")
    args = parser.parse_args()
    run(args.config)
