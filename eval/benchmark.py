"""Benchmark: world model vs three baselines on the immediate next-step prediction task (the
world model's K-step rollout is a separate capability none of the baselines have — demonstrated
in the Streamlit app, not benchmarked here, since there's nothing to compare it against fairly).

Three baselines, each isolating a different question:
  - Baseline (LR, last window): no temporal context at all — the traditional "classify each flow
    in isolation" approach the problem statement contrasts world models against.
  - Baseline (LR, stacked window): the SAME L-window history the world model sees, flattened into
    one vector for a non-sequential classifier — isolates "does temporal/sequential modeling
    matter, or would more columns alone do the same job."
  - Persistence: no learning — predicts the current window's own state persists unchanged. If the
    world model can't beat this, it isn't learning real dynamics.

Two operating points per model: the default 0.5 threshold, and a fixed 5% false-positive-rate
budget (threshold selected on the VAL split only, then applied to test) — the second is how a
defender actually tunes such a system, not an arbitrary cutoff.

Usage:
    python -m eval.benchmark --config configs/default.yaml
"""
from __future__ import annotations

import argparse

import numpy as np
import torch

from common.config import load_config, resolve_path
from eval.metrics import binary_metrics, stage_metrics, threshold_at_fpr
from models.baseline_lr import BaselineModel, PersistenceBaseline
from models.dataset import SequenceDataset, build_datasets
from models.forecast import load_world_model
from models.world_model import WorldModel

TARGET_FPR = 0.05


def _world_model_predictions(model: WorldModel, ds: SequenceDataset, device) -> tuple[np.ndarray, np.ndarray]:
    with torch.no_grad():
        X = ds.X.to(device)
        _, stage_logits, infiltration_logit = model(X)
        infiltration_prob = torch.sigmoid(infiltration_logit).cpu().numpy()
        stage_pred = torch.softmax(stage_logits, dim=-1).argmax(dim=-1).cpu().numpy()
    return infiltration_prob, stage_pred


def _evaluate_model(
    name: str, val_target: np.ndarray, val_prob: np.ndarray, test_prob: np.ndarray, test_stage_pred: np.ndarray,
    infiltration_target: np.ndarray, stage_target: np.ndarray, stage_valid_mask: np.ndarray,
) -> dict:
    default_metrics = binary_metrics(infiltration_target, test_prob, threshold=0.5)
    fpr_threshold = threshold_at_fpr(val_target, val_prob, target_fpr=TARGET_FPR)
    budget_metrics = binary_metrics(infiltration_target, test_prob, threshold=fpr_threshold)
    stage = stage_metrics(stage_target, test_stage_pred, stage_valid_mask)
    return {"name": name, "default": default_metrics, "budget": budget_metrics, "stage": stage}


def run(config_path: str = "configs/default.yaml") -> str:
    config = load_config(config_path)
    train_ds, val_ds, test_ds, scaler = build_datasets(config)

    checkpoint_dir = resolve_path(config, "checkpoint_dir")
    model, _ = load_world_model(checkpoint_dir / "world_model_best.pt")
    device = next(model.parameters()).device

    test_infiltration_target = test_ds.infiltration[:, 0].numpy()
    test_stage_target = test_ds.future_stages[:, 0].numpy()
    stage_valid_mask = test_stage_target != -1
    val_infiltration_target = val_ds.infiltration[:, 0].numpy()

    results = []

    wm_val_prob, _ = _world_model_predictions(model, val_ds, device)
    wm_test_prob, wm_stage_pred = _world_model_predictions(model, test_ds, device)
    results.append(_evaluate_model(
        "World Model (Transformer)", val_infiltration_target, wm_val_prob, wm_test_prob, wm_stage_pred,
        test_infiltration_target, test_stage_target, stage_valid_mask,
    ))

    for mode, label in [("last", "Baseline (LR, last window)"), ("stacked", "Baseline (LR, stacked window)")]:
        baseline = BaselineModel(config, mode=mode).fit(train_ds)
        val_prob, _ = baseline.predict(val_ds.X.numpy())
        test_prob, test_stage_probs = baseline.predict(test_ds.X.numpy())
        results.append(_evaluate_model(
            label, val_infiltration_target, val_prob, test_prob, test_stage_probs.argmax(axis=-1),
            test_infiltration_target, test_stage_target, stage_valid_mask,
        ))

    persistence = PersistenceBaseline()
    val_prob, _ = persistence.predict(val_ds)
    test_prob, test_stage_probs = persistence.predict(test_ds)
    results.append(_evaluate_model(
        "Persistence (no learning)", val_infiltration_target, val_prob, test_prob, test_stage_probs.argmax(axis=-1),
        test_infiltration_target, test_stage_target, stage_valid_mask,
    ))

    report = _format_report(config, len(test_ds), results)

    report_path = resolve_path(config, "eval_report")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report, encoding="utf-8")
    print(report)
    print(f"\nWritten to {report_path}")
    return report


def _format_report(config, n_test, results: list[dict]) -> str:
    def row(r, key):
        m = r[key]
        return f"| {r['name']} | {m['f1']:.3f} | {m['precision']:.3f} | {m['recall']:.3f} | {m['false_positive_rate']:.3f} |"

    def stage_row(r):
        m = r["stage"]
        return f"| {r['name']} | {m['f1_macro']:.3f} | {m['precision_macro']:.3f} | {m['recall_macro']:.3f} |"

    default_rows = "\n".join(row(r, "default") for r in results)
    budget_rows = "\n".join(row(r, "budget") for r in results)
    stage_rows = "\n".join(stage_row(r) for r in results)

    return f"""# Evaluation: World Model vs Baselines

Test set: {n_test} sequences. All four models predict the immediate next window (t+1) from
identical targets; the world model additionally supports K-step autoregressive rollout (see
models/forecast.py), which none of the baselines have an equivalent of — demonstrated in the
Streamlit app rather than benchmarked here, since there's nothing to compare it against fairly.

## Infiltration probability — default threshold (0.5)

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
{default_rows}

## Infiltration probability — fixed {TARGET_FPR:.0%} false-positive-rate budget

Threshold selected on the validation split only (never test), then applied here — this is the
operating point a defender would actually tune to, not an arbitrary 0.5 cutoff.

| Model | F1 | Precision | Recall | False Positive Rate |
|---|---|---|---|---|
{budget_rows}

## MITRE stage classification (5-way, `impact`-mapped windows excluded)

| Model | F1 (macro) | Precision (macro) | Recall (macro) |
|---|---|---|---|
{stage_rows}

## Interpretation

- **World Model vs Baseline (LR, last window)**: the last-window baseline sees only the current
  snapshot, no temporal context. A gap here shows the world model is using *some* form of history.
- **World Model vs Baseline (LR, stacked window)**: the stacked baseline sees the exact same
  {config['windowing']['sequence_length']}-window history as the world model, just flattened for a
  non-sequential classifier. A gap here — not just vs. the last-window baseline — is the real
  evidence that sequential/recurrent structure matters, not just having more input columns.
- **World Model vs Persistence**: persistence needs no training at all. If the world model doesn't
  clear this bar, it isn't learning real dynamics, whatever its other metrics say.
{_stacked_baseline_caveat(results)}
"""


def _stacked_baseline_caveat(results: list[dict]) -> str:
    """Computed rather than hand-written, so this stays honest as the numbers change (e.g. once
    trained on real data instead of the synthetic sample) instead of silently going stale."""
    by_name = {r["name"]: r for r in results}
    wm_f1 = by_name["World Model (Transformer)"]["budget"]["f1"]
    stacked_f1 = by_name["Baseline (LR, stacked window)"]["budget"]["f1"]
    if stacked_f1 >= wm_f1:
        return (
            "\n**Honest caveat**: the stacked-window baseline matches or beats the world model "
            "here. On the current (small, synthetic) sample the attack-phase transitions are "
            "clean enough that a flat classifier with the same information does just as well — "
            "this benchmark hasn't yet demonstrated that sequential/recurrent structure earns its "
            "keep. That's exactly the kind of gap real CIC-IDS-2018 data, with much noisier and "
            "more overlapping traffic, is expected to actually show; see docs/02-dataset-and-features.md."
        )
    return ""


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/default.yaml")
    args = parser.parse_args()
    run(args.config)
