"""Manual security check (not a pytest — needs a trained checkpoint, so it's not run in CI): how
much deliberate, bounded perturbation does it take to push a genuinely malicious traffic pattern's
predicted infiltration probability below the alerting threshold?

This runs a small PGD-style (Projected Gradient Descent) evasion attack against the model's own
t+1 infiltration head. The model is fully differentiable (see models/world_model.py), so an
attacker with white-box access to the weights — or a good-enough surrogate trained on its
outputs — could compute this same gradient. The perturbation is bounded to +/- `epsilon`
standardized-feature units and applied only to the MOST RECENT window (the one an attacker
actually controls in real time); the earlier windows in the sequence are held fixed as
already-observed history the attacker cannot rewrite.

Honest caveat: this treats every feature as equally easy to perturb, which is not realistic — an
attacker can shape SYN ratio or destination-port diversity far more easily than, say, flip
`has_ip_data`. This is a proof-of-concept LOWER BOUND on adversarial robustness (if evasion is
hard even with an unconstrained attacker, it's harder still for a realistic one), not a
feasibility-constrained red-team exercise. The printed per-feature perturbation breakdown is
itself informative: it shows which features the attack actually leans on, i.e. which ones would
be worth constraining in a follow-up, more realistic study.

Usage:
    python -m scripts.check_adversarial_robustness --config configs/real_data.yaml
"""
from __future__ import annotations

import argparse

import numpy as np
import pandas as pd
import torch

from common.config import feature_columns, load_config, resolve_path
from models.dataset import FeatureScaler
from models.forecast import ForecastEngine, latest_sequence, load_world_model
from pipeline.flow_features import COLUMN_RENAME, clean_and_normalize
from pipeline.graph_features import build_graph_window_features
from pipeline.windowing import build_flow_windows, merge_graph_features, merge_packet_features

RNG = np.random.default_rng(13)

EPSILON = 1.5   # max perturbation per feature, in standardized (scaler-output) units
STEPS = 25
STEP_SIZE = 0.15
THRESHOLD = 0.5  # matches eval/benchmark.py's default operating point


def _malicious_flows(n_windows: int, window_seconds: int) -> pd.DataFrame:
    """A brute-force attack: single target port, high SYN ratio, many short flows per window.

    Deliberately omits Src/Dst IP so it falls back to a network-wide pseudo-host (see
    pipeline/flow_features.py::_fill_missing_ip_columns) at real CIC-IDS-2018 scale (thousands of
    flows/window) — 9 of the 10 real training days have no per-host IPs, so that's the only shape
    the real-data model has ever actually seen brute-force labels attached to. An earlier version
    of this script used a single low-volume per-host capture with real IPs and was never flagged
    as malicious at all (0.0 infiltration probability) — not because the model is robust, but
    because that combination (has_ip_data=1, low volume, elevated SYN ratio) is off-distribution
    in a different direction than what it was trained on. Confirmed via a quick scaled-feature
    inspection before settling on this shape."""
    base_time = pd.Timestamp("2026-01-01 00:00:00")
    target_port = 22
    rows = []
    for w in range(n_windows):
        window_start = base_time + pd.Timedelta(seconds=w * window_seconds)
        for _ in range(int(RNG.integers(3000, 6000))):
            rows.append({
                "Dst Port": target_port,
                "Protocol": 6,
                "Timestamp": window_start + pd.Timedelta(seconds=float(RNG.uniform(0, window_seconds))),
                "Flow Duration": int(RNG.uniform(1_000, 50_000)),
                "Tot Fwd Pkts": int(RNG.integers(1, 5)),
                "Tot Bwd Pkts": int(RNG.integers(0, 2)),
                "TotLen Fwd Pkts": int(RNG.integers(40, 200)),
                "TotLen Bwd Pkts": int(RNG.integers(0, 100)),
                "SYN Flag Cnt": 1, "ACK Flag Cnt": int(RNG.integers(0, 2)),
                "FIN Flag Cnt": 0, "RST Flag Cnt": int(RNG.integers(0, 2)), "PSH Flag Cnt": 0, "URG Flag Cnt": 0,
                "Flow IAT Mean": float(RNG.uniform(1, 50)),
                "Flow IAT Std": float(RNG.uniform(0.1, 10)),
                "Flow IAT Max": float(RNG.uniform(1, 100)),
                "Label": "SSH-Bruteforce",
            })
    return pd.DataFrame(rows)


def pgd_evade(
    engine: ForecastEngine, raw_sequence: np.ndarray, epsilon: float = EPSILON, steps: int = STEPS,
    step_size: float = STEP_SIZE,
) -> tuple[np.ndarray, list[float], np.ndarray]:
    """Perturbs only the last window, within +/- epsilon standardized units per feature, trying to
    minimize the model's t+1 infiltration probability. Returns (adversarial_raw_sequence,
    probability_per_step, final_delta_in_std_units)."""
    scaler = engine.scaler
    model = engine.model
    device = engine.device

    scaled = scaler.transform(raw_sequence).astype(np.float32)
    original_last = scaled[-1].copy()

    was_training = model.training
    model.eval()

    delta = np.zeros_like(original_last)
    history: list[float] = []
    try:
        for _ in range(steps):
            x = scaled.copy()
            x[-1] = np.clip(original_last + delta, -scaler.clip_std, scaler.clip_std)
            x_t = torch.tensor(x, dtype=torch.float32, device=device).unsqueeze(0)
            x_t.requires_grad_(True)

            _, _, infiltration_logit = model(x_t)
            prob = torch.sigmoid(infiltration_logit)
            history.append(float(prob.item()))

            model.zero_grad(set_to_none=True)
            prob.backward()

            grad_last = x_t.grad.squeeze(0)[-1].detach().cpu().numpy()
            delta = delta - step_size * np.sign(grad_last)
            delta = np.clip(delta, -epsilon, epsilon)
    finally:
        model.train(was_training)

    final_last = np.clip(original_last + delta, -scaler.clip_std, scaler.clip_std)
    adv_scaled = scaled.copy()
    adv_scaled[-1] = final_last
    adv_raw = scaler.inverse_transform(adv_scaled)
    return adv_raw, history, delta


def main(config_path: str = "configs/real_data.yaml") -> None:
    config = load_config(config_path)
    checkpoint_dir = resolve_path(config, "checkpoint_dir")
    processed_dir = resolve_path(config, "processed_dir")

    checkpoint_path = checkpoint_dir / "world_model_best.pt"
    if not checkpoint_path.exists():
        raise FileNotFoundError(f"No trained checkpoint at {checkpoint_path} — run `python -m models.train` first")

    model, _ = load_world_model(checkpoint_path)
    scaler = FeatureScaler.load(processed_dir / "scaler.npz")

    seq_len = config["windowing"]["sequence_length"]
    n_windows = seq_len + 2
    raw = _malicious_flows(n_windows, config["windowing"]["window_seconds"])
    raw.columns = [COLUMN_RENAME.get(c, c) for c in raw.columns]
    flow_df = clean_and_normalize(raw)
    windows = build_flow_windows(flow_df, config)
    graph_windows = build_graph_window_features(flow_df, config)
    windows = merge_graph_features(windows, graph_windows, config)
    windows = merge_packet_features(windows, None, config)

    host_id = windows["src_ip"].iloc[0]
    feature_cols = feature_columns(config)
    raw_sequence = latest_sequence(windows, feature_cols, host_id, seq_len)
    if raw_sequence is None:
        raise RuntimeError("not enough synthetic malicious windows were generated — increase n_windows")

    engine = ForecastEngine(model, scaler, config)
    before = engine.rollout(raw_sequence)

    print(f"Synthetic SSH brute-force capture (network-wide pseudo-host {host_id}):")
    print(f"  infiltration probability before attack (K-step): {np.round(before.infiltration_probs, 4).tolist()}")

    adv_raw, history, delta = pgd_evade(engine, raw_sequence)
    after = engine.rollout(adv_raw)

    print(f"\nPGD evasion attack: {STEPS} steps, epsilon={EPSILON} std, step_size={STEP_SIZE}")
    print(f"  t+1 infiltration probability: {history[0]:.4f} -> {history[-1]:.4f} "
          f"(min reached: {min(history):.4f})")
    print(f"  full K-step forecast after evasion: {np.round(after.infiltration_probs, 4).tolist()}")

    order = np.argsort(-np.abs(delta))[:5]
    print("\n  Top perturbed features (standardized units, +/- means increase/decrease):")
    for i in order:
        print(f"    {feature_cols[i]}: {delta[i]:+.3f} std")

    print()
    if history[-1] < THRESHOLD <= history[0]:
        print(f"  WARNING — evasion succeeded: probability dropped below the {THRESHOLD} operating "
              f"threshold within an epsilon={EPSILON}-std budget on the most recent window alone.")
    elif history[-1] < history[0] - 0.1:
        print(f"  PARTIAL — probability dropped meaningfully ({history[0]:.2f} -> {history[-1]:.2f}) "
              f"but did not cross the {THRESHOLD} threshold within this budget.")
    else:
        print(f"  PASS — the model held: probability barely moved ({history[0]:.4f} -> {history[-1]:.4f}) "
              f"despite an unconstrained, white-box gradient attack on the current window.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/real_data.yaml")
    args = parser.parse_args()
    main(args.config)
