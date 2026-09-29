import numpy as np
import torch

from models.dataset import FeatureScaler
from models.forecast import (
    ForecastEngine, latest_sequences_batch, one_step_reconstruction_error, previous_sequence_and_actual,
)
from models.world_model import WorldModel

CONFIG = {
    "windowing": {"sequence_length": 5, "forecast_horizon": 4},
    "model": {"d_model": 16, "n_heads": 2, "n_layers": 2, "d_ff": 32, "dropout": 0.0},
    "mitre_stages": ["benign", "reconnaissance", "initial_access", "lateral_movement", "command_and_control", "exfiltration"],
}


def _engine(n_features=7):
    model = WorldModel(n_features, len(CONFIG["mitre_stages"]), CONFIG)
    model.eval()  # matches load_world_model()'s production behaviour — rollout() is deterministic by default
    scaler = FeatureScaler(mean=np.zeros(n_features), std=np.ones(n_features))
    return ForecastEngine(model, scaler, CONFIG)


def test_rollout_shapes():
    n_features = 7
    engine = _engine(n_features)
    raw_sequence = np.random.randn(CONFIG["windowing"]["sequence_length"], n_features).astype(np.float32)

    result = engine.rollout(raw_sequence)

    K = CONFIG["windowing"]["forecast_horizon"]
    L = CONFIG["windowing"]["sequence_length"]
    n_stages = len(CONFIG["mitre_stages"])

    assert result.infiltration_probs.shape == (K,)
    assert len(result.stage_predictions) == K
    assert result.stage_probs.shape == (K, n_stages)
    assert result.attentions.shape == (K, L)
    assert result.transition_magnitude.shape == (K,)
    assert result.state_deltas.shape == (K, n_features)
    assert np.all(result.transition_magnitude >= 0)
    assert np.all((result.infiltration_probs >= 0) & (result.infiltration_probs <= 1))
    assert all(s in CONFIG["mitre_stages"] for s in result.stage_predictions)


def test_stage_probs_are_valid_distributions():
    engine = _engine()
    raw_sequence = np.random.randn(5, 7).astype(np.float32)
    result = engine.rollout(raw_sequence)
    np.testing.assert_allclose(result.stage_probs.sum(axis=-1), 1.0, atol=1e-5)


def test_rollout_is_deterministic_in_eval_mode():
    # Also the rollout-integrity guarantee: rollout() takes no ground-truth-future argument, so
    # two calls with identical input must produce identical output by construction.
    engine = _engine()
    raw_sequence = np.random.randn(5, 7).astype(np.float32)
    r1 = engine.rollout(raw_sequence)
    r2 = engine.rollout(raw_sequence)
    np.testing.assert_allclose(r1.infiltration_probs, r2.infiltration_probs)
    np.testing.assert_allclose(r1.state_deltas, r2.state_deltas)


def test_rollout_restores_eval_mode_after_use():
    engine = _engine()
    assert engine.model.training is False
    raw_sequence = np.random.randn(5, 7).astype(np.float32)
    engine.rollout(raw_sequence)
    assert engine.model.training is False, "rollout() must not leave the model in train mode"


def test_rollout_with_uncertainty_band_is_ordered_and_restores_mode():
    engine = _engine()
    raw_sequence = np.random.randn(5, 7).astype(np.float32)

    result = engine.rollout_with_uncertainty(raw_sequence, n_samples=5)

    K = CONFIG["windowing"]["forecast_horizon"]
    assert result.infiltration_p10.shape == (K,)
    assert result.infiltration_p50.shape == (K,)
    assert result.infiltration_p90.shape == (K,)
    assert np.all(result.infiltration_p10 <= result.infiltration_p50 + 1e-6)
    assert np.all(result.infiltration_p50 <= result.infiltration_p90 + 1e-6)
    assert len(result.stage_predictions) == K
    # must restore the model's original (eval) mode, not leave it stuck in train mode
    assert engine.model.training is False


def test_one_step_reconstruction_error_is_nonnegative_and_zero_history_free():
    n_features = 7
    engine = _engine(n_features)
    prior = np.random.randn(5, n_features).astype(np.float32)
    actual = np.random.randn(n_features).astype(np.float32)

    error = one_step_reconstruction_error(engine.model, engine.scaler, prior, actual)

    assert error >= 0
    assert np.isfinite(error)


def test_previous_sequence_and_actual_needs_one_more_window_than_latest_sequence():
    import pandas as pd

    feature_cols = ["f0"]
    seq_len = 3
    # exactly seq_len windows -> not enough for previous_sequence_and_actual (needs seq_len + 1)
    windows = pd.DataFrame({
        "src_ip": ["a"] * seq_len,
        "window_start": pd.date_range("2026-01-01", periods=seq_len, freq="10s"),
        "f0": [1.0, 2.0, 3.0],
    })
    assert previous_sequence_and_actual(windows, feature_cols, "a", seq_len) is None

    windows_plus_one = pd.concat([windows, pd.DataFrame({
        "src_ip": ["a"], "window_start": [pd.Timestamp("2026-01-01") + pd.Timedelta(seconds=30)], "f0": [4.0],
    })], ignore_index=True)
    result = previous_sequence_and_actual(windows_plus_one, feature_cols, "a", seq_len)
    assert result is not None
    prior, actual = result
    assert prior.shape == (seq_len, 1)
    np.testing.assert_array_equal(prior[:, 0], [1.0, 2.0, 3.0])
    assert actual[0] == 4.0


def test_latest_sequences_batch_matches_per_host_latest_sequence():
    import pandas as pd

    from models.forecast import latest_sequence

    feature_cols = ["f0", "f1"]
    seq_len = 4
    rows = []
    for host, n_windows in [("a", 6), ("b", 4), ("c", 2)]:  # c has too little history
        for i in range(n_windows):
            rows.append({
                "src_ip": host, "window_start": pd.Timestamp("2026-01-01") + pd.Timedelta(seconds=10 * i),
                "f0": float(i), "f1": float(i) * 2,
            })
    windows = pd.DataFrame(rows)

    host_ids, sequences = latest_sequences_batch(windows, feature_cols, seq_len)

    assert set(host_ids) == {"a", "b"}  # "c" excluded — fewer than seq_len windows
    assert sequences.shape == (2, seq_len, 2)
    for i, host in enumerate(host_ids):
        expected = latest_sequence(windows, feature_cols, host, seq_len)
        np.testing.assert_array_equal(sequences[i], expected)


def test_rollout_batch_matches_individual_rollout():
    n_features = 7
    engine = _engine(n_features)
    seq_a = np.random.randn(5, n_features).astype(np.float32)
    seq_b = np.random.randn(5, n_features).astype(np.float32)

    batch_result = engine.rollout_batch(["a", "b"], np.stack([seq_a, seq_b]))
    single_a = engine.rollout(seq_a)
    single_b = engine.rollout(seq_b)

    assert batch_result.host_ids == ["a", "b"]
    assert batch_result.infiltration_probs.shape == (2, 4)
    np.testing.assert_allclose(batch_result.infiltration_probs[0], single_a.infiltration_probs, atol=1e-5)
    np.testing.assert_allclose(batch_result.infiltration_probs[1], single_b.infiltration_probs, atol=1e-5)
    assert batch_result.stage_predictions[0] == single_a.stage_predictions
    assert batch_result.stage_predictions[1] == single_b.stage_predictions


def test_rollout_batch_chunking_gives_same_result_as_one_batch():
    n_features = 7
    engine = _engine(n_features)
    sequences = np.random.randn(5, 5, n_features).astype(np.float32)  # 5 hosts
    host_ids = [f"host{i}" for i in range(5)]

    one_chunk = engine.rollout_batch(host_ids, sequences, batch_size=2048)
    many_chunks = engine.rollout_batch(host_ids, sequences, batch_size=2)

    np.testing.assert_allclose(one_chunk.infiltration_probs, many_chunks.infiltration_probs, atol=1e-5)


def test_rollout_batch_empty_input():
    engine = _engine(7)
    result = engine.rollout_batch([], np.zeros((0, 5, 7), dtype=np.float32))
    assert result.host_ids == []
    assert result.infiltration_probs.shape == (0, 4)


def test_or_gate_alarm_fires_on_either_signal():
    from models.forecast import or_gate_alarm

    assert or_gate_alarm(infiltration_prob=0.9, reconstruction_error=0.0, prob_threshold=0.5, recon_threshold=1.0)
    assert or_gate_alarm(infiltration_prob=0.0, reconstruction_error=2.0, prob_threshold=0.5, recon_threshold=1.0)
    assert not or_gate_alarm(infiltration_prob=0.1, reconstruction_error=0.2, prob_threshold=0.5, recon_threshold=1.0)


def test_batched_reconstruction_errors_matches_one_step_version():
    from models.forecast import batched_reconstruction_errors

    n_features = 7
    engine = _engine(n_features)
    seq_len = CONFIG["windowing"]["sequence_length"]
    n = 10
    X = torch.randn(n, seq_len, n_features)
    next_state = torch.randn(n, n_features)

    errors = batched_reconstruction_errors(engine.model, X, next_state, device=engine.device, batch_size=3)

    assert errors.shape == (n,)
    assert np.all(errors >= 0) and np.all(np.isfinite(errors))
    # Cross-check row 0 against the single-sequence helper operating in the SAME (already-scaled)
    # space -- one_step_reconstruction_error itself calls scaler.transform, so use an identity
    # scaler here to make the two comparable.
    identity_scaler = FeatureScaler(mean=np.zeros(n_features), std=np.ones(n_features))
    manual = one_step_reconstruction_error(
        engine.model, identity_scaler, X[0].numpy(), next_state[0].numpy(),
    )
    assert abs(manual - float(errors[0])) < 1e-4
