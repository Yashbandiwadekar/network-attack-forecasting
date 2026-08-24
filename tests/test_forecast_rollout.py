import numpy as np
import torch

from models.dataset import FeatureScaler
from models.forecast import ForecastEngine
from models.world_model import WorldModel

CONFIG = {
    "windowing": {"sequence_length": 5, "forecast_horizon": 4},
    "model": {"d_model": 16, "n_heads": 2, "n_layers": 2, "d_ff": 32, "dropout": 0.0},
    "mitre_stages": ["benign", "reconnaissance", "initial_access", "lateral_movement", "command_and_control", "exfiltration"],
}


def _engine(n_features=7):
    model = WorldModel(n_features, len(CONFIG["mitre_stages"]), CONFIG)
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
    assert np.all((result.infiltration_probs >= 0) & (result.infiltration_probs <= 1))
    assert all(s in CONFIG["mitre_stages"] for s in result.stage_predictions)


def test_stage_probs_are_valid_distributions():
    engine = _engine()
    raw_sequence = np.random.randn(5, 7).astype(np.float32)
    result = engine.rollout(raw_sequence)
    np.testing.assert_allclose(result.stage_probs.sum(axis=-1), 1.0, atol=1e-5)


def test_rollout_is_deterministic_in_eval_mode():
    engine = _engine()
    raw_sequence = np.random.randn(5, 7).astype(np.float32)
    r1 = engine.rollout(raw_sequence)
    r2 = engine.rollout(raw_sequence)
    np.testing.assert_allclose(r1.infiltration_probs, r2.infiltration_probs)
