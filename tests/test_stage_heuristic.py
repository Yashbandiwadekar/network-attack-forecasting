import numpy as np

from models.dataset import FeatureScaler
from models.forecast import ForecastEngine, _heuristic_stage_override
from models.world_model import WorldModel

FEATURE_NAMES = ["flow_count", "unique_dst_ips", "total_bytes", "total_packets", "port_scan_score", "other"]
FEATURE_INDEX = {name: i for i, name in enumerate(FEATURE_NAMES)}

FULL_CONFIG = {
    "windowing": {
        "sequence_length": 5, "forecast_horizon": 4,
        "recon_port_scan_threshold": 0.5, "impact_volume_zscore": 4.0,
    },
    "model": {"d_model": 16, "n_heads": 2, "n_layers": 2, "d_ff": 32, "dropout": 0.0},
    "mitre_stages": ["benign", "reconnaissance", "initial_access", "lateral_movement", "command_and_control", "exfiltration"],
    "features": {
        "flow_level": ["flow_count", "unique_dst_ips", "total_bytes", "total_packets", "other"],
        "packet_level": ["port_scan_score"],
    },
}

MINIMAL_CONFIG = {  # matches tests/test_forecast_rollout.py's CONFIG -- no `features` section at all
    "windowing": {"sequence_length": 5, "forecast_horizon": 4},
    "model": {"d_model": 16, "n_heads": 2, "n_layers": 2, "d_ff": 32, "dropout": 0.0},
    "mitre_stages": ["benign", "reconnaissance", "initial_access", "lateral_movement", "command_and_control", "exfiltration"],
}


def _zero_mean_unit_std_scaler(n: int) -> FeatureScaler:
    # mean=0, std=1 so raw feature values ARE their own z-scores, for arithmetic simplicity below.
    return FeatureScaler(mean=np.zeros(n), std=np.ones(n))


def _raw(**overrides) -> np.ndarray:
    row = {name: 0.0 for name in FEATURE_NAMES}
    row.update(overrides)
    return np.array([row[name] for name in FEATURE_NAMES])


# ---------------------------------------------------------------------------
# _heuristic_stage_override as a pure function (audit S6/S7)
# ---------------------------------------------------------------------------

def test_extreme_volume_low_destination_diversity_overrides_to_impact():
    scaler = _zero_mean_unit_std_scaler(len(FEATURE_NAMES))
    raw = _raw(flow_count=10.0, total_bytes=10.0, total_packets=10.0, unique_dst_ips=0.0)

    stage, was_heuristic = _heuristic_stage_override(raw, FEATURE_INDEX, scaler, FULL_CONFIG, "command_and_control")

    assert stage == "impact"
    assert was_heuristic is True


def test_override_gated_off_below_alert_threshold():
    # Audit G7: even a textbook flood signature must not override the stage when the model's own
    # infiltration probability is below the alert threshold (default 0.3) -- a stage label can
    # never contradict a "not flagged" score.
    scaler = _zero_mean_unit_std_scaler(len(FEATURE_NAMES))
    raw = _raw(flow_count=10.0, total_bytes=10.0, total_packets=10.0, unique_dst_ips=0.0)

    stage, was_heuristic = _heuristic_stage_override(
        raw, FEATURE_INDEX, scaler, FULL_CONFIG, "command_and_control", infiltration_prob=0.1,
    )

    assert was_heuristic is False
    assert stage == "command_and_control"  # unchanged, not overridden


def test_override_fires_above_alert_threshold():
    scaler = _zero_mean_unit_std_scaler(len(FEATURE_NAMES))
    raw = _raw(flow_count=10.0, total_bytes=10.0, total_packets=10.0, unique_dst_ips=0.0)

    stage, was_heuristic = _heuristic_stage_override(
        raw, FEATURE_INDEX, scaler, FULL_CONFIG, "command_and_control", infiltration_prob=0.9,
    )

    assert was_heuristic is True
    assert stage == "impact"


def test_high_volume_but_high_destination_diversity_is_not_impact():
    # High volume alone isn't enough -- a genuine flood also concentrates on very few destinations
    # (the opposite of a scan). Spread across many destinations looks more like a scan/legit burst.
    scaler = _zero_mean_unit_std_scaler(len(FEATURE_NAMES))
    raw = _raw(flow_count=10.0, total_bytes=10.0, total_packets=10.0, unique_dst_ips=10.0)

    stage, was_heuristic = _heuristic_stage_override(raw, FEATURE_INDEX, scaler, FULL_CONFIG, "command_and_control")

    assert was_heuristic is False
    assert stage == "command_and_control"  # unchanged


def test_high_port_scan_score_overrides_to_reconnaissance():
    scaler = _zero_mean_unit_std_scaler(len(FEATURE_NAMES))
    raw = _raw(port_scan_score=0.9)

    stage, was_heuristic = _heuristic_stage_override(raw, FEATURE_INDEX, scaler, FULL_CONFIG, "benign")

    assert stage == "reconnaissance"
    assert was_heuristic is True


def test_ordinary_traffic_is_never_overridden():
    scaler = _zero_mean_unit_std_scaler(len(FEATURE_NAMES))
    raw = _raw(flow_count=0.1, port_scan_score=0.05)

    stage, was_heuristic = _heuristic_stage_override(raw, FEATURE_INDEX, scaler, FULL_CONFIG, "benign")

    assert stage == "benign"
    assert was_heuristic is False


def test_zero_fed_port_scan_score_never_fires_without_pcap():
    # Matches the training-time heuristic's documented limitation (docs/03-mitre-mapping.md):
    # flow-only mode zero-fills port_scan_score, so it can never cross the threshold.
    scaler = _zero_mean_unit_std_scaler(len(FEATURE_NAMES))
    raw = _raw(port_scan_score=0.0)

    stage, was_heuristic = _heuristic_stage_override(raw, FEATURE_INDEX, scaler, FULL_CONFIG, "benign")

    assert was_heuristic is False


# ---------------------------------------------------------------------------
# Wiring into ForecastEngine
# ---------------------------------------------------------------------------

def _engine(config, n_features):
    model = WorldModel(n_features, len(config["mitre_stages"]), config)
    model.eval()
    scaler = _zero_mean_unit_std_scaler(n_features)
    return ForecastEngine(model, scaler, config)


def test_engine_builds_feature_index_when_config_has_features_section():
    engine = _engine(FULL_CONFIG, n_features=6)
    assert engine._feature_index is not None
    assert engine._feature_index["port_scan_score"] == 5  # last flow_level entries then packet_level


def test_engine_skips_heuristic_gracefully_without_features_section():
    """The pre-existing minimal test config (tests/test_forecast_rollout.py) has no `features`
    key at all -- the heuristic must disable itself, not crash feature_columns()'s KeyError."""
    engine = _engine(MINIMAL_CONFIG, n_features=7)
    assert engine._feature_index is None

    stage, was_heuristic = engine._override_stage(np.zeros(7), "command_and_control")
    assert stage == "command_and_control"
    assert was_heuristic is False


def test_engine_override_stage_delegates_to_heuristic_function():
    engine = _engine(FULL_CONFIG, n_features=6)
    raw = _raw(flow_count=10.0, total_bytes=10.0, total_packets=10.0, unique_dst_ips=0.0)

    stage, was_heuristic = engine._override_stage(raw, "command_and_control")

    assert stage == "impact"
    assert was_heuristic is True
