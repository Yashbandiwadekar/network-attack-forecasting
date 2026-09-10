import numpy as np

from models.forecast import ForecastResult
from models.narrative import generate_attack_narrative
from models.response import RESPONSE_PLAYBOOK, recommended_action
from pipeline.mitre_mapping import (
    BENIGN, COMMAND_AND_CONTROL, EXFILTRATION, IMPACT, INITIAL_ACCESS, LATERAL_MOVEMENT, RECONNAISSANCE,
    STAGE_CLASSIFICATION_LABELS,
)


def test_recommended_action_covers_every_classification_stage_and_impact():
    for stage in STAGE_CLASSIFICATION_LABELS + [IMPACT]:
        assert stage in RESPONSE_PLAYBOOK, f"no playbook entry for stage {stage}"
        action = recommended_action(stage)
        assert action["action"]
        assert action["detail"] != "No playbook entry for this stage."


def test_recommended_action_falls_back_gracefully_for_unknown_stage():
    action = recommended_action("not_a_real_stage")
    assert "Manual review" in action["action"]


def test_benign_action_says_no_action_needed():
    assert recommended_action(BENIGN)["action"] == "No action needed"


def _fake_result(K=4, L=5, n_features=3, infiltration_probs=None) -> ForecastResult:
    infiltration_probs = np.asarray(infiltration_probs if infiltration_probs is not None else [0.1] * K)
    attentions = np.zeros((K, L), dtype=np.float32)
    attentions[:, -1] = 1.0  # all attention on the most recent window, trivially valid distribution
    return ForecastResult(
        infiltration_probs=infiltration_probs,
        stage_predictions=[RECONNAISSANCE, INITIAL_ACCESS, LATERAL_MOVEMENT, COMMAND_AND_CONTROL][:K],
        stage_probs=np.tile(np.eye(1, len(STAGE_CLASSIFICATION_LABELS), 0), (K, 1)),
        attentions=attentions,
        transition_magnitude=np.ones(K),
        state_deltas=np.arange(K * n_features, dtype=np.float32).reshape(K, n_features),
    )


def test_narrative_mentions_host_stage_and_recommended_action():
    result = _fake_result(infiltration_probs=[0.1, 0.4, 0.7, 0.9])
    feature_cols = ["syn_ratio", "unique_dst_ports", "total_bytes"]
    text = generate_attack_narrative("10.0.0.5", result, feature_cols, window_seconds=10, current_stage=RECONNAISSANCE)

    assert "10.0.0.5" in text
    assert "reconnaissance" in text
    assert "rising" in text  # 0.9 > 0.1 + 0.05
    peak_action = recommended_action(result.stage_predictions[-1])["action"]
    assert peak_action in text


def test_narrative_falling_trend_and_benign_opening():
    result = _fake_result(infiltration_probs=[0.9, 0.6, 0.3, 0.1])
    feature_cols = ["syn_ratio", "unique_dst_ports", "total_bytes"]
    text = generate_attack_narrative("10.0.0.9", result, feature_cols, window_seconds=10, current_stage=None)

    assert "within normal bounds" in text
    assert "falling" in text


def test_narrative_never_crashes_on_minimal_horizon():
    result = _fake_result(K=1, infiltration_probs=[0.5])
    text = generate_attack_narrative("10.0.0.1", result, ["a", "b", "c"], window_seconds=10)
    assert isinstance(text, str) and len(text) > 0
