from pipeline.mitre_mapping import (
    BENIGN, COMMAND_AND_CONTROL, IMPACT, INITIAL_ACCESS, LATERAL_MOVEMENT,
    STAGE_CLASSIFICATION_LABELS, label_to_stage, stage_to_index,
)


def test_benign_maps_to_benign():
    assert label_to_stage("BENIGN") == BENIGN


def test_bruteforce_maps_to_initial_access():
    assert label_to_stage("SSH-Bruteforce") == INITIAL_ACCESS
    assert label_to_stage("FTP-BruteForce") == INITIAL_ACCESS


def test_infiltration_maps_to_lateral_movement():
    assert label_to_stage("Infilteration") == LATERAL_MOVEMENT  # dataset's actual spelling
    assert label_to_stage("Infiltration") == LATERAL_MOVEMENT


def test_bot_maps_to_c2():
    assert label_to_stage("Bot") == COMMAND_AND_CONTROL


def test_dos_maps_to_impact_not_a_ps_stage():
    assert label_to_stage("DoS attacks-Hulk") == IMPACT
    assert IMPACT not in STAGE_CLASSIFICATION_LABELS


def test_unknown_label_falls_back_to_impact_not_benign():
    assert label_to_stage("Some-Future-Attack-Type") == IMPACT


def test_stage_to_index_excludes_impact():
    assert stage_to_index(IMPACT) is None
    assert stage_to_index(BENIGN) == 0


def test_whitespace_is_stripped():
    assert label_to_stage("  BENIGN  ") == BENIGN
