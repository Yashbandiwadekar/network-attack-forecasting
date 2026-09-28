"""Audit W19: close the schema-drift class (S13, G11, H3, the a60c549 merge bug), not just the
fourth instance of it.

1. `models/checkpoint_io.py::validate_feature_names` raises a clear error at load time when a
   checkpoint's own stored feature list disagrees with what's being checked against it -- by
   NAME and ORDER, not just count, since a right-width-wrong-column matrix is exactly what every
   prior instance of this bug produced.
2. A grep-based check that no module outside common/config.py builds a model input by hand-picking
   `config["features"]["flow_level"]` (or similar) instead of calling
   `common.config.feature_columns(config)`, the one supported way to assemble a model input.
"""
import subprocess
import sys
from pathlib import Path

import pytest

from models.checkpoint_io import validate_feature_names

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_matching_feature_names_passes():
    checkpoint = {"feature_names": ["a", "b", "c"]}
    validate_feature_names(checkpoint, ["a", "b", "c"])  # must not raise


def test_checkpoint_without_feature_names_is_not_checked():
    validate_feature_names({}, ["a", "b", "c"])  # older checkpoint -- passed through, not raised


def test_wrong_column_list_raises_a_clear_error_at_load_time():
    checkpoint = {"feature_names": ["flow_count", "total_bytes", "graph_embed_0"]}
    wrong = ["flow_count", "total_bytes", "wrong_column"]  # same width, one column swapped
    with pytest.raises(ValueError, match="Feature schema mismatch"):
        validate_feature_names(checkpoint, wrong)


def test_wrong_order_raises_even_at_matching_width_and_names():
    checkpoint = {"feature_names": ["a", "b"]}
    with pytest.raises(ValueError, match="Feature schema mismatch"):
        validate_feature_names(checkpoint, ["b", "a"])  # same set, wrong order


def test_no_module_hand_picks_flow_level_only_as_a_model_input():
    """Grep-based (audit W19 explicitly accepts this as honest): the only place
    `config["features"]["flow_level"]` may be read without going through feature_columns() is
    common/config.py itself, which defines feature_columns() in terms of it."""
    result = subprocess.run(
        ["git", "grep", "-n", "--", r'features"\]\["flow_level"\]',
         "*.py", ":!tests/test_feature_schema_guard.py"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    code_hits = [
        line for line in result.stdout.splitlines()
        if line and not line.startswith("common/config.py:")
    ]
    assert code_hits == [], f"found a hand-picked flow_level-only feature matrix outside common/config.py: {code_hits}"
