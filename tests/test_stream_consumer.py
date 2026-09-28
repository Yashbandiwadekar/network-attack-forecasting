"""Audit H3/W15: scripts/stream_consumer.py must assemble the SAME feature width and column
order the checkpoint was trained with (common.config.feature_columns), not a hand-picked
flow_level-only subset zero-padded to fit."""
from common.config import feature_columns, load_config
from models.dataset import FeatureScaler
from pipeline.flow_features import clean_and_normalize, load_flow_csv
from scripts.stream_consumer import _build_batch_windows


def test_assembled_matrix_width_matches_checkpoint_in_features():
    config = load_config("configs/default.yaml")
    scaler = FeatureScaler.load("data/processed/cicids2018/splits/scaler.npz")
    cols = feature_columns(config)
    assert len(cols) == len(scaler.mean)

    df = clean_and_normalize(load_flow_csv("data/raw/flows/synthetic_sample.csv", require_label=False))
    batch = df.sort_values("timestamp").iloc[:200]
    windows = _build_batch_windows(batch, config)

    for col in cols:
        assert col in windows.columns, f"{col} missing from assembled window columns"
    assert (windows["graph_embed_0"] != 0).any(), "graph-embedding columns must not be all-zero (H3)"
