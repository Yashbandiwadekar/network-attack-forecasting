"""Regression tests for dataset discovery, capability exposure, atomic switching, and rollback.

Covers:
1. Dataset discovery for CIC-IDS-2018, UNSW-NB15, CTU-13
2. Separation of dataset availability from model checkpoint availability
3. GET /api/v1/datasets API contract
4. GET /api/v1/datasets/diagnostics endpoint
5. POST /api/v1/datasets/select success case
6. POST /api/v1/datasets/select failure case (409 on missing checkpoint)
7. State integrity & atomic rollback (failed switch preserves previous valid dataset & model)
8. 404 handling on unknown dataset ID
9. Environment variable path override via resolve_path
"""
import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.server import app, STATE, _dataset_registry
from common.config import PROJECT_ROOT, load_config, resolve_path


@pytest.fixture
def client():
    # Ensure auth check is bypassed in tests unless explicitly testing auth
    old_auth = os.environ.get("PHOENIX_REQUIRE_AUTH")
    os.environ["PHOENIX_REQUIRE_AUTH"] = "0"
    yield TestClient(app)
    if old_auth is not None:
        os.environ["PHOENIX_REQUIRE_AUTH"] = old_auth
    else:
        os.environ.pop("PHOENIX_REQUIRE_AUTH", None)


def test_dataset_registry_discovery():
    """Verify all 3 datasets are discovered by the registry with capability metadata."""
    registry = _dataset_registry()
    dataset_ids = [d["id"] for d in registry]

    assert "CIC-IDS-2018" in dataset_ids
    assert "UNSW-NB15" in dataset_ids
    assert "CTU-13" in dataset_ids

    # CIC-IDS-2018 has a trained checkpoint on disk
    cic = next(d for d in registry if d["id"] == "CIC-IDS-2018")
    assert cic["checkpoint_loaded"] is True
    assert cic["checkpoint_available"] is True
    assert cic["can_select"] is True
    assert cic["can_forecast"] is True
    assert cic["status"] == "Available"
    assert cic["total_sequences"] is not None
    assert cic["features"] == 41

    # UNSW-NB15 has no checkpoint on this installation
    unsw = next(d for d in registry if d["id"] == "UNSW-NB15")
    assert unsw["checkpoint_loaded"] is False
    assert unsw["checkpoint_available"] is False
    assert unsw["can_select"] is True
    assert unsw["can_forecast"] is False
    assert unsw["reason"] is not None

    # CTU-13 has no checkpoint on this installation
    ctu = next(d for d in registry if d["id"] == "CTU-13")
    assert ctu["checkpoint_loaded"] is False
    assert ctu["checkpoint_available"] is False
    assert ctu["can_select"] is True
    assert ctu["can_forecast"] is False


def test_get_datasets_endpoint(client):
    """GET /api/v1/datasets returns active dataset and rich capabilities."""
    res = client.get("/api/v1/datasets")
    assert res.status_code == 200
    data = res.json()

    assert "active_dataset" in data
    assert "datasets" in data
    assert len(data["datasets"]) >= 3

    for entry in data["datasets"]:
        assert "id" in entry
        assert "name" in entry
        assert "config" in entry
        assert "status" in entry
        assert "checkpoint_loaded" in entry
        assert "dataset_available" in entry
        assert "checkpoint_available" in entry
        assert "can_select" in entry
        assert "can_forecast" in entry


def test_get_dataset_diagnostics_endpoint(client):
    """GET /api/v1/datasets/diagnostics returns filesystem diagnostics."""
    res = client.get("/api/v1/datasets/diagnostics")
    assert res.status_code == 200
    data = res.json()

    assert "active_dataset" in data
    assert "active_config" in data
    assert "project_root" in data
    assert "environment_overrides" in data
    assert "datasets" in data


def test_select_valid_dataset(client):
    """Switching to CIC-IDS-2018 (which has an active checkpoint) succeeds."""
    res = client.post("/api/v1/datasets/select", json={"dataset_id": "CIC-IDS-2018"})
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "success"
    assert body["active_dataset"] == "CIC-IDS-2018"
    assert STATE.dataset_id == "CIC-IDS-2018"
    assert STATE.config_path == "configs/real_data.yaml"


def test_select_missing_checkpoint_fails_with_409(client):
    """Switching to UNSW-NB15 returns 409 Conflict with informative explanation."""
    res = client.post("/api/v1/datasets/select", json={"dataset_id": "UNSW-NB15"})
    assert res.status_code == 409
    body = res.json()
    assert "UNSW-NB15 could not be activated" in body["detail"]
    assert "forecasting checkpoint" in body["detail"]


def test_select_dataset_atomic_rollback(client):
    """A failed switch leaves the previous valid dataset and model completely intact."""
    # Ensure starting in a valid CIC-IDS-2018 state
    client.post("/api/v1/datasets/select", json={"dataset_id": "CIC-IDS-2018"})
    assert STATE.dataset_id == "CIC-IDS-2018"
    assert STATE.config_path == "configs/real_data.yaml"

    # Attempt to switch to CTU-13 (fails due to missing checkpoint)
    res = client.post("/api/v1/datasets/select", json={"dataset_id": "CTU-13"})
    assert res.status_code == 409

    # Verify state was NOT mutated
    assert STATE.dataset_id == "CIC-IDS-2018"
    assert STATE.config_path == "configs/real_data.yaml"


def test_select_unknown_dataset_fails_with_404(client):
    """Attempting to select an unregistered dataset returns 404."""
    res = client.post("/api/v1/datasets/select", json={"dataset_id": "Unknown-999"})
    assert res.status_code == 404
    assert res.json()["detail"] == "Dataset not found"


def test_resolve_path_environment_override():
    """Setting PHOENIX_CHECKPOINT_DIR or PHOENIX_DATA_DIR overrides path resolution."""
    config = load_config("configs/real_data.yaml")

    # Default resolution
    default_ckpt = resolve_path(config, "checkpoint_dir")
    assert default_ckpt == PROJECT_ROOT / "checkpoints_real"

    # Environment override
    custom_dir = PROJECT_ROOT / "custom_checkpoints"
    os.environ["PHOENIX_CHECKPOINT_DIR"] = str(custom_dir)
    try:
        resolved = resolve_path(config, "checkpoint_dir")
        assert resolved == custom_dir
    finally:
        os.environ.pop("PHOENIX_CHECKPOINT_DIR", None)
