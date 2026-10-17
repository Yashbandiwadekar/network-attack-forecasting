"""docs/09 A2: model bundles (common/bundle.py, scripts/make_model_bundle.py, scripts/bench_cpu.py).

Uses a tiny synthetic checkpoint so it runs anywhere (no trained weights, no data/, no V:)."""
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import numpy as np
import pytest
import torch
import yaml
from fastapi.testclient import TestClient

from app import service
from common import bundle as bundle_mod
from common.bundle import BundleError, build_bundle, make_archive, verify_bundle
from common.config import PROJECT_ROOT, feature_columns, load_config, resolve_path
from models.checkpoint_io import with_config_json
from models.world_model import WorldModel

SRC_CONFIG = PROJECT_ROOT / "configs" / "real_data_v2_converged_seed1.yaml"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for v in bundle_mod.ENV_OVERRIDES + ("PHOENIX_BUNDLE", "PHOENIX_CONFIG", "PHOENIX_STATE_DIR"):
        monkeypatch.delenv(v, raising=False)
    service.clear_backend_cache()
    yield
    service.clear_backend_cache()


@pytest.fixture
def src(tmp_path):
    """A tiny trained-looking model laid out like a real config's checkpoint_dir + processed_dir."""
    cfg = yaml.safe_load(SRC_CONFIG.read_text(encoding="utf-8"))
    cfg["model"].update(d_model=16, n_heads=2, n_layers=1, d_ff=32)
    names = feature_columns(cfg)
    ck_dir, proc = tmp_path / "ck", tmp_path / "proc"
    ck_dir.mkdir()
    proc.mkdir()
    cfg["paths"].update(checkpoint_dir=str(ck_dir), processed_dir=str(proc))
    torch.manual_seed(0)
    model = WorldModel(len(names), len(cfg["mitre_stages"]), cfg)
    torch.save(with_config_json({"model_state": model.state_dict(), "n_features": len(names),
                                 "n_stage_classes": len(cfg["mitre_stages"]), "feature_names": names,
                                 "config": cfg}), ck_dir / "world_model_best.pt")
    np.savez(proc / "scaler.npz", mean=np.zeros(len(names)), std=np.ones(len(names)), clip_std=6.0)
    (proc / "metadata.json").write_text(json.dumps({"feature_columns": names, "flow_only": True,
                                                    "packet_features_available": False}), encoding="utf-8")
    cfg_path = tmp_path / "tiny.yaml"
    cfg_path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return cfg_path


@pytest.fixture
def bundle(src, tmp_path):
    out = tmp_path / "dist" / "tinybundle"
    build_bundle(src, out)
    return out


def _flip_byte(path: Path, offset: int = 100):
    data = bytearray(path.read_bytes())
    data[offset] ^= 0x01
    path.write_bytes(bytes(data))


def test_bundle_contents_and_manifest(bundle):
    m = json.loads((bundle / "MANIFEST.json").read_text(encoding="utf-8"))
    assert {f["path"] for f in m["files"]} == {"config.yaml", "checkpoint/world_model_best.pt",
                                              "processed/scaler.npz", "processed/metadata.json"}
    assert m["n_features"] == len(m["feature_names"]) == 41 and m["model_name"] == "tinybundle"
    assert all(len(f["sha256"]) == 64 and f["size"] > 0 for f in m["files"])
    assert not (bundle / "processed" / "shap_background.npy").exists()  # QC-20: unused, not shipped
    assert {p.name for p in bundle.rglob("*.npz")} == {"scaler.npz"}
    assert verify_bundle(bundle)["checksums_ok"] is True


def test_roundtrip_load_and_forecast_without_source_files(bundle, src, tmp_path):
    # Delete the source files entirely: the bundle must stand alone.
    for p in list((tmp_path / "ck").iterdir()) + list((tmp_path / "proc").iterdir()):
        p.unlink()
    config, model, scaler, background = service.load_backend(str(bundle / "config.yaml"))
    assert model is not None and scaler is not None and background is None
    assert config["_bundle_dir"] == str(bundle.resolve())
    status = service.bundle_status(config)
    assert status["checksums_ok"] and status["schema_ok"] and status["encoder_fingerprint_ok"]
    from models.forecast import ForecastEngine
    seq = np.zeros((config["windowing"]["sequence_length"], 41), dtype=np.float32)
    res = ForecastEngine(model, scaler, config).rollout(seq)
    assert len(res.infiltration_probs) == config["windowing"]["forecast_horizon"]


def test_bundle_config_ignores_global_env_overrides(bundle, monkeypatch, tmp_path):
    """QC-11: global overrides must not redirect a bundle (it would silently load other weights)."""
    monkeypatch.setenv("PHOENIX_CHECKPOINT_DIR", str(tmp_path / "elsewhere"))
    monkeypatch.setenv("PHOENIX_PROCESSED_DIR", str(tmp_path / "elsewhere"))
    monkeypatch.setenv("PHOENIX_DATA_DIR", str(tmp_path / "elsewhere"))
    config = load_config(bundle / "config.yaml")
    assert resolve_path(config, "checkpoint_dir") == bundle.resolve() / "checkpoint"
    assert resolve_path(config, "processed_dir") == bundle.resolve() / "processed"
    assert service.load_backend(str(bundle / "config.yaml"))[1] is not None


def test_flow_only_guard_survives_bundle_without_data_dir(bundle):
    """G11/W3: is_flow_only_model fails open (False) when metadata.json is unreadable. In a bundle it must be True."""
    config = load_config(bundle / "config.yaml")
    assert service.is_flow_only_model(config) is True


@pytest.mark.parametrize("victim", ["checkpoint/world_model_best.pt", "processed/scaler.npz",
                                    "processed/metadata.json", "config.yaml"])
def test_tampering_one_byte_fails_loudly(bundle, victim):
    _flip_byte(bundle / victim, offset=10)
    with pytest.raises(BundleError, match="SHA256 mismatch"):
        verify_bundle(bundle)
    service.clear_backend_cache()
    with pytest.raises(BundleError):
        service.load_backend(str(bundle / "config.yaml"))  # raised, not swallowed into (config, None, None, None)


def test_truncated_and_missing_files_fail(bundle):
    p = bundle / "processed" / "scaler.npz"
    p.write_bytes(p.read_bytes()[:-1])
    with pytest.raises(BundleError, match="Size mismatch"):
        verify_bundle(bundle)
    p.unlink()
    with pytest.raises(BundleError, match="missing"):
        verify_bundle(bundle)


def test_feature_schema_mismatch_fails(bundle):
    mf = bundle / "MANIFEST.json"
    m = json.loads(mf.read_text(encoding="utf-8"))
    m["feature_names"][0], m["feature_names"][1] = m["feature_names"][1], m["feature_names"][0]  # same width, wrong order
    mf.write_text(json.dumps(m), encoding="utf-8")
    with pytest.raises(BundleError, match="Feature schema mismatch"):
        verify_bundle(bundle)


def test_encoder_fingerprint_drift_fails(bundle):
    mf = bundle / "MANIFEST.json"
    m = json.loads(mf.read_text(encoding="utf-8"))
    m["graph_embedding_encoder"]["sha256"] = "0" * 64
    m["graph_embedding_encoder"]["params"][0]["sum"] += 1.0
    mf.write_text(json.dumps(m), encoding="utf-8")
    with pytest.raises(BundleError, match="encoder fingerprint"):
        verify_bundle(bundle)


def test_manifest_path_traversal_rejected(bundle):
    mf = bundle / "MANIFEST.json"
    m = json.loads(mf.read_text(encoding="utf-8"))
    m["files"].append({"path": "../outside.txt", "size": 0, "sha256": "0" * 64})
    mf.write_text(json.dumps(m), encoding="utf-8")
    with pytest.raises(BundleError, match="escapes"):
        verify_bundle(bundle)


def test_build_refuses_env_overrides_and_nonempty_out(src, tmp_path, monkeypatch):
    monkeypatch.setenv("PHOENIX_PROCESSED_DIR", str(tmp_path))
    with pytest.raises(BundleError, match="QC-11"):
        build_bundle(src, tmp_path / "o1")
    monkeypatch.delenv("PHOENIX_PROCESSED_DIR")
    out = tmp_path / "o2"
    out.mkdir()
    (out / "x").write_text("x")
    with pytest.raises(BundleError, match="not empty"):
        build_bundle(src, out)


def test_archive_roundtrip(bundle, tmp_path):
    (bundle / "state").mkdir()
    (bundle / "state" / "audit_ledger.jsonl").write_text("secret")
    arc = tmp_path / "b.tar.gz"
    digest = make_archive(bundle, arc)
    assert len(digest) == 64
    dest = tmp_path / "unpacked"
    with tarfile.open(arc) as t:
        t.extractall(dest, filter="data")
    assert not (dest / bundle.name / "state").exists()
    assert verify_bundle(dest / bundle.name)["checksums_ok"]


def test_server_loads_bundle_and_health_reports_checksum(bundle, monkeypatch):
    from app import server
    monkeypatch.setenv("PHOENIX_BUNDLE", str(bundle))
    path = server.resolve_config_choice()
    assert path == str((bundle / "config.yaml").resolve())
    monkeypatch.setenv("PHOENIX_REQUIRE_AUTH", "0")
    monkeypatch.setattr(server.STATE, "config_path", path)
    monkeypatch.setattr(server.STATE, "dataset_id", bundle.name)
    server.check_model_artifacts(path)
    client = TestClient(server.app)
    h = client.get("/api/v1/health").json()
    assert h["checkpoint_loaded"] and h["model_name"] == "tinybundle"
    assert h["bundle"]["checksums_ok"] and h["bundle"]["manifest_sha256"]
    ds = client.get("/api/v1/datasets").json()["datasets"]
    assert [d["id"] for d in ds] == ["tinybundle"] and ds[0]["can_forecast"]
    # the audit ledger goes to <bundle>/state, outside the manifest, so writing it keeps the bundle valid
    assert server._ledger_path() == bundle.resolve() / "state" / "audit_ledger.jsonl"
    verify_bundle(bundle)


def test_server_refuses_tampered_bundle_at_startup(bundle):
    from app import server
    _flip_byte(bundle / "checkpoint" / "world_model_best.pt")
    with pytest.raises(BundleError):
        server.check_model_artifacts(str((bundle / "config.yaml").resolve()))


def test_bundle_and_config_together_is_ambiguous(bundle, monkeypatch):
    from app import server
    monkeypatch.setenv("PHOENIX_BUNDLE", str(bundle))
    monkeypatch.setenv("PHOENIX_CONFIG", "v1")
    with pytest.raises(server.ModelUnavailableError, match="Both"):
        server.resolve_config_choice()
    monkeypatch.delenv("PHOENIX_CONFIG")
    monkeypatch.setenv("PHOENIX_BUNDLE", str(bundle / "nope"))
    with pytest.raises(server.ModelUnavailableError, match="not a model bundle"):
        server.resolve_config_choice()


def test_bench_cpu_smoke(bundle, tmp_path):
    """Subprocess, so CUDA is hidden before torch is imported (as on the laptop)."""
    out = tmp_path / "bench"
    r = subprocess.run([sys.executable, "-m", "scripts.bench_cpu", "--bundle", str(bundle), "--out-dir", str(out),
                        "--single-iters", "5", "--batch-iters", "2", "--explain-iters", "3", "--warmup", "1",
                        "--hosts", "1,4", "--threads", "2"],
                       cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stderr[-2000:]
    js = list(out.glob("bench_cpu_*.json"))
    assert len(js) == 1 and list(out.glob("bench_cpu_*.md"))
    data = json.loads(js[0].read_text(encoding="utf-8"))
    assert data["software"]["cuda_available"] is False and data["software"]["model_device"] == "cpu"
    assert data["software"]["torch_threads"] == 2 and data["hardware"]["cpu_model"]
    assert data["bundle"]["checksums_ok"] is True
    res = data["results"]
    for k in ("single_host_rollout", "explain_gradient_x_input", "explain_endpoint_equivalent"):
        assert res[k]["p50_ms"] > 0 and res[k]["p99_ms"] >= res[k]["p50_ms"]
    assert set(res["batched_rollout"]) == {"1", "4"}
    assert data["model_load_seconds"]["load_checkpoint_and_scaler"] >= 0 and data["peak_rss_mb"]
