"""Self-contained model bundles (docs/09 A2, docs/10).

A bundle is the minimum a machine needs to SERVE one model, with no data/ folder, no V: drive and
no GPU:

    <bundle>/
      MANIFEST.json                  file list + sizes + SHA256, feature schema, git commit, ...
      config.yaml                    the model's config, copied verbatim
      checkpoint/world_model_best.pt
      processed/scaler.npz
      processed/metadata.json        read by app.service.is_flow_only_model (G11 guard)
      state/                         created at run time (audit ledger); NOT part of the manifest

Deliberately NOT included: shap_background.npy (the API never uses it -- every caller of
service.load_backend discards the 4th value, QC-20), train/val/test.npz and window_graphs.pkl
(training only). The graph-embedding features need no file either: the GraphSAGE encoder is
re-derived from a fixed seed at inference time (pipeline/graph_embedding_features._frozen_encoder),
so the manifest stores a numeric FINGERPRINT of those re-derived weights and verify_bundle()
recomputes it -- a different torch build that drew different random weights would otherwise
silently shift every graph_embed_* column.

verify_bundle() raises BundleError (a RuntimeError) on ANY mismatch; nothing here swallows errors.
"""
from __future__ import annotations

import hashlib
import json
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

MANIFEST_NAME = "MANIFEST.json"
FORMAT_VERSION = 1
CHECKPOINT_REL = "checkpoint/world_model_best.pt"
SCALER_REL = "processed/scaler.npz"
METADATA_REL = "processed/metadata.json"
CONFIG_REL = "config.yaml"
REQUIRED_FILES = (CONFIG_REL, CHECKPOINT_REL, SCALER_REL, METADATA_REL)
ENV_OVERRIDES = (
    "PHOENIX_CHECKPOINT_DIR", "PHOENIX_MODEL_DIR", "PHOENIX_CHECKPOINTS_DIR",
    "PHOENIX_PROCESSED_DIR", "PHOENIX_DATA_DIR", "PHOENIX_RAW_FLOW_DIR", "PHOENIX_RAW_PCAP_DIR",
)
_ENCODER_RTOL = 1e-4


class BundleError(RuntimeError):
    """The bundle is missing, tampered with, or inconsistent with its own manifest."""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _git(*args: str) -> str | None:
    try:
        root = Path(__file__).resolve().parent.parent
        out = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, timeout=20)
        return out.stdout.strip() if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def encoder_fingerprint() -> dict[str, Any]:
    """Numeric fingerprint of the frozen graph-embedding encoder as re-derived in THIS process."""
    from pipeline.graph_embedding_features import GRAPH_EMBED_SEED, _frozen_encoder

    params = []
    h = hashlib.sha256()
    for name, p in _frozen_encoder().named_parameters():
        arr = p.detach().cpu().numpy().astype(np.float32)
        h.update(name.encode()); h.update(arr.tobytes())
        params.append({"name": name, "shape": list(arr.shape),
                       "sum": float(arr.sum(dtype=np.float64)),
                       "abs_sum": float(np.abs(arr).sum(dtype=np.float64))})
    return {"seed": GRAPH_EMBED_SEED, "sha256": h.hexdigest(), "params": params}


def _fingerprints_match(a: dict[str, Any], b: dict[str, Any]) -> bool:
    if a["sha256"] == b["sha256"]:
        return True
    if [p["name"] for p in a["params"]] != [p["name"] for p in b["params"]]:
        return False
    return all(
        pa["shape"] == pb["shape"]
        and np.isclose(pa["sum"], pb["sum"], rtol=_ENCODER_RTOL, atol=1e-5)
        and np.isclose(pa["abs_sum"], pb["abs_sum"], rtol=_ENCODER_RTOL, atol=1e-5)
        for pa, pb in zip(a["params"], b["params"])
    )


def bundle_dir_of(config_path: str | Path) -> Path | None:
    """The bundle directory if `config_path` is a bundle's config.yaml, else None."""
    p = Path(config_path)
    return p.parent.resolve() if p.name == "config.yaml" and (p.parent / MANIFEST_NAME).is_file() else None


def build_bundle(config_path: str | Path, out_dir: str | Path, name: str | None = None) -> dict[str, Any]:
    """Copy exactly what inference needs from a config's checkpoint/processed dirs into `out_dir`
    and write MANIFEST.json. Returns the manifest."""
    import os
    from common.config import feature_columns, load_config, resolve_path
    from models.checkpoint_io import load_checkpoint

    set_vars = [v for v in ENV_OVERRIDES if os.environ.get(v)]
    if set_vars:
        # QC-11: a global override makes EVERY config resolve to the same directory, so the files
        # copied would not be the ones this config names.
        raise BundleError(f"Refusing to build a bundle with path overrides set ({', '.join(set_vars)}): "
                          "they redirect every config to the same directory (QC-11). Unset them.")
    config = load_config(config_path)
    if config.get("_bundle_dir"):
        raise BundleError("--config points at a bundle already; build bundles from a configs/*.yaml.")
    cfg_file = Path(config_path)
    if not cfg_file.is_absolute():
        from common.config import PROJECT_ROOT
        cfg_file = PROJECT_ROOT / cfg_file
    ckpt_src = resolve_path(config, "checkpoint_dir") / "world_model_best.pt"
    proc = resolve_path(config, "processed_dir")
    sources = {CONFIG_REL: cfg_file, CHECKPOINT_REL: ckpt_src,
               SCALER_REL: proc / "scaler.npz", METADATA_REL: proc / "metadata.json"}
    missing = [f"{rel} <- {src}" for rel, src in sources.items() if not src.is_file()]
    if missing:
        raise BundleError("Cannot build bundle, missing source file(s): " + "; ".join(missing))

    out = Path(out_dir)
    if out.exists() and any(out.iterdir()):
        raise BundleError(f"{out} exists and is not empty; refusing to overwrite a bundle. Delete it first.")
    out.mkdir(parents=True, exist_ok=True)
    for rel, src in sources.items():
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)

    feature_names = feature_columns(config)
    ckpt = load_checkpoint(out / CHECKPOINT_REL, "cpu")
    git_status = _git("status", "--porcelain")
    import torch
    manifest: dict[str, Any] = {
        "format_version": FORMAT_VERSION,
        "model_name": name or Path(out).name,
        "source_config": cfg_file.name,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "git_commit": _git("rev-parse", "HEAD"),
        "git_dirty": bool(git_status) if git_status is not None else None,
        "torch_version": torch.__version__,
        "python_version": platform.python_version(),
        "n_features": len(feature_names),
        "n_stage_classes": int(ckpt["n_stage_classes"]),
        "feature_names": feature_names,
        "sequence_length": int(config["windowing"]["sequence_length"]),
        "forecast_horizon": int(config["windowing"]["forecast_horizon"]),
        "window_seconds": int(config["windowing"]["window_seconds"]),
        "mitre_stages": list(config["mitre_stages"]),
        "serving": config.get("serving"),
        "shap_background": "not included: the API never uses it (QC-20)",
        "graph_embedding_encoder": encoder_fingerprint(),
        "files": [
            {"path": rel, "size": (out / rel).stat().st_size, "sha256": sha256_file(out / rel)}
            for rel in sources
        ],
    }
    (out / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    verify_bundle(out)  # a bundle that does not verify straight after building is a bug, say so now
    return manifest


def read_manifest(bundle_dir: str | Path) -> dict[str, Any]:
    path = Path(bundle_dir) / MANIFEST_NAME
    if not path.is_file():
        raise BundleError(f"Not a model bundle: {path} not found.")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise BundleError(f"{path} is not valid JSON: {exc}") from exc
    if manifest.get("format_version") != FORMAT_VERSION:
        raise BundleError(f"Unsupported bundle format_version {manifest.get('format_version')!r}.")
    return manifest


def verify_bundle(bundle_dir: str | Path, check_encoder: bool = True) -> dict[str, Any]:
    """Raise BundleError unless every manifest file is present with the recorded size and SHA256
    and the feature schema is consistent everywhere it is recorded. Returns a status summary."""
    from common.config import feature_columns, load_config
    from models.checkpoint_io import load_checkpoint
    from models.dataset import FeatureScaler

    root = Path(bundle_dir).resolve()
    manifest = read_manifest(root)
    listed = {f["path"]: f for f in manifest["files"]}
    for req in REQUIRED_FILES:
        if req not in listed:
            raise BundleError(f"Manifest does not list required file {req}.")
    for rel, entry in listed.items():
        if Path(rel).is_absolute() or ".." in Path(rel).parts:
            raise BundleError(f"Manifest path escapes the bundle: {rel!r}")
        p = root / rel
        if not p.is_file():
            raise BundleError(f"Bundle file missing: {rel}")
        if p.stat().st_size != entry["size"]:
            raise BundleError(f"Size mismatch for {rel}: manifest {entry['size']}, on disk {p.stat().st_size}.")
        actual = sha256_file(p)
        if actual != entry["sha256"]:
            raise BundleError(f"SHA256 mismatch for {rel}: manifest {entry['sha256']}, on disk {actual}. "
                              "The file was modified or corrupted in transit; re-copy the bundle.")

    # Feature schema: every place the column list is recorded must agree, by NAME and ORDER.
    names = list(manifest["feature_names"])
    config = load_config(root / CONFIG_REL)
    meta = json.loads((root / METADATA_REL).read_text(encoding="utf-8"))
    ckpt = load_checkpoint(root / CHECKPOINT_REL, "cpu")
    scaler = FeatureScaler.load(root / SCALER_REL)
    checks = {
        "config feature_columns": list(feature_columns(config)),
        "processed/metadata.json feature_columns": list(meta.get("feature_columns", [])),
    }
    if ckpt.get("feature_names") is not None:
        checks["checkpoint feature_names"] = list(ckpt["feature_names"])
    for what, got in checks.items():
        if got != names:
            raise BundleError(f"Feature schema mismatch: {what} ({len(got)} cols) != manifest ({len(names)} cols).")
    widths = {"manifest n_features": manifest["n_features"], "checkpoint n_features": int(ckpt["n_features"]),
              "scaler mean": int(np.asarray(scaler.mean).shape[0]), "scaler std": int(np.asarray(scaler.std).shape[0])}
    for what, w in widths.items():
        if w != len(names):
            raise BundleError(f"Feature schema mismatch: {what} is {w}, expected {len(names)} feature names.")

    encoder_ok = None
    if check_encoder:
        now = encoder_fingerprint()
        encoder_ok = _fingerprints_match(manifest["graph_embedding_encoder"], now)
        if not encoder_ok:
            raise BundleError(
                "Graph-embedding encoder fingerprint differs from the one recorded when the bundle was built "
                f"(built with torch {manifest.get('torch_version')}, running torch {_torch_version()}). The frozen "
                "random encoder produces different graph_embed_* features here, so forecasts would silently drift.")
    return {
        "name": manifest["model_name"],
        "bundle_dir": str(root),
        "manifest_sha256": sha256_file(root / MANIFEST_NAME),
        "checksums_ok": True,
        "schema_ok": True,
        "encoder_fingerprint_ok": encoder_ok,
        "n_files": len(listed),
        "n_features": len(names),
        "git_commit": manifest.get("git_commit"),
        "git_dirty": manifest.get("git_dirty"),
        "created_utc": manifest.get("created_utc"),
        "built_with_torch": manifest.get("torch_version"),
        "running_torch": _torch_version(),
    }


def _torch_version() -> str:
    import torch
    return torch.__version__


def bundle_state_dir(bundle_dir: str | Path) -> Path:
    """Writable run-time state (audit ledger). $PHOENIX_STATE_DIR wins; default <bundle>/state,
    which is outside the manifest so writing there never invalidates the checksums."""
    import os
    env = os.environ.get("PHOENIX_STATE_DIR")
    return Path(env) if env else Path(bundle_dir) / "state"


def make_archive(bundle_dir: str | Path, archive_path: str | Path) -> str:
    """tar.gz of the bundle folder (top-level directory = bundle name). Returns its SHA256."""
    import tarfile
    bundle_dir = Path(bundle_dir)
    with tarfile.open(archive_path, "w:gz") as tar:
        for p in sorted(bundle_dir.rglob("*")):
            if p.relative_to(bundle_dir).parts[0] == "state":
                continue  # run-time state is never shipped
            tar.add(p, arcname=str(Path(bundle_dir.name) / p.relative_to(bundle_dir)), recursive=False)
    return sha256_file(Path(archive_path))


if __name__ == "__main__":  # python -m common.bundle <dir>  -- verify a bundle
    try:
        print(json.dumps(verify_bundle(sys.argv[1]), indent=2))
    except BundleError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(2)
