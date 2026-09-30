# Dataset Switching Remediation

**Status:** ? Complete
**Tracking ID:** DATASET-SWITCH-001
**Date:** 2026-09-30

---

## Problem Statement

The Phoenix IDPS dashboard DATA SOURCE CONTEXT selector was regressed: UNSW-NB15 and CTU-13 entries were **disabled** in the UI because their checkpoint files were not found at hardcoded `V:\Datasets\...` absolute paths. This is not a valid reason to disable a dataset — the system should discover resources wherever they are configured and communicate capability honestly rather than silently masking availability.

### Root Causes Identified

| # | Location | Issue |
|---|----------|-------|
| R1 | `common/config.py` | `resolve_path` used hardcoded `V:\` prefix; not portable across machines |
| R2 | `configs/*.yaml` | Dataset and checkpoint paths were absolute (`V:\Datasets\...`) — broke on any other machine |
| R3 | `app/service.py` | `load_backend` had no existence check for scaler/checkpoint before committing state |
| R4 | `app/server.py` | Dataset registry did not expose capability metadata (checkpoint present/loaded) to frontend |
| R5 | `frontend/src/pages/Dashboard.jsx` | Dropdown disabled entries instead of labelling them; no actionable error UX on failure |

---

## Changes Made

### `common/config.py` — `resolve_path`
- Added **environment variable override** support: any path key can be overridden via `PHOENIX_<KEY>_PATH`.
- Absolute paths that do not exist are treated as configuration errors (logged) rather than silently redirecting to a bad default.
- Relative paths are resolved from the project root.

### `configs/cic_ids_2018.yaml`, `unsw_nb15.yaml`, `ctu13.yaml`
- Converted all absolute `V:\...` paths to **relative paths** from the project root.
- Operators can now override via environment variable if data lives elsewhere.

### `app/service.py` — `load_backend`
- Before committing a new model/scaler pair into `STATE`, existence of both the checkpoint file and the scaler file is verified.
- Added `clear_backend_cache()` to allow atomic invalidation on dataset switch.
- Returns a structured result so callers can report specific failure mode (missing checkpoint vs. missing scaler).

### `app/server.py` — Dataset endpoints
- `GET /api/v1/datasets` now returns per-dataset capability metadata including `checkpoint_available` and `checkpoint_loaded`.
- `POST /api/v1/datasets/select` performs **atomic selection**: model and scaler are validated before `STATE.config_path` is committed; returns HTTP 409 with a descriptive message on failure.
- `GET /api/v1/diagnostics` added — returns full path resolution results for operator troubleshooting.

### `frontend/src/pages/Dashboard.jsx`
- Dropdown renders **all configured datasets** (never disabled).
- Datasets whose checkpoint is unavailable are labelled `(Model checkpoint unavailable)`.
- `handleDatasetChange` wrapped in loading state; previous dataset retained on failure.
- Dismissible error banner on failure with cleaned backend error message.

---

## Test Coverage

### Backend — `tests/test_dataset_switching.py`
- Dataset discovery with missing checkpoints
- Atomic selection success path
- Atomic selection rejection (missing checkpoint)

### Frontend — `frontend/src/__tests__/datasetSwitching.test.jsx`
- All three datasets rendered in the combobox
- Successful switch updates select.value
- Failed switch retains previous value and renders error banner

Run backend tests:
```
cd network-attack-forecasting-copy
python -m pytest tests/test_dataset_switching.py -v
```

Run frontend tests:
```
cd network-attack-forecasting-copy/frontend
npx vitest run src/__tests__/datasetSwitching.test.jsx
```

---

## Operator Guide — Adding a New Dataset

1. Create `configs/<dataset_id>.yaml` with relative paths.
2. Place model checkpoint under `checkpoints/` (or set `PHOENIX_CHECKPOINT_PATH`).
3. Place scaler under `models/` (or set `PHOENIX_SCALER_PATH`).
4. Register in `app/server.py::_dataset_registry`.
5. Restart the backend.

---

## What Was NOT Done

- Fake dataset availability was **not introduced**.
- Datasets are **not disabled** in the UI based on file existence.
- Hardcoded developer-machine absolute paths were **removed**.
