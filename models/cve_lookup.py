"""CVE/NVD threat-intel enrichment: attaches real, notable CVEs to a forecasted MITRE stage.

Competitor differentiation (see docs/05-related-work-and-competitive-landscape.md Section 4):
`ErenSnowh/Argus` is the only other SIH26153 team found integrating CVE/NVD data into its
output. This module closes that gap without adding a live network dependency to the dashboard --
same "runs fully offline" principle already applied to the audit ledger and compliance report.

Scope, stated honestly (same ethos as models/compliance.py's docstring): CIC-IDS-2018/CTU-13 flow
records carry no software name or version field, so this system has no way to identify *which*
specific CVE a given host is actually vulnerable to or being exploited via -- that would require
active/passive fingerprinting this project doesn't do. What this module actually provides is a
curated reference: for the MITRE stage the world model forecasts, which real, well-documented CVEs
were historically exploited to reach that stage in major, publicly reported incidents. It's a
starting point for an analyst's own investigation ("here's the kind of vulnerability that produces
this behavior"), not an automated vulnerability match against the specific host in the alert.

Data source: data/threat_intel/cve_snapshot.json, a one-time cached snapshot of real NVD
(https://nvd.nist.gov/) records -- see that file's `_meta` block for provenance. Not fetched live
at runtime, so the dashboard has no NVD API dependency or rate limit to fail against during a demo.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_SNAPSHOT_PATH = Path(__file__).resolve().parent.parent / "data" / "threat_intel" / "cve_snapshot.json"

_cache: dict[str, Any] | None = None


def _load_snapshot() -> dict[str, Any]:
    global _cache
    if _cache is None:
        with open(_SNAPSHOT_PATH, "r", encoding="utf-8") as f:
            _cache = json.load(f)
    return _cache


def related_cves(stage: str) -> list[dict[str, Any]]:
    """Returns the curated list of real CVEs associated with `stage` (empty for `benign` or any
    stage not covered in the snapshot -- never fabricated on the fly)."""
    snapshot = _load_snapshot()
    return snapshot.get(stage, [])


def snapshot_metadata() -> dict[str, str]:
    """Provenance info (source, fetch date, scope note) for display alongside any CVE shown in
    the UI, so a viewer can see this is a cached snapshot rather than a live lookup."""
    return _load_snapshot().get("_meta", {})
