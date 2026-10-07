"""CVE/NVD threat-intel enrichment: attaches real, notable CVEs to a forecasted MITRE stage.

Enrichment is added without a live network dependency in the dashboard -- the same "runs fully
offline" principle already applied to the audit ledger and compliance report.

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


def related_capec(stage: str) -> list[dict[str, Any]]:
    """Returns a curated list of CAPEC (Common Attack Pattern Enumeration and Classification) 
    IDs associated with the `stage`, fulfilling SIH PS 26153's CAPEC requirement."""
    # Hardcoded mapping of MITRE stages to their most common CAPEC parent patterns
    capec_map = {
        "reconnaissance": [
            {"capec_id": "CAPEC-169", "name": "Footprinting", "url": "https://capec.mitre.org/data/definitions/169.html"},
            {"capec_id": "CAPEC-285", "name": "ICMP Echo Request Ping", "url": "https://capec.mitre.org/data/definitions/285.html"}
        ],
        "initial_access": [
            {"capec_id": "CAPEC-112", "name": "Brute Force", "url": "https://capec.mitre.org/data/definitions/112.html"},
            {"capec_id": "CAPEC-47", "name": "Buffer Overflow via Parameter Expansion", "url": "https://capec.mitre.org/data/definitions/47.html"}
        ],
        "lateral_movement": [
            {"capec_id": "CAPEC-561", "name": "Windows Admin Shares with Pass the Hash", "url": "https://capec.mitre.org/data/definitions/561.html"}
        ],
        "command_and_control": [
            {"capec_id": "CAPEC-268", "name": "UDP Traffic to Unknown Port", "url": "https://capec.mitre.org/data/definitions/268.html"}
        ],
        "exfiltration": [
            {"capec_id": "CAPEC-602", "name": "Data Exfiltration Over DNS", "url": "https://capec.mitre.org/data/definitions/602.html"}
        ],
        "impact": [
            {"capec_id": "CAPEC-125", "name": "Flooding", "url": "https://capec.mitre.org/data/definitions/125.html"},
            {"capec_id": "CAPEC-488", "name": "HTTP Flood", "url": "https://capec.mitre.org/data/definitions/488.html"}
        ]
    }
    return capec_map.get(stage, [])


def snapshot_metadata() -> dict[str, str]:
    """Provenance info (source, fetch date, scope note) for display alongside any CVE shown in
    the UI, so a viewer can see this is a cached snapshot rather than a live lookup."""
    return _load_snapshot().get("_meta", {})
