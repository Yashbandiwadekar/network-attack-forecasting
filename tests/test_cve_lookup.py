from models.cve_lookup import related_cves, snapshot_metadata
from pipeline.mitre_mapping import (
    BENIGN, COMMAND_AND_CONTROL, EXFILTRATION, IMPACT, INITIAL_ACCESS, LATERAL_MOVEMENT, RECONNAISSANCE,
)


def test_every_non_benign_stage_has_at_least_one_cve():
    for stage in [RECONNAISSANCE, INITIAL_ACCESS, LATERAL_MOVEMENT, COMMAND_AND_CONTROL, EXFILTRATION, IMPACT]:
        cves = related_cves(stage)
        assert len(cves) >= 1, f"no CVE entries for stage {stage}"


def test_benign_has_no_cve_entries():
    assert related_cves(BENIGN) == []


def test_unknown_stage_returns_empty_list_not_an_error():
    assert related_cves("not_a_real_stage") == []


def test_cve_entries_have_required_fields():
    for stage in [INITIAL_ACCESS, LATERAL_MOVEMENT]:
        for entry in related_cves(stage):
            assert entry["cve_id"].startswith("CVE-")
            assert 0.0 <= entry["cvss_v3_score"] <= 10.0
            assert entry["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
            assert entry["url"].startswith("https://nvd.nist.gov/")


def test_snapshot_metadata_documents_provenance():
    meta = snapshot_metadata()
    assert "nvd.nist.gov" in meta["source"].lower() or "NVD" in meta["source"]
    assert "fetched" in meta
