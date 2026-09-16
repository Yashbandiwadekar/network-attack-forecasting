import re
from datetime import datetime, timedelta, timezone

from models.compliance import CERT_IN_CATEGORY, REPORTING_DEADLINE_HOURS, generate_cert_in_report
from pipeline.mitre_mapping import (
    BENIGN, COMMAND_AND_CONTROL, EXFILTRATION, IMPACT, INITIAL_ACCESS, LATERAL_MOVEMENT, RECONNAISSANCE,
    STAGE_CLASSIFICATION_LABELS,
)


def test_every_classification_stage_and_impact_has_a_mapping_entry():
    for stage in STAGE_CLASSIFICATION_LABELS + [IMPACT]:
        assert stage in CERT_IN_CATEGORY, f"no CERT-In category mapping for stage {stage}"


def test_benign_is_not_reportable():
    detected_at = datetime.now(timezone.utc)
    report = generate_cert_in_report(
        "10.0.0.9", detected_at, BENIGN, 0.05, "No action needed", "Traffic looks normal.",
    )
    assert report.is_reportable is False
    assert report.category is None
    assert "No draft generated" in report.text


def test_reportable_stage_produces_a_draft_with_deadline_six_hours_out():
    detected_at = datetime.now(timezone.utc)
    report = generate_cert_in_report(
        "10.0.0.5", detected_at, LATERAL_MOVEMENT, 0.86,
        "Isolate the host from internal network segments.", "Host is pivoting internally.",
    )
    assert report.is_reportable is True
    assert report.category == CERT_IN_CATEGORY[LATERAL_MOVEMENT]
    assert report.reporting_deadline - report.detected_at == timedelta(hours=REPORTING_DEADLINE_HOURS)
    assert "10.0.0.5" in report.text
    assert "DRAFT" in report.text
    assert "not a submitted report" in report.text


def test_hours_remaining_counts_down_from_detection_time():
    detected_two_hours_ago = datetime.now(timezone.utc) - timedelta(hours=2)
    report = generate_cert_in_report(
        "10.0.0.5", detected_two_hours_ago, EXFILTRATION, 0.9, "Block egress.", "Data is leaving the network.",
    )
    # 6h deadline minus 2h already elapsed leaves ~4h -- allow slack for test execution time.
    assert 3.9 <= report.hours_remaining <= 4.0


def test_historical_timestamp_does_not_produce_a_nonsensical_countdown():
    # Real CIC-IDS-2018/CTU-13 data carries genuine 2018-era timestamps -- comparing that to
    # actual wall-clock "now" would produce a huge negative "hours remaining", which is exactly
    # the bug this test guards against.
    detected_in_2018 = datetime(2018, 3, 2, 12, 59, 50, tzinfo=timezone.utc)
    report = generate_cert_in_report(
        "NETWORK-2018-03-02", detected_in_2018, COMMAND_AND_CONTROL, 1.0,
        "Block the destination IP/domain.", "Host is establishing a C2 channel.",
    )
    assert report.hours_remaining is None
    assert "not applicable" in report.text
    # the actual bug this guards against: a huge negative hour count like "-74880.3 hours" leaking in
    assert not re.search(r"-\d", report.text.split("Time remaining")[1].split("\n")[0])


def test_future_detected_at_is_treated_as_a_live_clock():
    detected_soon = datetime.now(timezone.utc) + timedelta(minutes=5)
    report = generate_cert_in_report(
        "10.0.0.5", detected_soon, EXFILTRATION, 0.9, "Block egress.", "Data is leaving the network.",
    )
    assert report.hours_remaining is not None
    assert report.hours_remaining > REPORTING_DEADLINE_HOURS - 0.2


def test_ledger_hash_included_when_provided_and_noted_absent_when_not():
    detected_at = datetime.now(timezone.utc)
    with_hash = generate_cert_in_report(
        "10.0.0.5", detected_at, INITIAL_ACCESS, 0.7, "Rotate credentials.", "Foothold attempt.",
        ledger_hash="abc123",
    )
    without_hash = generate_cert_in_report(
        "10.0.0.5", detected_at, INITIAL_ACCESS, 0.7, "Rotate credentials.", "Foothold attempt.",
    )
    assert "abc123" in with_hash.text
    assert "not yet logged" in without_hash.text


def test_reconnaissance_and_command_and_control_and_impact_all_map_to_reportable_categories():
    for stage in [RECONNAISSANCE, COMMAND_AND_CONTROL, IMPACT]:
        assert CERT_IN_CATEGORY[stage] is not None
