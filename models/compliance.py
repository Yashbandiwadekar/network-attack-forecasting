"""CERT-In-aligned incident report drafting.

Maps this system's own forecast outputs onto the categories and timeline India's CERT-In 2022
Directions actually require, so a drafted report is grounded in the real regulation rather than
invented compliance language:

    CERT-In Directions No. 20(3)/2022-CERT-In, dated 28 April 2022, issued under Section 70B(6)
    of the Information Technology Act, 2000 -- mandates reporting of specified cyber security
    incident categories to CERT-In within SIX HOURS of an entity noticing (or being notified of)
    the incident. The 2022 Directions also expanded the reportable-category list to explicitly
    include data breach, data leak, and (among others) attacks on systems related to AI/ML and
    blockchain -- both directly relevant to this project's own subject matter.

Scope, stated honestly (this project's whole credibility rests on not overclaiming, same as the
robustness/adversarial findings elsewhere): this drafts a report for a human compliance/SOC team
to review and file. It does NOT submit anything to CERT-In, does NOT reproduce CERT-In's exact
Annexure-I form field-by-field (that requires the official form, not a general-purpose
description), and the category mapping below is this project's own best-effort alignment of
MITRE ATT&CK stages onto CERT-In's published category *names*, not an official, government-issued
mapping. It exists to give a compliance team a running start inside a legally mandatory six-hour
window, not to replace their judgment or the official form.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from pipeline.mitre_mapping import (
    BENIGN, COMMAND_AND_CONTROL, EXFILTRATION, IMPACT, INITIAL_ACCESS, LATERAL_MOVEMENT, RECONNAISSANCE,
)

REPORTING_DEADLINE_HOURS = 6  # CERT-In Directions 2022, under Section 70B(6) of the IT Act, 2000

# This project's own mapping of MITRE stages onto CERT-In's published reportable-incident category
# *names* (drawn from the 20-category list in the 2022 Directions) -- see module docstring caveat.
CERT_IN_CATEGORY: dict[str, str | None] = {
    BENIGN: None,
    RECONNAISSANCE: "Targeted scanning/probing of critical networks or systems",
    INITIAL_ACCESS: "Unauthorised access to IT systems or data",
    LATERAL_MOVEMENT: "Compromise of critical systems or information",
    COMMAND_AND_CONTROL: "Malicious code activity (e.g. Trojan/Bot/spyware) indicating compromise",
    EXFILTRATION: "Data breach / data leak",
    IMPACT: "Denial of Service (DoS) / Distributed Denial of Service (DDoS) attack",
}


@dataclass(frozen=True)
class ComplianceReport:
    is_reportable: bool
    category: str | None
    detected_at: datetime
    reporting_deadline: datetime
    hours_remaining: float | None  # None when detected_at is historical/demo data, not a live clock
    text: str


def generate_cert_in_report(
    host: str,
    detected_at: datetime,
    peak_stage: str,
    peak_infiltration_prob: float,
    recommended_action: str,
    narrative: str,
    ledger_hash: str | None = None,
) -> ComplianceReport:
    """Drafts a CERT-In-aligned incident report for one host's forecasted/observed attack stage.

    `detected_at` should be timezone-aware (UTC). In a live deployment this is a real wall-clock
    detection time and the six-hour countdown is meaningful. Against historical/demo data (e.g.
    replaying 2018 CIC-IDS-2018 traffic, or the synthetic sample), `detected_at` can be years away
    from actual wall-clock "now" — comparing it to `datetime.now()` would produce a nonsensical
    countdown (a huge negative number of "hours remaining"), so that comparison is only made when
    `detected_at` is plausibly recent (within the reporting window already, or in the future).
    Otherwise `hours_remaining` is None and the report says so explicitly rather than showing a
    misleading figure.
    """
    category = CERT_IN_CATEGORY.get(peak_stage)
    is_reportable = category is not None
    deadline = detected_at + timedelta(hours=REPORTING_DEADLINE_HOURS)

    now = datetime.now(timezone.utc)
    is_live_clock = detected_at >= now - timedelta(hours=REPORTING_DEADLINE_HOURS)
    hours_remaining = (deadline - now).total_seconds() / 3600.0 if is_live_clock else None

    if not is_reportable:
        text = (
            f"No CERT-In-reportable incident category applies to {host} at this time "
            f"(current classification: {peak_stage}). No draft generated."
        )
        return ComplianceReport(False, None, detected_at, deadline, hours_remaining, text)

    evidence_line = (
        f"Audit ledger reference (SHA-256, tamper-evident): {ledger_hash}"
        if ledger_hash else
        "Audit ledger reference: not yet logged for this host."
    )

    if hours_remaining is not None:
        clock_line = f"Time remaining as of report generation: {hours_remaining:.1f} hours"
    else:
        clock_line = (
            "Time remaining: not applicable -- detected_at is a historical/demo timestamp, not a "
            "live detection. In a real deployment this line would show a live countdown from "
            "actual wall-clock detection time."
        )

    text = f"""CYBER SECURITY INCIDENT REPORT (DRAFT)
Prepared for reporting to CERT-In under the Directions No. 20(3)/2022-CERT-In, issued under
Section 70B(6) of the Information Technology Act, 2000 (mandatory reporting within
{REPORTING_DEADLINE_HOURS} hours of detection).

*** DRAFT ONLY -- not a submitted report. Review against the official CERT-In Annexure-I format
before filing. This system has no authority to submit reports and does not do so. ***

1. Reporting entity system reference
   Host / asset identifier: {host}

2. Incident category (CERT-In reportable category, per this system's MITRE ATT&CK mapping)
   {category}
   (Underlying MITRE ATT&CK stage: {peak_stage})

3. Time of detection and reporting deadline
   Detected at (UTC): {detected_at.isoformat()}
   Mandatory reporting deadline (detected_at + {REPORTING_DEADLINE_HOURS}h): {deadline.isoformat()}
   {clock_line}

4. Confidence / severity
   Peak forecast infiltration probability: {peak_infiltration_prob:.0%}

5. Incident description
   {narrative}

6. Remedial action taken / recommended
   {recommended_action}

7. Evidence reference
   {evidence_line}

8. Log retention note
   The 2022 Directions require ICT system logs to be retained for a rolling 180 days within
   Indian jurisdiction and furnished to CERT-In on request or when reporting an incident --
   confirm this host's log retention configuration meets that requirement before filing.
"""
    return ComplianceReport(True, category, detected_at, deadline, hours_remaining, text)
