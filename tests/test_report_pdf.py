"""The incident-report PDF builder (models/report_pdf.py): pure function, dict in, PDF bytes out."""
from models.report_pdf import build_incident_pdf

FULL = {
    "host": "NETWORK-2018-03-02", "generated_at": "2026-09-30T12:00:00+00:00", "dataset_source": "demo.csv",
    "peak_prob": 0.9997, "peak_stage": "Impact", "horizon_seconds": 60,
    "forecast": [{"seconds": 10, "prob": 0.5, "stage": "Command & Control", "heuristic": False},
                 {"seconds": 20, "prob": 0.9997, "stage": "Impact", "heuristic": True}],
    "compliance": {"is_reportable": True, "category": "Denial of Service (DoS)", "detected_at": "x",
                   "reporting_deadline": "y", "hours_remaining": None},
    "narrative": "The host is heading toward impact.",
    "recommended_action": {"action": "Activate DDoS mitigation", "detail": "Volume indicates DoS."},
    "attributions": [{"feature": "graph_fan_out_ratio", "share": 0.279, "direction": "raises"}],
    "provenance_share_total": 0.196, "provenance_note": "Data-provenance flag, not traffic behaviour.",
    "ledger": {"index": 4, "prev_hash": "a" * 64, "record_hash": "b" * 64, "intact": True},
}


def test_builds_a_real_pdf():
    pdf = build_incident_pdf(FULL)
    assert pdf.startswith(b"%PDF-")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert len(pdf) > 2000


def test_survives_markup_characters_in_dynamic_text():
    """Host names and narrative come from capture files; reportlab parses Paragraph text as markup, so an
    unescaped '<' or '&' would raise or corrupt the page."""
    data = {**FULL, "host": "evil<b>&host", "narrative": "5 < 6 & <unclosed"}
    assert build_incident_pdf(data).startswith(b"%PDF-")


def test_tolerates_missing_sections():
    assert build_incident_pdf({"host": "10.0.0.1"}).startswith(b"%PDF-")
    assert build_incident_pdf({}).startswith(b"%PDF-")


def test_says_draft_not_certified():
    """The disclaimer is drawn on the page itself, so check the source text the builder embeds."""
    from models import report_pdf

    assert "not a certified" in report_pdf.DISCLAIMER.lower()
    assert "DRAFT" in report_pdf.DISCLAIMER
