from audit_checks import AuditFinding
from scripts.generate_live_audit_pdfs import _live_pdf_qa_passed


def _mobile_unavailable():
    return AuditFinding(
        category="mobile_ux",
        title="Rendered mobile checks could not be completed",
        status="not_tested",
        severity="info",
        evidence="Browser inspection unavailable; no mobile layout conclusion was drawn.",
        explanation="Static HTML checks cannot establish rendered mobile layout.",
        recommendation="Rerun browser-based inspection.",
        verification_steps=["Run the manual browser QA workflow."],
        source_url="https://shop.example/",
    )


def test_live_pdf_qa_requires_successful_audit_and_both_screenshots():
    assert _live_pdf_qa_passed(True, "desktop-data-uri", "mobile-data-uri", []) is True
    assert _live_pdf_qa_passed(False, "desktop-data-uri", "mobile-data-uri", []) is False
    assert _live_pdf_qa_passed(True, None, "mobile-data-uri", []) is False
    assert _live_pdf_qa_passed(True, "desktop-data-uri", None, []) is False


def test_live_pdf_qa_fails_when_mobile_browser_inspection_was_not_tested():
    assert _live_pdf_qa_passed(
        True,
        "desktop-data-uri",
        "mobile-data-uri",
        [_mobile_unavailable()],
    ) is False


def test_live_pdf_qa_allows_observed_mobile_findings_for_manual_review():
    finding = _mobile_unavailable()
    finding.title = "Rendered page overflows the mobile viewport"
    finding.status = "manual_review_required"
    assert _live_pdf_qa_passed(
        True,
        "desktop-data-uri",
        "mobile-data-uri",
        [finding],
    ) is True
