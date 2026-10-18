from audit_checks import AuditCheckResult, AuditFinding
from report_generator import render_audit_pdf


def test_render_audit_pdf_returns_pdf_with_evidence_and_limitations():
    result = AuditCheckResult(
        target_url="https://shop.example/",
        checked_at_utc="2026-10-17T00:00:00+00:00",
        pages_checked=["https://shop.example/"],
        limitations=["Only the public homepage was inspected."],
        findings=[
            AuditFinding(
                category="mobile_ux",
                title="Mobile viewport",
                status="verified",
                severity="low",
                evidence='No meta name="viewport" was found.',
                explanation="The page may not adapt to the device width.",
                recommendation="Add a responsive viewport declaration; do not disable zoom.",
                verification_steps=["Inspect the source.", "Test at 320 CSS px."],
                source_url="https://shop.example/",
            )
        ],
    )

    pdf = render_audit_pdf(result)

    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 1000


def test_render_audit_pdf_handles_html_special_characters():
    result = AuditCheckResult(
        target_url="https://shop.example/?a=1&b=2",
        checked_at_utc="2026-10-17T00:00:00+00:00",
        findings=[
            AuditFinding(
                category="on_page_seo",
                title="Title with <tags> & symbols",
                status="verified",
                severity="info",
                evidence="Text with <unsafe> & untrusted values.",
                explanation="Explanation.",
                recommendation="Recommendation.",
                verification_steps=["Check A & B."],
                source_url="https://shop.example/?a=1&b=2",
            )
        ],
    )

    pdf = render_audit_pdf(result)
    assert pdf.startswith(b"%PDF-")
