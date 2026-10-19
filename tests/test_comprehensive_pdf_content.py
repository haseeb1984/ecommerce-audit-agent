"""Regression checks for evidence and limitation text in the real rendered PDF."""
from datetime import datetime, timezone

import report_generator
from audit_checks import AuditCheckResult, AuditFinding


def test_real_pdf_render_contains_findings_evidence_limitations_and_final_disclaimer(monkeypatch):
    rendered_paragraphs = []
    original_paragraph = report_generator.Paragraph

    def capture_paragraph(text, style, *args, **kwargs):
        rendered_paragraphs.append(str(text))
        return original_paragraph(text, style, *args, **kwargs)

    # Capture text passed to ReportLab while retaining the real Paragraph and PDF renderer.
    monkeypatch.setattr(report_generator, "Paragraph", capture_paragraph)

    disclaimer = (
        "This report presents observations from a bounded set of public website checks at the time shown. "
        "It is not a complete security assessment, penetration test, WCAG conformance audit, legal opinion, "
        "guarantee of search rankings, or forecast of conversions or revenue. Checks not performed or not "
        "verified must not be interpreted as passing. Confirm findings in the relevant production context "
        "before acting on them."
    )
    limitation = (
        "Google indexing is not verified because Search Console access is not connected."
    )
    result = AuditCheckResult(
        target_url="https://shop.example/",
        checked_at_utc=datetime(2026, 10, 17, tzinfo=timezone.utc).isoformat(),
        pages_checked=[
            "https://shop.example/",
            "https://shop.example/products/example",
        ],
        limitations=[
            limitation,
            "JavaScript-rendered behavior is not fully tested by static HTML checks.",
        ],
        findings=[
            AuditFinding(
                category="technical_seo",
                title="Google indexing status not verified",
                status="not_tested",
                severity="info",
                evidence="This audit does not query Google Search Console URL Inspection.",
                explanation="A sitemap entry does not prove that Google has indexed a URL.",
                recommendation="Check the exact URL in the authorized Google Search Console property.",
                verification_steps=["Use URL Inspection for the exact canonical URL."],
                source_url="https://shop.example/",
            ),
            AuditFinding(
                category="accessibility",
                title="Product form control may lack an accessible name",
                status="manual_review_required",
                severity="medium",
                evidence="A sampled form control has no detectable associated label.",
                explanation="Some assistive-technology users may not know what the control does.",
                recommendation="Provide a programmatic label and verify it in a browser.",
                verification_steps=["Inspect the control's accessible name in browser devtools."],
                source_url="https://shop.example/products/example",
                potential_benefit="A verified accessible name can help people identify the control.",
                risk_if_unresolved="Some users may have difficulty identifying the control.",
            ),
        ],
    )

    pdf = report_generator.render_audit_pdf(result)

    assert pdf.startswith(b"%PDF-")
    assert b"%%EOF" in pdf[-2048:]
    assert len(pdf) > 1000

    text = "\n".join(rendered_paragraphs)
    assert "Google indexing status not verified" in text
    assert "Status: Not tested" in text
    assert "A sitemap entry does not prove that Google has indexed a URL." in text
    assert "Check the exact URL in the authorized Google Search Console property." in text
    assert "Product form control may lack an accessible name" in text
    assert "Status: Manual review required" in text
    assert "Potential benefit if addressed" in text
    assert "A verified accessible name can help people identify the control." in text
    assert "Risk if left unresolved" in text
    assert "Some users may have difficulty identifying the control." in text
    assert "Evidence & References" in text
    assert "E1: https://shop.example/" in text
    assert "E2: https://shop.example/products/example" in text
    assert limitation in text
    assert "JavaScript-rendered behavior is not fully tested by static HTML checks." in text

    # The disclaimer is present once, as the final report paragraph, not a repeating footer.
    assert rendered_paragraphs.count(disclaimer) == 1
    assert rendered_paragraphs[-1] == disclaimer
