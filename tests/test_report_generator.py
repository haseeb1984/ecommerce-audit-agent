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



def test_security_assessment_score_is_scoped_and_not_a_hack_probability():
    from report_generator import calculate_security_assessment

    headers = [
        AuditFinding(
            category="security_headers",
            title=label,
            status="verified",
            severity="info",
            evidence="Header value observed.",
            explanation="Explanation.",
            recommendation="Recommendation.",
            verification_steps=[],
        )
        for label in (
            "HSTS header", "Content Security Policy",
            "X-Content-Type-Options", "Referrer-Policy",
            "X-Frame-Options", "Permissions-Policy",
        )
    ]
    score = calculate_security_assessment(
        headers,
        ["Passive exposure probes checked only 8 common paths; not a penetration test."],
    )
    assert score["score"] == 82
    assert score["passed"] == 14
    assert score["issues"] == 0
    assert score["unverified"] == 3


def test_security_assessment_does_not_treat_missing_header_as_pass():
    from report_generator import calculate_security_assessment

    finding = AuditFinding(
        category="security_headers",
        title="Content Security Policy",
        status="manual_review_required",
        severity="medium",
        evidence="Response did not include content-security-policy.",
        explanation="Explanation.",
        recommendation="Recommendation.",
        verification_steps=[],
    )
    score = calculate_security_assessment([finding], [])
    assert score["score"] == 0
    assert score["issues"] == 1
    assert score["unverified"] == 16


def test_security_assessment_is_not_zero_when_all_checks_are_unverified():
    from report_generator import calculate_security_assessment

    score = calculate_security_assessment([], [])
    assert score["score"] is None
    assert score["passed"] == 0
    assert score["issues"] == 0
    assert score["unverified"] == 17
    assert score["assessed"] == 17


def test_security_assessment_keeps_unknown_controls_out_of_pass_count():
    from report_generator import calculate_security_assessment

    finding = AuditFinding(
        category="security_transport",
        title="HTTP redirects to HTTPS",
        status="manual_review_required",
        severity="medium",
        evidence="Redirect behavior was ambiguous.",
        explanation="Explanation.",
        recommendation="Recommendation.",
        verification_steps=[],
    )
    score = calculate_security_assessment([finding], [])
    assert score["passed"] == 0
    assert score["issues"] == 0
    assert score["unverified"] == 17
    assert score["score"] is None

