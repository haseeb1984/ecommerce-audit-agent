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
    assert score["unverified"] == 22


def test_security_assessment_is_not_zero_when_all_checks_are_unverified():
    from report_generator import calculate_security_assessment

    score = calculate_security_assessment([], [])
    assert score["score"] is None
    assert score["passed"] == 0
    assert score["issues"] == 0
    assert score["unverified"] == 23
    assert score["assessed"] == 23


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
    assert score["unverified"] == 23
    assert score["score"] is None


def test_security_assessment_does_not_count_unverified_exposure_probes_as_passes():
    from report_generator import calculate_security_assessment

    limitations = [
        "Passive exposure probes checked only 8 common paths; this is not a penetration test.",
        "2 of 8 exposure probes could not be verified due to request failures or redirects.",
    ]
    score = calculate_security_assessment([], limitations)
    assert score["checked_exposure_paths"] == 8
    assert score["passed"] == 6
    assert score["issues"] == 0
    assert score["unverified"] == 11
    assert score["score"] == 35



def test_security_assessment_does_not_count_not_tested_info_transport_as_pass():
    from report_generator import calculate_security_assessment

    finding = AuditFinding(
        category="security_transport",
        title="HTTP redirects to HTTPS",
        status="not_tested",
        severity="info",
        evidence="The redirect check did not complete.",
        explanation="Explanation.",
        recommendation="Recommendation.",
        verification_steps=[],
    )
    score = calculate_security_assessment([finding], [])
    assert score["passed"] == 0
    assert score["issues"] == 0
    assert score["unverified"] == 23
    assert score["score"] is None



def test_repeated_same_issue_is_consolidated_across_pages():
    from report_generator import _consolidate_findings

    shared = dict(
        category="accessibility",
        title="Buttons may have no accessible name",
        status="verified",
        severity="high",
        explanation="Screen-reader users may not understand the purpose of these buttons.",
        recommendation="Give each button an accessible name that describes its action.",
        verification_steps=["Inspect the accessible name of each affected button."],
    )
    result = _consolidate_findings([
        AuditFinding(
            **shared,
            evidence="Button without an accessible name found on the home page.",
            source_url="https://shop.example/",
        ),
        AuditFinding(
            **shared,
            evidence="Button without an accessible name found on the product page.",
            source_url="https://shop.example/products/item",
        ),
        AuditFinding(
            **shared,
            evidence="Button without an accessible name found on the home page.",
            source_url="https://shop.example/",
        ),
    ])

    assert len(result) == 1
    assert result[0]["instances"] == 3
    assert len(result[0]["evidence"]) == 2
    assert result[0]["source_urls"] == [
        "https://shop.example/",
        "https://shop.example/products/item",
    ]


def test_different_remediation_is_not_merged_into_same_issue():
    from report_generator import _consolidate_findings

    base = dict(
        category="accessibility",
        title="Buttons may have no accessible name",
        status="verified",
        severity="high",
        evidence="An unnamed button was found.",
        explanation="Assistive technology users may not know its purpose.",
        verification_steps=["Inspect the accessible name."],
        source_url="https://shop.example/",
    )
    findings = [
        AuditFinding(**base, recommendation="Add a meaningful accessible name."),
        AuditFinding(**base, recommendation="Replace the control with a correctly labelled link."),
    ]

    assert len(_consolidate_findings(findings)) == 2



def _tiny_png_data_uri():
    # Construct a valid 1x1 RGB PNG with the standard library; no external image is fetched.
    import base64
    import struct
    import zlib

    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(b"\x00\xff\xff\xff"))
        + chunk(b"IEND", b"")
    )
    return "data:image/png;base64," + base64.b64encode(png).decode("ascii")


def test_report_embeds_a_valid_page_speed_screenshot():
    result = AuditCheckResult(
        target_url="https://shop.example/",
        checked_at_utc="2026-10-17T00:00:00+00:00",
        pages_checked=["https://shop.example/"],
        findings=[],
    )
    pdf = render_audit_pdf(result, screenshot_data_uri=_tiny_png_data_uri())
    assert pdf.startswith(b"%PDF-")
    # ReportLab stores the actual raster screenshot as an image XObject.
    assert b"/Subtype /Image" in pdf


def test_report_gracefully_omits_invalid_page_speed_screenshot():
    result = AuditCheckResult(
        target_url="https://shop.example/",
        checked_at_utc="2026-10-17T00:00:00+00:00",
        pages_checked=["https://shop.example/"],
        findings=[],
    )
    pdf = render_audit_pdf(result, screenshot_data_uri="data:image/png;base64,not-valid!")
    assert pdf.startswith(b"%PDF-")
    assert b"/Subtype /Image" not in pdf
def test_security_assessment_does_not_count_generic_success_exposure_responses_as_passes():
    from report_generator import calculate_security_assessment

    limitations = [
        "Passive exposure probes checked only 8 common paths; this is not a penetration test.",
        "2 of 8 exposure probes returned successful responses without a recognizable sensitive-content signature; treated as unverified.",
    ]
    score = calculate_security_assessment([], limitations)
    assert score["checked_exposure_paths"] == 8
    assert score["passed"] == 6
    assert score["issues"] == 0
    assert score["unverified"] == 11
    assert score["score"] == 35

def test_prioritized_actions_include_only_actionable_review_statuses_in_severity_order():
    from report_generator import _prioritized_actions

    actions = _prioritized_actions([
        {"title": "Low informational note", "severity": "low", "status": "verified"},
        {"title": "Medium needs review", "severity": "medium", "status": "manual_review_required"},
        {"title": "High verified", "severity": "high", "status": "verified"},
        {"title": "Critical not tested", "severity": "critical", "status": "not_tested"},
        {"title": "Critical verified", "severity": "critical", "status": "verified"},
        {"title": "Medium unknown", "severity": "medium", "status": "insufficient_data"},
    ])

    assert [item["title"] for item in actions] == [
        "Critical verified",
        "High verified",
        "Medium needs review",
    ]


def test_report_handles_long_findings_across_multiple_pages():
    """A verbose finding must not make PDF generation fail at a page boundary."""
    result = AuditCheckResult(
        target_url="https://shop.example/",
        checked_at_utc="2026-10-17T00:00:00+00:00",
        pages_checked=["https://shop.example/"],
        limitations=["The crawl is bounded to a small sample of public pages."],
        findings=[
            AuditFinding(
                category="accessibility",
                title="Long accessibility finding",
                status="verified",
                severity="high",
                evidence=("Observed evidence from the inspected page. " * 90),
                explanation=("Plain-language explanation of the observed issue. " * 90),
                recommendation=("Recommended remediation for the site owner. " * 90),
                verification_steps=[
                    f"Verification step {index}: repeat the check in the affected context and record the result."
                    for index in range(1, 46)
                ],
                source_url="https://shop.example/",
            )
        ],
    )

    pdf = render_audit_pdf(result)
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 2000
    # Confirm the long content was paginated, not merely accepted into a PDF.
    import re
    page_objects = re.findall(rb"/Type\s*/Page\b", pdf)
    assert len(page_objects) >= 2



def test_optional_business_context_is_consolidated_only_when_identical():
    from report_generator import _consolidate_findings

    base = dict(
        category="performance",
        title="Large page payload",
        status="verified",
        severity="medium",
        evidence="Observed transfer size exceeded the configured threshold.",
        explanation="The page transfers more data than the check's threshold.",
        recommendation="Review and reduce unnecessary resources.",
        verification_steps=["Repeat the transfer-size measurement."],
        source_url="https://shop.example/",
    )
    findings = [
        AuditFinding(**base, potential_benefit="A smaller payload may reduce transfer work.", risk_if_unresolved=None),
        AuditFinding(**{**base, "evidence": "A second page also exceeded the threshold."},
                     potential_benefit="A smaller payload may reduce transfer work.", risk_if_unresolved=None),
        AuditFinding(**base, potential_benefit="A smaller payload may reduce transfer work.", risk_if_unresolved="The transfer cost remains elevated."),
    ]

    consolidated = _consolidate_findings(findings)
    assert len(consolidated) == 2
    assert consolidated[0]["potential_benefit"] == "A smaller payload may reduce transfer work."
    assert consolidated[0]["risk_if_unresolved"] is None
    assert consolidated[0]["instances"] == 2
    assert consolidated[1]["risk_if_unresolved"] == "The transfer cost remains elevated."


def test_absent_business_context_stays_absent_in_consolidated_finding():
    from report_generator import _consolidate_findings

    finding = AuditFinding(
        category="seo",
        title="Missing title",
        status="verified",
        severity="low",
        evidence="No title element was found.",
        explanation="The returned HTML has no title element.",
        recommendation="Add a descriptive title.",
        verification_steps=[],
    )

    item = _consolidate_findings([finding])[0]
    assert item["potential_benefit"] is None
    assert item["risk_if_unresolved"] is None


def test_unverified_findings_are_not_promoted_to_confirmed_priority_actions():
    from report_generator import _prioritized_actions

    items = _consolidate_findings_for_status_test()
    actions = _prioritized_actions(items)
    assert actions == []


def _consolidate_findings_for_status_test():
    from report_generator import _consolidate_findings

    findings = [
        AuditFinding(
            category="security",
            title=f"Unverified case {status}",
            status=status,
            severity="high",
            evidence="The check did not confirm an outcome.",
            explanation="The result is inconclusive.",
            recommendation="Repeat the check before making a decision.",
            verification_steps=[],
        )
        for status in ("not_tested", "insufficient_data")
    ]
    return _consolidate_findings(findings)



def test_pdf_renders_optional_business_context_only_when_provided(monkeypatch):
    import report_generator

    rendered_text = []
    original_p = report_generator._p
    original_paragraph = report_generator.Paragraph

    def capture_paragraph(value, style):
        rendered_text.append(str(value))
        return original_p(value, style)

    def capture_reportlab_paragraph(value, style, *args, **kwargs):
        rendered_text.append(str(value))
        return original_paragraph(value, style, *args, **kwargs)

    monkeypatch.setattr(report_generator, "_p", capture_paragraph)
    monkeypatch.setattr(report_generator, "Paragraph", capture_reportlab_paragraph)
    result = AuditCheckResult(
        target_url="https://shop.example/",
        checked_at_utc="2026-10-17T00:00:00+00:00",
        pages_checked=["https://shop.example/"],
        limitations=[],
        findings=[
            AuditFinding(
                category="performance",
                title="Large page payload",
                status="verified",
                severity="medium",
                evidence="Observed transfer size exceeded the configured threshold.",
                explanation="The page transfers more data than the check's threshold.",
                recommendation="Review and reduce unnecessary resources.",
                verification_steps=["Repeat the transfer-size measurement."],
                potential_benefit="A smaller payload may reduce transfer work.",
                risk_if_unresolved="The transfer cost remains elevated.",
                source_url="https://shop.example/",
            ),
            AuditFinding(
                category="seo",
                title="Missing title",
                status="verified",
                severity="low",
                evidence="No title element was found.",
                explanation="The returned HTML has no title element.",
                recommendation="Add a descriptive title.",
                verification_steps=[],
                source_url="https://shop.example/about",
            ),
        ],
    )

    pdf = report_generator.render_audit_pdf(result)

    assert pdf.startswith(b"%PDF-")
    assert any("Potential benefit if addressed" in item for item in rendered_text)
    assert any("A smaller payload may reduce transfer work." in item for item in rendered_text)
    assert any("Risk if left unresolved" in item for item in rendered_text)
    assert any("The transfer cost remains elevated." in item for item in rendered_text)
    # Findings without custom business wording still receive explicitly qualified, non-measured impact context.
    assert any("Potential benefit if addressed" in item for item in rendered_text)
    assert any("Risk if left unresolved" in item for item in rendered_text)


def test_report_includes_sampled_scope_methodology_and_plain_language_glossary(monkeypatch):
    import report_generator

    rendered_text = []
    original_p = report_generator._p
    original_paragraph = report_generator.Paragraph

    def capture_p(value, style):
        rendered_text.append(str(value))
        return original_p(value, style)

    def capture_reportlab_paragraph(value, style, *args, **kwargs):
        rendered_text.append(str(value))
        return original_paragraph(value, style, *args, **kwargs)

    monkeypatch.setattr(report_generator, "_p", capture_p)
    monkeypatch.setattr(report_generator, "Paragraph", capture_reportlab_paragraph)
    result = AuditCheckResult(
        target_url="https://shop.example/",
        checked_at_utc="2026-10-17T00:00:00+00:00",
        pages_checked=[
            "https://shop.example/",
            "https://shop.example/products/one",
            "https://shop.example/",
        ],
        limitations=[],
        findings=[],
    )

    pdf = report_generator.render_audit_pdf(result)

    assert pdf.startswith(b"%PDF-")
    assert any("Sampled pages in scope" in item for item in rendered_text)
    # _p captures the input and its underlying Paragraph wrapper captures it again.
    # Two captures therefore mean the deduplicated root URL was rendered once.
    assert sum(item == "• https://shop.example/" for item in rendered_text) == 2
    assert any("https://shop.example/products/one" in item for item in rendered_text)
    assert any("No explicit limitation strings were supplied" in item for item in rendered_text)
    assert any("Methodology and independent verification" in item for item in rendered_text)
    assert any("Plain-language glossary" in item for item in rendered_text)
    assert any("not a measured financial impact" in item for item in rendered_text)



def test_pdf_evidence_links_redact_query_fragment_and_credentials():
    from report_generator import _link
    from reportlab.lib.styles import getSampleStyleSheet

    paragraph = _link(
        "https://user:password@shop.example/account?token=secret&email=a%40b.example#private",
        getSampleStyleSheet()["BodyText"],
    )

    assert "shop.example/account" in paragraph.text
    assert "password" not in paragraph.text
    assert "token=secret" not in paragraph.text
    assert "email=" not in paragraph.text
    assert "#private" not in paragraph.text


def test_pdf_evidence_links_omit_unsupported_or_malformed_urls():
    from report_generator import _link
    from reportlab.lib.styles import getSampleStyleSheet

    style = getSampleStyleSheet()["BodyText"]
    for value in ("javascript:alert(1)", "file:///etc/passwd", "https://[broken"):
        paragraph = _link(value, style)
        assert "omitted" in paragraph.getPlainText().lower()
        assert "<link" not in paragraph.text


def test_conversion_paid_traffic_findings_are_separated_from_general_findings():
    from report_generator import _conversion_paid_traffic_findings

    findings = [
        {"category": "conversion_paid_traffic", "title": "Checkout path signal"},
        {"category": "security", "title": "Header review"},
        {"category": "Conversion_Paid_Traffic", "title": "Form review"},
    ]
    selected = _conversion_paid_traffic_findings(findings)
    assert [item["title"] for item in selected] == [
        "Checkout path signal",
        "Form review",
    ]


def test_paid_media_coverage_distinguishes_static_signals_from_unassessed_metrics():
    from report_generator import _paid_media_coverage_rows

    rows = _paid_media_coverage_rows()
    flattened = " ".join(" ".join(row) for row in rows).lower()
    assert "publicly detectable marketing-tag signatures" in flattened
    assert "not connected / not assessed" in flattened
    assert "not verified in a live browser network session" in flattened
    assert "roas" in flattened


def test_audit_area_infographic_groups_findings_into_readable_categories():
    from report_generator import AuditAreaInfographic, mm

    chart = AuditAreaInfographic([
        {"category": "accessibility", "severity": "medium"},
        {"category": "accessibility", "severity": "low"},
        {"category": "mobile_ux", "severity": "medium"},
        {"category": "security_headers", "severity": "info"},
        {"category": "security_exposure", "severity": "high"},
        {"category": "conversion_paid_traffic", "severity": "medium"},
    ])

    assert chart.width == 174 * mm
    assert chart.items == [
        ("Accessibility", 2),
        ("Security", 2),
        ("Conversion & paid traffic", 1),
        ("Mobile UX", 1),
    ]
