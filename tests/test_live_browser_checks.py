from scripts.generate_live_audit_pdfs import _mobile_render_findings


def test_mobile_render_findings_detect_overflow_viewport_and_hidden_focusables():
    findings = _mobile_render_findings("https://shop.example/", {
        "viewport_width": 390,
        "document_width": 428,
        "viewport_meta": "width=device-width, initial-scale=1",
        "aria_hidden_focusables": 2,
    })
    titles = {finding.title for finding in findings}
    assert "Rendered page overflows the mobile viewport" in titles
    assert "Rendered focusable controls are hidden from assistive technology" in titles
    assert "Rendered page lacks a device-width viewport declaration" not in titles
    assert all(finding.status == "manual_review_required" for finding in findings)


def test_mobile_render_findings_report_missing_viewport_and_clean_layout():
    findings = _mobile_render_findings("https://shop.example/", {
        "viewport_width": 390,
        "document_width": 390,
        "viewport_meta": "",
        "aria_hidden_focusables": 0,
    })
    assert len(findings) == 1
    assert findings[0].title == "Rendered page lacks a device-width viewport declaration"


def test_mobile_render_findings_do_not_infer_results_from_missing_browser_metrics():
    findings = _mobile_render_findings("https://shop.example/", {})
    assert findings == []
