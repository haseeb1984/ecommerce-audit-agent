import browser_audit_service


def test_rendered_accessibility_evidence_describes_heuristic_not_wcag_verdict():
    evidence = browser_audit_service._format_accessibility_evidence({
        "image_count": 12,
        "images_missing_alt": 2,
        "control_count": 8,
        "controls_without_name": 1,
    })
    assert "images missing an alt attribute: 2" in evidence
    assert "controls without a detectable accessible-name heuristic: 1" in evidence
    assert "not a WCAG conformance verdict" in evidence
