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


def test_product_page_evidence_reports_rendered_signals_and_limitations():
    evidence = browser_audit_service._format_product_page_evidence({
        "is_product_page": True,
        "product_entities": 1,
        "visible_h1": 1,
        "visible_price": 2,
        "purchase_controls": 1,
    })
    assert "Product-like page detected: True" in evidence
    assert "Product JSON-LD entities: 1" in evidence
    assert "visible price candidates: 2" in evidence
    assert "visible purchase controls: 1" in evidence
    assert "not a checkout test" in evidence


def test_product_page_evidence_handles_non_product_page_without_inventing_signals():
    evidence = browser_audit_service._format_product_page_evidence({
        "is_product_page": False,
        "product_entities": 0,
        "visible_h1": 1,
        "visible_price": 0,
        "purchase_controls": 0,
    })
    assert "Product-like page detected: False" in evidence
    assert "Product JSON-LD entities: 0" in evidence
