import browser_audit_service


def test_product_page_evidence_reports_visible_rendered_signals():
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


def test_product_page_evidence_does_not_invent_signals_for_non_product_page():
    evidence = browser_audit_service._format_product_page_evidence({
        "is_product_page": False,
        "product_entities": 0,
        "visible_h1": 1,
        "visible_price": 0,
        "purchase_controls": 0,
    })
    assert "Product-like page detected: False" in evidence
    assert "Product JSON-LD entities: 0" in evidence
