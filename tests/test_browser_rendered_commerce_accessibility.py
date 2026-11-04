import browser_audit_service


def test_rendered_accessibility_evidence_describes_heuristic_not_wcag_verdict():
    evidence = browser_audit_service._format_accessibility_evidence({
        "image_count": 12,
        "images_missing_alt": 2,
        "control_count": 8,
        "controls_without_name": 1,
        "positive_tabindex_count": 2,
        "negative_tabindex_count": 1,
    })
    assert "images missing an alt attribute: 2" in evidence
    assert "controls without a detectable accessible-name heuristic: 1" in evidence
    assert "positive tabindex: 2" in evidence
    assert "tabindex=-1: 1" in evidence
    assert "positive tabindex: 2" in evidence
    assert "tabindex=-1: 1" in evidence
    assert "not a WCAG conformance verdict" in evidence


def test_product_page_evidence_reports_rendered_signals_and_limitations():
    evidence = browser_audit_service._format_product_page_evidence({
        "is_product_page": True,
        "product_entities": 1,
        "visible_h1": 1,
        "visible_price": 2,
        "purchase_controls": 1,
        "variant_controls": 3,
        "product_images": 4,
        "quantity_controls": 1,
    })
    assert "Product-like page detected: True" in evidence
    assert "Product JSON-LD entities: 1" in evidence
    assert "visible price candidates: 2" in evidence
    assert "visible purchase controls: 1" in evidence
    assert "visible variant-selection controls: 3" in evidence
    assert "product image candidates: 4" in evidence
    assert "quantity controls: 1" in evidence
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


def test_orientation_evidence_names_both_fixed_viewports_and_limitations():
    evidence = browser_audit_service._format_orientation_evidence({
        "portrait_width": 390, "portrait_height": 844, "portrait_scroll_width": 390,
        "landscape_width": 844, "landscape_height": 390, "landscape_scroll_width": 900,
    })
    assert "390x844" in evidence
    assert "844x390" in evidence
    assert "900px" in evidence
    assert "does not verify device sensors" in evidence


def test_unavailable_rendered_checks_are_not_assessed_when_browser_is_not_run():
    from types import SimpleNamespace
    from unavailable_checks import append_unavailable_check_outcomes

    result = SimpleNamespace(check_outcomes=[], target_url="https://shop.example/", limitations=[])
    added = append_unavailable_check_outcomes(result, browser_audit_completed=False)
    by_id = {item.check_id: item for item in result.check_outcomes}
    assert added > 0
    for check_id in (
        "mobile_ux.rendered_orientation",
        "accessibility.rendered_images_alt",
        "accessibility.rendered_controls_name",
        "ecommerce.product_page_rendered_signals",
    ):
        assert by_id[check_id].outcome == "not_assessed"


def test_successful_browser_run_does_not_append_browser_only_not_assessed_records():
    from types import SimpleNamespace
    from unavailable_checks import append_unavailable_check_outcomes

    result = SimpleNamespace(check_outcomes=[], target_url="https://shop.example/", limitations=[])
    append_unavailable_check_outcomes(result, browser_audit_completed=True)
    ids = {item.check_id for item in result.check_outcomes}
    assert "mobile_ux.rendered_orientation" not in ids
    assert "accessibility.rendered_images_alt" not in ids
    assert "accessibility.rendered_controls_name" not in ids
    assert "ecommerce.product_page_rendered_signals" not in ids


def test_unavailable_keyboard_focus_order_is_not_assessed_without_browser():
    from types import SimpleNamespace
    from unavailable_checks import append_unavailable_check_outcomes

    result = SimpleNamespace(check_outcomes=[], target_url="https://shop.example/", limitations=[])
    append_unavailable_check_outcomes(result, browser_audit_completed=False)
    by_id = {item.check_id: item for item in result.check_outcomes}
    assert by_id["accessibility.keyboard_focus_order"].outcome == "not_assessed"
