from mobile_ux_checks import inspect_mobile_viewport


def test_missing_viewport_is_reviewed():
    findings = inspect_mobile_viewport("<html><head></head><body></body></html>", "https://shop.example/")
    assert len(findings) == 1
    assert findings[0].title == "Viewport declaration not detected"
    assert findings[0].status == "manual_review_required"


def test_device_width_viewport_is_not_flagged():
    html = '<meta name="viewport" content="width=device-width, initial-scale=1">'
    assert inspect_mobile_viewport(html, "https://shop.example/") == []


def test_viewport_without_device_width_needs_review():
    html = '<meta name="viewport" content="width=1024, initial-scale=1">'
    findings = inspect_mobile_viewport(html, "https://shop.example/")
    assert any(f.title == "Viewport width setting needs mobile review" for f in findings)


def test_zoom_restrictions_are_flagged_for_review():
    html = '<meta name="viewport" content="width=device-width, maximum-scale=1, user-scalable=no">'
    findings = inspect_mobile_viewport(html, "https://shop.example/")
    finding = next(f for f in findings if f.title == "Viewport may restrict user zoom")
    assert finding.status == "manual_review_required"
    assert "Remove unnecessary zoom restrictions" in finding.recommendation


def test_malformed_html_is_handled_without_crashing():
    findings = inspect_mobile_viewport("<meta", "https://shop.example/")
    assert isinstance(findings, list)
