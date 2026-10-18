from accessibility_checks import inspect_static_accessibility_signals


def test_unlabeled_controls_and_icon_only_links_are_reviewed():
    html = (
        '<html><head></head><body>'
        '<input id="email" type="email">'
        '<a href="/cart"><svg></svg></a>'
        '<button type="button"><svg></svg></button>'
        '</body></html>'
    )
    findings = inspect_static_accessibility_signals(html, "https://shop.example/")
    titles = {finding.title for finding in findings}
    assert "Form controls may lack accessible labels" in titles
    assert "Links may have no accessible name" in titles
    assert "Buttons may have no accessible name" in titles
    assert "Document language is not declared in returned HTML" in titles
    assert all(finding.status == "manual_review_required" for finding in findings)


def test_visible_labels_and_named_controls_do_not_trigger_findings():
    html = (
        '<html lang="en"><body>'
        '<label for="email">Email address</label><input id="email" type="email">'
        '<a href="/cart" aria-label="View shopping cart"><svg></svg></a>'
        '<button type="button" aria-label="Open menu"><svg></svg></button>'
        '</body></html>'
    )
    findings = inspect_static_accessibility_signals(html, "https://shop.example/")
    assert findings == []


def test_wrapped_label_and_informative_image_link_are_recognized():
    html = (
        '<html lang="en"><body>'
        '<label>Search <input type="search"></label>'
        '<a href="/"><img src="logo.svg" alt="Store home"></a>'
        '</body></html>'
    )
    findings = inspect_static_accessibility_signals(html, "https://shop.example/")
    assert not any(f.title == "Form controls may lack accessible labels" for f in findings)
    assert not any(f.title == "Links may have no accessible name" for f in findings)
    assert not any(f.title == "Document language is not declared in returned HTML" for f in findings)



def test_missing_image_alt_is_flagged_but_explicit_empty_alt_is_not():
    findings = inspect_static_accessibility_signals(
        '<html lang="en"><body><img src="/product.jpg"><img src="/ornament.svg" alt=""></body></html>',
        "https://shop.example/products/item",
    )
    image_finding = next(f for f in findings if f.title == "Images may be missing text alternatives")
    assert image_finding.status == "manual_review_required"
    assert "1 image(s)" in image_finding.evidence
    assert "ornament.svg" not in image_finding.evidence


def test_image_with_alt_attribute_does_not_trigger_missing_alt_finding():
    findings = inspect_static_accessibility_signals(
        '<html lang="en"><body><img src="/product.jpg" alt="Blue cotton shirt"></body></html>',
        "https://shop.example/products/item",
    )
    assert not any(f.title == "Images may be missing text alternatives" for f in findings)
