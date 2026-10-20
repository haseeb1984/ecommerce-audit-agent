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


def test_duplicate_ids_are_flagged_for_relationship_review():
    findings = inspect_static_accessibility_signals(
        '<html lang="en"><body><label for="email">Email</label>'
        '<input id="email"><span id="status">Ready</span><span id="status">Updated</span>'
        '</body></html>',
        "https://shop.example/account",
    )
    finding = next(
        f for f in findings
        if f.title == "Duplicate HTML IDs may affect accessible relationships"
    )
    assert finding.status == "manual_review_required"
    assert "status" in finding.evidence
    assert "email" not in finding.evidence


def test_unique_ids_do_not_trigger_duplicate_id_finding():
    findings = inspect_static_accessibility_signals(
        '<html lang="en"><body><label for="email">Email</label>'
        '<input id="email"><span id="status">Ready</span></body></html>',
        "https://shop.example/account",
    )
    assert not any(
        f.title == "Duplicate HTML IDs may affect accessible relationships"
        for f in findings
    )


def test_broken_aria_and_label_references_are_flagged():
    findings = inspect_static_accessibility_signals(
        '<html lang="en"><body><label for="missing-input">Email</label>'
        '<button aria-describedby="missing-help" aria-controls="missing-panel">Open</button>'
        '</body></html>',
        "https://shop.example/account",
    )
    finding = next(
        f for f in findings
        if f.title == "Some label or ARIA references point to missing IDs"
    )
    assert finding.status == "manual_review_required"
    assert "missing-input" in finding.evidence
    assert "missing-help" in finding.evidence
    assert "missing-panel" in finding.evidence


def test_valid_aria_and_label_references_do_not_trigger_missing_id_finding():
    findings = inspect_static_accessibility_signals(
        '<html lang="en"><body><label for="email">Email</label>'
        '<input id="email" aria-describedby="email-help">'
        '<span id="email-help">Required</span><button aria-controls="panel">Open</button>'
        '<div id="panel"></div></body></html>',
        "https://shop.example/account",
    )
    assert not any(
        f.title == "Some label or ARIA references point to missing IDs"
        for f in findings
    )


def test_unlabeled_select_and_textarea_are_reviewed():
    findings = inspect_static_accessibility_signals(
        '<html lang="en"><body><select name="country"><option>Choose</option></select>'
        '<textarea name="message"></textarea></body></html>',
        "https://shop.example/contact",
    )
    finding = next(f for f in findings if f.title == "Form controls may lack accessible labels")
    assert "2 form control(s)" in finding.evidence
    assert finding.status == "manual_review_required"


def test_labeled_select_and_textarea_do_not_trigger_form_label_finding():
    findings = inspect_static_accessibility_signals(
        '<html lang="en"><body><label for="country">Country</label>'
        '<select id="country"><option>Choose</option></select>'
        '<label for="message">Message</label><textarea id="message"></textarea>'
        '</body></html>',
        "https://shop.example/contact",
    )
    assert not any(f.title == "Form controls may lack accessible labels" for f in findings)


def test_svg_title_names_icon_only_links_and_buttons():
    html = (
        '<html lang="en"><body>'
        '<a href="/cart"><svg><title>View cart</title><path d="M0 0"/></svg></a>'
        '<button type="button"><svg><title>Open menu</title><path d="M0 0"/></svg></button>'
        '</body></html>'
    )
    findings = inspect_static_accessibility_signals(html, "https://shop.example/")
    assert not any(f.title == "Links may have no accessible name" for f in findings)
    assert not any(f.title == "Buttons may have no accessible name" for f in findings)


def test_svg_title_is_an_accessible_name_not_visible_control_text():
    from accessibility_checks import _AccessibilityParser

    parser = _AccessibilityParser()
    parser.feed(
        '<html lang="en"><body>'
        '<a href="/cart"><svg><title>View cart</title></svg></a>'
        '<button><svg><title>Open menu</title></svg></button>'
        '</body></html>'
    )
    assert parser.links[0]["text"] == ""
    assert parser.links[0]["has_svg_title"] is True
    assert parser.buttons[0]["text"] == ""
    assert parser.buttons[0]["has_svg_title"] is True



def test_image_submit_control_without_name_is_flagged():
    findings = inspect_static_accessibility_signals(
        '<html lang="en"><body><form><input type="image" src="/submit.png"></form></body></html>',
        "https://shop.example/checkout",
    )
    finding = next(
        f for f in findings
        if f.title == "Image submit controls may lack accessible names"
    )
    assert finding.status == "manual_review_required"
    assert "1 image submit control(s)" in finding.evidence


def test_named_image_submit_control_is_not_flagged():
    findings = inspect_static_accessibility_signals(
        '<html lang="en"><body><form><input type="image" src="/submit.png" alt="Place order"></form></body></html>',
        "https://shop.example/checkout",
    )
    assert not any(
        f.title == "Image submit controls may lack accessible names"
        for f in findings
    )

def test_unresolved_aria_labelledby_does_not_count_as_accessible_name():
    findings = inspect_static_accessibility_signals(
        '<html lang="en"><body>'
        '<input aria-labelledby="missing-input-label">'
        '<span id="empty-label"></span><input aria-labelledby="empty-label">'
        '<a href="/cart" aria-labelledby="missing-link-label"><svg></svg></a>'
        '<button aria-labelledby="missing-button-label"><svg></svg></button>'
        '</body></html>',
        "https://shop.example/checkout",
    )
    titles = {finding.title for finding in findings}
    assert "Some label or ARIA references point to missing IDs" in titles
    assert "Form controls may lack accessible labels" in titles
    assert "Links may have no accessible name" in titles
    assert "Buttons may have no accessible name" in titles


def test_resolved_aria_labelledby_is_recognized_as_name():
    findings = inspect_static_accessibility_signals(
        '<html lang="en"><body>'
        '<span id="email-label">Email address</span><input aria-labelledby="email-label">'
        '<span id="cart-label">View cart</span><a href="/cart" aria-labelledby="cart-label"></a>'
        '<span id="menu-label">Open menu</span><button aria-labelledby="menu-label"></button>'
        '</body></html>',
        "https://shop.example/checkout",
    )
    assert not any(
        finding.title in {
            "Some label or ARIA references point to missing IDs",
            "Form controls may lack accessible labels",
            "Links may have no accessible name",
            "Buttons may have no accessible name",
        }
        for finding in findings
    )




def test_invalid_document_language_tag_is_flagged_for_review():
    findings = inspect_static_accessibility_signals(
        '<html lang="english_US"><body><h1>Store</h1></body></html>',
        "https://shop.example/",
    )
    finding = next(
        f for f in findings if f.title == "Document language tag needs review"
    )
    assert finding.status == "manual_review_required"
    assert "english_US" in finding.evidence


def test_valid_regional_document_language_tag_is_not_flagged():
    findings = inspect_static_accessibility_signals(
        '<html lang="en-GB"><body><h1>Store</h1></body></html>',
        "https://shop.example/",
    )
    assert not any(
        f.title == "Document language tag needs review" for f in findings
    )
