from conversion_checks import inspect_conversion_html


def test_detects_forms_checkout_paths_and_tracking_without_claiming_success():
    html = """
    <html><body>
      <form action="/contact">
        <input type="email" name="email">
        <button type="submit">Request a quote</button>
      </form>
      <a href="/checkout">Checkout</a>
      <script src="https://www.googletagmanager.com/gtag/js?id=G-EXAMPLE"></script>
      <script>fbq('init', '123456');</script>
    </body></html>
    """
    findings = inspect_conversion_html(html, "https://shop.example/")
    by_title = {finding.title: finding for finding in findings}

    assert by_title["Homepage contains HTML form(s)"].status == "verified"
    assert "1 form(s)" in by_title["Homepage contains HTML form(s)"].evidence
    assert "1 same-origin cart/checkout/payment-like link(s)" in by_title["Primary conversion path signals"].evidence
    assert "Google tag / Analytics" in by_title["Publicly detectable marketing tags"].evidence
    assert "Meta Pixel" in by_title["Publicly detectable marketing tags"].evidence
    assert "script host: www.googletagmanager.com" in by_title["Publicly detectable marketing tags"].evidence
    assert "inline signature: fbq(" in by_title["Publicly detectable marketing tags"].evidence
    assert "do not prove" in by_title["Publicly detectable marketing tags"].explanation
    assert all(f.evidence and f.explanation and f.recommendation and f.verification_steps for f in findings)


def test_no_form_or_tracking_is_reported_as_unverified_not_proven_absent():
    findings = inspect_conversion_html(
        "<html><body><h1>Shop</h1><a href='/about'>About</a></body></html>",
        "https://shop.example/",
    )
    by_title = {finding.title: finding for finding in findings}
    assert by_title["No HTML form detected on homepage"].status == "manual_review_required"
    assert by_title["Publicly detectable marketing tags"].status == "manual_review_required"
    assert "not proof" in by_title["No HTML form detected on homepage"].explanation
    assert "do not prove" in by_title["Publicly detectable marketing tags"].explanation


def test_detects_button_without_accessible_name():
    findings = inspect_conversion_html(
        "<html><body><button><svg></svg></button></body></html>",
        "https://shop.example/",
    )
    finding = next(f for f in findings if f.title == "Buttons may lack an accessible name")
    assert finding.status == "manual_review_required"
    assert "1 button element(s)" in finding.evidence

def test_detects_anchor_without_readable_name():
    findings = inspect_conversion_html('<html><body><a href="/cart"></a></body></html>', "https://shop.example/")
    finding = next(f for f in findings if f.title == "Links may lack an accessible name")
    assert finding.status == "manual_review_required"
    assert "1 same-origin link(s)" in finding.evidence
