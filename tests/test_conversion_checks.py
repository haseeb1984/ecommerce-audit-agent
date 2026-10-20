import asyncio

import conversion_checks
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

def test_repeated_marketing_tag_signatures_need_review_not_confirmed_duplicate_firing():
    html = """
    <html><body>
      <script src="https://www.googletagmanager.com/gtag/js?id=G-ONE"></script>
      <script src="https://www.googletagmanager.com/gtag/js?id=G-TWO"></script>
    </body></html>
    """
    findings = inspect_conversion_html(html, "https://shop.example/")
    finding = next(f for f in findings if f.title == "Repeated marketing tag signatures need review")
    assert finding.status == "manual_review_required"
    assert finding.severity == "medium"
    assert "Google tag / Analytics" in finding.evidence
    assert "cannot confirm" in finding.explanation

def test_repeated_same_host_tag_occurrences_are_counted():
    html = """
    <html><body>
      <script src="https://www.googletagmanager.com/gtag/js?id=G-ONE"></script>
      <script src="https://www.googletagmanager.com/gtag/js?id=G-TWO"></script>
    </body></html>
    """
    findings = inspect_conversion_html(html, "https://shop.example/")
    finding = next(f for f in findings if f.title == "Repeated marketing tag signatures need review")
    assert "2 matching occurrences" in finding.evidence

def test_form_without_explicit_submit_control_needs_manual_review():
    findings = inspect_conversion_html(
        '<html><body><form><input name="email" type="email"></form></body></html>',
        "https://shop.example/",
    )
    finding = next(f for f in findings if f.title == "HTML form has no explicit submit control")
    assert finding.status == "manual_review_required"
    assert finding.severity == "low"
    assert "1 form(s)" in finding.evidence


def test_button_without_type_counts_as_default_submit_control():
    findings = inspect_conversion_html(
        '<html><body><form><input name="email"><button>Send request</button></form></body></html>',
        "https://shop.example/",
    )
    assert not any(f.title == "HTML form has no explicit submit control" for f in findings)


def test_submit_input_is_recognized_as_explicit_form_submit_control():
    findings = inspect_conversion_html(
        '<html><body><form><input name="email" type="email"><input type="submit" value="Send"></form></body></html>',
        "https://shop.example/",
    )
    assert not any(f.title == "HTML form has no explicit submit control" for f in findings)
    assert "submit control detected: yes" in next(
        f.evidence for f in findings if f.title == "Homepage contains HTML form(s)"
    )


def test_image_submit_input_is_recognized_as_explicit_form_submit_control():
    findings = inspect_conversion_html(
        '<html><body><form><input type="image" alt="Submit order"></form></body></html>',
        "https://shop.example/",
    )
    assert not any(f.title == "HTML form has no explicit submit control" for f in findings)



def test_conversion_paths_include_mailto_and_telephone_links():
    findings = inspect_conversion_html(
        '<html><body><a href="mailto:sales@example.com">Email sales</a>'
        '<a href="tel:+15551234567">Call us</a></body></html>',
        "https://shop.example/",
    )
    finding = next(f for f in findings if f.title == "Primary conversion path signals")
    assert "1 mailto link(s)" in finding.evidence
    assert "1 telephone link(s)" in finding.evidence



def test_malformed_link_url_is_skipped_without_aborting_conversion_audit():
    findings = inspect_conversion_html(
        '<html><body><a href="http://[broken">Broken link</a>'
        '<a href="/checkout">Checkout</a></body></html>',
        "https://shop.example/",
    )
    finding = next(f for f in findings if f.title == "Primary conversion path signals")
    assert "1 same-origin cart/checkout/payment-like link(s)" in finding.evidence
    assert "1 malformed URL(s) skipped safely" in finding.evidence


def test_fetch_failure_does_not_leak_exception_details(monkeypatch):
    async def fail_fetch(_client, _url):
        raise RuntimeError("authorization=secret-token-123; private host detail")

    monkeypatch.setattr(conversion_checks, "_safe_get", fail_fetch)
    findings, pages_checked, _limitations = asyncio.run(
        conversion_checks.run_conversion_paid_traffic_checks("https://shop.example/")
    )

    finding = next(f for f in findings if f.title == "Conversion signals not inspected")
    assert finding.status == "not_tested"
    assert "RuntimeError" in finding.evidence
    assert "secret-token-123" not in finding.evidence
    assert "private host detail" not in finding.evidence
    assert pages_checked == []


def test_flags_http_form_action_on_https_homepage():
    findings = inspect_conversion_html(
        '<html><body><form action="http://payments.example/submit?token=private"><input name="email">'
        '<button type="submit">Continue</button></form></body></html>',
        "https://shop.example/",
    )
    finding = next(f for f in findings if f.title == "Form submission may downgrade to unencrypted HTTP")
    assert finding.status == "verified"
    assert finding.severity == "high"
    assert "http://payments.example/submit" in finding.evidence
    assert "private" not in finding.evidence


def test_https_form_action_is_not_flagged_as_http_downgrade():
    findings = inspect_conversion_html(
        '<html><body><form action="https://payments.example/submit"><button>Continue</button></form></body></html>',
        "https://shop.example/",
    )
    assert not any(f.title == "Form submission may downgrade to unencrypted HTTP" for f in findings)


def test_flags_get_form_with_personal_fields_as_manual_security_review():
    findings = inspect_conversion_html(
        '<html><body><form method="get" action="/search"><input name="email" type="email">'
        '<input name="password" type="password"><button type="submit">Continue</button></form></body></html>',
        "https://shop.example/",
    )
    finding = next(f for f in findings if f.title == "GET form may place personal or sensitive fields in the URL")
    assert finding.status == "manual_review_required"
    assert finding.severity == "high"
    assert "1 GET form(s)" in finding.evidence


def test_post_form_with_personal_fields_is_not_flagged_for_get_url_exposure():
    findings = inspect_conversion_html(
        '<html><body><form method="post" action="/login"><input name="email" type="email">'
        '<input name="password" type="password"><button type="submit">Sign in</button></form></body></html>',
        "https://shop.example/",
    )
    assert not any(f.title == "GET form may place personal or sensitive fields in the URL" for f in findings)


def test_flags_get_form_with_address_and_date_of_birth_fields_for_review():
    findings = inspect_conversion_html(
        '<html><body><form method="get" action="/lookup">'
        '<input name="shipping_address" autocomplete="street-address">'
        '<input name="date_of_birth" type="date">'
        '<button type="submit">Continue</button></form></body></html>',
        "https://shop.example/",
    )
    finding = next(
        f for f in findings
        if f.title == "GET form may place personal or sensitive fields in the URL"
    )
    assert finding.status == "manual_review_required"
    assert finding.severity == "high"
    assert "1 GET form(s)" in finding.evidence


def test_get_form_with_non_sensitive_search_fields_is_not_flagged_as_personal_data():
    findings = inspect_conversion_html(
        '<html><body><form method="get" action="/search">'
        '<input name="q" type="search"><input name="page" type="number">'
        '<button type="submit">Search</button></form></body></html>',
        "https://shop.example/",
    )
    assert not any(
        f.title == "GET form may place personal or sensitive fields in the URL"
        for f in findings
    )



def test_external_form_destination_is_reported_for_trust_review_without_query_data():
    findings = inspect_conversion_html(
        '<html><body><form action="https://forms.vendor.example/submit?token=secret">'
        '<input name="email" type="email"><button type="submit">Request info</button></form></body></html>',
        "https://shop.example/",
    )
    finding = next(f for f in findings if f.title == "External form destination needs trust review")
    assert finding.status == "manual_review_required"
    assert finding.severity == "medium"
    assert "https://forms.vendor.example/submit" in finding.evidence
    assert "secret" not in finding.evidence


def test_same_origin_form_destination_is_not_reported_as_external():
    findings = inspect_conversion_html(
        '<html><body><form action="/contact"><input name="email"><button>Send</button></form></body></html>',
        "https://shop.example/",
    )
    assert not any(f.title == "External form destination needs trust review" for f in findings)


def test_http_external_form_destination_is_reported_and_query_is_redacted():
    findings = inspect_conversion_html(
        '<html><body><form action="http://forms.vendor.example/submit?api_key=secret">'
        '<button>Send</button></form></body></html>',
        "https://shop.example/",
    )
    external = next(f for f in findings if f.title == "External form destination needs trust review")
    insecure = next(f for f in findings if f.title == "Form submission may downgrade to unencrypted HTTP")
    assert "http://forms.vendor.example/submit" in external.evidence
    assert "secret" not in external.evidence
    assert insecure.severity == "high"
