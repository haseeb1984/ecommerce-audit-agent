from trust_checks import inspect_trust_signals

def test_detected_trust_cues_are_presence_signals_not_authenticity_claims():
    html = """<html><body><p>PayPal accepted. 30-day money back guarantee.</p>
    <section class="customer-reviews"><h2>Customer reviews</h2></section>
    <a href="/contact">Contact us</a><a href="/returns">Returns policy</a></body></html>"""
    findings = inspect_trust_signals(html, "https://shop.example/")
    assert len(findings) == 4
    assert all(f.category == "trust_inspector" and f.status == "verified" for f in findings)
    assert all("does not prove" in f.explanation for f in findings)

def test_absent_cues_require_manual_review_and_are_not_failures():
    findings = inspect_trust_signals("<html><body><p>Welcome</p></body></html>", "https://shop.example/")
    assert len(findings) == 4
    assert all(f.status == "manual_review_required" and f.severity == "info" for f in findings)
    assert all("does not establish" in f.explanation for f in findings)

def test_review_widget_name_does_not_prove_review_authenticity():
    findings = inspect_trust_signals('<div class="trustpilot-widget" aria-label="Customer reviews"></div>', "https://shop.example/")
    review = next(f for f in findings if "Review/testimonial" in f.title)
    assert review.status == "verified"
    assert "does not prove" in review.explanation

def test_script_and_style_text_are_not_treated_as_visible_trust_evidence():
    html = """<html><head><style>.badge { content: 'Visa secure checkout'; }</style>
    <script>const marketing = 'PayPal accepted, money back guarantee, customer reviews';</script>
    </head><body><p>Welcome to our store</p></body></html>"""
    findings = inspect_trust_signals(html, "https://shop.example/")
    assert all(item.status == "manual_review_required" for item in findings)
