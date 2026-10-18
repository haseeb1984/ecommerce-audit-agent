"""Conservative source-level trust-signal inventory for public ecommerce pages."""
from __future__ import annotations
import re
from html.parser import HTMLParser
from audit_checks import AuditFinding, _finding

MAX_TEXT_CHARS = 250_000
MAX_ASSET_REFERENCES = 2_000
PATTERNS = {
    "payment": re.compile(r"visa|mastercard|american express|amex|paypal|apple pay|google pay|klarna|stripe|payment method|secure checkout", re.I),
    "guarantee": re.compile(r"money[- ]back|money back guarantee|satisfaction guarantee|free returns|easy returns|refund policy|warranty", re.I),
    "reviews": re.compile(r"customer reviews?|verified reviews?|testimonials?|trustpilot|reviews\.io|yotpo|judge\.me", re.I),
    "support": re.compile(r"contact us|customer support|help center|shipping policy|returns policy|privacy policy|terms and conditions", re.I),
}
ASSET_HINTS = {
    "payment": re.compile(r"visa|mastercard|amex|paypal|apple.?pay|google.?pay|klarna|payment|stripe", re.I),
    "guarantee": re.compile(r"guarantee|money.?back|refund|warranty|return.?policy|secure.?checkout", re.I),
    "reviews": re.compile(r"review|testimonial|trustpilot|yotpo|judge.?me|rating|stars?", re.I),
}
class _TrustSignalParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text_parts = []
        self.asset_refs = []
        self.text_length = 0
    def handle_starttag(self, tag, attrs):
        values = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag in {"img", "iframe", "source"}:
            for key in ("src", "data-src", "alt", "title", "aria-label"):
                value = values.get(key, "").strip()
                if value and len(self.asset_refs) < MAX_ASSET_REFERENCES:
                    self.asset_refs.append(value[:500])
        elif tag in {"a", "button", "section", "div", "span"}:
            for key in ("aria-label", "title", "class", "id"):
                value = values.get(key, "").strip()
                if value and len(self.asset_refs) < MAX_ASSET_REFERENCES:
                    self.asset_refs.append(value[:500])
    def handle_data(self, data):
        if self.text_length >= MAX_TEXT_CHARS:
            return
        clean = " ".join(data.split())
        if clean:
            clean = clean[:MAX_TEXT_CHARS - self.text_length]
            self.text_parts.append(clean)
            self.text_length += len(clean)

def inspect_trust_signals(html: str, source_url: str) -> list[AuditFinding]:
    """Inventory detectable cues; never judge trustworthiness or badge authenticity."""
    parser = _TrustSignalParser()
    parser.feed(html[:MAX_TEXT_CHARS])
    visible_text = " ".join(parser.text_parts)
    assets = " ".join(parser.asset_refs)
    findings = []
    for key, label in (
        ("payment", "Payment-method cues"),
        ("guarantee", "Guarantee/returns cues"),
        ("reviews", "Review/testimonial cues"),
        ("support", "Support and policy cues"),
    ):
        text_match = bool(PATTERNS[key].search(visible_text))
        asset_match = key in ASSET_HINTS and bool(ASSET_HINTS[key].search(assets))
        if text_match or asset_match:
            details = []
            if text_match: details.append("matching text was found in returned HTML")
            if asset_match: details.append("matching image/asset attributes or component labels were found")
            findings.append(_finding(
                "trust_inspector", f"{label} detected in source", "verified", "info",
                f"{label} were detected on {source_url}: " + "; ".join(details) + ".",
                "This is only a source-level presence signal. It does not prove a badge is genuine, a payment method is available at checkout, a guarantee is honored, reviews are authentic, or a policy is legally adequate.",
                "Manually confirm the signal is visible and accurate in the rendered customer journey. Verify third-party badges with their provider and ensure policies match actual operations.",
                ["Open the page in a browser and confirm the cue is visible and current.", "Verify any badge or review widget with its issuing provider.", "Check relevant product, cart, checkout, and policy pages where applicable."],
                source_url,
            ))
        else:
            findings.append(_finding(
                "trust_inspector", f"{label} not detected in initial HTML", "manual_review_required", "info",
                f"No recognizable {label.lower()} text or source attribute was detected in the inspected HTML for {source_url}.",
                "The cue may be unnecessary, appear on another page, or be injected by JavaScript/third-party widgets. This result does not establish that the store lacks the signal or is untrustworthy.",
                "Review the rendered storefront and relevant purchase journey. Add or change trust information only when accurate, applicable, and useful to customers.",
                ["Inspect rendered homepage and relevant product/cart/checkout pages.", "Check JavaScript-rendered widgets and mobile layout.", "Confirm claims and policy links are accurate before changing them."],
                source_url,
            ))
    return findings
