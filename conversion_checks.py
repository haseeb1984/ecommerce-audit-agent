"""Evidence-first public conversion and paid-traffic diagnostics.

These are static HTML signals, not conversion-rate, revenue-loss, or ad-attribution measurements.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from audit_checks import (
    AuditFinding,
    PublicOnlyResolver,
    _finding,
    _safe_get,
    normalize_target,
)
import aiohttp
import socket


MAX_LINKS_TO_REVIEW = 500
TRACKING_PATTERNS = {
    "Google tag / Analytics": re.compile(r"(googletagmanager\\.com|google-analytics\\.com|gtag\\s*\\()", re.I),
    "Meta Pixel": re.compile(r"(connect\\.facebook\\.net|fbq\\s*\\()", re.I),
    "TikTok Pixel": re.compile(r"(analytics\\.tiktok\\.com|ttq\\.load)", re.I),
    "Microsoft Clarity": re.compile(r"(clarity\\.ms|clarity\\s*\\()", re.I),
}


class _ConversionParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms = 0
        self.form_fields = 0
        self.form_has_email = False
        self.form_has_submit = False
        self.buttons = 0
        self.buttons_without_name = 0
        self.links: list[tuple[str, str, str]] = []
        self._active_form = False
        self._active_button = False
        self._button_text: list[str] = []
        self._button_has_name = False
        self._active_link: tuple[str, str] | None = None
        self._link_text: list[str] = []
        self.script_sources: list[str] = []
        self._in_script = False
        self._script_parts: list[str] = []
        self.form_actions: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag == "form":
            self.forms += 1
            self._active_form = True
            self.form_actions.append(values.get("action", ""))
        elif tag in {"input", "select", "textarea"} and self._active_form:
            input_type = values.get("type", "text").lower()
            if input_type not in {"hidden", "submit", "button", "reset", "image"}:
                self.form_fields += 1
            if input_type == "email" or values.get("autocomplete", "").lower() == "email":
                self.form_has_email = True
        elif tag == "button":
            self.buttons += 1
            self._active_button = True
            self._button_text = []
            self._button_has_name = bool(values.get("aria-label", "").strip() or values.get("title", "").strip())
            if values.get("type", "").lower() == "submit" and self._active_form:
                self.form_has_submit = True
        elif tag == "input" and values.get("type", "").lower() == "submit" and self._active_form:
            self.form_has_submit = True
        elif tag == "a" and values.get("href") and len(self.links) < MAX_LINKS_TO_REVIEW:
            self._active_link = (values["href"].strip(), values.get("aria-label", "").strip())
            self._link_text = []
        elif tag == "script":
            src = values.get("src", "").strip()
            if src:
                self.script_sources.append(src)
            self._in_script = True
            self._script_parts = []

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "form":
            self._active_form = False
        elif tag == "button" and self._active_button:
            if not self._button_has_name and not " ".join("".join(self._button_text).split()):
                self.buttons_without_name += 1
            self._active_button = False
        elif tag == "a" and self._active_link:
            href, aria = self._active_link
            label = aria or " ".join("".join(self._link_text).split())
            self.links.append((href, label, ""))
            self._active_link = None
        elif tag == "script" and self._in_script:
            text = "".join(self._script_parts)
            if text:
                self.script_sources.append(text[:100_000])
            self._script_parts = []
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._active_button:
            self._button_text.append(data)
        if self._active_link:
            self._link_text.append(data)
        if self._in_script:
            self._script_parts.append(data)


def inspect_conversion_html(html: str, final_url: str) -> list[AuditFinding]:
    parser = _ConversionParser()
    parser.feed(html)
    findings: list[AuditFinding] = []
    origin = f"{urlsplit(final_url).scheme}://{urlsplit(final_url).netloc}"
    internal_checkout = []
    internal_contact = []
    unlabeled_links = 0
    for href, label, _ in parser.links:
        absolute = urljoin(final_url, href)
        parsed = urlsplit(absolute)
        if parsed.scheme not in {"http", "https"} or parsed.netloc.lower() != urlsplit(origin).netloc.lower():
            continue
        path = parsed.path.lower()
        if any(token in path for token in ("checkout", "cart", "basket", "payment")):
            internal_checkout.append(absolute)
        if any(token in path for token in ("contact", "support", "help")):
            internal_contact.append(absolute)
        if not label and not href.strip():
            unlabeled_links += 1

    if parser.forms:
        findings.append(_finding(
            "conversion_paid_traffic", "Homepage contains HTML form(s)", "verified", "info",
            f"Detected {parser.forms} form(s), {parser.form_fields} non-hidden form field(s); "
            f"email field detected: {'yes' if parser.form_has_email else 'no'}; "
            f"submit control detected: {'yes' if parser.form_has_submit else 'not detected'}.",
            "A form is a potential interaction point, but source HTML alone cannot establish that submission works, that validation is usable, or that the form contributes to a business goal.",
            "Test the form end to end on desktop and mobile, including validation, error messages, success confirmation, and delivery of the submitted data.",
            ["Submit a test entry with valid and invalid values.", "Verify the expected confirmation and backend/email receipt.", "Check keyboard and screen-reader operation."],
            final_url,
        ))
    else:
        findings.append(_finding(
            "conversion_paid_traffic", "No HTML form detected on homepage", "manual_review_required", "info",
            "No <form> element was detected in the returned homepage HTML.",
            "The homepage may not need a form, and JavaScript-rendered or embedded forms may not appear in the initial HTML. This is not proof that the site lacks a lead or purchase journey.",
            "Review the primary user journey and test relevant landing pages, product pages, cart, checkout, and contact flow in a real browser.",
            ["Inspect rendered UI and JavaScript-loaded components.", "Complete a test journey where permitted without placing a real order."],
            final_url,
        ))

    findings.append(_finding(
        "conversion_paid_traffic", "Primary conversion path signals", "manual_review_required", "info",
        f"Static HTML link scan detected {len(internal_checkout)} same-origin cart/checkout/payment-like link(s) "
        f"and {len(internal_contact)} contact/support/help-like link(s), among {len(parser.links)} parsed links.",
        "URL names can suggest navigation paths but do not prove that checkout or contact journeys work, are easy to find, or convert visitors.",
        "Manually follow the intended purchase or lead path on mobile and desktop. Confirm key steps, costs, shipping/returns information, and error states are understandable before asking users to commit.",
        ["Open each detected path in a browser.", "Test keyboard navigation and mobile layouts.", "Verify forms and checkout using a safe test mode if available."],
        final_url,
    ))

    combined_sources = "\n".join(parser.script_sources)
    detected = [name for name, pattern in TRACKING_PATTERNS.items() if pattern.search(combined_sources)]
    findings.append(_finding(
        "conversion_paid_traffic", "Publicly detectable marketing tags", "verified" if detected else "manual_review_required",
        "info",
        ("Static HTML contained signals matching: " + ", ".join(detected) + ".")
        if detected else
        "No known Google tag/Analytics, Meta Pixel, TikTok Pixel, or Microsoft Clarity signature was detected in the parsed static HTML.",
        "Tag signatures are only presence signals. They do not prove the tag fires correctly, consent is handled properly, events are configured, or ad platforms attribute conversions. Absence from initial HTML does not prove tracking is absent.",
        "Use the relevant browser tag debugger and analytics/ad-platform diagnostics to verify page-view and intended conversion events, consent behavior, and duplicate firing. Never infer conversion performance from tag presence alone.",
        ["Test in the browser with official tag debugging tools.", "Verify the intended conversion event appears once in the correct account.", "Check consent choices and network requests."],
        final_url,
    ))

    if parser.buttons_without_name:
        findings.append(_finding(
            "conversion_paid_traffic", "Buttons may lack an accessible name", "manual_review_required", "medium",
            f"{parser.buttons_without_name} button element(s) had neither an aria-label/title nor readable text in the returned HTML.",
            "A button without an accessible name can make an important action unclear to screen-reader users. This can also make a primary journey harder to use, but conversion impact is not measured here.",
            "Give each button a concise accessible name that describes its action; icon-only buttons need a meaningful accessible label.",
            ["Inspect each flagged button in the rendered page.", "Check its computed accessible name with browser accessibility tools."],
            final_url,
        ))
    return findings


async def run_conversion_paid_traffic_checks(target: str) -> tuple[list[AuditFinding], list[str], list[str]]:
    """Inspect only the public homepage HTML for conservative conversion-path signals."""
    normalized = normalize_target(target)
    timeout = aiohttp.ClientTimeout(total=10.0)
    connector = aiohttp.TCPConnector(resolver=PublicOnlyResolver(), use_dns_cache=False, family=socket.AF_UNSPEC)
    limitations = [
        "Conversion and paid-traffic checks inspect static homepage HTML only; they do not measure conversion rate, ad spend, CPC, attribution, or revenue loss.",
        "JavaScript-rendered UI, checkout flows, consent-gated tags, authenticated pages, and third-party embedded widgets may not be visible to this check.",
        "Tag signature detection is not proof that analytics or conversion events fire correctly.",
    ]
    async with aiohttp.ClientSession(
        timeout=timeout, connector=connector,
        headers={"User-Agent": "EcommerceAuditBot/1.0 (+https://junctiontools.com)"},
        trust_env=False,
    ) as client:
        try:
            status, html, _, final_url = await _safe_get(client, normalized)
            if not 200 <= status < 300:
                return [
                    _finding(
                        "conversion_paid_traffic", "Conversion signals not inspected", "not_tested", "info",
                        f"Homepage returned HTTP {status}; static conversion checks were skipped.",
                        "A non-successful response does not provide a reliable view of the homepage's user journey.",
                        "Resolve reachability or access restrictions and rerun the audit.",
                        ["Open the target in a browser and check the HTTP response."], final_url,
                    )
                ], [], limitations
            return inspect_conversion_html(html, final_url), [final_url], limitations
        except Exception as exc:
            return [
                _finding(
                    "conversion_paid_traffic", "Conversion signals not inspected", "not_tested", "info",
                    f"Static homepage fetch did not complete: {type(exc).__name__}: {str(exc)[:180]}",
                    "No reliable HTML was available, so conversion-path signals could not be checked.",
                    "Confirm the target is publicly reachable and rerun; do not interpret this as proof that conversion elements are missing.",
                    ["Open the target in a browser and verify DNS, TLS, and access rules."], normalized,
                )
            ], [], limitations
