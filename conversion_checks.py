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
    "Google tag / Analytics": re.compile(r"(googletagmanager\.com|google-analytics\.com|gtag\s*\()", re.I),
    "Meta Pixel": re.compile(r"(connect\.facebook\.net|fbq\s*\()", re.I),
    "TikTok Pixel": re.compile(r"(analytics\.tiktok\.com|ttq\.load)", re.I),
    "Microsoft Clarity": re.compile(r"(clarity\.ms|clarity\s*\()", re.I),
}


class _ConversionParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms = 0
        self.form_fields = 0
        self.form_has_email = False
        self.form_has_submit = False
        self.forms_without_submit = 0
        self._current_form_has_submit = False
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
        self._active_form_method = "get"
        self._active_get_form_has_sensitive_field = False
        self.get_forms_with_sensitive_fields = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag == "form":
            self.forms += 1
            self._active_form = True
            self._current_form_has_submit = False
            self._active_form_method = values.get("method", "get").strip().lower() or "get"
            self._active_get_form_has_sensitive_field = False
            self.form_actions.append(values.get("action", ""))
        elif tag in {"input", "select", "textarea"} and self._active_form:
            input_type = values.get("type", "text").lower()
            field_identity = " ".join((
                values.get("name", ""), values.get("id", ""),
                values.get("autocomplete", ""), input_type,
            )).lower()
            if self._active_form_method == "get" and any(
                marker in field_identity
                for marker in ("password", "passwd", "secret", "token", "credit-card", "cc-", "cvv", "cvc", "email", "phone", "telephone", "address", "street", "postal", "postcode", "zip-code", "birth", "date-of-birth", "dob", "national-id", "ssn")
            ):
                self._active_get_form_has_sensitive_field = True
            if input_type not in {"hidden", "submit", "button", "reset", "image"}:
                self.form_fields += 1
            if input_type == "email" or values.get("autocomplete", "").lower() == "email":
                self.form_has_email = True
            # Handle submit inputs here: the broader input/select/textarea branch
            # otherwise makes the dedicated input[type=submit] branch unreachable.
            if tag == "input" and input_type in {"submit", "image"}:
                self.form_has_submit = True
                self._current_form_has_submit = True
        elif tag == "button":
            self.buttons += 1
            self._active_button = True
            self._button_text = []
            self._button_has_name = bool(values.get("aria-label", "").strip() or values.get("title", "").strip())
            if values.get("type", "submit").lower() in {"", "submit"} and self._active_form:
                self.form_has_submit = True
                self._current_form_has_submit = True
        elif tag == "input" and values.get("type", "").lower() == "submit" and self._active_form:
            self.form_has_submit = True
            self._current_form_has_submit = True
        elif tag == "a" and values.get("href") and len(self.links) < MAX_LINKS_TO_REVIEW:
            target_blank = values.get("target", "").strip().lower() == "_blank"
            rel_tokens = set(values.get("rel", "").strip().lower().split())
            missing_opener_protection = target_blank and not (
                {"noopener", "noreferrer"} & rel_tokens
            )
            self._active_link = (
                values["href"].strip(),
                values.get("aria-label", "").strip(),
                "true" if missing_opener_protection else "",
            )
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
            if self._active_form and not self._current_form_has_submit:
                self.forms_without_submit += 1
            if self._active_form and self._active_get_form_has_sensitive_field:
                self.get_forms_with_sensitive_fields += 1
            self._active_form = False
            self._active_form_method = "get"
            self._active_get_form_has_sensitive_field = False
        elif tag == "button" and self._active_button:
            if not self._button_has_name and not " ".join("".join(self._button_text).split()):
                self.buttons_without_name += 1
            self._active_button = False
        elif tag == "a" and self._active_link:
            href, aria, missing_opener_protection = self._active_link
            label = aria or " ".join("".join(self._link_text).split())
            self.links.append((href, label, missing_opener_protection))
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
    policy_links: dict[str, list[str]] = {
        "privacy": [], "terms": [], "returns": [], "shipping": [], "payment": [],
    }
    direct_contact_links = {"mailto": 0, "tel": 0}
    unlabeled_links = 0
    malformed_links = 0
    new_tab_links_without_opener_protection: list[str] = []
    for href, label, missing_opener_protection in parser.links:
        if missing_opener_protection == "true":
            # Exclude query strings so tokens and campaign identifiers are not copied into evidence.
            try:
                link_parts = urlsplit(urljoin(final_url, href))
                new_tab_links_without_opener_protection.append(
                    f"{link_parts.scheme}://{link_parts.netloc}{link_parts.path or '/'}"
                )
            except (ValueError, UnicodeError):
                new_tab_links_without_opener_protection.append("(malformed target=_blank link)")
        # Public HTML is untrusted input: malformed authorities (for example,
        # unmatched IPv6 brackets or invalid ports) must not abort the whole audit.
        try:
            absolute = urljoin(final_url, href)
            parsed = urlsplit(absolute)
            _ = parsed.port  # Force validation of an explicit port.
        except (ValueError, UnicodeError):
            malformed_links += 1
            continue
        if parsed.scheme.lower() in direct_contact_links:
            direct_contact_links[parsed.scheme.lower()] += 1
            continue
        if parsed.scheme.lower() not in {"http", "https"} or parsed.netloc.lower() != urlsplit(origin).netloc.lower():
            continue
        path = parsed.path.lower()
        searchable = f"{path} {label.lower()}"
        if any(token in searchable for token in ("checkout", "cart", "basket", "payment")):
            internal_checkout.append(absolute)
        if any(token in searchable for token in ("contact", "support", "help")):
            internal_contact.append(absolute)
        # Policy and fulfilment links help shoppers evaluate trust and total cost.
        # Treat these as visibility signals only: links may be in menus/footer,
        # and absence from static homepage HTML is not proof the policy is missing.
        policy_patterns = {
            "privacy": ("privacy", "data protection"),
            "terms": ("terms", "conditions", "legal"),
            "returns": ("return", "refund", "exchange"),
            "shipping": ("shipping", "delivery", "dispatch"),
            "payment": ("payment", "accepted cards", "billing"),
        }
        for category, tokens in policy_patterns.items():
            if any(token in searchable for token in tokens):
                if absolute not in policy_links[category]:
                    policy_links[category].append(absolute)
        if not label:
            unlabeled_links += 1

    if new_tab_links_without_opener_protection:
        examples = list(dict.fromkeys(new_tab_links_without_opener_protection))[:5]
        findings.append(_finding(
            "security", "New-tab links need opener-protection review",
            "manual_review_required", "low",
            f"Found {len(new_tab_links_without_opener_protection)} link(s) with target=\"_blank\" and no explicit rel=\"noopener\" or rel=\"noreferrer\". Examples: "
            + ", ".join(examples),
            "Explicit opener protection is a useful compatibility and defense-in-depth measure for links that open a new tab. Modern browsers generally apply implicit noopener behavior to target=_blank, so this source signal alone does not establish an exploitable vulnerability.",
            "For links that open a new tab, add rel=\"noopener\" or rel=\"noreferrer\" where appropriate, then verify expected referrer behavior and the rendered link attributes.",
            ["Inspect the affected links in the rendered page.", "Confirm the destination cannot control the opener in supported browsers.", "Keep referrer information only where the business and privacy requirements call for it."],
            final_url,
        ))

    if parser.forms_without_submit:
        findings.append(_finding(
            "conversion_paid_traffic", "HTML form has no explicit submit control",
            "manual_review_required", "low",
            f"Found {parser.forms_without_submit} form(s) without a detected submit button or submit input in the returned HTML.",
            "A form may submit through Enter, JavaScript, or an external widget, so a missing explicit submit control is not proof that submission is impossible. It can nevertheless make the next step unclear to some users.",
            "Test each affected form with keyboard-only navigation and on mobile. Add a clearly named submit control where it improves discoverability, and verify that validation and success/error feedback are available.",
            ["Inspect the rendered form and accessible controls.", "Test submission using keyboard and touch.", "Confirm valid and invalid submissions produce clear feedback."],
            final_url,
        ))

    insecure_form_actions: list[str] = []
    if urlsplit(final_url).scheme.lower() == "https":
        for action in parser.form_actions:
            try:
                resolved_action = urljoin(final_url, action.strip() or final_url)
                action_parts = urlsplit(resolved_action)
                _ = action_parts.port
            except (ValueError, UnicodeError):
                continue
            if action_parts.scheme.lower() == "http" and action_parts.netloc:
                # Keep the report evidence free of query strings, which may contain tokens.
                safe_destination = f"http://{action_parts.netloc}{action_parts.path or '/'}"
                if safe_destination not in insecure_form_actions:
                    insecure_form_actions.append(safe_destination)

    # Third-party form destinations can be legitimate (for example, hosted payment
    # providers), but deserve explicit ownership and transport review. Never include
    # query strings because they may carry tokens or personal data.
    external_form_actions: list[str] = []
    final_parts = urlsplit(final_url)
    final_origin = (final_parts.scheme.lower(), final_parts.hostname or "", final_parts.port)
    for action in parser.form_actions:
        try:
            resolved_action = urljoin(final_url, action.strip() or final_url)
            action_parts = urlsplit(resolved_action)
            _ = action_parts.port
        except (ValueError, UnicodeError):
            continue
        if action_parts.scheme.lower() not in {"http", "https"} or not action_parts.hostname:
            continue
        action_origin = (action_parts.scheme.lower(), action_parts.hostname.lower(), action_parts.port)
        if action_origin != (final_origin[0], final_origin[1].lower(), final_origin[2]):
            safe_destination = (
                f"{action_parts.scheme.lower()}://{action_parts.netloc}{action_parts.path or '/'}"
            )
            if safe_destination not in external_form_actions:
                external_form_actions.append(safe_destination)

    if external_form_actions:
        findings.append(_finding(
            "security", "External form destination needs trust review",
            "manual_review_required", "medium",
            f"Found {len(external_form_actions)} form action destination(s) outside the homepage origin: "
            + ", ".join(external_form_actions[:5]),
            "A third-party form destination can be an intentional payment, CRM, or hosted-form integration. This static check cannot establish who controls the endpoint, what data is sent, or whether the provider is approved.",
            "Verify each destination is an expected, trusted service, uses HTTPS for sensitive submissions, and receives only the data required for the stated purpose. Prefer an approved provider endpoint and document the integration owner.",
            ["Compare each destination with the site's approved payment, CRM, and form-provider configuration.", "Inspect submitted fields and consent disclosures without sending real customer data.", "Confirm sensitive submissions never travel over HTTP and that the destination is controlled by the expected provider."],
            final_url,
        ))

    if parser.get_forms_with_sensitive_fields:
        findings.append(_finding(
            "security", "GET form may place personal or sensitive fields in the URL",
            "manual_review_required", "high",
            f"Detected {parser.get_forms_with_sensitive_fields} GET form(s) containing fields whose names or types suggest passwords, tokens, payment data, email, or phone information.",
            "GET form values are normally encoded into the request URL, where they may be retained in browser history, server logs, analytics systems, and referrer data. Field names are only heuristic evidence; this check does not submit the form or inspect runtime behavior.",
            "Use POST for forms that collect personal, authentication, or payment-related data, transmit it only over HTTPS, and review logging, analytics, and referrer policies for accidental exposure.",
            ["Inspect the method and fields of each flagged form in the rendered page.", "Confirm personal or authentication values are not placed in query strings.", "Use non-sensitive test data and inspect the final request URL and server handling."],
            final_url,
        ))

    if insecure_form_actions:
        findings.append(_finding(
            "security", "Form submission may downgrade to unencrypted HTTP",
            "verified", "high",
            f"Found {len(insecure_form_actions)} form action destination(s) using HTTP from an HTTPS homepage: "
            + ", ".join(insecure_form_actions[:5]),
            "A form that submits sensitive fields over plain HTTP can expose submitted data in transit. The presence of an HTTP action is a source-level signal; this check does not submit the form or determine which fields are sensitive.",
            "Change affected form actions to HTTPS endpoints under the intended trusted service, and verify redirects and the final submission destination in a safe test flow.",
            ["Inspect each listed form action in the rendered page.", "Confirm the destination supports HTTPS and does not redirect submission to HTTP.", "Test with non-sensitive sample data and verify the final request uses HTTPS."],
            final_url,
        ))

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

    missing_policy_signals = [name for name, urls in policy_links.items() if not urls]
    visible_policy_signals = [name for name, urls in policy_links.items() if urls]
    findings.append(_finding(
        "conversion_paid_traffic", "Homepage policy and fulfilment-link visibility",
        "manual_review_required", "low" if missing_policy_signals else "info",
        "Static homepage link scan found visible signals for: "
        + (", ".join(visible_policy_signals) if visible_policy_signals else "none of the checked policy/fulfilment categories")
        + ". No visible link signal was found for: "
        + (", ".join(missing_policy_signals) if missing_policy_signals else "none; all checked categories had a signal")
        + ".",
        "Privacy, terms, returns/refunds, shipping/delivery, and payment information can help shoppers understand data use, fulfilment, and purchase conditions. This check searches static same-origin link URLs and labels only; links may be in JavaScript-rendered menus, footer widgets, or differently named pages.",
        "Review the homepage, navigation, footer, product pages, and checkout in a browser. Make relevant privacy/terms links easy to find and show returns, delivery costs/timing, and accepted payment information before customers commit where applicable.",
        ["Inspect the rendered header, footer, product pages, and checkout for the relevant policies.",
         "Open each available policy and confirm it is current, readable, and consistent with the checkout.",
         "Do not add irrelevant policy links solely to satisfy this heuristic."],
        final_url,
    ))

    findings.append(_finding(
        "conversion_paid_traffic", "Primary conversion path signals", "manual_review_required", "info",
        f"Static HTML link scan detected {len(internal_checkout)} same-origin cart/checkout/payment-like link(s) "
        f"and {len(internal_contact)} contact/support/help-like link(s); "
        f"{direct_contact_links['mailto']} mailto link(s) and {direct_contact_links['tel']} telephone link(s), "
        f"among {len(parser.links)} parsed links; {malformed_links} malformed URL(s) skipped safely.",
        "URL names can suggest navigation paths but do not prove that checkout or contact journeys work, are easy to find, or convert visitors.",
        "Manually follow the intended purchase or lead path on mobile and desktop. Confirm key steps, costs, shipping/returns information, and error states are understandable before asking users to commit.",
        ["Open each detected path in a browser.", "Test keyboard navigation and mobile layouts.", "Verify forms and checkout using a safe test mode if available."],
        final_url,
    ))

    # Keep concrete, bounded match context so a reviewer can tell why each tag was flagged.
    # Do not print full inline scripts, query-string IDs, or arbitrary page source into the report.
    source_matches: dict[str, list[str]] = {name: [] for name in TRACKING_PATTERNS}
    for source in parser.script_sources:
        parsed_source = urlsplit(source)
        if parsed_source.scheme in {"http", "https"} and parsed_source.netloc:
            host = (parsed_source.hostname or "").lower()
            for name, pattern in TRACKING_PATTERNS.items():
                if pattern.search(host):
                    source_matches[name].append(f"script host: {host}")
        else:
            compact = " ".join(source.split())
            for name, pattern in TRACKING_PATTERNS.items():
                match = pattern.search(compact)
                if match:
                    # Report only the short matching token, not the surrounding script or identifiers.
                    source_matches[name].append(f"inline signature: {match.group(0)[:60]}")
    detected = [name for name, matches in source_matches.items() if matches]
    if detected:
        match_details = []
        for name in detected:
            unique_details = list(dict.fromkeys(source_matches[name]))[:3]
            match_details.append(f"{name} ({'; '.join(unique_details)})")
        tracking_evidence = "Static HTML signals detected: " + "; ".join(match_details) + "."
    else:
        tracking_evidence = (
            "No known Google tag/Analytics, Meta Pixel, TikTok Pixel, or Microsoft Clarity signature "
            "was detected in the parsed static HTML."
        )
    repeated_tags = {
        name: matches
        for name, matches in source_matches.items()
        if len(matches) > 1
    }
    if repeated_tags:
        repeated_evidence = "; ".join(
            f"{name}: {len(matches)} matching occurrences" for name, matches in repeated_tags.items()
        )
        findings.append(_finding(
            "conversion_paid_traffic", "Repeated marketing tag signatures need review",
            "manual_review_required", "medium",
            f"Multiple static signatures were detected for the same vendor: {repeated_evidence}.",
            "Repeated tag snippets or hosts can indicate duplicate analytics installation and duplicate event counting, but multiple containers or intentional integrations may be legitimate. Static HTML cannot confirm that events fire more than once.",
            "Compare the detected snippets with the intended tag-manager and analytics setup. Use browser network inspection and the official vendor debugger to verify page-view and conversion events fire the expected number of times.",
            ["Inspect each vendor snippet and its container/account configuration.", "Use browser network tools and official tag debuggers.", "Trigger a test conversion and confirm the event is recorded once."],
            final_url,
        ))

    findings.append(_finding(
        "conversion_paid_traffic", "Publicly detectable marketing tags", "verified" if detected else "manual_review_required",
        "info", tracking_evidence,
        "Tag signatures are only presence signals. They do not prove the tag fires correctly, consent is handled properly, events are configured, or ad platforms attribute conversions. A generic matching word or a tag loaded only after interaction can be missed or misclassified by static inspection. Absence from initial HTML does not prove tracking is absent.",
        "Review each reported host/signature, then use the relevant browser tag debugger and analytics/ad-platform diagnostics to verify page-view and intended conversion events, consent behavior, and duplicate firing. Never infer conversion performance from tag presence alone.",
        ["Check the reported host/signature against the expected vendor integration.", "Test in the browser with official tag debugging tools.", "Verify the intended conversion event appears once in the correct account.", "Check consent choices and network requests."],
        final_url,
    ))

    if unlabeled_links:
        findings.append(_finding(
            "accessibility", "Links may lack an accessible name", "manual_review_required", "medium",
            f"{unlabeled_links} same-origin link(s) had no readable text or aria-label in the returned HTML.",
            "Links without an accessible name can make navigation difficult for screen-reader users. Source HTML alone cannot determine whether an image or another rendered technique supplies an accessible name.",
            "Review each flagged link in the rendered page and provide a concise accessible name that describes its destination or action.",
            ["Inspect flagged links in the browser accessibility tree.", "Confirm icon-only links expose an appropriate computed accessible name."],
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
                    f"Static homepage fetch did not complete ({type(exc).__name__}); internal exception details were withheld.",
                    "No reliable HTML was available, so conversion-path signals could not be checked.",
                    "Confirm the target is publicly reachable and rerun; do not interpret this as proof that conversion elements are missing.",
                    ["Open the target in a browser and verify DNS, TLS, and access rules."], normalized,
                )
            ], [], limitations
