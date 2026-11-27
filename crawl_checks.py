"""Bounded same-origin crawl for public ecommerce pages.

The crawler follows a capped queue of discovered same-origin HTML links and sitemap
URLs, stays on the audited origin, and never submits forms or authenticates.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from html.parser import HTMLParser
from defusedxml import ElementTree as ET
from urllib.parse import parse_qsl, urldefrag, urljoin, urlsplit, urlunsplit

import aiohttp
import json
import re

from performance_checks import inspect_static_performance_signals
from accessibility_checks import inspect_static_accessibility_signals
from mobile_ux_checks import inspect_mobile_viewport
from trust_checks import inspect_trust_signals

from security_checks import (
    probe_common_exposure_paths,
    inspect_transport_security,
    inspect_security_header_quality,
    inspect_standard_security_headers,
)
from dependency_checks import inspect_client_dependency_versions
from document_basics_checks import inspect_document_basics

from audit_checks import (
    REQUEST_TIMEOUT_SECONDS,
    USER_AGENT,
    AuditFinding,
    PublicOnlyResolver,
    _finding,
    _safe_get,
    normalize_target,
    _PageParser,
    CheckOutcome,
)
from audit_checks import record_homepage_outcomes
from product_consistency_checks import inspect_visible_product_consistency
from content_quality_checks import inspect_content_quality


MAX_CRAWL_PAGES = 12
MAX_LINKS_FROM_HOME = 100
MAX_URLS_FROM_SITEMAP = 100
MAX_CHILD_SITEMAPS = 3
MAX_SITEMAP_DOCUMENTS = 8

PRODUCT_DETAIL_PATH = re.compile(r"(?:^|/)(?:products?|items?)(?:/|$)", re.I)

def _parse_robots_rules(body: str, user_agent: str) -> list[tuple[str, str]]:
    """Return the applicable Allow/Disallow rules for this crawler's product token."""
    groups: list[tuple[list[str], list[tuple[str, str]]]] = []
    agents: list[str] = []
    rules: list[tuple[str, str]] = []
    saw_rule = False

    def finish_group() -> None:
        nonlocal agents, rules, saw_rule
        if agents:
            groups.append((agents, rules))
        agents, rules, saw_rule = [], [], False

    product_token = (user_agent.split("/", 1)[0].split(" ", 1)[0] or "").lower()
    # Accept escaped line separators from plain-text transports/test fixtures as well
    # as the real CRLF/LF format used by robots.txt.
    body = body.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\r", "\n")
    for raw_line in body.splitlines()[:5000]:
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        key = key.lower()
        if key == "user-agent":
            if saw_rule:
                finish_group()
            agents.append(value.lower())
        elif key in {"allow", "disallow"} and agents:
            saw_rule = True
            # Empty Disallow means no restriction; empty Allow is ignored.
            if value or key == "disallow":
                rules.append((key, value))

    finish_group()
    exact_groups = [
        group_rules for group_agents, group_rules in groups
        if any(agent != "*" and agent and agent in product_token for agent in group_agents)
    ]
    wildcard_groups = [
        group_rules for group_agents, group_rules in groups
        if "*" in group_agents
    ]
    selected = exact_groups if exact_groups else wildcard_groups
    return [rule for group_rules in selected for rule in group_rules]


def _robots_path_allowed(url: str, rules: list[tuple[str, str]]) -> bool:
    """Apply the longest-match robots rule; Allow wins equal-length ties."""
    if not rules:
        return True
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    matched: list[tuple[int, bool]] = []
    for directive, pattern in rules:
        if not pattern:
            continue
        anchored = pattern.endswith("$")
        pattern_body = pattern[:-1] if anchored else pattern
        expression = re.escape(pattern_body).replace(r"\*", ".*")
        expression = "^" + expression + ("$" if anchored else "")
        try:
            if re.search(expression, path):
                specificity = len(pattern_body.replace("*", ""))
                matched.append((specificity, directive == "allow"))
        except re.error:
            continue
    if not matched:
        return True
    longest = max(length for length, _allowed in matched)
    return any(allowed for length, allowed in matched if length == longest)



class _SensitiveGetFormParser(HTMLParser):
    """Find GET forms that appear to submit credentials or payment-related fields."""
    SENSITIVE_NAMES = re.compile(
        r"(?:pass(?:word)?|secret|token|credit.?card|card.?number|cc.?num|cvv|cvc|"
        r"security.?code|one.?time.?password|one.?time.?code|verification.?code|auth.?code|otp|api.?key|payment|billing.?address|bank.?account|routing.?number)",
        re.I,
    )
    SENSITIVE_TYPES = {"password"}
    SENSITIVE_AUTOCOMPLETE = {
        "current-password", "new-password", "cc-number", "cc-csc",
        "cc-exp", "cc-exp-month", "cc-exp-year", "cc-name", "cc-type",
        "one-time-code", "transaction-amount",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._form_stack: list[dict[str, object]] = []
        self.sensitive_get_forms: list[tuple[str, list[str]]] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()
        values = {key.lower(): value or "" for key, value in attrs}
        if tag == "form":
            method = values.get("method", "get").strip().lower() or "get"
            self._form_stack.append({"method": method, "fields": []})
        elif tag in {"input", "select", "textarea", "button"} and self._form_stack:
            form = self._form_stack[-1]
            name = values.get("name", "").strip()
            field_type = values.get("type", "").strip().lower()
            autocomplete = values.get("autocomplete", "").strip().lower()
            if (
                field_type in self.SENSITIVE_TYPES
                or (name and self.SENSITIVE_NAMES.search(name))
                or autocomplete in self.SENSITIVE_AUTOCOMPLETE
            ):
                fields = form["fields"]
                if isinstance(fields, list):
                    label = name or autocomplete or field_type or tag
                    if label not in fields:
                        fields.append(label)

    def handle_startendtag(self, tag: str, attrs) -> None:
        self.handle_starttag(tag, attrs)
        if tag.lower() == "form":
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "form" or not self._form_stack:
            return
        form = self._form_stack.pop()
        fields = form["fields"]
        if form["method"] == "get" and isinstance(fields, list) and fields:
            self.sensitive_get_forms.append(("GET", fields))


def inspect_sensitive_get_forms(html: str, page_url: str) -> list[AuditFinding]:
    """Flag credential/payment-like fields inside GET forms for contextual security review."""
    parser = _SensitiveGetFormParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return []
    if not parser.sensitive_get_forms:
        return []
    field_labels = list(dict.fromkeys(
        field for _, fields in parser.sensitive_get_forms for field in fields
    ))
    return [_finding(
        "security", "Sensitive-looking fields appear in a GET form",
        "manual_review_required", "high",
        f"Found {len(parser.sensitive_get_forms)} GET form(s) containing credential/payment-like field names or autocomplete hints on {page_url}. Field identifiers: "
        + ", ".join(field_labels[:12]) + (" …" if len(field_labels) > 12 else "") + ".",
        "GET form values are commonly encoded in the request URL and may be retained in browser history, server logs, analytics, or referrer data. The field-name heuristic cannot determine what the application actually submits, and a custom JavaScript handler may change behavior.",
        "Inspect the rendered form and network request. Credentials, payment details, and other sensitive values should not be sent in a URL; use an appropriate POST-based flow and the payment provider's secure integration. Do not submit real credentials during this audit.",
        ["Review the form method and any JavaScript submit handler.", "Use browser developer tools with test data to confirm which values enter the request URL.", "Verify server logs, analytics, and referrer handling do not retain sensitive query values."],
        page_url,
    )]





def inspect_privacy_tracking_signals(html: str, page_url: str) -> list[AuditFinding]:
    """Detect source-visible tracking and consent UI signals without claiming events fire."""
    findings: list[AuditFinding] = []
    lower = html.lower()
    tracking_patterns = {
        "Google Tag Manager": re.compile(r"(?:googletagmanager\.com/gtm\.js|gtm-[a-z0-9]{4,})", re.I),
        "Google Analytics / gtag": re.compile(r"(?:googletagmanager\.com/gtag/js|google-analytics\.com/analytics\.js|\bgtag\s*\()", re.I),
        "Meta Pixel": re.compile(r"(?:connect\.facebook\.net/.*/fbevents\.js|\bfbq\s*\()", re.I),
        "TikTok Pixel": re.compile(r"(?:analytics\.tiktok\.com|\bttq\.load\s*\()", re.I),
        "Microsoft Clarity": re.compile(r"(?:clarity\.ms/tag|\bclarity\s*\(\s*['\"]set['\"])", re.I),
        "Pinterest Tag": re.compile(r"(?:s\.pinimg\.com/ct/core\.js|\bpinterest\.tag\s*\()", re.I),
        "LinkedIn Insight Tag": re.compile(r"(?:snap\.licdn\.com/li\.lms-analytics/insight\.min\.js|_linkedin_partner_id)", re.I),
        "Snapchat Pixel": re.compile(r"(?:sc-static\.net/scevent\.min\.js|snaptr\s*\()", re.I),
        "Hotjar": re.compile(r"(?:static\.hotjar\.com/c/hotjar-|hj\s*\(\s*['\"]event['\"])", re.I),
        "Matomo": re.compile(r"(?:matomo\.js|piwik\.js|_paq\s*\.push)", re.I),
        "Adobe Analytics": re.compile(r"(?:assets\.adobedtm\.com|omtrdc\.net|s\.t\s*\()", re.I),
        "Segment": re.compile(r"(?:cdn\.segment\.com/analytics\.js|analytics\.load\s*\()", re.I),
    }
    detected = [name for name, pattern in tracking_patterns.items() if pattern.search(html)]
    if detected:
        findings.append(_finding(
            "pixel_analytics", "Tracking technology references detected in page source",
            "verified", "info",
            f"Detected source-level references consistent with: {', '.join(detected)}. Page: {page_url}",
            "This is a source inspection only. It does not verify that network requests succeed, events fire correctly, consent is respected, or conversions are attributed.",
            "Compare detected tags with the site's approved analytics inventory. Use browser network tools and an authorized test environment to verify requests, event payloads, and consent-dependent behavior without submitting real customer data.",
            ["Inspect browser network requests on a representative page.", "Trigger only safe test events and confirm expected event names and parameters in the relevant analytics debugger.", "Repeat before and after each observable consent choice where applicable."],
            page_url,
        ))

    consent_patterns = (
        r"cookie-consent", r"cookie_consent", r"consent-manager", r"consentmanager",
        r"onetrust", r"cookiebot", r"iubenda", r"didomi", r"usercentrics",
        r"privacy-banner", r"cookie-banner", r"accept all cookies",
        r"reject all cookies", r"manage preferences", r"cookie settings",
    )
    consent_detected = any(re.search(pattern, lower, re.I) for pattern in consent_patterns)
    # Record distinct choice-label signals independently. A label in source is not
    # proof the control is visible, accessible, clickable, or respected by tracking.
    consent_choice_patterns = {
        "accept": re.compile(r"(?:accept all|allow all|agree to all|accept cookies)", re.I),
        "reject": re.compile(r"(?:reject all|decline all|deny all|reject cookies)", re.I),
        "preferences": re.compile(r"(?:manage preferences|customi[sz]e|cookie settings|privacy settings)", re.I),
    }
    consent_choices = [
        name for name, pattern in consent_choice_patterns.items()
        if pattern.search(html[:500_000])
    ]
    if not detected and not consent_detected:
        findings.append(_finding(
            "pixel_analytics", "No supported tracking or consent signatures detected in initial HTML",
            "manual_review_required", "info",
            f"No supported client-side tracking signatures or recognizable consent/banner source signals were found in the returned HTML for {page_url}.",
            "This does not prove that analytics or consent controls are absent. Tags may be injected after JavaScript execution, loaded through a tag manager, blocked by the response variant, or implemented server-side.",
            "Review the rendered page and authorized browser network traffic before concluding that tracking is absent. If analytics are expected, verify event delivery with safe test events and without real customer data.",
            ["Inspect the rendered DOM and network requests after the page settles.", "Review the tag manager and analytics configuration where authorized.", "Use a consent-aware test session to verify optional tracking behavior."],
            page_url,
        ))
    if detected or consent_detected:
        choice_summary = (
            ", ".join(consent_choices) if consent_choices else
            "no distinct accept/reject/preferences labels detected in initial HTML"
        )
        consent_evidence = (
            f"Consent/banner-related source signals were detected on {page_url}; source-level choice-label signals: {choice_summary}."
            if consent_detected else
            f"Tracking references were detected on {page_url}, but no recognizable consent/banner signal was found in the returned HTML; source-level choice-label signals: {choice_summary}."
        )
        findings.append(_finding(
            "pixel_analytics", "Review consent controls and tracking behavior",
            "manual_review_required", "medium",
            consent_evidence + f" Tracking references detected: {', '.join(detected) if detected else 'none from the supported source patterns'}.",
            "Static HTML cannot determine whether a consent interface is visible, whether optional requests are blocked before consent, or whether behavior satisfies applicable law. Consent may also be managed by scripts or a tag manager not visible in this response.",
            "Manually test the rendered consent interface in an authorized browser session. Confirm accept, reject, and preferences choices have observable effects on optional tracking; obtain jurisdiction-specific legal review where needed.",
            ["Open a fresh browser session with storage cleared.", "Record optional tracking requests before a choice and after accept/reject/preferences.", "Confirm the UI offers understandable choices and that the saved preference persists as intended."],
            page_url,
        ))
    return findings

def inspect_ecommerce_catalog_navigation(html: str, page_url: str) -> list[AuditFinding]:
    """Inventory source-level signals for variants, faceted URLs and listing pagination."""
    findings: list[AuditFinding] = []
    try:
        parsed_url = urlsplit(page_url)
        path_segments = {segment.lower() for segment in parsed_url.path.split("/") if segment}
    except (ValueError, UnicodeError):
        return findings

    likely_product = bool(PRODUCT_DETAIL_PATH.search(parsed_url.path))
    likely_listing = bool(
        path_segments.intersection({"collections", "collection", "category", "categories", "catalog", "shop"})
    )
    lower = html[:500_000].lower()

    if likely_product:
        variant_signals = [
            label for label, pattern in (
                ("variant query parameter", re.compile(r"[?&](?:variant|variant_id|sku|option|attribute)=", re.I)),
                ("variant selector attributes", re.compile(r"(?:name|id|data-)[^>]{0,100}(?:variant|option|size|colour|color)", re.I)),
                ("size/colour option labels", re.compile(r"(?:select a size|choose a size|select colour|select color|available sizes|product variants)", re.I)),
            ) if pattern.search(html[:500_000])
        ]
        if variant_signals:
            findings.append(_finding(
                "ecommerce_catalog", "Product variant controls or URL signals detected",
                "manual_review_required", "info",
                f"Source-level variant signals on {page_url}: {', '.join(variant_signals)}.",
                "These signatures suggest variant selection may exist but do not establish that every variant is crawlable, selectable, in stock, or consistent with Product/Offer structured data.",
                "Review representative variants and ensure each selectable option has accurate price, availability, SKU/GTIN where applicable, canonical/indexing behavior, and structured data. Do not submit orders or change inventory during this audit.",
                ["Inspect each available size/colour/variant in an authorized browser session.", "Compare visible selected-variant price and stock state with structured data and variant URLs.", "Confirm invalid or unavailable variant URLs fail safely and do not advertise stale availability."],
                page_url,
            ))

    if likely_listing:
        navigation_signals = []
        if re.search(r"""<link\b[^>]*\brel\s*=\s*['"][^'"]*\bnext\b""", lower, re.I):
            navigation_signals.append("rel=next link")
        if re.search(r"""(?:aria-label|class|id|rel)\s*=\s*['"][^'"]*(?:pagination|page-next|next-page|load-more|loadmore)""", lower, re.I):
            navigation_signals.append("pagination/load-more label or attribute")
        if re.search(r"[?&](?:page|p|offset|cursor|sort_by|filter|filter\.|facet|vendor|type|availability)=", html[:500_000], re.I):
            navigation_signals.append("pagination/filter/sort query parameters")
        if navigation_signals:
            findings.append(_finding(
                "ecommerce_catalog", "Category pagination or faceted-navigation signals detected",
                "manual_review_required", "info",
                f"Detected listing-navigation signatures on {page_url}: {', '.join(navigation_signals)}.",
                "Source signatures do not prove that pagination works, all products are discoverable, or filtered URLs avoid duplicate-content and crawl-budget problems. JavaScript-only load-more controls may not be represented in initial HTML.",
                "Manually check first/next/last listing pages, load-more behavior, filter combinations, canonical targets, and internal links to important products. Avoid blanket noindex/canonical changes without confirming the site's intended indexing strategy.",
                ["Follow listing pagination and confirm product sets change as expected.", "Inspect a small representative sample of filter/sort URLs and their canonical/noindex directives.", "Confirm important products remain reachable through ordinary links without interacting with checkout."],
                page_url,
            ))
        else:
            findings.append(_finding(
                "ecommerce_catalog", "Listing pagination and faceted navigation not confirmed from source",
                "manual_review_required", "info",
                f"The URL path resembles an ecommerce collection/category, but no supported pagination or filter signatures were detected in the inspected HTML for {page_url}.",
                "Pagination and filters may be implemented with JavaScript, buttons without recognizable labels, or platform-specific markup. Absence of these source signatures does not prove the listing lacks navigation.",
                "Review the rendered listing and verify pagination, load-more, filters, and sorting work and expose an appropriate crawlable URL strategy where required.",
                ["Inspect the rendered category/collection on desktop and mobile.", "Test pagination, load-more, filters and sort controls without entering checkout.", "Review canonical and indexability signals for representative filtered URLs."],
                page_url,
            ))
    return findings


def inspect_product_page_schema_presence(html: str, page_url: str) -> list[AuditFinding]:
    """Prompt review when a likely product-detail URL has no detectable Product JSON-LD.

    URL patterns are only heuristics: storefront routes vary, and structured data may
    be supplied by Microdata, RDFa, or JavaScript after the initial HTML response.
    """
    try:
        path = urlsplit(page_url).path
    except (ValueError, UnicodeError):
        return []
    if not PRODUCT_DETAIL_PATH.search(path):
        return []

    parser = _PageParser()
    try:
        parser.feed(html)
    except Exception:
        return []
    if not parser.jsonld_scripts:
        return [_finding(
            "structured_data", "Product structured data not detected",
            "manual_review_required", "low",
            f"The URL path resembles a product-detail route, but no application/ld+json block was found in the returned HTML for {page_url}.",
            "Product structured data can help search systems interpret product details, but not every implementation uses JSON-LD. This source-only check does not inspect JavaScript-rendered markup, Microdata, RDFa, or determine rich-result eligibility.",
            "Inspect the rendered product page and structured-data output. If product JSON-LD is appropriate for this store, add accurate properties that match the visible item and selected variant; do not add markup solely to satisfy this heuristic.",
            ["Confirm the URL is a product-detail page rather than a category or application route.", "Inspect the rendered DOM for Product structured data in any supported format.", "Validate any JSON-LD against the visible product details."],
            page_url,
        )]

    found_product = False
    malformed = False

    def contains_product(value):
        if isinstance(value, list):
            return any(contains_product(item) for item in value)
        if not isinstance(value, dict):
            return False
        raw_type = value.get("@type", [])
        types = raw_type if isinstance(raw_type, list) else [raw_type]

        def is_product_type(item: object) -> bool:
            if not isinstance(item, str):
                return False
            # JSON-LD permits compact names and absolute schema.org type IRIs.
            normalized = item.rstrip("/").rsplit("/", 1)[-1].rsplit("#", 1)[-1]
            return normalized.casefold() in {"product", "productgroup"}

        if any(is_product_type(item) for item in types):
            return True
        # Product entities can be nested in common JSON-LD containers rather than
        # appearing only at the document root or inside @graph.
        return any(
            contains_product(value.get(key, []))
            for key in ("@graph", "mainEntity", "itemListElement", "hasVariant")
        )

    for script in parser.jsonld_scripts:
        try:
            payload = json.loads(script)
        except (json.JSONDecodeError, TypeError):
            malformed = True
            continue
        if contains_product(payload):
            found_product = True
            break

    if found_product:
        # This crawler check is deliberately a presence heuristic. Detailed Product,
        # Offer, price, currency and availability completeness is recorded by the
        # dedicated structured-data module; duplicating it here creates contradictory
        # crawl findings for valid ProductGroup/variant markup.
        return []
    if malformed:
        return [_finding(
            "structured_data", "Product structured data could not be parsed",
            "manual_review_required", "low",
            f"At least one application/ld+json block on the likely product URL could not be parsed as JSON: {page_url}. Raw script contents are intentionally omitted from the report.",
            "Malformed JSON-LD may prevent consumers from reading that block, but this source-only check cannot determine whether the malformed block is intended for Product data or whether equivalent valid structured data exists elsewhere in the rendered page.",
            "Inspect each JSON-LD script in the rendered page, correct syntax errors in the intended structured-data block, and confirm the final product properties match the visible product and selected variant. Do not copy private data into structured markup.",
            ["Open the page in an authorized browser and inspect each JSON-LD script for syntax errors.", "Validate the corrected markup with an authoritative structured-data validator.", "Compare product, offer, and selected-variant values with what customers see."],
            page_url,
        )]
    return [_finding(
        "structured_data", "Product structured data not detected",
        "manual_review_required", "low",
        f"The URL path resembles a product-detail route, but the inspected JSON-LD blocks contain no Product or ProductGroup entity: {page_url}.",
        "A product-detail page may benefit from accurate Product structured data, but this check cannot establish that the URL is a true product page or that JSON-LD is the site's chosen structured-data format. Other markup formats and JavaScript-rendered data are outside this source check.",
        "Confirm the page type and inspect the rendered structured data. If Product JSON-LD is appropriate, add accurate information matching the visible product and selected variant; never invent price, currency, availability, or images.",
        ["Confirm this is a product-detail page.", "Inspect rendered JSON-LD, Microdata, or RDFa.", "Validate Product markup and compare it with the visible product information."],
        page_url,
    )]


def inspect_canonical_declaration(html: str, page_url: str) -> list[AuditFinding]:
    """Review canonical link declaration shape without assuming every page needs one."""
    parser = _PageParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return []
    findings: list[AuditFinding] = []
    if parser.canonical_count > 1:
        findings.append(_finding(
            "indexability", "Page declares multiple canonical links",
            "manual_review_required", "medium",
            f"Found {parser.canonical_count} canonical link elements in the returned HTML for {page_url}.",
            "Multiple canonical declarations can send conflicting consolidation signals. This source check does not establish which URL search engines will select.",
            "Review the page template and keep one intentional canonical declaration where appropriate. Verify the final rendered HTML and response behavior.",
            ["Inspect all rel=canonical elements in the raw HTML.", "Confirm the intended canonical URL with the site's routing and duplicate-page strategy."],
            page_url,
        ))
    if parser.canonical_missing_href_count:
        findings.append(_finding(
            "indexability", "Canonical link is missing its href",
            "manual_review_required", "medium",
            f"Found {parser.canonical_missing_href_count} canonical link element(s) without an href on {page_url}.",
            "A canonical link without a target cannot clearly communicate the intended preferred URL.",
            "Add a valid absolute or correctly resolved canonical target, or remove the incomplete declaration if it is unintended.",
            ["Inspect the rel=canonical element in the returned HTML.", "Verify the resolved target in the rendered page source."],
            page_url,
        ))
    if parser.canonical_href:
        try:
            target = urljoin(page_url, parser.canonical_href)
            parts = urlsplit(target)
            _ = parts.port
            valid = (
                parts.scheme.lower() in {"http", "https"}
                and bool(parts.hostname)
                and parts.username is None
                and parts.password is None
            )
        except (ValueError, UnicodeError):
            valid = False
        if not valid:
            findings.append(_finding(
                "indexability", "Canonical target URL needs review",
                "manual_review_required", "medium",
                f"The first canonical link on {page_url} does not resolve to a valid credential-free HTTP(S) URL.",
                "Malformed canonical targets may prevent the preferred URL from being interpreted as intended. This check validates URL shape only, not whether the destination is the correct canonical page.",
                "Replace the malformed target with the intended valid URL and confirm that the destination is accessible and suitable for canonicalization.",
                ["Inspect the canonical href in the returned HTML.", "Resolve the URL and verify its status, redirect chain, and page equivalence."],
                page_url,
            ))
        else:
            page_parts = urlsplit(page_url)
            target_host = (parts.hostname or "").lower().rstrip(".")
            page_host = (page_parts.hostname or "").lower().rstrip(".")
            target_scheme = parts.scheme.lower()
            page_scheme = page_parts.scheme.lower()
            try:
                target_port = parts.port or (443 if target_scheme == "https" else 80)
                page_port = page_parts.port or (443 if page_scheme == "https" else 80)
            except ValueError:
                target_port = page_port = None
            if (target_scheme, target_host, target_port) == (page_scheme, page_host, page_port):
                current_key = (page_parts.path or "/", page_parts.query)
                target_key = (parts.path or "/", parts.query)
                if current_key != target_key:
                    findings.append(_finding(
                        "indexability", "Canonical target differs from the inspected page URL",
                        "manual_review_required", "low",
                        f"The page {page_url} declares a same-origin canonical target at {target_scheme}://{target_host}{parts.path or '/'}" + (f"?{parts.query}" if parts.query else "") + ".",
                        "A same-origin canonical that points to a different path or query can be intentional for duplicate or parameterized URLs, but it may also be a template or routing mistake. The source check does not determine which URL should be preferred or fetch the target.",
                        "Confirm that the target is the intended equivalent, preferred URL and that it returns the expected page. Keep non-self canonicals where the site's duplicate-content strategy requires them.",
                        ["Compare the inspected page and canonical target content.", "Check target status, redirects, indexability directives, and internal-link conventions before changing the canonical."],
                        page_url,
                    ))
            if (target_scheme, target_host, target_port) != (page_scheme, page_host, page_port):
                # Cross-origin canonicals can be intentional, but deserve review
                # because they consolidate indexing signals onto another origin.
                findings.append(_finding(
                    "indexability", "Canonical target points to a different origin",
                    "manual_review_required", "medium",
                    f"The canonical declaration on {page_url} points to a different origin ({target_scheme}://{target_host}); this source check does not fetch or validate the destination.",
                    "Cross-origin canonicals may be appropriate for syndicated or deliberately consolidated content, but this check does not fetch or validate the destination. An unintended host, scheme, or port can direct search engines to prefer a different URL.",
                    "Confirm that cross-origin canonicalization is intentional and that the destination contains equivalent content. Otherwise, point the canonical to the intended URL on this site's origin.",
                    ["Compare the canonical destination with the page's intended indexable URL.", "Open the destination independently and verify content equivalence and redirect behavior."],
                    page_url,
                ))
    return findings


class _HreflangParser(HTMLParser):
    """Collect declared hreflang alternate links from the returned HTML only."""
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "link":
            return
        values = {key.lower(): value or "" for key, value in attrs}
        rel_tokens = values.get("rel", "").lower().split()
        language = values.get("hreflang", "").strip()
        if "alternate" in rel_tokens and language:
            self.links.append((language, values.get("href", "").strip()))


def inspect_hreflang(html: str, final_url: str) -> list[AuditFinding]:
    """Report source-level hreflang consistency signals, not full international SEO validity."""
    parser = _HreflangParser()
    parser.feed(html)
    if not parser.links:
        return []

    findings: list[AuditFinding] = []
    seen_languages: set[str] = set()
    duplicate_languages: set[str] = set()
    invalid_targets: list[str] = []
    invalid_language_tags: list[str] = []
    self_reference_found = False

    def comparable_page_url(value: str) -> tuple[str, str, str] | None:
        try:
            parts = urlsplit(value)
            _ = parts.port
            if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
                return None
            host = parts.hostname.lower()
            port = parts.port
            default_port = 443 if parts.scheme.lower() == "https" else 80
            authority = f"[{host}]" if ":" in host else host
            if port is not None and port != default_port:
                authority += f":{port}"
            return parts.scheme.lower(), authority, parts.path or "/"
        except (ValueError, UnicodeError):
            return None

    current_page = comparable_page_url(final_url)

    def safe_target_label(href: str) -> str:
        """Return a bounded URL label without credentials, query, or fragment data."""
        if not href:
            return "(missing href)"
        try:
            resolved = urljoin(final_url, href)
            parts = urlsplit(resolved)
            _ = parts.port
            if parts.scheme.lower() in {"http", "https"} and parts.hostname:
                host = parts.hostname.lower()
                display_host = f"[{host}]" if ":" in host else host
                port = parts.port
                default_port = 443 if parts.scheme.lower() == "https" else 80
                if port is not None and port != default_port:
                    display_host = f"{display_host}:{port}"
                return f"{parts.scheme.lower()}://{display_host}{(parts.path or '/')[:120]}"
        except (ValueError, UnicodeError):
            if "://" in href and "@" not in href and "?" not in href and "#" not in href:
                return href[:120]
        try:
            parts = urlsplit(href)
            if parts.scheme and parts.scheme.lower() not in {"http", "https"}:
                return "(malformed or unsupported target URL omitted)"
        except (ValueError, UnicodeError):
            # Malformed URLs without credentials or query data can be shown as bounded
            # evidence to help the site owner find the source declaration.
            if "://" in href and "@" not in href and "?" not in href and "#" not in href:
                return href[:120]
        return "(malformed or unsupported target URL omitted)"

    for language, href in parser.links:
        normalized_language = language.lower()
        if normalized_language in seen_languages:
            duplicate_languages.add(language)
        seen_languages.add(normalized_language)

        # Accept common BCP 47-like subtags and the special x-default token.
        if normalized_language != "x-default" and not re.fullmatch(
            r"[a-z]{2,3}(?:-[a-z0-9]{2,8})*", normalized_language
        ):
            invalid_language_tags.append(language)

        try:
            resolved = urljoin(final_url, href) if href else ""
            parts = urlsplit(resolved)
            # Accessing .port validates that an explicit port is numeric and in range.
            _ = parts.port
            valid_target = (
                parts.scheme.lower() in {"http", "https"}
                and bool(parts.hostname)
                and parts.username is None
                and parts.password is None
            )
        except (ValueError, UnicodeError):
            # Malformed IPv6 brackets, invalid ports, and malformed URL text
            # are reviewable input, not reasons for the whole audit to fail.
            valid_target = False
        if not valid_target:
            invalid_targets.append(safe_target_label(href))
        elif current_page is not None and comparable_page_url(resolved) == current_page:
            self_reference_found = True

    if invalid_language_tags or invalid_targets or duplicate_languages or not self_reference_found:
        details = []
        if invalid_language_tags:
            details.append("language tag(s): " + ", ".join(value[:40] for value in sorted(set(invalid_language_tags))[:8]))
        if invalid_targets:
            details.append("target URL issue(s): " + ", ".join(sorted(set(invalid_targets))[:8]))
        if duplicate_languages:
            details.append("duplicate language tag(s): " + ", ".join(sorted(duplicate_languages)[:8]))
        if not self_reference_found:
            details.append("no hreflang target appears to reference this page itself")
        findings.append(_finding(
            "international_seo",
            "Hreflang declarations need review",
            "manual_review_required",
            "medium",
            f"Found {len(parser.links)} alternate hreflang declaration(s) on {final_url}; " + "; ".join(details) + ".",
            "Hreflang annotations can help search engines understand language or regional variants. This source check only catches common declaration inconsistencies; it does not verify reciprocal references, language targeting, or whether destination pages are suitable.",
            "Review each language/region code and destination, then confirm that each localized page links back to its alternate versions where required. Do not add hreflang unless the site actually serves distinct localized versions.",
            ["Inspect alternate link elements in the page source.", "Compare the declared URLs and language/region codes across the localized page set.", "Use a search-engine international targeting/debugging workflow where available."],
            final_url,
        ))
    return findings


class _MetaRefreshParser(HTMLParser):
    """Collect meta-refresh directives without executing or following them."""
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.targets: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "meta":
            return
        values = {key.lower(): value or "" for key, value in attrs}
        if values.get("http-equiv", "").strip().lower() != "refresh":
            return
        content = values.get("content", "").strip()
        match = re.search(r"(?:^|;)\s*url\s*=\s*(['\"]?)(.*?)\1\s*$", content, re.I)
        if match:
            self.targets.append(match.group(2).strip())


def inspect_meta_refresh(html: str, final_url: str) -> list[AuditFinding]:
    """Flag HTML meta-refresh redirects for manual review without exposing URL credentials."""
    parser = _MetaRefreshParser()
    try:
        parser.feed(html)
    except Exception:
        return []
    if not parser.targets:
        return []

    def origin(parts):
        scheme = parts.scheme.lower()
        try:
            port = parts.port
        except ValueError:
            return None
        if port is None:
            port = 443 if scheme == "https" else 80
        return scheme, (parts.hostname or "").lower(), port

    page_parts = urlsplit(final_url)
    page_origin = origin(page_parts)
    external_targets: list[str] = []
    malformed_targets = 0
    checked_targets = parser.targets[:20]
    for target in checked_targets:
        try:
            resolved = urljoin(final_url, target)
            parts = urlsplit(resolved)
            target_origin = origin(parts)
            if (
                parts.scheme.lower() not in {"http", "https"}
                or not parts.hostname
                or target_origin is None
            ):
                malformed_targets += 1
                continue
            if target_origin != page_origin:
                # Rebuild authority from validated host/port; never echo userinfo,
                # fragments, or query parameters that could contain tokens.
                host = parts.hostname.lower()
                display_host = f"[{host}]" if ":" in host else host
                explicit_port = parts.port
                default_port = 443 if parts.scheme.lower() == "https" else 80
                if explicit_port is not None and explicit_port != default_port:
                    display_host = f"{display_host}:{explicit_port}"
                external_targets.append(
                    f"{parts.scheme.lower()}://{display_host}{parts.path or '/'}"
                )
        except (ValueError, UnicodeError):
            malformed_targets += 1

    details = [
        f"Detected {len(parser.targets)} meta-refresh directive(s) in returned HTML."
    ]
    if len(parser.targets) > len(checked_targets):
        details.append(
            f"Only the first {len(checked_targets)} directives were inspected due to the safety cap."
        )
    if external_targets:
        details.append(
            "External destination host(s): " + ", ".join(list(dict.fromkeys(external_targets))[:5]) + "."
        )
    if malformed_targets:
        details.append(
            f"{malformed_targets} malformed or unsupported target(s) were not resolved."
        )
    return [_finding(
        "security", "HTML meta-refresh redirect needs review",
        "manual_review_required", "medium" if external_targets else "low",
        " ".join(details),
        "Meta-refresh redirects can be legitimate, but unexpected or external destinations may confuse users and complicate browser, accessibility, and search-engine behavior. This source signal does not establish malicious intent, and the audit does not follow the target.",
        "Confirm each redirect is intentional, clearly communicated, and points to the expected destination. Prefer a correctly configured server-side redirect when appropriate; never use an untrusted input directly as a redirect destination.",
        ["Inspect the returned meta http-equiv=refresh element.", "Verify the destination and timing in a browser or staging environment.", "Check that users can understand and control navigation where required."],
        final_url,
    )]


class _AnchorNameParser(HTMLParser):
    """Collect anchor hrefs with no text or detectable accessible-name attribute."""
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.empty_name_hrefs: list[str] = []
        self._active: tuple[str, bool] | None = None
        self._text = ""

    def handle_starttag(self, tag, attrs):
        values = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag == "a" and values.get("href"):
            named = bool(values.get("aria-label", "").strip() or values.get("title", "").strip())
            self._active = (values["href"], named)
            self._text = ""
        elif self._active is not None and tag == "img" and values.get("alt", "").strip():
            href, named = self._active
            self._active = (href, True)

    def handle_data(self, data):
        if self._active is not None:
            self._text += data

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._active is not None:
            href, named = self._active
            if not named and not self._text.strip():
                self.empty_name_hrefs.append(href)
            self._active = None
            self._text = ""


class _LinkParser(HTMLParser):
    """Collect anchor hrefs and the first HTML base URL from source markup."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.base_href: str | None = None

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        values = {key.lower(): value or "" for key, value in attrs}
        if tag == "base" and self.base_href is None:
            href = values.get("href", "").strip()
            if href:
                self.base_href = href
            return
        if tag != "a":
            return
        href = values.get("href", "").strip()
        if href:
            self.links.append(href)




def _catalog_query_parameter_signature(url: str) -> tuple[str, tuple[tuple[str, str], ...]] | None:
    """Return a value-free signature for recognized ecommerce query parameters."""
    try:
        parts = urlsplit(url)
        if not parts.query:
            return None
        pairs = parse_qsl(parts.query, keep_blank_values=True, max_num_fields=50)
    except (ValueError, UnicodeError):
        return None

    variant_names = {"variant", "variant_id", "sku", "option", "attribute"}
    pagination_names = {"page", "paged", "p", "offset", "start", "cursor", "after", "before"}
    sorting_names = {"sort", "sort_by", "order", "orderby"}
    facet_names = {
        "brand", "category", "color", "size", "price", "min_price", "max_price",
        "price_min", "price_max", "availability", "vendor", "product_type", "tag",
    }
    search_names = {"q", "query", "search", "keyword"}
    path = parts.path or "/"
    catalog_path = bool(
        PRODUCT_DETAIL_PATH.search(path)
        or re.search(r"(?:^|/)(?:collections?|categories?|category|catalog|shop)(?:/|$)", path, re.I)
    )
    search_path = bool(re.search(r"(?:^|/)search(?:/|$)", path, re.I))
    recognized: dict[str, str] = {}
    for raw_name, _value in pairs:
        name = raw_name.strip().lower()
        if not re.fullmatch(r"[a-z0-9_.\[\]-]{1,80}", name):
            continue
        if name in variant_names or name.startswith("variant_") or name.startswith("options["):
            kind = "variant"
        elif name.startswith(("filter.", "filter_", "facet")):
            kind = "filtering"
        elif name in facet_names and catalog_path:
            kind = "filtering"
        elif name in pagination_names and catalog_path:
            kind = "pagination"
        elif name in sorting_names and (catalog_path or search_path):
            kind = "sorting"
        elif name in search_names and (catalog_path or search_path):
            kind = "search"
        else:
            # Tracking, session, unrelated content pagination and unknown parameters are omitted.
            continue
        recognized[name] = kind

    if not recognized:
        return None
    return parts.path or "/", tuple(sorted(recognized.items()))


def _canonical_page_url(url: str) -> str:
    """Normalize crawl keys so equivalent default-port URLs do not consume extra page slots."""
    parts = urlsplit(urldefrag(url)[0])
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").rstrip(".").lower()
    try:
        port = parts.port
    except ValueError:
        # Keep malformed values distinct and query-free; URL validation happens before fetch.
        return urlunsplit((scheme, parts.netloc.lower(), parts.path or "/", "", ""))
    if not host or scheme not in {"http", "https"}:
        return urlunsplit((scheme, parts.netloc.lower(), parts.path or "/", "", ""))
    default_port = 443 if scheme == "https" else 80
    display_host = f"[{host}]" if ":" in host else host
    authority = display_host if port is None or port == default_port else f"{display_host}:{port}"
    # Avoid multiplying the crawl through tracking and filter query parameters.
    return urlunsplit((scheme, authority, parts.path or "/", "", ""))


def _same_origin(left_url: str, right_url: str) -> bool:
    """Compare origins while treating explicit default ports as their defaults."""
    left = urlsplit(left_url)
    right = urlsplit(right_url)
    try:
        left_explicit_port = left.port
        right_explicit_port = right.port
        left_port = left_explicit_port if left_explicit_port is not None else (443 if left.scheme.lower() == "https" else 80)
        right_port = right_explicit_port if right_explicit_port is not None else (443 if right.scheme.lower() == "https" else 80)
    except ValueError:
        return False
    return (
        left.scheme.lower() == right.scheme.lower()
        and (left.hostname or "").lower() == (right.hostname or "").lower()
        and left_port == right_port
        and left.username is None and left.password is None
        and right.username is None and right.password is None
    )


def inspect_crawl_sitemap(body: str, sitemap_url: str) -> list[AuditFinding]:
    """Validate sitemap structure used for crawler discovery without trusting its URLs."""
    try:
        root = ET.fromstring(body)
    except Exception as exc:
        return [_finding(
            "sitemap_xml", "Discovered sitemap XML is malformed",
            "manual_review_required", "medium",
            f"The sitemap at {sitemap_url} could not be parsed ({type(exc).__name__}).",
            "A successful HTTP response does not mean the sitemap is valid XML. Invalid sitemap documents may prevent URL discovery.",
            "Publish well-formed XML using a urlset or sitemapindex root and validate the live response.",
            ["Validate the sitemap XML.", "Check the sitemap report in the relevant search-engine tools."],
            sitemap_url,
        )]

    root_type = root.tag.rsplit("}", 1)[-1].lower()
    if root_type not in {"urlset", "sitemapindex"}:
        return [_finding(
            "sitemap_xml", "Discovered sitemap has an unexpected root element",
            "manual_review_required", "medium",
            f"The XML root element is {root_type or 'empty'}; expected urlset or sitemapindex. Source: {sitemap_url}",
            "The document may be XML but not a sitemap document recognized by standard sitemap consumers.",
            "Use a urlset for page URLs or a sitemapindex for child sitemap references.",
            ["Inspect the root XML element.", "Validate the published sitemap format."],
            sitemap_url,
        )]

    loc_elements = [
        element for element in root.iter()
        if element.tag.rsplit("}", 1)[-1].lower() == "loc"
    ]
    invalid = 0
    empty = 0
    for element in loc_elements:
        value = (element.text or "").strip()
        if not value:
            empty += 1
            invalid += 1
            continue
        try:
            parts = urlsplit(value)
            _ = parts.port
            valid = (
                parts.scheme.lower() in {"http", "https"}
                and bool(parts.hostname)
                and parts.username is None
                and parts.password is None
            )
        except (ValueError, UnicodeError):
            valid = False
        if not valid:
            invalid += 1

    if not loc_elements or invalid:
        return [_finding(
            "sitemap_xml", "Discovered sitemap contains invalid location entries",
            "manual_review_required", "medium",
            f"Root element: {root_type}; loc entries: {len(loc_elements)}; empty or invalid absolute HTTP(S) locations: {invalid}; empty locations: {empty}. Source: {sitemap_url}",
            "Sitemap entries should contain absolute HTTP(S) locations. Empty or malformed entries can reduce reliable discovery. Valid syntax alone does not prove that URLs are canonical or indexable.",
            "Remove empty or malformed loc entries, then verify listed URLs resolve to the intended canonical pages.",
            ["Inspect each loc element.", "Validate representative listed URLs and the sitemap with search-engine tools."],
            sitemap_url,
        )]
    return []


def inspect_robots_txt(text: str, robots_url: str) -> tuple[list[AuditFinding], list[str]]:
    """Review high-impact robots.txt directives without treating them as access controls.

    A new user-agent group begins when a User-agent directive follows directives
    in the current group. Consecutive User-agent lines before any rule belong to
    the same group, as defined by the robots exclusion protocol.
    """
    findings: list[AuditFinding] = []
    limitations: list[str] = []
    group_agents: list[str] = []
    group_has_rules = False
    wildcard_disallow_all = False
    sitemap_count = 0

    for raw_line in text.splitlines()[:5000]:
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        key_lower = key.lower()

        if key_lower == "user-agent":
            if group_has_rules:
                group_agents = []
                group_has_rules = False
            if value:
                group_agents.append(value.lower())
        elif key_lower in {"allow", "disallow", "crawl-delay"}:
            # A blank Disallow is explicitly not a site-wide block.
            if key_lower == "disallow" and value == "/" and "*" in group_agents:
                wildcard_disallow_all = True
            if value or key_lower != "disallow":
                group_has_rules = True
        elif key_lower == "sitemap" and value:
            sitemap_count += 1

    if wildcard_disallow_all:
        findings.append(_finding(
            "indexing", "robots.txt blocks the entire site for wildcard crawlers",
            "manual_review_required", "high",
            f"robots.txt at {robots_url} contains a Disallow: / directive in a User-agent: * group.",
            "A site-wide disallow directive can prevent compliant search crawlers from fetching pages. robots.txt is a crawl directive, not an access-control or security boundary; group inheritance and crawler-specific behavior can affect interpretation.",
            "Confirm the directive is intentional for the live production site. If pages should appear in search, narrow the rule and verify important URLs in the relevant search-engine tools.",
            ["Review all User-agent groups and rule ordering in robots.txt.",
             "Check representative product, category, and landing-page URLs with search-engine inspection tools.",
             "Do not use robots.txt as a substitute for authentication or authorization."],
            robots_url,
        ))
    if sitemap_count == 0:
        limitations.append("robots.txt did not declare a Sitemap URL in the inspected text; this does not prove that no sitemap exists.")
    return findings, limitations


def inspect_llms_txt(body: str, status: int, source_url: str, content_type: str = "") -> list[AuditFinding]:
    """Inspect the conventional llms.txt endpoint without treating it as a ranking requirement."""
    safe_url = source_url
    if status == 404:
        return [_finding(
            "llms_txt", "No llms.txt file found at the conventional path",
            "manual_review_required", "info",
            f"The conventional /llms.txt endpoint returned HTTP 404 at {safe_url}.",
            "llms.txt is a proposed convention, not a required web standard or a guaranteed search or AI-crawler control. Its absence alone does not establish an SEO problem.",
            "Decide whether a curated machine-readable site guide is useful for your publishing goals. Do not add one solely to promise rankings or AI visibility.",
            ["Check whether /llms.txt is intentionally absent.", "If used, document only public, current pages and verify each listed destination."],
            safe_url,
        )]
    if status < 200 or status >= 300:
        return [_finding(
            "llms_txt", "llms.txt could not be inspected",
            "manual_review_required", "info",
            f"The conventional /llms.txt endpoint returned HTTP {status} at {safe_url}.",
            "The response does not establish whether a valid file exists; access controls and transient server errors can affect this check.",
            "Check the endpoint and server response before deciding whether any change is needed.",
            ["Request /llms.txt directly.", "Retest after confirming the endpoint is publicly reachable."],
            safe_url,
        )]
    text = (body or "").strip()
    if not text:
        return [_finding(
            "llms_txt", "llms.txt response is empty",
            "manual_review_required", "low",
            f"The endpoint returned HTTP {status} but contained no non-whitespace text.",
            "An empty file provides no curated links or explanatory content. This convention is optional and does not control whether search engines index pages.",
            "If you intentionally publish llms.txt, add a short purpose statement and useful links, or remove the empty file if it serves no purpose.",
            ["Open the file and confirm its intended contents.", "Retest the response after editing."],
            safe_url,
        )]
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    first = lines[0]
    has_heading = first.startswith("# ")
    has_markdown_links = bool(re.search(r"\[[^\]]+\]\(https?://[^)]+\)", text))
    if not has_heading or not has_markdown_links:
        missing = []
        if not has_heading:
            missing.append("a leading Markdown H1 heading")
        if not has_markdown_links:
            missing.append("at least one absolute HTTP(S) Markdown link")
        return [_finding(
            "llms_txt", "llms.txt format needs a quick review",
            "manual_review_required", "low",
            f"The endpoint returned HTTP {status}; basic checks did not detect {', '.join(missing)}. Non-empty lines: {len(lines)}. Content type: {(content_type or 'not supplied')[:80]}.",
            "This lightweight heuristic checks only a few readable format cues. It does not validate a formal schema, check every link, or establish that AI systems use the file.",
            "If you choose to maintain llms.txt, use a clear heading, concise context, and relevant public Markdown links. Keep the file accurate and avoid listing private or sensitive URLs.",
            ["Review the file as plain text.", "Open each listed URL independently and remove stale or private destinations."],
            safe_url,
        )]
    return [_finding(
        "llms_txt", "llms.txt is present and passes basic format checks",
        "verified", "info",
        f"The endpoint returned HTTP {status}, a leading Markdown H1 heading, and at least one absolute HTTP(S) Markdown link. Non-empty lines: {len(lines)}.",
        "These are basic structural signals only. They do not prove that an AI crawler will fetch, trust, or use the file, and llms.txt is not a guaranteed ranking or indexing control.",
        "Keep the file concise, current, and limited to public pages that genuinely help readers understand the site.",
        ["Open the listed destinations and check that they remain public and relevant.", "Recheck after significant site structure changes."],
        safe_url,
    )]


def _record_static_check_outcome(
    outcome_records: list[CheckOutcome] | None,
    *,
    check_id: str,
    category: str,
    page_url: str,
    findings: list[AuditFinding],
    method: str,
) -> None:
    """Record a check's actual evaluation, including a pass when it found no signal."""
    if outcome_records is None:
        return
    statuses = {str(item.status or "").casefold() for item in findings}
    if any(status in {"not_tested", "not tested", "insufficient_data"} for status in statuses):
        outcome = "not_assessed"
    elif any(
        str(item.status or "").casefold() == "verified"
        and str(item.severity or "").casefold() != "info"
        for item in findings
    ):
        # "Verified" means the signal was observed, not necessarily that it is a defect.
        # Informational detections (for example, valid structured data) must not inflate
        # issue counts merely because their presence was confirmed.
        outcome = "issue"
    elif findings:
        outcome = "warning"
    else:
        outcome = "pass"
    evidence = (
        "; ".join(
            f"{item.title}: {str(item.evidence or '').strip()[:350]}"
            for item in findings[:3]
        )
        if findings else
        "The static checker completed successfully and emitted no issue or review signal for this page."
    )
    outcome_records.append(CheckOutcome(
        check_id=check_id,
        category=category,
        page_url=page_url,
        outcome=outcome,
        observed_at_utc=datetime.now(timezone.utc).isoformat(),
        method=method,
        evidence=evidence[:1800],
        evidence_ref=check_id,
    ))


async def run_bounded_site_crawl(
    target: str,
    outcome_records: list[CheckOutcome] | None = None,
) -> tuple[list[AuditFinding], list[str], list[str]]:
    """Inspect a capped set of same-origin HTML links; no form submission or login."""
    normalized = normalize_target(target)
    parsed_target = urlsplit(normalized)
    origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
    connector = aiohttp.TCPConnector(
        resolver=PublicOnlyResolver(), use_dns_cache=False
    )
    findings: list[AuditFinding] = []
    pages_checked: list[str] = []
    limitations = [
        f"Same-origin crawl is capped at {MAX_CRAWL_PAGES} URLs and follows discovered HTML links only while page budget remains; it does not crawl the whole site.",
        "Query-string variants, JavaScript-rendered links, authenticated pages, and form/checkout flows are not crawled.",
        f"Sitemap discovery considers at most {MAX_CHILD_SITEMAPS} same-origin Sitemap directives from robots.txt (falling back to /sitemap.xml when none are usable), at most {MAX_SITEMAP_DOCUMENTS} fetched sitemap documents across all discovery paths, and at most {MAX_URLS_FROM_SITEMAP} page URLs. The primary sitemap index expands one level into at most {MAX_CHILD_SITEMAPS} same-origin child sitemaps; additional declared sitemap files are inspected within the same bounded discovery budget, but child indexes referenced by those additional files and deeper sitemap-index nesting are not fully expanded.",
    ]

    async with aiohttp.ClientSession(
        timeout=timeout,
        connector=connector,
        headers={"User-Agent": USER_AGENT},
        trust_env=False,
    ) as client:
        try:
            status, homepage, headers, final_home = await _safe_get(client, normalized)
            if status < 200 or status >= 300:
                findings.append(_finding(
                    "crawl", "Homepage could not be audited",
                    "manual_review_required", "medium" if status >= 500 else "low",
                    f"The normalized target returned HTTP {status}; page-level checks were not run for this response.",
                    "An unsuccessful response prevents this crawler from evaluating the homepage HTML. It does not, by itself, establish that the whole website is unavailable to users or search crawlers.",
                    "Confirm the expected public homepage URL, response status, redirects, and any access controls. Retest after resolving transient errors if the response was unexpected.",
                    ["Open the exact URL in a browser and inspect its HTTP status.", "Check the final redirect destination and server logs without exposing credentials.", "Rerun the audit after the page responds successfully."],
                    final_home or normalized,
                ))
                limitations.append(f"Homepage HTML checks were skipped because the final response returned HTTP {status}.")
                if outcome_records is not None:
                    outcome_records.append(CheckOutcome(
                        check_id="crawl.bounded_crawl",
                        category="crawlability",
                        page_url=final_home or normalized,
                        outcome="not_assessed",
                        observed_at_utc=datetime.now(timezone.utc).isoformat(),
                        method="bounded same-origin crawl",
                        evidence=f"Homepage returned HTTP {status}; HTML page checks were not executed.",
                        evidence_ref="crawl.bounded_crawl",
                    ))
                return findings, pages_checked, limitations
            # Normalize redirect destinations before constructing robots/sitemap
            # URLs. In particular, :443 and :80 must not make a safe same-origin
            # crawl appear to be a different origin to the next bounded request.
            final_home = _canonical_page_url(final_home or normalized)
            if "text/html" not in headers.get("content-type", "").lower():
                findings.append(_finding(
                    "crawl", "Homepage response is not HTML",
                    "manual_review_required", "low",
                    f"The homepage returned HTTP {status} with content type {(headers.get('content-type') or 'not provided')[:100]}; HTML-based checks were not run.",
                    "The URL may intentionally serve a file, API response, or other non-HTML content. This result alone does not indicate a website defect, but this crawler cannot assess page metadata or internal links from a non-HTML response.",
                    "Confirm that the supplied URL is the intended storefront page and that it serves HTML to ordinary visitors. If the response is intentional, choose the canonical public HTML entry point for a page audit.",
                    ["Inspect the response content type and first bytes.", "Confirm the URL is the intended public storefront page.", "Retry with the canonical HTML page URL when appropriate."],
                    final_home or normalized,
                ))
                limitations.append("Homepage HTML checks were skipped because the final response was not text/html.")
                if outcome_records is not None:
                    outcome_records.append(CheckOutcome(
                        check_id="crawl.bounded_crawl",
                        category="crawlability",
                        page_url=final_home or normalized,
                        outcome="not_assessed",
                        observed_at_utc=datetime.now(timezone.utc).isoformat(),
                        method="bounded same-origin crawl",
                        evidence="Homepage response was not text/html; HTML page checks were not executed.",
                        evidence_ref="crawl.bounded_crawl",
                    ))
                return findings, pages_checked, limitations
            dependency_findings, dependency_limitations = await inspect_client_dependency_versions(
                homepage, final_home
            )
            findings.extend(dependency_findings)
            limitations.extend(dependency_limitations)
        except Exception as exc:
            if outcome_records is not None:
                outcome_records.append(CheckOutcome(
                    check_id="crawl.bounded_crawl",
                    category="crawlability",
                    page_url=normalized,
                    outcome="error",
                    observed_at_utc=datetime.now(timezone.utc).isoformat(),
                    method="bounded same-origin crawl",
                    evidence=f"Homepage fetch failed with {type(exc).__name__}; page-level outcomes are unavailable.",
                    evidence_ref="crawl.bounded_crawl",
                ))
            return findings, pages_checked, limitations + [
                f"Bounded crawl could not fetch the homepage: {type(exc).__name__}."
            ]

        # llms.txt is an optional proposed convention. Inspect only the same-origin
        # conventional path and report basic format cues without implying ranking value.
        llms_url = urljoin(f"{urlsplit(final_home).scheme}://{urlsplit(final_home).netloc}/", "llms.txt")
        try:
            llms_status, llms_body, llms_headers, llms_final_url = await _safe_get(client, llms_url, allowed_origin=final_home)
            if _same_origin(llms_final_url, final_home):
                llms_findings = inspect_llms_txt(
                    llms_body, llms_status, llms_final_url,
                    llms_headers.get("content-type", ""),
                )
                findings.extend(llms_findings)
                _record_static_check_outcome(
                    outcome_records,
                    check_id="llms_txt.basic_format",
                    category="llms_txt",
                    page_url=llms_final_url,
                    findings=llms_findings,
                    method="same-origin llms.txt HTTP response and bounded Markdown format heuristics",
                )
            else:
                limitations.append("llms.txt inspection was skipped because its redirect left the audited origin.")
                if outcome_records is not None:
                    outcome_records.append(CheckOutcome(
                        check_id="llms_txt.basic_format",
                        category="llms_txt",
                        page_url=llms_url,
                        outcome="not_assessed",
                        observed_at_utc=datetime.now(timezone.utc).isoformat(),
                        method="same-origin llms.txt HTTP response and bounded Markdown format heuristics",
                        evidence="Inspection skipped because the response redirected outside the audited origin.",
                        evidence_ref="llms_txt.basic_format",
                    ))
        except Exception as exc:
            limitations.append(f"llms.txt inspection was inconclusive ({type(exc).__name__}).")
            if outcome_records is not None:
                outcome_records.append(CheckOutcome(
                    check_id="llms_txt.basic_format",
                    category="llms_txt",
                    page_url=llms_url,
                    outcome="error",
                    observed_at_utc=datetime.now(timezone.utc).isoformat(),
                    method="same-origin llms.txt HTTP response and bounded Markdown format heuristics",
                    evidence=f"Inspection failed with {type(exc).__name__}; no file content was included.",
                    evidence_ref="llms_txt.basic_format",
                ))

        # Inspect robots.txt as a discovery/indexing signal. It is fetched through
        # the same public-only resolver and redirect/response-size safeguards.
        robots_sitemap_urls: list[str] = []
        robots_declared_sitemap_urls: list[str] = []
        robots_rules: list[tuple[str, str]] = []
        robots_url = urljoin(f"{urlsplit(final_home).scheme}://{urlsplit(final_home).netloc}/", "robots.txt")
        try:
            robots_status, robots_body, robots_headers, robots_final_url = await _safe_get(client, robots_url, allowed_origin=final_home)
            if 200 <= robots_status < 300 and _same_origin(robots_final_url, final_home):
                robots_findings, robots_limitations = inspect_robots_txt(robots_body, robots_final_url)
                robots_rules = _parse_robots_rules(robots_body, USER_AGENT)
                findings.extend(robots_findings)
                limitations.extend(robots_limitations)
                _record_static_check_outcome(
                    outcome_records,
                    check_id="robots_txt.discovery_rules",
                    category="indexing",
                    page_url=robots_final_url,
                    findings=robots_findings,
                    method="same-origin robots.txt response and bounded directive parsing",
                )
                # Sitemap directives may point to a nonstandard path. Accept only
                # bounded, credential-free HTTP(S) URLs on the audited origin; the
                # same-origin requirement keeps this discovery step from becoming
                # an arbitrary URL fetch mechanism.
                # Some proxy/test transports preserve escaped line separators in
                # text bodies. Normalize them here too so Sitemap directives are
                # discovered consistently with the robots rule parser.
                normalized_robots_body = (
                    robots_body.replace("\\r\\n", "\n")
                    .replace("\\n", "\n")
                    .replace("\\r", "\n")
                )
                for raw_line in normalized_robots_body.splitlines()[:5000]:
                    line = raw_line.split("#", 1)[0].strip()
                    if ":" not in line:
                        continue
                    key, value = (part.strip() for part in line.split(":", 1))
                    if key.lower() != "sitemap" or not value:
                        continue
                    try:
                        parts = urlsplit(value)
                        _ = parts.port
                        if (
                            parts.scheme.lower() in {"http", "https"}
                            and parts.hostname
                            and parts.username is None
                            and parts.password is None
                        ):
                            if value not in robots_declared_sitemap_urls:
                                robots_declared_sitemap_urls.append(value)
                            if _same_origin(value, final_home) and value not in robots_sitemap_urls:
                                robots_sitemap_urls.append(value)
                    except (ValueError, UnicodeError):
                        continue
                    # Keep parsing bounded, but retain off-origin declarations for
                    # reporting instead of silently discarding them.
                    if len(robots_declared_sitemap_urls) >= MAX_CHILD_SITEMAPS:
                        break
            elif robots_status == 404:
                # A missing robots.txt is an unavailable file, not a server failure.
                # With no published rules, bounded same-origin discovery can proceed.
                robots_rules = []
                if outcome_records is not None:
                    outcome_records.append(CheckOutcome(
                        check_id="robots_txt.discovery_rules",
                        category="indexing",
                        page_url=robots_final_url or robots_url,
                        outcome="not_assessed",
                        observed_at_utc=datetime.now(timezone.utc).isoformat(),
                        method="same-origin robots.txt response and bounded directive parsing",
                        evidence="No robots.txt file was published (HTTP 404); no crawl directives were available to inspect.",
                        evidence_ref="robots_txt.discovery_rules",
                    ))
            elif robots_status in {401, 403}:
                limitations.append("robots.txt could not be inspected because the server returned an access-denied response.")
                if outcome_records is not None:
                    outcome_records.append(CheckOutcome(
                        check_id="robots_txt.discovery_rules",
                        category="indexing",
                        page_url=robots_final_url or robots_url,
                        outcome="not_assessed",
                        observed_at_utc=datetime.now(timezone.utc).isoformat(),
                        method="same-origin robots.txt response and bounded directive parsing",
                        evidence=f"Inspection skipped because robots.txt returned HTTP {robots_status}.",
                        evidence_ref="robots_txt.discovery_rules",
                    ))
            elif robots_status >= 500:
                robots_rules = [("disallow", "/")]
                limitations.append(f"robots.txt could not be inspected because the server returned HTTP {robots_status}.")
                if outcome_records is not None:
                    outcome_records.append(CheckOutcome(
                        check_id="robots_txt.discovery_rules",
                        category="indexing",
                        page_url=robots_final_url or robots_url,
                        outcome="error",
                        observed_at_utc=datetime.now(timezone.utc).isoformat(),
                        method="same-origin robots.txt response and bounded directive parsing",
                        evidence=f"Inspection unavailable because robots.txt returned HTTP {robots_status}.",
                        evidence_ref="robots_txt.discovery_rules",
                    ))
            elif 200 <= robots_status < 300:
                robots_rules = [("disallow", "/")]
                limitations.append("robots.txt inspection was skipped because the response redirected outside the audited origin.")
                if outcome_records is not None:
                    outcome_records.append(CheckOutcome(
                        check_id="robots_txt.discovery_rules",
                        category="indexing",
                        page_url=robots_url,
                        outcome="not_assessed",
                        observed_at_utc=datetime.now(timezone.utc).isoformat(),
                        method="same-origin robots.txt response and bounded directive parsing",
                        evidence="Inspection skipped because the response redirected outside the audited origin.",
                        evidence_ref="robots_txt.discovery_rules",
                    ))
            else:
                limitations.append(f"robots.txt returned HTTP {robots_status}; directive inspection was not performed.")
                if outcome_records is not None:
                    outcome_records.append(CheckOutcome(
                        check_id="robots_txt.discovery_rules",
                        category="indexing",
                        page_url=robots_final_url or robots_url,
                        outcome="not_assessed",
                        observed_at_utc=datetime.now(timezone.utc).isoformat(),
                        method="same-origin robots.txt response and bounded directive parsing",
                        evidence=f"Directive inspection was not performed for HTTP {robots_status}.",
                        evidence_ref="robots_txt.discovery_rules",
                    ))
        except Exception as exc:
            # A transient robots.txt fetch/parse failure must be disclosed, but
            # should not silently turn a crawl into zero-page coverage. We still
            # restrict every candidate to the public audited origin and hard page
            # caps; an explicit successfully fetched Disallow rule remains honored.
            robots_rules = []
            limitations.append(f"robots.txt inspection was inconclusive ({type(exc).__name__}); bounded same-origin discovery continued without inferred crawl directives.")
            if outcome_records is not None:
                outcome_records.append(CheckOutcome(
                    check_id="robots_txt.discovery_rules",
                    category="indexing",
                    page_url=robots_url,
                    outcome="error",
                    observed_at_utc=datetime.now(timezone.utc).isoformat(),
                    method="same-origin robots.txt response and bounded directive parsing",
                    evidence=f"Inspection failed with {type(exc).__name__}; response contents were not included.",
                    evidence_ref="robots_txt.discovery_rules",
                ))

        link_parser = _LinkParser()
        link_parser.feed(homepage)
        candidates: list[str] = []
        seen: set[str] = set()
        parameterized_url_signatures: set[tuple[str, tuple[tuple[str, str], ...]]] = set()
        parameterized_parameter_names: set[str] = set()
        parameterized_parameter_kinds: set[str] = set()

        def record_parameterized_url(value: str) -> None:
            signature = _catalog_query_parameter_signature(value)
            if signature is None or signature in parameterized_url_signatures:
                return
            parameterized_url_signatures.add(signature)
            parameterized_parameter_names.update(name for name, _kind in signature[1])
            parameterized_parameter_kinds.update(kind for _name, kind in signature[1])

        final_origin = urlsplit(final_home)

        # Use the conventional sitemap as a secondary discovery source. A sitemap
        # index is expanded only one level, with a strict child-sitemap and URL cap.
        # Every child sitemap must remain on the audited origin before it is fetched.
        sitemap_urls: list[str] = []
        sitemap_documents_fetched = 0
        conventional_sitemap_url = urljoin(f"{final_origin.scheme}://{final_origin.netloc}/", "sitemap.xml")

        def _same_origin_http_url(value: str, base: str) -> bool:
            try:
                parts = urlsplit(urljoin(base, value))
                _ = parts.port
                return (
                    parts.scheme.lower() in {"http", "https"}
                    and bool(parts.hostname)
                    and parts.username is None
                    and parts.password is None
                    and _same_origin(parts.geturl(), final_home)
                )
            except (ValueError, UnicodeError):
                return False

        # robots.txt is untrusted input. Do not request an off-origin Sitemap URL
        # just to discover later that it is outside this crawl's scope.
        same_origin_sitemaps: list[str] = []
        seen_declared_sitemaps: set[str] = set()
        for value in robots_sitemap_urls:
            if not _same_origin_http_url(value, final_home):
                continue
            try:
                normalized_sitemap = _canonical_page_url(value)
            except (ValueError, UnicodeError):
                continue
            if normalized_sitemap in seen_declared_sitemaps:
                continue
            seen_declared_sitemaps.add(normalized_sitemap)
            same_origin_sitemaps.append(value)
            if len(same_origin_sitemaps) >= MAX_CHILD_SITEMAPS:
                break
        for declared_sitemap in robots_declared_sitemap_urls:
            if not _same_origin_http_url(declared_sitemap, final_home):
                findings.append(_finding(
                    "indexing", "robots.txt declares an off-origin sitemap",
                    "manual_review_required", "low",
                    f"robots.txt declares sitemap {declared_sitemap}, which is outside the audited origin and was not fetched by this crawler.",
                    "Sitemap locations can be hosted separately in supported configurations, but this bounded audit deliberately restricts discovery requests to the audited origin.",
                    "Confirm the sitemap host and ownership are intentional. If cross-origin sitemap hosting is required, validate it through the relevant search-engine configuration rather than assuming this crawler inspected it.",
                    ["Review the Sitemap directive and its destination.", "Confirm the sitemap's ownership and intended search-engine setup."],
                    declared_sitemap,
                ))
        sitemap_url = same_origin_sitemaps[0] if same_origin_sitemaps else conventional_sitemap_url
        seen_sitemap_documents = {_canonical_page_url(sitemap_url)}

        def _safe_sitemap_label(value: str) -> str:
            try:
                parts = urlsplit(value)
                _ = parts.port
                if parts.scheme.lower() in {"http", "https"} and parts.hostname:
                    host = parts.hostname.lower()
                    display_host = f"[{host}]" if ":" in host else host
                    port = parts.port
                    default_port = 443 if parts.scheme.lower() == "https" else 80
                    if port is not None and port != default_port:
                        display_host = f"{display_host}:{port}"
                    return f"{parts.scheme.lower()}://{display_host}{(parts.path or '/')[:120]}"
            except (ValueError, UnicodeError):
                pass
            return "(malformed or unsupported sitemap URL omitted)"

        def _loc_values(root):
            return [
                element.text.strip()
                for element in root.iter()
                if element.tag.rsplit("}", 1)[-1].lower() == "loc" and element.text and element.text.strip()
            ]

        try:
            sitemap_documents_fetched += 1
            sitemap_status, sitemap_body, sitemap_headers, sitemap_final_url = await _safe_get(client, sitemap_url, allowed_origin=final_home)
            if 200 <= sitemap_status < 300 and _same_origin(sitemap_final_url, final_home) and (
                "xml" in sitemap_headers.get("content-type", "").lower()
                or sitemap_body.lstrip().startswith("<")
            ):
                # The main audit semantically validates the conventional sitemap.
                # Custom robots-declared locations need equivalent evidence here.
                if sitemap_url != conventional_sitemap_url:
                    findings.extend(inspect_crawl_sitemap(sitemap_body, sitemap_final_url))
                root = ET.fromstring(sitemap_body)
                root_type = root.tag.rsplit("}", 1)[-1].lower()
                if root_type == "urlset":
                    sitemap_urls.extend(_loc_values(root)[:MAX_URLS_FROM_SITEMAP])
                elif root_type == "sitemapindex":
                    child_sitemaps = []
                    seen_child_sitemaps: set[str] = set()
                    rejected_child_sitemaps: list[str] = []
                    for child in root:
                        if child.tag.rsplit("}", 1)[-1].lower() != "sitemap":
                            continue
                        child_loc = next((
                            (loc.text or "").strip()
                            for loc in child
                            if loc.tag.rsplit("}", 1)[-1].lower() == "loc"
                        ), "")
                        if not child_loc:
                            rejected_child_sitemaps.append("(missing or empty loc)")
                            continue
                        try:
                            resolved_child = urljoin(sitemap_final_url, child_loc)
                            if not _same_origin_http_url(resolved_child, sitemap_final_url):
                                rejected_child_sitemaps.append(_safe_sitemap_label(child_loc))
                                continue
                            normalized_child = _canonical_page_url(resolved_child)
                        except (ValueError, UnicodeError):
                            rejected_child_sitemaps.append(_safe_sitemap_label(child_loc))
                            continue
                        if normalized_child in seen_child_sitemaps:
                            continue
                        seen_child_sitemaps.add(normalized_child)
                        child_sitemaps.append(resolved_child)
                        if len(child_sitemaps) >= MAX_CHILD_SITEMAPS:
                            break

                    if rejected_child_sitemaps:
                        findings.append(_finding(
                            "indexing", "Sitemap index contains unusable child sitemap locations",
                            "manual_review_required", "low",
                            f"Found {len(rejected_child_sitemaps)} missing, malformed, or off-origin child sitemap location(s) in {sitemap_final_url}; those locations were not fetched. Examples: "
                            + ", ".join(rejected_child_sitemaps[:5]) + ".",
                            "A sitemap index should reference usable sitemap documents. This crawler deliberately refuses off-origin or malformed targets, and a rejected entry does not prove that search engines cannot discover the URLs by other means.",
                            "Review each rejected sitemap-index location. Correct malformed entries and confirm any cross-origin sitemap hosting is intentional and supported by your search-engine configuration.",
                            ["Inspect each sitemapindex/sitemap/loc entry.", "Confirm each child sitemap URL is valid and belongs to the intended sitemap setup."],
                            sitemap_final_url,
                        ))

                    for child_sitemap_url in child_sitemaps:
                        if len(sitemap_urls) >= MAX_URLS_FROM_SITEMAP:
                            break
                        child_key = _canonical_page_url(child_sitemap_url)
                        if child_key in seen_sitemap_documents:
                            continue
                        seen_sitemap_documents.add(child_key)
                        if sitemap_documents_fetched >= MAX_SITEMAP_DOCUMENTS:
                            limitations.append(f"Sitemap document inspection stopped at the global limit of {MAX_SITEMAP_DOCUMENTS} documents.")
                            break
                        try:
                            sitemap_documents_fetched += 1
                            child_status, child_body, child_headers, child_final_url = await _safe_get(client, child_sitemap_url, allowed_origin=final_home)
                            if not _same_origin(child_final_url, final_home):
                                findings.append(_finding(
                                    "indexing", "Child sitemap redirect left the audited origin",
                                    "manual_review_required", "low",
                                    f"Child sitemap {child_sitemap_url} redirected to a different origin and was not used for discovery.",
                                    "The crawler limits sitemap discovery to the audited origin so external redirect destinations are not silently treated as part of this site's sitemap structure.",
                                    "Confirm the redirect is intentional and ensure the sitemap index points to the intended same-origin sitemap location where appropriate.",
                                    ["Inspect the child sitemap redirect chain.", "Confirm the sitemap index references the intended sitemap host."],
                                    child_sitemap_url,
                                ))
                                continue
                            if child_status < 200 or child_status >= 300:
                                findings.append(_finding(
                                    "indexing", "Child sitemap could not be retrieved",
                                    "manual_review_required", "low",
                                    f"Same-origin sitemap index referenced {child_sitemap_url}, which returned HTTP {child_status}.",
                                    "A sitemap index can point crawlers toward important URLs. An unavailable child sitemap can leave part of that discovery list uninspected; it does not prove those pages are not indexed.",
                                    "Check the child sitemap URL, its response status, and whether access restrictions or a stale sitemap-index entry are intentional.",
                                    ["Open the child sitemap URL directly.", "Confirm the sitemap index references current, accessible sitemap files."],
                                    child_sitemap_url,
                                ))
                                continue
                            if not (
                                "xml" in child_headers.get("content-type", "").lower()
                                or child_body.lstrip().startswith("<")
                            ):
                                findings.append(_finding(
                                    "indexing", "Child sitemap response is not recognizable XML",
                                    "manual_review_required", "low",
                                    f"Same-origin sitemap index referenced {child_sitemap_url}, but the response did not look like XML.",
                                    "A sitemap endpoint should return a sitemap document rather than an HTML error or unrelated content. This bounded check does not assess every sitemap protocol rule.",
                                    "Verify the child sitemap endpoint returns a valid XML sitemap and correct content type, or remove the stale entry from the index.",
                                    ["Inspect the response status, content type, and first bytes.", "Validate the child sitemap XML with a sitemap validator."],
                                    child_sitemap_url,
                                ))
                                continue
                            findings.extend(inspect_crawl_sitemap(child_body, child_sitemap_url))
                            child_root = ET.fromstring(child_body)
                            if child_root.tag.rsplit("}", 1)[-1].lower() != "urlset":
                                continue
                            remaining = MAX_URLS_FROM_SITEMAP - len(sitemap_urls)
                            sitemap_urls.extend(_loc_values(child_root)[:remaining])
                        except Exception as child_exc:
                            findings.append(_finding(
                                "indexing", "Child sitemap could not be inspected",
                                "not_tested", "info",
                                f"Could not inspect same-origin child sitemap {child_sitemap_url}: {type(child_exc).__name__}.",
                                "The child sitemap did not yield usable discovery data during this audit. This is not proof that its URLs are unavailable to search engines.",
                                "Retry the sitemap URL and inspect its XML structure, server response, and any access restrictions.",
                                ["Open the child sitemap URL directly.", "Retry the audit after resolving any transient server or parsing issue."],
                                child_sitemap_url,
                            ))
                            continue
            elif sitemap_url != conventional_sitemap_url:
                if not _same_origin(sitemap_final_url, final_home):
                    findings.append(_finding(
                        "indexing", "Sitemap redirect left the audited origin",
                        "manual_review_required", "medium",
                        f"Same-origin sitemap {sitemap_url} redirected to a different origin; its response was not used for crawl discovery.",
                        "A sitemap redirect to another origin can complicate the intended discovery path and is outside this crawler's same-origin discovery policy. This does not by itself establish an indexing failure.",
                        "Confirm the redirect is intentional. If the sitemap should belong to this store, serve it from the audited origin or document the platform's supported cross-origin sitemap arrangement.",
                        ["Inspect the sitemap's redirect chain in a browser or HTTP client.", "Confirm the final sitemap URL and search-engine configuration."],
                        sitemap_url,
                    ))
                elif sitemap_status < 200 or sitemap_status >= 300:
                    findings.append(_finding(
                        "indexing", "Robots-declared sitemap could not be retrieved",
                        "manual_review_required", "medium",
                        f"robots.txt declared same-origin sitemap {sitemap_url}, which returned HTTP {sitemap_status}.",
                        "A declared sitemap that cannot be retrieved may reduce reliable URL discovery. This does not establish that search engines cannot discover or index the site's pages through other routes.",
                        "Check the declared sitemap URL, status, redirects, access rules, and whether the sitemap directive is still current.",
                        ["Open the sitemap URL directly and confirm a successful response.", "Validate the sitemap and update robots.txt if the declared path is stale."],
                        sitemap_url,
                    ))
                else:
                    findings.append(_finding(
                        "indexing", "Robots-declared sitemap response is not recognizable XML",
                        "manual_review_required", "medium",
                        f"robots.txt declared same-origin sitemap {sitemap_url}, but the response was not recognizable XML (HTTP {sitemap_status}, content type {sitemap_headers.get('content-type', 'not provided')}).",
                        "Search crawlers expect a sitemap document at the declared endpoint. An HTML page or unrelated response may prevent sitemap-based discovery, although other discovery paths can still work.",
                        "Ensure the declared endpoint returns a valid XML sitemap with an appropriate content type, or correct the Sitemap directive to the intended file.",
                        ["Inspect the response body and content type.", "Validate the sitemap XML and confirm its URLs are current."],
                        sitemap_url,
                    ))
        except Exception:
            # The main audit reports sitemap availability/format separately.
            # Failure here only means sitemap-based URL discovery is unavailable.
            pass

        # Preserve sitemap provenance for URLs that enter the bounded page sample.
        sitemap_discovered_urls: set[str] = set()

        # Inspect additional same-origin Sitemap directives rather than silently
        # ignoring every directive after the first. Keep the total number of
        # sitemap documents small and the URL discovery budget bounded.
        additional_sitemaps = [
            value for value in same_origin_sitemaps
            if _canonical_page_url(value) != _canonical_page_url(sitemap_url)
        ][:max(0, MAX_CHILD_SITEMAPS - 1)]
        for extra_sitemap_url in additional_sitemaps:
            if len(sitemap_urls) >= MAX_URLS_FROM_SITEMAP:
                break
            extra_key = _canonical_page_url(extra_sitemap_url)
            if extra_key in seen_sitemap_documents:
                continue
            seen_sitemap_documents.add(extra_key)
            if sitemap_documents_fetched >= MAX_SITEMAP_DOCUMENTS:
                limitations.append(f"Sitemap document inspection stopped at the global limit of {MAX_SITEMAP_DOCUMENTS} documents.")
                break
            try:
                sitemap_documents_fetched += 1
                extra_status, extra_body, extra_headers, extra_final_url = await _safe_get(
                    client, extra_sitemap_url, allowed_origin=final_home
                )
                if not _same_origin(extra_final_url, final_home):
                    findings.append(_finding(
                        "indexing", "Additional robots-declared sitemap redirected off-origin",
                        "manual_review_required", "low",
                        f"Additional sitemap {extra_sitemap_url} redirected away from the audited origin and was excluded from discovery.",
                        "This crawler only follows same-origin sitemap locations. A redirect outside the origin may be intentional, but its contents are not used as evidence for this site's crawl.",
                        "Confirm the redirect and sitemap ownership are intentional, and keep sitemap references consistent with the store's canonical host.",
                        ["Inspect the sitemap redirect chain.", "Confirm the intended sitemap host and search-engine configuration."],
                        extra_sitemap_url,
                    ))
                    continue
                if extra_status < 200 or extra_status >= 300:
                    findings.append(_finding(
                        "indexing", "Additional robots-declared sitemap could not be retrieved",
                        "manual_review_required", "low",
                        f"Additional same-origin sitemap {extra_sitemap_url} returned HTTP {extra_status}.",
                        "An unavailable sitemap can leave some declared URLs out of this audit's discovery sample; it does not prove those pages are not indexed.",
                        "Check the sitemap endpoint, access rules, and robots.txt entry.",
                        ["Open the sitemap URL directly.", "Validate its status and XML response."],
                        extra_sitemap_url,
                    ))
                    continue
                if not (
                    "xml" in extra_headers.get("content-type", "").lower()
                    or extra_body.lstrip().startswith("<")
                ):
                    findings.extend(inspect_crawl_sitemap(extra_body, extra_sitemap_url))
                    continue
                findings.extend(inspect_crawl_sitemap(extra_body, extra_sitemap_url))
                extra_root = ET.fromstring(extra_body)
                extra_type = extra_root.tag.rsplit("}", 1)[-1].lower()
                if extra_type == "urlset":
                    remaining = MAX_URLS_FROM_SITEMAP - len(sitemap_urls)
                    sitemap_urls.extend(_loc_values(extra_root)[:remaining])
                elif extra_type == "sitemapindex":
                    # Expand a bounded number of children from secondary sitemap
                    # indexes too; every candidate is validated before any request.
                    nested_children: list[str] = []
                    seen_nested: set[str] = set()
                    for nested_node in extra_root:
                        if nested_node.tag.rsplit("}", 1)[-1].lower() != "sitemap":
                            continue
                        nested_loc = next((
                            (loc.text or "").strip()
                            for loc in nested_node
                            if loc.tag.rsplit("}", 1)[-1].lower() == "loc"
                        ), "")
                        if not nested_loc:
                            continue
                        try:
                            resolved_nested = urljoin(extra_sitemap_url, nested_loc)
                            if not _same_origin_http_url(resolved_nested, extra_sitemap_url):
                                continue
                            normalized_nested = _canonical_page_url(resolved_nested)
                        except (ValueError, UnicodeError):
                            continue
                        if normalized_nested in seen_nested:
                            continue
                        seen_nested.add(normalized_nested)
                        nested_children.append(resolved_nested)
                        if len(nested_children) >= MAX_CHILD_SITEMAPS:
                            break

                    for nested_url in nested_children:
                        if len(sitemap_urls) >= MAX_URLS_FROM_SITEMAP:
                            break
                        nested_key = _canonical_page_url(nested_url)
                        if nested_key in seen_sitemap_documents:
                            continue
                        seen_sitemap_documents.add(nested_key)
                        if sitemap_documents_fetched >= MAX_SITEMAP_DOCUMENTS:
                            limitations.append(f"Sitemap document inspection stopped at the global limit of {MAX_SITEMAP_DOCUMENTS} documents.")
                            break
                        try:
                            sitemap_documents_fetched += 1
                            nested_status, nested_body, nested_headers, nested_final = await _safe_get(
                                client, nested_url, allowed_origin=final_home
                            )
                            if not _same_origin(nested_final, final_home):
                                continue
                            if nested_status < 200 or nested_status >= 300:
                                continue
                            if not (
                                "xml" in nested_headers.get("content-type", "").lower()
                                or nested_body.lstrip().startswith("<")
                            ):
                                continue
                            findings.extend(inspect_crawl_sitemap(nested_body, nested_url))
                            nested_root = ET.fromstring(nested_body)
                            if nested_root.tag.rsplit("}", 1)[-1].lower() == "urlset":
                                remaining = MAX_URLS_FROM_SITEMAP - len(sitemap_urls)
                                sitemap_urls.extend(_loc_values(nested_root)[:remaining])
                            elif nested_root.tag.rsplit("}", 1)[-1].lower() == "sitemapindex":
                                limitations.append(
                                    f"Nested sitemap index {nested_url} was not expanded beyond the configured depth."
                                )
                        except Exception:
                            # A child sitemap is optional discovery input; do not
                            # fail the whole audit when one nested file is unusable.
                            continue
            except Exception as extra_exc:
                findings.append(_finding(
                    "indexing", "Additional robots-declared sitemap could not be inspected",
                    "not_tested", "info",
                    f"Could not inspect additional sitemap {extra_sitemap_url}: {type(extra_exc).__name__}.",
                    "This sitemap did not yield reliable discovery evidence during the audit.",
                    "Retry the sitemap URL and inspect its XML structure and access restrictions.",
                    ["Open the sitemap directly.", "Retry the audit after resolving transient failures."],
                    extra_sitemap_url,
                ))

        # HTML's first <base href> changes how relative anchor links resolve.
        # Treat it as untrusted input: all resolved candidates still pass the
        # existing HTTP(S), credential, same-origin, robots and file-type gates.
        link_resolution_base: str | None = final_home
        if link_parser.base_href:
            try:
                proposed_base = urljoin(final_home, link_parser.base_href)
                base_parts = urlsplit(proposed_base)
                _ = base_parts.port
                if (
                    base_parts.scheme.lower() not in {"http", "https"}
                    or not base_parts.hostname
                    or base_parts.username is not None
                    or base_parts.password is not None
                    or not _same_origin(proposed_base, final_home)
                ):
                    # HTML base changes the meaning of every relative link. If it
                    # points off-origin or is malformed, skip relative anchors
                    # rather than silently reinterpreting them against the homepage.
                    link_resolution_base = None
                else:
                    link_resolution_base = proposed_base
            except (ValueError, UnicodeError):
                link_resolution_base = None

        discovery_hrefs = [
            *link_parser.links[:MAX_LINKS_FROM_HOME],
            *sitemap_urls,
        ]
        for href in discovery_hrefs:
            # Reserve one slot for the homepage; a one-page budget must not
            # accidentally admit one additional discovered URL.
            if len(candidates) >= max(0, MAX_CRAWL_PAGES - 1):
                break
            # Sitemap entries and page links are untrusted input. A malformed
            # authority (for example, an unmatched IPv6 bracket) must not abort
            # discovery for the remaining valid URLs.
            try:
                is_page_link = href in link_parser.links
                # Relative anchors cannot be safely resolved when a malformed or
                # off-origin base element was present. Absolute same-origin links
                # still pass the normal origin and robots checks below.
                if is_page_link and link_resolution_base is None and not urlsplit(href).scheme and not href.startswith("//"):
                    continue
                absolute = urljoin((link_resolution_base or final_home) if is_page_link else final_home, href)
                parts = urlsplit(absolute)
                if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
                    continue
                # Accessing port validates malformed and out-of-range explicit ports.
                _ = parts.port
                if parts.username is not None or parts.password is not None:
                    continue
                # Compare parsed origins rather than netloc strings so :443 and
                # the implicit HTTPS port (or :80 and implicit HTTP) are equivalent.
                if not _same_origin(absolute, final_home):
                    continue
                suffix = parts.path.lower()
                if suffix.endswith((".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".pdf",
                                     ".css", ".js", ".woff", ".woff2", ".zip", ".xml")):
                    continue
                candidate = _canonical_page_url(absolute)
                if not _robots_path_allowed(candidate, robots_rules):
                    continue
                record_parameterized_url(absolute)
                if candidate in seen or candidate == _canonical_page_url(final_home):
                    continue
            except (ValueError, UnicodeError):
                continue
            seen.add(candidate)
            candidates.append(candidate)
            if any(candidate == _canonical_page_url(item) for item in sitemap_urls):
                sitemap_discovered_urls.add(candidate)
            if len(candidates) >= MAX_CRAWL_PAGES - 1:
                break

        # A small fixed set of safe GET probes looks for recognizable exposed artifacts.
        # The public-only resolver, redirect validation, timeout and response cap still apply.
        exposure_findings, exposure_limitations = await probe_common_exposure_paths(
            client, final_home, allowed_url=lambda candidate_url: _robots_path_allowed(candidate_url, robots_rules)
        )
        findings.extend(exposure_findings)
        _record_static_check_outcome(
            outcome_records, check_id="security.exposure_path_probes",
            category="security_exposure", page_url=final_home,
            findings=[item for item in exposure_findings if item.category == "security_exposure"],
            method="bounded public GET probes for common accidentally exposed artifacts",
        )
        _record_static_check_outcome(
            outcome_records, check_id="security.api_documentation_exposure",
            category="security_api_documentation", page_url=final_home,
            findings=[item for item in exposure_findings if item.category == "security_api_documentation"],
            method="bounded public GET probes for common API documentation and schema endpoints",
        )
        limitations.extend(exposure_limitations)

        transport_findings, transport_limitations = await inspect_transport_security(
            client, homepage, final_home
        )
        findings.extend(transport_findings)
        _record_static_check_outcome(
            outcome_records, check_id="security.transport_tls_and_mixed_content",
            category="security_transport", page_url=final_home,
            findings=transport_findings,
            method="public HTTPS/TLS redirect and static mixed-content inspection",
        )
        limitations.extend(transport_limitations)

        title_pages: dict[str, list[str]] = defaultdict(list)
        description_pages: dict[str, list[str]] = defaultdict(list)
        content_fingerprints: dict[str, str] = {}
        # Keep the initial homepage/sitemap discoveries, then append newly found
        # same-origin links as pages are inspected. Python's list iterator observes
        # appended entries, providing bounded breadth-first traversal without an
        # unbounded queue or a second crawler implementation.
        crawl_queue = [_canonical_page_url(final_home), *candidates]
        queued_urls = set(crawl_queue)
        processed_page_keys: set[str] = set()
        for url in crawl_queue:
            # Sitemap and link discovery can converge on the same canonical page.
            # Process each normalized request URL once so page outcomes and findings
            # are not duplicated by overlapping discovery sources.
            page_key = _canonical_page_url(url)
            if page_key in processed_page_keys:
                continue
            processed_page_keys.add(page_key)
            try:
                # Reuse the homepage response already fetched for link discovery.
                # This avoids spending a second request on the same page and keeps
                # the recorded homepage evidence consistent within this audit run.
                if url == _canonical_page_url(final_home):
                    page_status, body, page_headers, final_url = status, homepage, headers, final_home
                else:
                    page_status, body, page_headers, final_url = await _safe_get(client, url, allowed_origin=final_home)
            except Exception as exc:
                findings.append(_finding(
                    "crawl", "Internal page could not be checked", "not_tested", "info",
                    f"Could not fetch {url}: {type(exc).__name__}.",
                    "The page could not be checked reliably; this is not proof the URL is broken.",
                    "Open the URL in a browser and check server, DNS, TLS, and access restrictions.",
                    ["Retry the URL with a browser and an HTTP status checker."], url,
                ))
                if url in sitemap_discovered_urls and outcome_records is not None:
                    outcome_records.append(CheckOutcome(
                        check_id="sitemap.discovered_url_status",
                        category="indexing",
                        page_url=url,
                        outcome="error",
                        observed_at_utc=datetime.now(timezone.utc).isoformat(),
                        method="bounded GET of a sampled same-origin sitemap URL",
                        evidence=f"The sitemap-listed URL could not be fetched ({type(exc).__name__}); no HTTP status or indexability conclusion is inferred.",
                        evidence_ref="sitemap.discovered_url_status",
                    ))
                continue

            if url not in pages_checked:
                pages_checked.append(url)
            if url in sitemap_discovered_urls and outcome_records is not None:
                if not _same_origin(final_url, final_home):
                    sitemap_outcome = "not_assessed"
                    sitemap_evidence = "The sitemap-listed URL redirected off-origin; its destination was not treated as an in-scope page."
                elif 200 <= page_status < 300:
                    sitemap_outcome = "pass"
                    sitemap_evidence = f"The sampled sitemap-listed URL returned HTTP {page_status} on the audited origin. This does not establish indexing."
                elif page_status >= 500:
                    sitemap_outcome = "error"
                    sitemap_evidence = f"The sampled sitemap-listed URL returned HTTP {page_status}; availability is inconclusive."
                elif page_status >= 400:
                    sitemap_outcome = "issue"
                    sitemap_evidence = f"The sampled sitemap-listed URL returned HTTP {page_status}."
                else:
                    sitemap_outcome = "not_assessed"
                    sitemap_evidence = f"The sampled sitemap-listed URL returned HTTP {page_status}; no pass/fail conclusion is assigned."
                outcome_records.append(CheckOutcome(
                    check_id="sitemap.discovered_url_status",
                    category="indexing",
                    page_url=url,
                    outcome=sitemap_outcome,
                    observed_at_utc=datetime.now(timezone.utc).isoformat(),
                    method="bounded GET of a sampled same-origin sitemap URL",
                    evidence=sitemap_evidence,
                    evidence_ref="sitemap.discovered_url_status",
                ))
            if page_headers.get("x-audit-decoding-fallback") == "unsupported-or-invalid-charset":
                findings.append(_finding(
                    "crawl", "Page text was decoded with a fallback charset",
                    "not_tested", "info",
                    f"The response for {final_url} declared an unsupported or invalid character encoding; UTF-8 replacement decoding was used for source inspection.",
                    "Some text may be replaced or misread, so checks that depend on exact page text or markup content may be incomplete. This does not by itself indicate a site defect.",
                    "Configure the response with a valid, accurate Content-Type charset and retry the audit.",
                    ["Inspect the Content-Type response header.", "Confirm the declared encoding matches the actual response bytes and rerun the audit."],
                    final_url,
                ))
            if page_status < 200 or page_status >= 400:
                findings.append(_finding(
                    "broken_internal_links", "Internal URL returned an error",
                    "verified", "high" if page_status >= 500 else "medium",
                    f"GET {url} returned HTTP {page_status}.",
                    "A homepage link points to a URL that returned an error to this audit request. Some sites intentionally restrict automated clients, so confirm in a normal browser.",
                    "Repair the link or restore the intended destination; if access restrictions are intentional, verify that users and search crawlers receive the expected behavior.",
                    ["Open the URL in a browser.", "Recheck its HTTP status and redirect destination."], url,
                ))
                continue
            if "text/html" not in page_headers.get("content-type", "").lower():
                continue

            page_findings_start = len(findings)
            page_parser = _PageParser()
            page_parser.feed(body)

            # Expand only from successfully fetched HTML pages, with a strict
            # per-page link cap, total page cap, same-origin enforcement, and
            # canonical URL keys that discard fragments/tracking query variants.
            if len(crawl_queue) < MAX_CRAWL_PAGES:
                discovered_links = _LinkParser()
                discovered_links.feed(body)
                # Apply each document's own <base href> during breadth-first
                # discovery too, not only during homepage seed collection.
                # Otherwise a relative link skipped above could be re-added here
                # when the homepage is revisited from the crawl queue.
                page_link_base: str | None = final_url
                if discovered_links.base_href:
                    try:
                        proposed_page_base = urljoin(final_url, discovered_links.base_href)
                        base_parts = urlsplit(proposed_page_base)
                        _ = base_parts.port
                        if (
                            base_parts.scheme.lower() not in {"http", "https"}
                            or not base_parts.hostname
                            or base_parts.username is not None
                            or base_parts.password is not None
                            or not _same_origin(proposed_page_base, final_url)
                        ):
                            page_link_base = None
                        else:
                            page_link_base = proposed_page_base
                    except (ValueError, UnicodeError):
                        page_link_base = None
                for href in discovered_links.links[:MAX_LINKS_FROM_HOME]:
                    if len(crawl_queue) >= MAX_CRAWL_PAGES:
                        break
                    try:
                        if (
                            page_link_base is None
                            and not urlsplit(href).scheme
                            and not href.startswith("//")
                        ):
                            continue
                        absolute = urljoin(page_link_base or final_url, href)
                        parts = urlsplit(absolute)
                        if (
                            parts.scheme.lower() not in {"http", "https"}
                            or not parts.hostname
                            or parts.username is not None
                            or parts.password is not None
                        ):
                            continue
                        _ = parts.port
                        if not _same_origin(absolute, final_home):
                            continue
                        candidate_url = _canonical_page_url(absolute)
                        path = parts.path.lower()
                        if path.endswith((
                            ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg",
                            ".pdf", ".css", ".js", ".woff", ".woff2", ".zip", ".xml",
                        )):
                            continue
                        if not _robots_path_allowed(candidate_url, robots_rules):
                            continue
                        record_parameterized_url(absolute)
                        if candidate_url in queued_urls:
                            continue
                        queued_urls.add(candidate_url)
                        crawl_queue.append(candidate_url)
                    except (ValueError, UnicodeError):
                        # A malformed link must not stop inspection of other links.
                        continue

            product_schema_findings = inspect_product_page_schema_presence(body, final_url)
            findings.extend(product_schema_findings)
            catalog_findings = inspect_ecommerce_catalog_navigation(body, final_url)
            findings.extend(catalog_findings)
            # The page-family outcome pass below applies product and catalog checks
            # only to matching routes and records each canonical check once. Do not
            # emit unconditional homepage outcomes here.
            sensitive_form_findings = inspect_sensitive_get_forms(body, final_url)
            findings.extend(sensitive_form_findings)
            _record_static_check_outcome(
                outcome_records, check_id="security.sensitive_get_forms",
                category="security_baseline", page_url=final_url,
                findings=sensitive_form_findings,
                method="static HTML form-method and sensitive-field heuristic",
            )
            canonical_findings = inspect_canonical_declaration(body, final_url)
            findings.extend(canonical_findings)
            _record_static_check_outcome(
                outcome_records, check_id="indexability.canonical",
                category="indexability", page_url=final_url,
                findings=canonical_findings,
                method="static HTML canonical-link declaration review",
            )

            # Run the existing header/cookie review on every sampled HTML page.
            # These are configuration review signals, not automatic vulnerability claims.
            header_quality_findings = inspect_security_header_quality(page_headers, final_url)
            findings.extend(header_quality_findings)
            _record_static_check_outcome(
                outcome_records, check_id="security_headers.header_quality",
                category="security_headers", page_url=final_url,
                findings=[item for item in header_quality_findings if item.category == "security_headers"],
                method="static HTTP response-header and CSP/HSTS review",
            )
            _record_static_check_outcome(
                outcome_records, check_id="security_cookies.cookie_attributes",
                category="security_cookies", page_url=final_url,
                findings=[item for item in header_quality_findings if item.category == "security_cookies"],
                method="static Set-Cookie attribute inspection; cookie values are not retained",
            )
            standard_header_findings = inspect_standard_security_headers(page_headers, final_url)
            findings.extend(standard_header_findings)
            _record_static_check_outcome(
                outcome_records, check_id="security_headers.standard_headers",
                category="security_headers", page_url=final_url,
                findings=standard_header_findings, method="static HTTP response-header review",
            )

            # Basic document metadata and semantic landmarks are independently recorded.
            # These are source-level signals, not a rendered accessibility verdict.
            document_findings = inspect_document_basics(body, final_url)
            findings.extend(document_findings)
            _record_static_check_outcome(
                outcome_records, check_id="document.basics_metadata_landmarks",
                category="technical_seo", page_url=final_url,
                findings=document_findings, method="static HTML document metadata and landmark inspection",
            )

            # Content volume and exact duplicate text are bounded editorial signals,
            # not a subjective content-quality score or ranking prediction.
            content_findings, content_outcomes, content_fingerprint = inspect_content_quality(
                body, final_url, prior_fingerprints=content_fingerprints
            )
            findings.extend(content_findings)
            if content_fingerprint:
                content_fingerprints.setdefault(content_fingerprint, final_url)
            if outcome_records is not None:
                outcome_records.extend(content_outcomes)

            hreflang_findings = inspect_hreflang(body, final_url)
            findings.extend(hreflang_findings)
            _record_static_check_outcome(
                outcome_records, check_id="international_seo.hreflang",
                category="international_seo", page_url=final_url,
                findings=hreflang_findings,
                method="static HTML hreflang declaration and reciprocal-reference review",
            )
            hreflang_declared = bool(
                re.search(r"(?is)<link\b[^>]*\bhreflang\s*=", body[:500_000])
            )

            refresh_findings = inspect_meta_refresh(body, final_url)
            findings.extend(refresh_findings)
            _record_static_check_outcome(
                outcome_records, check_id="technical_seo.meta_refresh",
                category="technical_seo", page_url=final_url,
                findings=refresh_findings,
                method="static HTML meta-refresh redirect inspection",
            )
            viewport_findings = inspect_mobile_viewport(body, final_url)
            findings.extend(viewport_findings)
            _record_static_check_outcome(
                outcome_records, check_id="mobile_ux.viewport_declaration",
                category="mobile_ux", page_url=final_url,
                findings=viewport_findings, method="static HTML viewport declaration inspection",
            )

            # Static resource patterns are review signals, not measured Core Web Vitals.
            performance_findings = inspect_static_performance_signals(body, final_url)
            findings.extend(performance_findings)
            _record_static_check_outcome(
                outcome_records, check_id="performance.static_resource_signals",
                category="performance", page_url=final_url,
                findings=performance_findings, method="static HTML resource-pattern inspection",
            )
            # Source-level accessibility signals are review prompts, not a WCAG verdict.
            accessibility_findings = inspect_static_accessibility_signals(body, final_url)
            findings.extend(accessibility_findings)
            _record_static_check_outcome(
                outcome_records, check_id="accessibility.static_html_signals",
                category="accessibility", page_url=final_url,
                findings=accessibility_findings, method="static HTML accessibility signal inspection",
            )
            aria_findings = [
                item for item in accessibility_findings
                if any(token in item.title.lower() for token in (
                    "aria reference", "label or aria", "duplicate html ids",
                    "accessible name", "accessible labels", "accessible label",
                    "focusable controls may be hidden",
                ))
            ]
            _record_static_check_outcome(
                outcome_records, check_id="aria.accessible_names_and_relationships",
                category="aria", page_url=final_url,
                findings=aria_findings,
                method="static HTML accessible-name, label association, ID-reference and aria-hidden focusability inspection",
            )
            # Trust inventory is source-level only and explicitly avoids authenticity claims.
            trust_findings = inspect_trust_signals(body, final_url)
            findings.extend(trust_findings)
            _record_static_check_outcome(
                outcome_records, check_id="trust.visible_signal_inventory",
                category="trust", page_url=final_url,
                findings=trust_findings, method="static visible trust-signal inventory",
            )
            # Detect source-visible tags and consent signals; never infer event success or legal compliance.
            privacy_tracking_findings = inspect_privacy_tracking_signals(body, final_url)
            findings.extend(privacy_tracking_findings)
            _record_static_check_outcome(
                outcome_records, check_id="pixel_analytics.source_tag_and_consent_signals",
                category="pixel_analytics", page_url=final_url,
                findings=privacy_tracking_findings,
                method="static HTML analytics/pixel tag and consent-interface signal inspection",
            )

            # The homepage alt-attribute check is already part of Phase 1. Add
            # page-specific findings for sampled internal pages without duplicating it.
            if page_parser.images_missing_alt and url != _canonical_page_url(final_home):
                findings.append(_finding(
                    "aria_alt_text", "Internal page images missing alt attributes",
                    "verified", "medium",
                    f"{page_parser.images_missing_alt} of {page_parser.images} image element(s) on {final_url} lack an alt attribute in the returned HTML.",
                    "Alternative text communicates meaningful image content to screen-reader users. Decorative images can use an empty alt attribute; this source check does not judge whether existing text is appropriate.",
                    "Review each image in context, add concise descriptive alt text to informative images, and use alt=\"\" for decorative images. Avoid keyword stuffing.",
                    ["Inspect the images on the rendered page.", "Retest with a browser accessibility inspector or automated accessibility scanner."],
                    final_url,
                ))

            # Empty alt is valid for decorative images, but may be an accessibility
            # problem when the image conveys information. Keep this distinct from
            # missing attributes and avoid treating every empty alt as a definite bug.
            if page_parser.images_empty_alt and url != _canonical_page_url(final_home):
                findings.append(_finding(
                    "aria_alt_text", "Internal page images have empty alt text",
                    "manual_review_required", "low",
                    f"{page_parser.images_empty_alt} of {page_parser.images} image element(s) on {final_url} have an empty alt attribute in the returned HTML.",
                    "An empty alt attribute is appropriate for decorative images. If an image communicates product details, product variants, or other information not available nearby, empty alt text may leave that information inaccessible.",
                    "Review each empty-alt image in context. Keep alt=\"\" for decorative images and add concise descriptive alternatives only when the image conveys meaningful information.",
                    ["Inspect each empty-alt image on the rendered page.", "Check whether its information is available in adjacent text or another accessible control."],
                    final_url,
                ))

            # Product structured data is inspected only on product-detail-like paths.
            # Static JSON-LD property checks are evidence, not a guarantee of Google
            # rich-result eligibility; variants and platform-specific output need review.
            path_segments = [part.lower() for part in urlsplit(final_url).path.split("/") if part]
            looks_like_product = any(
                segment in {"product", "products"} for segment in path_segments
            )
            looks_like_category = any(
                segment in {"collection", "collections", "category", "categories", "catalog"}
                for segment in path_segments
            )
            if looks_like_category and page_parser.h1_count == 0:
                findings.append(_finding(
                    "ecommerce_category", "Category-like page has no H1 in returned HTML",
                    "manual_review_required", "low",
                    f"The URL path resembles a category/collection page, but no H1 was found in returned HTML: {final_url}.",
                    "Category pages benefit from a clear heading that tells shoppers what products they are browsing. Some themes add headings with JavaScript, which this source-only check does not execute.",
                    "Check the rendered page and add a clear category heading if one is missing; do not add a redundant heading solely to satisfy an automated check.",
                    ["Open the category page at desktop and mobile widths.", "Inspect the rendered heading outline and retest after any template change."],
                    final_url,
                ))

            if looks_like_category:
                category_schema_found = False
                category_schema_types = {"collectionpage", "itemlist"}
                for script_text in page_parser.jsonld_scripts:
                    try:
                        schema_data = json.loads(script_text)
                    except (json.JSONDecodeError, TypeError):
                        continue
                    stack = [schema_data]
                    while stack:
                        item = stack.pop()
                        if isinstance(item, dict):
                            raw_type = item.get("@type", [])
                            types = raw_type if isinstance(raw_type, list) else [raw_type]
                            normalized_types = {
                                str(value).rstrip("/").rsplit("/", 1)[-1].rsplit("#", 1)[-1].lower()
                                for value in types
                            }
                            if normalized_types.intersection(category_schema_types):
                                category_schema_found = True
                            stack.extend(value for value in item.values() if isinstance(value, (dict, list)))
                        elif isinstance(item, list):
                            stack.extend(item)

                findings.append(_finding(
                    "structured_data",
                    "Category/list structured data detected" if category_schema_found else "Category/list structured data not detected",
                    "verified" if category_schema_found else "manual_review_required",
                    "info" if category_schema_found else "low",
                    (
                        f"Detected CollectionPage or ItemList JSON-LD on category-like URL {final_url}."
                        if category_schema_found else
                        f"No CollectionPage or ItemList type was detected in the inspected JSON-LD on category-like URL {final_url}."
                    ),
                    "Collection and item-list markup may describe a category page, but structured-data needs vary by site and search feature. Its absence alone does not prove an SEO defect.",
                    "Review whether structured data is useful for this template, ensure any markup accurately reflects visible page content, and validate it with a structured-data tool. Do not add schema just to chase a ranking guarantee.",
                    ["Inspect the rendered category page and its JSON-LD.", "Validate any markup with Schema.org Validator and applicable search-engine documentation."],
                    final_url,
                ))

            if looks_like_product:
                product_nodes: list[dict] = []
                for script_text in page_parser.jsonld_scripts:
                    try:
                        schema_data = json.loads(script_text)
                    except (json.JSONDecodeError, TypeError):
                        continue

                    stack = [schema_data]
                    while stack:
                        item = stack.pop()
                        if isinstance(item, dict):
                            raw_type = item.get("@type", [])
                            types = raw_type if isinstance(raw_type, list) else [raw_type]
                            normalized_types = {
                                str(value).rstrip("/").rsplit("/", 1)[-1].rsplit("#", 1)[-1].lower()
                                for value in types
                            }
                            if normalized_types.intersection({"product", "productgroup"}):
                                product_nodes.append(item)
                            stack.extend(value for value in item.values() if isinstance(value, (dict, list)))
                        elif isinstance(item, list):
                            stack.extend(item)

                product_schema_found = bool(product_nodes)
                findings.append(_finding(
                    "structured_data",
                    "Product structured data detected" if product_schema_found else "Product structured data not detected",
                    "verified" if product_schema_found else "manual_review_required",
                    "info" if product_schema_found else "low",
                    (
                        f"Detected {len(product_nodes)} Product/ProductGroup object(s) in JSON-LD on {final_url}; "
                        f"scanned {len(page_parser.jsonld_scripts)} JSON-LD script block(s)."
                        if product_schema_found else
                        f"No Product/ProductGroup type was detected in {len(page_parser.jsonld_scripts)} JSON-LD script block(s) on {final_url}."
                    ),
                    "Product structured data can help search engines interpret product details, but presence alone does not prove validity, rich-result eligibility, or that a search engine will display it.",
                    "If this is an indexable product detail page, validate its structured data and ensure it matches visible page content. Some ecommerce platforms inject markup outside the initial HTML response.",
                    ["Inspect page source for JSON-LD Product or ProductGroup data.", "Use a structured-data testing tool and compare the results with the visible product page."],
                    final_url,
                ))

                if product_nodes:
                    def nonempty_string(value):
                        return isinstance(value, str) and bool(value.strip())

                    def has_image(value):
                        if nonempty_string(value):
                            return True
                        if isinstance(value, list):
                            return any(has_image(entry) for entry in value)
                        if isinstance(value, dict):
                            return nonempty_string(value.get("url")) or nonempty_string(value.get("contentUrl"))
                        return False

                    def has_price(value):
                        if isinstance(value, bool):
                            return False
                        if isinstance(value, (int, float)):
                            return True
                        return nonempty_string(value)

                    missing_properties: list[str] = []
                    if not any(nonempty_string(node.get("name")) for node in product_nodes):
                        missing_properties.append("name")
                    if not any(has_image(node.get("image")) for node in product_nodes):
                        missing_properties.append("image")

                    offer_nodes = []
                    for node in product_nodes:
                        offers = node.get("offers", [])
                        if isinstance(offers, dict):
                            offers = [offers]
                        if isinstance(offers, list):
                            offer_nodes.extend(offer for offer in offers if isinstance(offer, dict))
                    if not offer_nodes:
                        missing_properties.append("offers (price and availability details)")
                    else:
                        if not any(has_price(offer.get("price")) for offer in offer_nodes):
                            missing_properties.append("offers.price")
                        if not any(nonempty_string(offer.get("priceCurrency")) for offer in offer_nodes):
                            missing_properties.append("offers.priceCurrency")
                        if not any(nonempty_string(offer.get("availability")) for offer in offer_nodes):
                            missing_properties.append("offers.availability")

                    # Flag suspicious offer values separately from missing-property checks.
                    # These are source-level sanity checks, not a full Schema.org validator.
                    suspicious_offer_values: list[str] = []
                    for offer in offer_nodes:
                        raw_price = offer.get("price")
                        if isinstance(raw_price, (int, float)) and not isinstance(raw_price, bool):
                            if raw_price < 0:
                                suspicious_offer_values.append("negative offer price")
                        elif isinstance(raw_price, str) and raw_price.strip():
                            try:
                                parsed_price = float(raw_price.strip().replace(",", ""))
                            except ValueError:
                                parsed_price = None
                            if parsed_price is not None and parsed_price < 0:
                                suspicious_offer_values.append("negative offer price")
                        raw_currency = offer.get("priceCurrency")
                        if nonempty_string(raw_currency) and not re.fullmatch(r"[A-Za-z]{3}", raw_currency.strip()):
                            suspicious_offer_values.append("priceCurrency is not a three-letter currency code")
                    suspicious_offer_values = list(dict.fromkeys(suspicious_offer_values))
                    if suspicious_offer_values:
                        findings.append(_finding(
                            "structured_data", "Product offer values need validation",
                            "manual_review_required", "medium",
                            f"On {final_url}, inspected Product/ProductGroup offer data contains suspicious value(s): "
                            + ", ".join(suspicious_offer_values) + ".",
                            "A negative numeric price is unlikely to represent a normal product offer, and priceCurrency is expected to use a three-letter currency code. This lightweight check does not confirm whether a currency exists or whether an offer matches the visible storefront.",
                            "Compare every flagged value with the actual selected product variant, visible price, currency, and current structured-data requirements. Correct the source only using verified commercial data.",
                            ["Compare JSON-LD offer values with the visible product and selected variant.", "Validate the page with Schema.org Validator and the applicable rich-result test."],
                            final_url,
                        ))

                    if missing_properties:
                        findings.append(_finding(
                            "structured_data", "Product JSON-LD needs property review",
                            "manual_review_required", "medium",
                            f"On {final_url}, sampled Product/ProductGroup JSON-LD does not expose these commonly useful properties in the inspected objects: "
                            + ", ".join(missing_properties) + ".",
                            "Missing properties in the initial HTML can limit how completely a search engine interprets a product. Requirements differ by schema type and search feature; this automated signal is not a formal validity verdict.",
                            "Compare the detected JSON-LD with the visible product and the current structured-data requirements for your intended search feature. Add only accurate values supported by the page; never invent price, currency, availability, or images.",
                            ["Run the URL through Google's Rich Results Test and Schema.org Validator.", "Confirm name, images, price, currency, and availability match the visible product and selected variant.", "Retest after changes."],
                            final_url,
                        ))

            if page_parser.canonical_missing_href_count:
                findings.append(_finding(
                    "technical_seo", "Canonical declaration is missing href",
                    "manual_review_required", "medium",
                    f"Page {final_url} contains {page_parser.canonical_missing_href_count} canonical link element(s) without a non-empty href.",
                    "A canonical link without a destination does not identify the preferred URL. This source-level signal does not determine the correct canonical destination.",
                    "Review the page template and ensure each canonical link has the intended valid URL; remove empty canonical elements.",
                    ["Inspect canonical link elements in the page source.", "Confirm the remaining canonical points to the intended preferred URL."],
                    final_url,
                ))

            # Multiple canonical declarations can send conflicting signals.
            # This detects duplication but does not decide which target is correct.
            if page_parser.canonical_count > 1:
                findings.append(_finding(
                    "technical_seo", "Multiple canonical declarations detected",
                    "manual_review_required", "medium",
                    f"Page {final_url} contains {page_parser.canonical_count} link elements declaring rel=canonical.",
                    "More than one canonical declaration can create ambiguity about the preferred URL. This source check does not determine which declaration a search engine will select.",
                    "Review the page template and ensure it emits one intentional canonical declaration for the page, then check the rendered source and final URL.",
                    ["Inspect all canonical link elements in the page source.", "Confirm the remaining canonical points to the intended preferred URL."],
                    final_url,
                ))

            # A canonical tag is a search-engine hint. Flag an off-origin target
            # for human review rather than assuming it is wrong in every setup.
            if page_parser.canonical_href:
                canonical_href = page_parser.canonical_href
                try:
                    canonical_url = urljoin(final_url, canonical_href)
                    canonical_parts = urlsplit(canonical_url)
                    canonical_host = canonical_parts.hostname
                    # Accessing .port validates numeric range and malformed authority syntax.
                    _ = canonical_parts.port
                    malformed_canonical = (
                        canonical_parts.scheme.lower() not in {"http", "https"}
                        or not canonical_host
                        or canonical_parts.username is not None
                        or canonical_parts.password is not None
                    )
                except (ValueError, UnicodeError):
                    canonical_url = "(could not safely resolve malformed canonical URL)"
                    malformed_canonical = True
                if malformed_canonical:
                    findings.append(_finding(
                        "technical_seo", "Canonical URL is malformed",
                        "manual_review_required", "medium",
                        f"Page {final_url} declares canonical href={canonical_href!r}; the target is not a valid absolute HTTP(S) URL after resolution.",
                        "A malformed canonical declaration may prevent search engines from using the intended preferred URL. The automated check cannot determine which URL the store should canonicalize to.",
                        "Review the canonical element and replace it only with the intended, valid preferred URL after checking platform routing and duplicate-page behavior.",
                        ["Inspect the canonical element in the raw HTML.", "Confirm the preferred URL loads successfully and is the intended canonical destination."],
                        final_url,
                    ))
                elif not _same_origin(canonical_url, final_url):
                    findings.append(_finding(
                        "technical_seo", "Canonical URL points outside this page origin",
                        "manual_review_required", "medium",
                        f"Page {final_url} declares canonical href={canonical_href!r}, resolving to {canonical_url}.",
                        "A canonical tag tells search engines which URL should represent similar or duplicate content. An off-origin canonical may be intentional for syndicated content, but can also divert indexing signals away from this store.",
                        "Confirm that the canonical destination is intentional, controlled, indexable, and the preferred version of this page. Do not change it without checking duplicate and platform routing behavior.",
                        ["Inspect the canonical element in page source.", "Compare the declared canonical with the preferred URL and the destination response."],
                        final_url,
                    ))

            # Duplicate meta robots tags can conflict; preserve all directives and request review.
            if page_parser.meta_robots_count > 1:
                findings.append(_finding(
                    "indexability", "Multiple meta robots declarations detected",
                    "manual_review_required", "medium",
                    f"Page {final_url} contains {page_parser.meta_robots_count} meta name=robots declarations.",
                    "Multiple robots meta elements may communicate conflicting indexing instructions. This source check reports the duplication but does not determine how each crawler will resolve conflicting directives.",
                    "Review the page template and consolidate intended robots directives into one clear meta element, while checking any X-Robots-Tag response header.",
                    ["Inspect every robots meta element in the raw HTML.", "Confirm the final intended index/follow behavior for this page."],
                    final_url,
                ))

            # Indexing directives may be delivered in HTML or the HTTP response.
            # Record both sources, since an X-Robots-Tag can apply even without a meta tag.
            meta_robots = page_parser.meta_robots.strip()
            x_robots_tag = page_headers.get("x-robots-tag", "").strip()
            robots_tokens = {
                token.strip().lower()
                for token in (meta_robots + "," + x_robots_tag).replace(";", ",").replace(" ", ",").split(",")
                if token.strip()
            }
            if "noindex" in robots_tokens or "none" in robots_tokens:
                sources = []
                if meta_robots:
                    sources.append(f"meta robots={meta_robots!r}")
                if x_robots_tag:
                    sources.append(f"X-Robots-Tag={x_robots_tag!r}")
                try:
                    path_segments = [segment.casefold() for segment in urlsplit(final_url).path.split("/") if segment]
                except (ValueError, UnicodeError):
                    path_segments = []
                commercial_route = any(
                    segment in {
                        "product", "products", "item", "items", "collection", "collections",
                        "category", "categories", "shop", "store", "catalog", "catalogue",
                    }
                    for segment in path_segments
                )
                severity = "high" if commercial_route else "medium"
                route_context = (
                    " The path resembles a product, category, collection, or store landing page, so unintended exclusion could affect commercially important organic landing pages; confirm the actual page purpose before changing anything."
                    if commercial_route else ""
                )
                findings.append(_finding(
                    "indexability", "Page contains a noindex directive",
                    "verified", severity,
                    f"Page {final_url} declares " + " and ".join(sources) + ".",
                    "A noindex directive in HTML or an HTTP response header asks compliant search crawlers not to index this page. It may be intentional for cart, account, internal-search, duplicate, or private pages." + route_context,
                    "Confirm this page should be excluded from search. If it is intended as an organic landing page, remove the unintended noindex directive from the relevant HTML or response header and verify the final response. Do not remove intentional exclusions from cart, account, or duplicate pages just to clear an audit finding.",
                    ["Confirm the page's business purpose and intended indexability.", "Inspect the page source and final response headers.", "Check the URL's indexing status in the site owner's search console."],
                    final_url,
                ))

            if page_parser.title_text:
                title_pages[page_parser.title_text.strip().casefold()].append(url)
                title_length = len(page_parser.title_text.strip())
                if title_length < 15 or title_length > 60:
                    findings.append(_finding(
                        "on_page_seo", "Internal page title length needs review",
                        "manual_review_required", "info",
                        f"Page title on {final_url} contains {title_length} characters.",
                        "Title display is not governed by a fixed character limit: search engines may truncate or rewrite titles based on pixel width, device, and query. Very short or long titles are a review signal, not proof of an SEO error.",
                        "Check that the title is descriptive, distinct, and useful to shoppers. Shorten or expand it only when doing so improves clarity; do not target a character count at the expense of meaning.",
                        ["Review the title as it appears in search previews on mobile and desktop.", "Confirm that the title accurately describes the page and is not duplicated across distinct pages."],
                        final_url,
                    ))
            if page_parser.meta_description:
                description_pages[page_parser.meta_description.strip().casefold()].append(url)
            if page_parser.h1_count > 1:
                findings.append(_finding(
                    "on_page_seo", "Internal page has multiple H1 headings",
                    "manual_review_required", "low",
                    f"Found {page_parser.h1_count} H1 elements in returned HTML for {final_url}.",
                    "Multiple H1 elements are allowed by modern HTML and are not automatically an SEO error. They can, however, indicate duplicated template headings or an unclear content hierarchy, so review the rendered page in context.",
                    "Inspect the rendered heading outline. Keep headings that accurately structure the page, and remove or adjust only redundant or misleading H1 elements rather than enforcing an arbitrary one-H1 rule.",
                    ["Review the rendered heading outline and identify each H1's purpose.", "Check responsive templates and product/category components for duplicated headings."],
                    final_url,
                ))
            if page_parser.empty_h1_count:
                findings.append(_finding(
                    "on_page_seo", "Internal page has empty H1 headings",
                    "manual_review_required", "low",
                    f"Found {page_parser.empty_h1_count} empty H1 element(s) among {page_parser.h1_count} H1 element(s) on {final_url}.",
                    "An empty H1 element does not communicate a useful heading. Some themes populate headings with JavaScript, which this source-only crawler does not execute, so review the rendered page before changing it.",
                    "Check whether each empty H1 is intentionally populated after rendering. Remove redundant empty elements or provide a meaningful heading when the page needs one.",
                    ["Inspect the raw HTML and rendered heading outline.", "Check whether JavaScript or responsive templates populate the heading after initial HTML."],
                    final_url,
                ))
            if page_parser.h1_count == 0:
                findings.append(_finding(
                    "on_page_seo", "Internal page missing primary heading (H1)",
                    "verified", "low",
                    f"No H1 heading was found in the returned HTML for {url}.",
                    "A primary heading helps visitors understand the page topic and gives the document a clearer semantic structure. Some themes render headings with JavaScript, which this source-only crawler does not execute.",
                    "Review the rendered page and add a meaningful main heading where appropriate. Avoid adding an H1 solely to satisfy a tool if the page already has an accessible, equivalent structure.",
                    ["Inspect the page source and rendered heading outline.", "Retest after the template change."], url,
                ))
            if page_parser.title_count > 1:
                findings.append(_finding(
                    "on_page_seo", "Internal page has multiple title elements",
                    "manual_review_required", "medium",
                    f"Found {page_parser.title_count} title elements in the returned HTML for {final_url}.",
                    "A document should have one clear, descriptive title. Multiple title elements can create ambiguity, although browsers and search engines may interpret malformed markup differently.",
                    "Review the page template and ensure it emits one intentional title element that accurately describes this page.",
                    ["Inspect all title elements in the raw HTML.", "Check the rendered document title after template changes."],
                    final_url,
                ))

            if page_parser.title_count == 0 and url != _canonical_page_url(final_home):
                findings.append(_finding(
                    "on_page_seo", "Internal page missing title element",
                    "verified", "medium",
                    f"No title element was found in the returned HTML for {final_url}.",
                    "A descriptive document title helps people identify the page in browser tabs and gives search engines a useful title signal. This source-level result may miss titles inserted after JavaScript runs.",
                    "Add one concise, page-specific title that reflects the page content and purpose. Verify the final rendered document title after any template change.",
                    ["Inspect the returned HTML and rendered document title.", "Check the page template to ensure it emits exactly one intentional title element."],
                    final_url,
                ))

            if not page_parser.title_text and page_parser.title_count > 0:
                findings.append(_finding(
                    "on_page_seo", "Internal page has an empty title element",
                    "verified", "low",
                    f"Found {page_parser.title_count} title element(s) but no readable title text in the returned HTML for {final_url}.",
                    "An empty title provides no useful document label for browser tabs, assistive technology, or search result title generation.",
                    "Add one concise, descriptive title that matches the page content and intent.",
                    ["Inspect the title element in the source.", "Confirm the final rendered document title is meaningful."],
                    final_url,
                ))
            elif not page_parser.title_text and page_parser.title_count == 0:
                findings.append(_finding(
                    "on_page_seo", "Internal page missing a title",
                    "verified", "low",
                    f"No readable title was found in the returned HTML for {url}.",
                    "A descriptive title helps people and search engines distinguish pages.",
                    "Add a unique, descriptive title that matches the page's purpose.",
                    ["Inspect the page source for the title element.", "Retest with a crawler."], url,
                ))
            if page_parser.meta_description:
                description_length = len(page_parser.meta_description.strip())
                if description_length < 50 or description_length > 160:
                    findings.append(_finding(
                        "on_page_seo", "Internal page meta description length needs review",
                        "manual_review_required", "info",
                        f"Meta description on {final_url} contains {description_length} characters.",
                        "There is no guaranteed character limit for search snippets, and search engines may generate a different snippet. Length alone does not prove that a description is poor.",
                        "Check whether the description clearly summarizes this specific page and puts useful information first. Adjust its length only when it improves usefulness and readability.",
                        ["Review the description in search-preview tools for common mobile and desktop layouts.", "Confirm that the description is page-specific and matches visible page content."],
                        final_url,
                    ))

            if page_parser.meta_description_count > 1:
                findings.append(_finding(
                    "on_page_seo", "Internal page has multiple meta descriptions",
                    "manual_review_required", "low",
                    f"Found {page_parser.meta_description_count} meta description elements in the returned HTML for {final_url}.",
                    "Multiple description elements can make it unclear which snippet is intended. Search engines may choose other page text regardless of the declared description.",
                    "Review the page template and keep one useful, page-specific meta description where it adds value.",
                    ["Inspect all meta name=description elements in the page source.", "Confirm the final template emits the intended description once."],
                    final_url,
                ))

            if page_parser.meta_description_empty_count:
                findings.append(_finding(
                    "on_page_seo", "Internal page has an empty meta description",
                    "manual_review_required", "info",
                    f"Found {page_parser.meta_description_empty_count} empty meta description element(s) on {final_url}.",
                    "An empty description provides no authored summary, though search engines may generate a snippet from page content. A separate non-empty description may still exist on the same page.",
                    "Remove empty duplicate elements or replace the intended description with a useful, page-specific summary; avoid keyword stuffing.",
                    ["Inspect each meta description element in the source.", "Check the final rendered HTML after template changes."],
                    final_url,
                ))

            if not page_parser.meta_description and page_parser.meta_description_count == 0:
                findings.append(_finding(
                    "on_page_seo", "Internal page missing meta description",
                    "verified", "info",
                    f"No meta description was found in the returned HTML for {url}.",
                    "Search engines may create their own snippets; a relevant description can help summarize the page.",
                    "Add a useful, page-specific description where appropriate.",
                    ["Inspect the page source.", "Recheck with an SEO crawler."], url,
                ))

        # Record explicit outcomes for every source-check family actually run on
        # each successfully fetched HTML page. An empty finding list is a pass only
        # for that executed source check; manual-review findings remain warnings.
        if outcome_records is not None:
            # Product detail pages need the same property-level Product/Offer
            # checks as the entry page. Keep this bounded to the product route
            # family and preserve existing phase-one outcomes for the homepage.
            try:
                is_product_page = bool(PRODUCT_DETAIL_PATH.search(urlsplit(final_url).path))
            except (ValueError, UnicodeError):
                is_product_page = False
            if is_product_page:
                detailed_structured_outcomes = record_homepage_outcomes(
                    body,
                    final_url,
                    page_headers,
                    datetime.now(timezone.utc).isoformat(),
                )
                for specialized in detailed_structured_outcomes:
                    if not specialized.check_id.startswith("structured_data."):
                        continue
                    already_recorded = any(
                        item.check_id == specialized.check_id
                        and _canonical_page_url(item.page_url) == _canonical_page_url(final_url)
                        for item in outcome_records
                    )
                    if not already_recorded:
                        outcome_records.append(specialized)

                consistency_findings, consistency_outcomes = inspect_visible_product_consistency(
                    body, final_url, datetime.now(timezone.utc).isoformat()
                )
                findings.extend(consistency_findings)
                outcome_records.extend(consistency_outcomes)

            page_check_families = (
                ("security.headers_and_forms", "security", "HTTP security headers and sensitive GET-form source inspection"),
                ("mobile_ux.viewport", "mobile_ux", "Mobile viewport source inspection"),
                ("performance.static_signals", "performance", "Static HTML performance signal inspection"),
                ("accessibility.static_signals", "accessibility", "Static HTML accessibility signal inspection"),
                ("aria_alt_text.images", "aria_alt_text", "Image alternative-text source inspection"),
                ("trust.signals", "trust", "Trust signal source inspection"),
                ("pixel_analytics.consent_signals", "pixel_analytics", "Tracking and consent source signal inspection"),
                ("on_page_seo.metadata", "on_page_seo", "Page title and meta description source inspection"),
                ("structured_data.product", "structured_data", "Product structured-data source inspection"),
                ("ecommerce_catalog.navigation", "ecommerce_catalog", "Product and catalog navigation source inspection"),
            )
            page_findings = findings[page_findings_start:]
            for check_id, category, method in page_check_families:
                matching = [item for item in page_findings if item.category == category]
                if check_id == "structured_data.product":
                    try:
                        if not PRODUCT_DETAIL_PATH.search(urlsplit(final_url).path):
                            continue
                    except (ValueError, UnicodeError):
                        continue
                if check_id == "ecommerce_catalog.navigation":
                    try:
                        catalog_path = urlsplit(final_url).path.lower()
                        catalog_segments = {segment for segment in catalog_path.split("/") if segment}
                        if not (
                            PRODUCT_DETAIL_PATH.search(catalog_path)
                            or catalog_segments.intersection({"collections", "collection", "category", "categories", "catalog", "shop"})
                        ):
                            continue
                    except (ValueError, UnicodeError):
                        continue
                if check_id == "international_seo.hreflang" and not hreflang_declared:
                    continue
                if any(getattr(item, "status", "") == "not_tested" for item in matching):
                    outcome = "not_assessed"
                else:
                    # A few checks emit a positive "detected" observation as a
                    # verified finding. Do not invert that evidence into a failure.
                    actionable_verified = [
                        item for item in matching
                        if getattr(item, "status", "") == "verified"
                        and not (
                            check_id == "structured_data.product"
                            and "structured data detected" in str(getattr(item, "title", "")).lower()
                            and "not detected" not in str(getattr(item, "title", "")).lower()
                        )
                        and not (
                            check_id == "trust.signals"
                            and str(getattr(item, "title", "")).lower().startswith("trust signal detected")
                        )
                    ]
                    if actionable_verified:
                        outcome = "issue"
                    elif matching:
                        outcome = "warning"
                    else:
                        outcome = "pass"
                # Some specialized checks (for example Product JSON-LD) record
                # richer outcomes earlier in the page pass. Do not append a second
                # generic family outcome for the same check and canonical page.
                if any(
                    item.check_id == check_id
                    and _canonical_page_url(item.page_url) == _canonical_page_url(final_url)
                    for item in outcome_records
                ):
                    continue
                outcome_records.append(CheckOutcome(
                    check_id=check_id,
                    category=category,
                    page_url=final_url,
                    outcome=outcome,
                    observed_at_utc=datetime.now(timezone.utc).isoformat(),
                    method=method + "; bounded initial-HTML inspection only",
                    evidence=(
                        f"{len(matching)} related finding(s) recorded on this page."
                        if matching else
                        "This source-check family ran on the returned HTML and produced no finding; this does not imply rendered-browser or full-site coverage."
                    ),
                    evidence_ref=check_id,
                ))

        for title, urls in title_pages.items():
            if len(urls) > 1:
                findings.append(_finding(
                    "duplicate_content", "Duplicate page title detected",
                    "verified", "low",
                    f"The same normalized title appears on {len(urls)} inspected URLs: " + ", ".join(urls[:6]),
                    "Repeated titles can make pages harder to distinguish in search results; whether this is harmful depends on page purpose.",
                    "Write distinct titles for pages with different purposes and keep genuinely equivalent variants consistent.",
                    ["Compare the listed pages in a crawler.", "Retest titles after changes."], urls[0],
                ))
        for description, urls in description_pages.items():
            if len(urls) > 1:
                findings.append(_finding(
                    "duplicate_content", "Duplicate meta description detected",
                    "verified", "info",
                    f"The same normalized meta description appears on {len(urls)} inspected URLs: " + ", ".join(urls[:6]),
                    "Repeated descriptions may not summarize individual pages well. Search engines can choose different snippets.",
                    "Use page-specific descriptions where they provide useful information; do not change them solely to force a ranking result.",
                    ["Compare the listed pages in a crawler.", "Retest after changes."], urls[0],
                ))
        if outcome_records is not None:
            duplicate_content_findings = [
                item for item in findings if item.category == "duplicate_content"
            ]
            if pages_checked:
                _record_static_check_outcome(
                    outcome_records, check_id="content_quality.duplicate_metadata",
                    category="content_quality", page_url=normalized,
                    findings=duplicate_content_findings,
                    method="cross-page comparison of normalized HTML title and meta-description values within the bounded crawl sample",
                )
            else:
                outcome_records.append(CheckOutcome(
                    check_id="content_quality.duplicate_metadata",
                    category="content_quality", page_url=normalized,
                    outcome="not_assessed",
                    observed_at_utc=datetime.now(timezone.utc).isoformat(),
                    method="bounded cross-page title and meta-description comparison",
                    evidence="No pages were successfully fetched; duplicate metadata could not be compared.",
                    evidence_ref="content_quality.duplicate_metadata",
                ))

    if len(candidates) >= MAX_CRAWL_PAGES - 1:
        limitations.append(f"The crawler reached its {MAX_CRAWL_PAGES}-page budget; additional links were not inspected.")
    # Make sitemap coverage limits explicit. Discovery is not equivalent to
    # fetching every sitemap URL: the shared page budget may only sample them.
    checked_keys = {_canonical_page_url(value) for value in pages_checked}
    discovered_sitemap_keys = {
        _canonical_page_url(value)
        for value in sitemap_urls
        if isinstance(value, str) and value
    }
    unchecked_sitemap_count = len(discovered_sitemap_keys - checked_keys)
    if unchecked_sitemap_count:
        limitations.append(
            f"{unchecked_sitemap_count} discovered sitemap URL(s) were not fetched during this audit because sitemap discovery shares the bounded crawl page budget; sitemap inclusion alone does not establish URL status, canonical consistency, or indexability."
        )
    if parameterized_url_signatures:
        kinds = ", ".join(sorted(parameterized_parameter_kinds))
        names = ", ".join(sorted(parameterized_parameter_names)[:20])
        findings.append(_finding(
            "ecommerce_catalog",
            "Parameterized internal catalog URLs detected",
            "manual_review_required",
            "low",
            f"Observed {len(parameterized_url_signatures)} unique same-origin internal URL pattern(s) with recognized ecommerce query parameters in the bounded link sample. Parameter classes: {kinds or 'not classified'}. Parameter names: {names or 'not available'}. Query values were omitted; query variants were normalized away from crawl keys and were not fetched as separate pages.",
            "Variant, pagination, sorting, search, and faceted-filter parameters can represent useful catalog states or create duplicate crawl paths. Their presence alone does not prove duplicate indexing, crawl-budget waste, or an incorrect canonical strategy.",
            "Review representative parameterized product and category URLs. Confirm that pagination and variants expose the intended products, filtered/sorted states have an intentional canonical or noindex strategy, and important products remain reachable through ordinary links.",
            ["Inspect representative URLs using the listed parameter names without sharing session or tracking values.", "Compare visible product sets and canonical/noindex directives for the base and parameterized states.", "Confirm pagination changes the product set and that variant URLs identify the intended variant."],
            normalized,
        ))
        limitations.append(
            "Parameterized ecommerce URL signals come from the bounded same-origin link sample. Query values were omitted and query variants were not fetched as separate crawl pages."
        )
    if outcome_records is not None:
        catalog_page_sampled = any(
            PRODUCT_DETAIL_PATH.search(urlsplit(page_url).path)
            or re.search(r"(?:^|/)(?:collections?|categories?|category|catalog|shop)(?:/|$)", urlsplit(page_url).path, re.I)
            for page_url in pages_checked
        )
        if parameterized_url_signatures:
            query_outcome = "warning"
            query_evidence = (
                f"Unique recognized parameterized URL patterns: {len(parameterized_url_signatures)}; "
                f"parameter classes: {', '.join(sorted(parameterized_parameter_kinds)) or 'none detected'}; "
                f"parameter names: {', '.join(sorted(parameterized_parameter_names)[:20]) or 'none detected'}. "
                "Query values are intentionally omitted; absence in this bounded sample does not prove the site has no parameterized URLs."
            )
        elif catalog_page_sampled:
            query_outcome = "pass"
            query_evidence = (
                "No recognized variant, filter, pagination, sorting or search query patterns were found in the bounded internal-link sample for inspected catalog pages. "
                "Query values are intentionally omitted; absence in this sample does not prove the site has no parameterized URLs."
            )
        else:
            query_outcome = "not_assessed"
            query_evidence = (
                "No product, category, collection, catalog or search page was identified in the fetched sample; "
                "parameterized catalog URL behavior was not assessed."
            )
        outcome_records.append(CheckOutcome(
            check_id="ecommerce_catalog.parameterized_internal_urls",
            category="ecommerce_catalog",
            page_url=normalized,
            outcome=query_outcome,
            observed_at_utc=datetime.now(timezone.utc).isoformat(),
            method="bounded same-origin internal-link query-parameter inventory",
            evidence=query_evidence,
            evidence_ref="ecommerce_catalog.parameterized_internal_urls",
        ))

    # The link-response category is assessed only for the bounded same-origin
    # pages that were actually fetched. Never infer a pass when the homepage
    # could not be fetched or the crawler produced no page denominator.
    if outcome_records is not None:
        broken_link_findings = [
            item for item in findings if item.category == "broken_internal_links"
        ]
        if pages_checked:
            _record_static_check_outcome(
                outcome_records, check_id="broken_internal_links.sampled_internal_urls",
                category="broken_internal_links", page_url=normalized,
                findings=broken_link_findings,
                method=f"HTTP response inspection for up to {MAX_CRAWL_PAGES - 1} sampled same-origin internal URLs",
            )
        else:
            outcome_records.append(CheckOutcome(
                check_id="broken_internal_links.sampled_internal_urls",
                category="broken_internal_links", page_url=normalized,
                outcome="not_assessed",
                observed_at_utc=datetime.now(timezone.utc).isoformat(),
                method="bounded same-origin URL response inspection",
                evidence="No page was successfully fetched; internal-link response health cannot be assessed.",
                evidence_ref="broken_internal_links.sampled_internal_urls",
            ))
    return findings, pages_checked, limitations
