"""Bounded same-origin crawl for public ecommerce pages.

This is a conservative first-hop crawler: it follows only HTML links found on the
homepage, stays on the same origin, and enforces a fixed page budget.
"""
from __future__ import annotations

from collections import defaultdict
from html.parser import HTMLParser
from defusedxml import ElementTree as ET
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit

import aiohttp
import json
import re

from performance_checks import inspect_static_performance_signals
from accessibility_checks import inspect_static_accessibility_signals
from mobile_ux_checks import inspect_mobile_viewport

from security_checks import (
    probe_common_exposure_paths,
    inspect_transport_security,
    inspect_security_header_quality,
    inspect_standard_security_headers,
)
from dependency_checks import inspect_client_dependency_versions

from audit_checks import (
    REQUEST_TIMEOUT_SECONDS,
    USER_AGENT,
    AuditFinding,
    PublicOnlyResolver,
    _finding,
    _safe_get,
    normalize_target,
    _PageParser,
)


MAX_CRAWL_PAGES = 12
MAX_LINKS_FROM_HOME = 100
MAX_URLS_FROM_SITEMAP = 100
MAX_CHILD_SITEMAPS = 3

PRODUCT_DETAIL_PATH = re.compile(r"(?:^|/)(?:products?|items?)(?:/|$)", re.I)


class _SensitiveGetFormParser(HTMLParser):
    """Find GET forms that appear to submit credentials or payment-related fields."""
    SENSITIVE_NAMES = re.compile(
        r"(?:pass(?:word)?|secret|token|credit.?card|card.?number|cc.?num|cvv|cvc|"
        r"security.?code|payment|billing.?address|bank.?account|routing.?number)",
        re.I,
    )
    SENSITIVE_TYPES = {"password"}
    SENSITIVE_AUTOCOMPLETE = {
        "current-password", "new-password", "cc-number", "cc-csc",
        "cc-exp", "cc-exp-month", "cc-exp-year", "transaction-amount",
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
            "structured_data", "Likely product page has no detectable Product JSON-LD",
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
        return contains_product(value.get("@graph", []))

    for script in parser.jsonld_scripts:
        try:
            payload = json.loads(script)
        except (json.JSONDecodeError, TypeError):
            malformed = True
            continue
        if contains_product(payload):
            found_product = True
            break

    if found_product or malformed:
        return []
    return [_finding(
        "structured_data", "Likely product page has no detectable Product JSON-LD",
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
            if (target_scheme, target_host, target_port) != (page_scheme, page_host, page_port):
                # Cross-origin canonicals can be intentional, but deserve review
                # because they consolidate indexing signals onto another origin.
                findings.append(_finding(
                    "indexability", "Canonical target points to a different origin",
                    "manual_review_required", "medium",
                    f"The canonical declaration on {page_url} points to a different origin ({target_scheme}://{target_host}); this source check does not fetch or validate the destination.",
                    "Cross-origin canonicals may be appropriate for syndicated or deliberately consolidated content, but an unintended host, scheme, or port can direct search engines to prefer a different URL.",
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
        try:
            resolved = urljoin(final_url, href) if href else ""
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
            pass
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
                or parts.username is not None
                or parts.password is not None
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


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        values = {key.lower(): value or "" for key, value in attrs}
        href = values.get("href", "").strip()
        if href:
            self.links.append(href)




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


async def run_bounded_site_crawl(target: str) -> tuple[list[AuditFinding], list[str], list[str]]:
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
        "Sitemap discovery uses the first usable same-origin Sitemap directive in robots.txt, falling back to /sitemap.xml; indexes expand one level into at most 3 same-origin child sitemaps and at most 100 page URLs. Additional declared sitemap locations and deeper nesting are not fully explored.",
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
                return findings, pages_checked, limitations
            if "text/html" not in headers.get("content-type", "").lower():
                return findings, pages_checked, limitations
            dependency_findings, dependency_limitations = await inspect_client_dependency_versions(
                homepage, final_home
            )
            findings.extend(dependency_findings)
            limitations.extend(dependency_limitations)
        except Exception as exc:
            return findings, pages_checked, limitations + [
                f"Bounded crawl could not fetch the homepage: {type(exc).__name__}."
            ]

        # Inspect robots.txt as a discovery/indexing signal. It is fetched through
        # the same public-only resolver and redirect/response-size safeguards.
        robots_sitemap_urls: list[str] = []
        robots_declared_sitemap_urls: list[str] = []
        robots_url = urljoin(f"{urlsplit(final_home).scheme}://{urlsplit(final_home).netloc}/", "robots.txt")
        try:
            robots_status, robots_body, robots_headers, robots_final_url = await _safe_get(client, robots_url)
            if 200 <= robots_status < 300 and _same_origin(robots_final_url, final_home):
                robots_findings, robots_limitations = inspect_robots_txt(robots_body, robots_final_url)
                findings.extend(robots_findings)
                limitations.extend(robots_limitations)
                # Sitemap directives may point to a nonstandard path. Accept only
                # bounded, credential-free HTTP(S) URLs on the audited origin; the
                # same-origin requirement keeps this discovery step from becoming
                # an arbitrary URL fetch mechanism.
                for raw_line in robots_body.splitlines()[:5000]:
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
            elif robots_status in {401, 403}:
                limitations.append("robots.txt could not be inspected because the server returned an access-denied response.")
            elif robots_status >= 500:
                limitations.append(f"robots.txt could not be inspected because the server returned HTTP {robots_status}.")
        except Exception as exc:
            limitations.append(f"robots.txt inspection was inconclusive ({type(exc).__name__}).")

        link_parser = _LinkParser()
        link_parser.feed(homepage)
        candidates: list[str] = []
        seen: set[str] = set()
        final_origin = urlsplit(final_home)

        # Use the conventional sitemap as a secondary discovery source. A sitemap
        # index is expanded only one level, with a strict child-sitemap and URL cap.
        # Every child sitemap must remain on the audited origin before it is fetched.
        sitemap_urls: list[str] = []
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
        same_origin_sitemaps = [
            value for value in robots_sitemap_urls
            if _same_origin_http_url(value, final_home)
        ]
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

        def _loc_values(root):
            return [
                element.text.strip()
                for element in root.iter()
                if element.tag.rsplit("}", 1)[-1].lower() == "loc" and element.text and element.text.strip()
            ]

        try:
            sitemap_status, sitemap_body, sitemap_headers, sitemap_final_url = await _safe_get(client, sitemap_url)
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
                                rejected_child_sitemaps.append(safe_target_label(child_loc))
                                continue
                            normalized_child = _canonical_page_url(resolved_child)
                        except (ValueError, UnicodeError):
                            rejected_child_sitemaps.append(safe_target_label(child_loc))
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
                        try:
                            child_status, child_body, child_headers, child_final_url = await _safe_get(client, child_sitemap_url)
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
            try:
                extra_status, extra_body, extra_headers, extra_final_url = await _safe_get(
                    client, extra_sitemap_url
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
                    limitations.append(
                        f"Additional sitemap index {extra_sitemap_url} was validated but its child sitemaps were not expanded."
                    )
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
                absolute = urljoin(final_home, href)
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
                candidate = _canonical_page_url(absolute)
                if candidate in seen or candidate == _canonical_page_url(final_home):
                    continue
                suffix = urlsplit(candidate).path.lower()
            except (ValueError, UnicodeError):
                continue
            if suffix.endswith((".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".pdf",
                                 ".css", ".js", ".woff", ".woff2", ".zip", ".xml")):
                continue
            seen.add(candidate)
            candidates.append(candidate)
            if len(candidates) >= MAX_CRAWL_PAGES - 1:
                break

        # A small fixed set of safe GET probes looks for recognizable exposed artifacts.
        # The public-only resolver, redirect validation, timeout and response cap still apply.
        exposure_findings, exposure_limitations = await probe_common_exposure_paths(client, final_home)
        findings.extend(exposure_findings)
        limitations.extend(exposure_limitations)

        transport_findings, transport_limitations = await inspect_transport_security(
            client, homepage, final_home
        )
        findings.extend(transport_findings)
        limitations.extend(transport_limitations)

        title_pages: dict[str, list[str]] = defaultdict(list)
        description_pages: dict[str, list[str]] = defaultdict(list)
        # Keep the initial homepage/sitemap discoveries, then append newly found
        # same-origin links as pages are inspected. Python's list iterator observes
        # appended entries, providing bounded breadth-first traversal without an
        # unbounded queue or a second crawler implementation.
        crawl_queue = [_canonical_page_url(final_home), *candidates]
        queued_urls = set(crawl_queue)
        for url in crawl_queue:
            try:
                # Reuse the homepage response already fetched for link discovery.
                # This avoids spending a second request on the same page and keeps
                # the recorded homepage evidence consistent within this audit run.
                if url == _canonical_page_url(final_home):
                    page_status, body, page_headers, final_url = status, homepage, headers, final_home
                else:
                    page_status, body, page_headers, final_url = await _safe_get(client, url)
            except Exception as exc:
                findings.append(_finding(
                    "crawl", "Internal page could not be checked", "not_tested", "info",
                    f"Could not fetch {url}: {type(exc).__name__}.",
                    "The page could not be checked reliably; this is not proof the URL is broken.",
                    "Open the URL in a browser and check server, DNS, TLS, and access restrictions.",
                    ["Retry the URL with a browser and an HTTP status checker."], url,
                ))
                continue

            if url not in pages_checked:
                pages_checked.append(url)
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

            page_parser = _PageParser()
            page_parser.feed(body)

            # Expand only from successfully fetched HTML pages, with a strict
            # per-page link cap, total page cap, same-origin enforcement, and
            # canonical URL keys that discard fragments/tracking query variants.
            if len(crawl_queue) < MAX_CRAWL_PAGES:
                discovered_links = _LinkParser()
                discovered_links.feed(body)
                for href in discovered_links.links[:MAX_LINKS_FROM_HOME]:
                    if len(crawl_queue) >= MAX_CRAWL_PAGES:
                        break
                    try:
                        absolute = urljoin(final_url, href)
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
                        if candidate_url in queued_urls:
                            continue
                        path = urlsplit(candidate_url).path.lower()
                        if path.endswith((
                            ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg",
                            ".pdf", ".css", ".js", ".woff", ".woff2", ".zip", ".xml",
                        )):
                            continue
                        queued_urls.add(candidate_url)
                        crawl_queue.append(candidate_url)
                    except (ValueError, UnicodeError):
                        # A malformed link must not stop inspection of other links.
                        continue

            findings.extend(inspect_product_page_schema_presence(body, final_url))
            findings.extend(inspect_sensitive_get_forms(body, final_url))
            findings.extend(inspect_canonical_declaration(body, final_url))

            # Run the existing header/cookie review on every sampled HTML page.
            # These are configuration review signals, not automatic vulnerability claims.
            findings.extend(inspect_security_header_quality(page_headers, final_url))
            findings.extend(inspect_standard_security_headers(page_headers, final_url))

            findings.extend(inspect_hreflang(body, final_url))
            findings.extend(inspect_meta_refresh(body, final_url))
            findings.extend(inspect_mobile_viewport(body, final_url))

            # Static resource patterns are review signals, not measured Core Web Vitals.
            findings.extend(inspect_static_performance_signals(body, final_url))
            # Source-level accessibility signals are review prompts, not a WCAG verdict.
            findings.extend(inspect_static_accessibility_signals(body, final_url))

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

    if len(candidates) >= MAX_CRAWL_PAGES - 1:
        limitations.append(f"The crawler reached its {MAX_CRAWL_PAGES}-page budget; additional links were not inspected.")
    return findings, pages_checked, limitations
