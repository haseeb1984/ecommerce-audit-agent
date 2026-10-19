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

from security_checks import probe_common_exposure_paths, inspect_transport_security

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
            invalid_targets.append(href or "(missing href)")

    if invalid_language_tags or invalid_targets or duplicate_languages:
        details = []
        if invalid_language_tags:
            details.append("language tag(s): " + ", ".join(sorted(set(invalid_language_tags))[:8]))
        if invalid_targets:
            details.append("target URL issue(s): " + ", ".join(sorted(set(invalid_targets))[:8]))
        if duplicate_languages:
            details.append("duplicate language tag(s): " + ", ".join(sorted(duplicate_languages)[:8]))
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
    parts = urlsplit(urldefrag(url)[0])
    # Avoid multiplying the crawl through tracking and filter query parameters.
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", "", ""))


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
        f"First-hop crawl is capped at {MAX_CRAWL_PAGES} URLs and does not recursively crawl all site pages.",
        "Query-string variants, JavaScript-rendered links, authenticated pages, and form/checkout flows are not crawled.",
        "Only the conventional /sitemap.xml URL set is sampled for discovery; sitemap indexes and alternate sitemap locations are not expanded.",
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
        except Exception as exc:
            return findings, pages_checked, limitations + [
                f"Bounded crawl could not fetch the homepage: {type(exc).__name__}."
            ]

        link_parser = _LinkParser()
        link_parser.feed(homepage)
        candidates: list[str] = []
        seen: set[str] = set()
        final_origin = urlsplit(final_home)

        # Use a conventional sitemap as a secondary discovery source. Parsing is
        # bounded and only same-origin URLs are considered below; sitemap-index
        # expansion is deliberately excluded to keep the request budget predictable.
        sitemap_urls: list[str] = []
        sitemap_url = urljoin(f"{final_origin.scheme}://{final_origin.netloc}/", "sitemap.xml")
        try:
            sitemap_status, sitemap_body, sitemap_headers, _ = await _safe_get(client, sitemap_url)
            if 200 <= sitemap_status < 300 and (
                "xml" in sitemap_headers.get("content-type", "").lower()
                or sitemap_body.lstrip().startswith("<")
            ):
                root = ET.fromstring(sitemap_body)
                if root.tag.rsplit("}", 1)[-1].lower() == "urlset":
                    for element in root.iter():
                        if element.tag.rsplit("}", 1)[-1].lower() == "loc" and element.text:
                            sitemap_urls.append(element.text.strip())
                            if len(sitemap_urls) >= MAX_URLS_FROM_SITEMAP:
                                break
        except (Exception):
            # The main audit reports sitemap availability/format separately.
            # Failure here only means sitemap-based URL discovery is unavailable.
            pass

        discovery_hrefs = [
            *link_parser.links[:MAX_LINKS_FROM_HOME],
            *sitemap_urls,
        ]
        for href in discovery_hrefs:
            absolute = urljoin(final_home, href)
            parts = urlsplit(absolute)
            if parts.scheme not in {"http", "https"} or not parts.hostname:
                continue
            if parts.username or parts.password:
                continue
            if parts.scheme.lower() != final_origin.scheme.lower() or parts.netloc.lower() != final_origin.netloc.lower():
                continue
            candidate = _canonical_page_url(absolute)
            if candidate in seen or candidate == _canonical_page_url(final_home):
                continue
            suffix = urlsplit(candidate).path.lower()
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
        for url in [_canonical_page_url(final_home), *candidates]:
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

            # Source-level trust cues are not proof of authenticity or usability.
            from trust_checks import inspect_trust_signals
            findings.extend(inspect_trust_signals(body, final_url))

            # Hreflang is checked only when the site declares localized alternates.
            findings.extend(inspect_hreflang(body, final_url))

            # Source-level viewport signals; this does not measure rendered responsiveness.
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
                findings.append(_finding(
                    "indexability", "Page contains a noindex directive",
                    "verified", "medium",
                    f"Page {final_url} declares " + " and ".join(sources) + ".",
                    "A noindex directive in HTML or an HTTP response header asks compliant search crawlers not to index this page. That may be correct for private, duplicate, cart, or account pages, but can be a problem on product or category pages intended to appear in search.",
                    "Confirm this page should be excluded from search. If it should be indexed, remove the unintended noindex directive from the relevant HTML or response header and recheck the final response.",
                    ["Inspect the page source and final response headers.", "Check the URL's indexing status in the site owner's search console."],
                    final_url,
                ))

            if page_parser.title_text:
                title_pages[page_parser.title_text.strip().casefold()].append(url)
            if page_parser.meta_description:
                description_pages[page_parser.meta_description.strip().casefold()].append(url)
            if page_parser.h1_count == 0:
                findings.append(_finding(
                    "on_page_seo", "Internal page missing primary heading (H1)",
                    "verified", "low",
                    f"No H1 heading was found in the returned HTML for {url}.",
                    "A primary heading helps visitors understand the page topic and gives the document a clearer semantic structure. Some themes render headings with JavaScript, which this source-only crawler does not execute.",
                    "Review the rendered page and add a meaningful main heading where appropriate. Avoid adding an H1 solely to satisfy a tool if the page already has an accessible, equivalent structure.",
                    ["Inspect the page source and rendered heading outline.", "Retest after the template change."], url,
                ))
            if not page_parser.title_text:
                findings.append(_finding(
                    "on_page_seo", "Internal page missing a title",
                    "verified", "low",
                    f"No readable title was found in the returned HTML for {url}.",
                    "A descriptive title helps people and search engines distinguish pages.",
                    "Add a unique, descriptive title that matches the page's purpose.",
                    ["Inspect the page source for the title element.", "Retest with a crawler."], url,
                ))
            if not page_parser.meta_description:
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
