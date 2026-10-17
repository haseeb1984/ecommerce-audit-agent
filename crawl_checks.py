"""Bounded same-origin crawl for public ecommerce pages.

This is a conservative first-hop crawler: it follows only HTML links found on the
homepage, stays on the same origin, and enforces a fixed page budget.
"""
from __future__ import annotations

from collections import defaultdict
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit

import aiohttp

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
        for href in link_parser.links[:MAX_LINKS_FROM_HOME]:
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

            # A canonical tag is a search-engine hint. Flag an off-origin target
            # for human review rather than assuming it is wrong in every setup.
            if page_parser.canonical_href:
                canonical_url = urljoin(final_url, page_parser.canonical_href)
                canonical_parts = urlsplit(canonical_url)
                final_parts = urlsplit(final_url)
                if (canonical_parts.scheme.lower() not in {"http", "https"}
                        or not canonical_parts.hostname
                        or canonical_parts.scheme.lower() != final_parts.scheme.lower()
                        or canonical_parts.netloc.lower() != final_parts.netloc.lower()):
                    findings.append(_finding(
                        "technical_seo", "Canonical URL points outside this page origin",
                        "manual_review_required", "medium",
                        f"Page {final_url} declares canonical href={page_parser.canonical_href!r}, resolving to {canonical_url}.",
                        "A canonical tag tells search engines which URL should represent similar or duplicate content. An off-origin canonical may be intentional for syndicated content, but can also divert indexing signals away from this store.",
                        "Confirm that the canonical destination is intentional, controlled, indexable, and the preferred version of this page. Do not change it without checking duplicate and platform routing behavior.",
                        ["Inspect the canonical element in page source.", "Compare the declared canonical with the preferred URL and the destination response."],
                        final_url,
                    ))

            robots_tokens = {
                token.strip().lower()
                for token in page_parser.meta_robots.replace(";", ",").replace(" ", ",").split(",")
                if token.strip()
            }
            if "noindex" in robots_tokens or "none" in robots_tokens:
                findings.append(_finding(
                    "indexability", "Page contains a noindex directive",
                    "verified", "medium",
                    f"Page {final_url} has meta robots content={page_parser.meta_robots!r}.",
                    "The directive asks compliant search crawlers not to index this page. That may be correct for private, duplicate, cart, or account pages, but can be a problem on product or category pages intended to appear in search.",
                    "Confirm this page should be excluded from search. If it should be indexed, remove the unintended noindex directive and verify the response headers do not also send X-Robots-Tag: noindex.",
                    ["Inspect the page source and response headers.", "Check the URL's indexing status in the site owner's search console."],
                    final_url,
                ))

            if page_parser.title_text:
                title_pages[page_parser.title_text.strip().casefold()].append(url)
            if page_parser.meta_description:
                description_pages[page_parser.meta_description.strip().casefold()].append(url)
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
