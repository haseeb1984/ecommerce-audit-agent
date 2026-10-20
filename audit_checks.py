"""Evidence-first, bounded public website checks for the ecommerce audit engine.

This module intentionally does not claim a full security, accessibility, or SEO audit.
It performs conservative public-page checks and reports limitations explicitly.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import aiohttp
from pydantic import BaseModel, Field


MAX_RESPONSE_BYTES = 1_000_000
MAX_REDIRECTS = 5
REQUEST_TIMEOUT_SECONDS = 10.0
USER_AGENT = "EcommerceAuditBot/1.0 (+https://junctiontools.com)"


class AuditFinding(BaseModel):
    category: str
    title: str
    status: str  # verified, manual_review_required, not_tested, insufficient_data
    severity: str  # critical, high, medium, low, info
    evidence: str
    explanation: str
    recommendation: str
    verification_steps: list[str] = Field(default_factory=list)
    source_url: str | None = None
    # Optional, evidence-backed business context. Never inferred by the renderer.
    potential_benefit: str | None = None
    risk_if_unresolved: str | None = None


class AuditCheckResult(BaseModel):
    target_url: str
    checked_at_utc: str
    findings: list[AuditFinding] = Field(default_factory=list)
    pages_checked: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


def normalize_target(value: str) -> str:
    """Normalize an input to an HTTP(S) origin URL, rejecting URL tricks."""
    raw = (value or "").strip()
    if not raw or len(raw) > 2048:
        raise ValueError("Provide a website URL or domain no longer than 2048 characters.")
    if any(ord(char) < 32 for char in raw) or "\\" in raw:
        raise ValueError("The website URL contains invalid characters.")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlsplit(raw)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only public HTTP and HTTPS websites can be audited.")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("The website URL must contain a hostname and no embedded credentials.")
    if parsed.port not in (None, 80, 443):
        raise ValueError("Non-standard ports are not supported by this public audit.")
    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        raise ValueError("Local and private network hosts cannot be audited.")
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        ip = None
    if ip is not None and (not ip.is_global):
        raise ValueError("Private, loopback, link-local, and reserved IP addresses are blocked.")
    # Browsers and some URL parsers interpret shortened, integer, octal, or hex
    # IPv4 spellings as IP addresses. Do not let those forms pass as DNS names.
    if ip is None and (
        re.fullmatch(r"[0-9.]+", host)
        or re.fullmatch(r"0x[0-9a-f]+", host)
    ):
        raise ValueError("Ambiguous numeric IP hostnames are not supported.")
    netloc = host
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]"
    port = parsed.port
    if port and not ((parsed.scheme.lower() == "https" and port == 443) or
                     (parsed.scheme.lower() == "http" and port == 80)):
        netloc = f"{netloc}:{port}"
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))


class PublicOnlyResolver(aiohttp.abc.AbstractResolver):
    """Resolve DNS once, validate every address, and return those exact IPs to aiohttp.

    This pins the connection to the checked DNS answer, preventing a second DNS lookup
    between preflight validation and TCP connection (a common DNS-rebinding gap).
    """
    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_UNSPEC):
        try:
            literal = ipaddress.ip_address(host.strip("[]"))
            addresses = [literal]
        except ValueError:
            loop = asyncio.get_running_loop()
            try:
                records = await loop.getaddrinfo(
                    host, port, family=family, type=socket.SOCK_STREAM
                )
            except OSError as exc:
                raise OSError(f"Could not resolve target host: {host}") from exc
            addresses = []
            seen = set()
            for record in records:
                address = ipaddress.ip_address(record[4][0])
                if address not in seen:
                    seen.add(address)
                    addresses.append(address)

        if not addresses or any(not address.is_global for address in addresses):
            raise OSError("Target host resolves to a private or non-public IP address.")

        return [
            {
                "hostname": host,
                "host": str(address),
                "port": port,
                "family": socket.AF_INET6 if address.version == 6 else socket.AF_INET,
                "proto": 0,
                "flags": 0,
            }
            for address in addresses
        ]

    async def close(self) -> None:
        return None


async def _resolve_public_host(host: str) -> None:
    """Compatibility helper that applies the same public-only DNS policy."""
    await PublicOnlyResolver().resolve(host, 443, socket.AF_UNSPEC)


async def _safe_get(client: aiohttp.ClientSession, url: str) -> tuple[int, str, dict[str, str], str]:
    """Fetch a public URL with pinned public DNS answers, bounded bytes, and safe redirects."""
    current = normalize_target(url)
    for redirect_count in range(MAX_REDIRECTS + 1):
        async with client.get(current, allow_redirects=False) as response:
            headers = {key.lower(): value for key, value in response.headers.items()}
            # X-Robots-Tag may be sent in multiple header fields. A dict
            # comprehension keeps only one duplicate key, which could discard a
            # noindex directive and incorrectly imply that the page is indexable.
            # Preserve duplicate directive/cookie headers that are meaningful
            # to downstream checks; a plain dict comprehension collapses duplicates.
            for header_name in ("X-Robots-Tag", "Set-Cookie"):
                try:
                    values = response.headers.getall(header_name, [])
                except (AttributeError, KeyError):
                    values = []
                if values:
                    headers[header_name.lower()] = ", ".join(str(value) for value in values)
            if response.status in {301, 302, 303, 307, 308}:
                location = headers.get("location")
                if not location:
                    return response.status, "", headers, current
                if redirect_count >= MAX_REDIRECTS:
                    raise ValueError("The website exceeded the redirect limit.")
                current = normalize_target(urljoin(current, location))
                continue
            content_length = headers.get("content-length")
            if content_length is not None:
                # Reject malformed or negative lengths instead of silently ignoring them.
                # The streamed byte counter below remains authoritative if the header lies.
                try:
                    declared_length = int(content_length.strip())
                except (TypeError, ValueError) as exc:
                    raise ValueError("Response included an invalid Content-Length header.") from exc
                if declared_length < 0:
                    raise ValueError("Response included an invalid Content-Length header.")
                if declared_length > MAX_RESPONSE_BYTES:
                    raise ValueError("Response exceeded the audit's 1 MB size limit.")
            chunks: list[bytes] = []
            size = 0
            async for chunk in response.content.iter_chunked(65536):
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise ValueError("Response exceeded the audit's 1 MB size limit.")
                chunks.append(chunk)
            body = b"".join(chunks).decode(response.charset or "utf-8", errors="replace")
            return response.status, body, headers, current
    raise ValueError("The website exceeded the redirect limit.")


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_text = ""
        self.title_count = 0
        self._in_title = False
        self.meta_description = ""
        self.meta_description_count = 0
        self.meta_description_empty_count = 0
        self.viewport = ""
        self.meta_robots = ""
        self.meta_robots_count = 0
        self.canonical_href = ""
        self.canonical_count = 0
        self.canonical_missing_href_count = 0
        self.h1_count = 0
        self.h1_text = ""
        self._in_h1 = False
        self.images = 0
        self.images_missing_alt = 0
        self.links = 0
        self._title_parts: list[str] = []
        self._h1_parts: list[str] = []
        self.jsonld_scripts: list[str] = []
        self._in_jsonld_script = False
        self._jsonld_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag == "title":
            self.title_count += 1
            self._in_title = True
        elif tag == "script":
            script_type = values.get("type", "").split(";", 1)[0].strip().lower()
            if script_type == "application/ld+json":
                self._in_jsonld_script = True
                self._jsonld_parts = []
        elif tag == "meta":
            name = values.get("name", "").strip().lower()
            if name == "description":
                self.meta_description_count += 1
                description = values.get("content", "").strip()
                if not description:
                    self.meta_description_empty_count += 1
                elif not self.meta_description:
                    self.meta_description = description
            elif name == "viewport":
                self.viewport = values.get("content", "").strip()
            elif name == "robots":
                robots_content = values.get("content", "").strip()
                self.meta_robots_count += 1
                if robots_content:
                    self.meta_robots = (
                        f"{self.meta_robots}, {robots_content}"
                        if self.meta_robots else robots_content
                    )
        elif tag == "link":
            rel_tokens = values.get("rel", "").strip().lower().split()
            if "canonical" in rel_tokens:
                self.canonical_count += 1
                href = values.get("href", "").strip()
                if not href:
                    self.canonical_missing_href_count += 1
                elif not self.canonical_href:
                    self.canonical_href = href
        elif tag == "h1":
            self.h1_count += 1
            self._in_h1 = True
            self._h1_parts = []
        elif tag == "img":
            self.images += 1
            if "alt" not in values:
                self.images_missing_alt += 1
        elif tag == "a" and values.get("href"):
            self.links += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False
        elif tag.lower() == "script" and self._in_jsonld_script:
            value = "".join(self._jsonld_parts).strip()
            if value:
                self.jsonld_scripts.append(value)
            self._jsonld_parts = []
            self._in_jsonld_script = False
        elif tag.lower() == "h1":
            if self._in_h1:
                text = " ".join("".join(self._h1_parts).split())
                if text and not self.h1_text:
                    self.h1_text = text
            self._in_h1 = False

    def handle_data(self, data: str) -> None:
        if self._in_jsonld_script:
            self._jsonld_parts.append(data)
        if self._in_title:
            self._title_parts.append(data)
            self.title_text = " ".join("".join(self._title_parts).split())
        if self._in_h1:
            self._h1_parts.append(data)
            self.h1_text = " ".join("".join(self._h1_parts).split())


def _finding(category: str, title: str, status: str, severity: str,
             evidence: str, explanation: str, recommendation: str,
             steps: list[str], source_url: str | None = None) -> AuditFinding:
    return AuditFinding(
        category=category, title=title, status=status, severity=severity,
        evidence=evidence, explanation=explanation, recommendation=recommendation,
        verification_steps=steps, source_url=source_url,
    )


def inspect_homepage(html: str, final_url: str, headers: dict[str, str]) -> list[AuditFinding]:
    parser = _PageParser()
    parser.feed(html)
    findings: list[AuditFinding] = []

    # Validate embedded JSON-LD syntax and flag Product entities without a name.
    # This is a bounded source check, not a complete Schema.org validator.
    product_entities: list[dict[str, Any]] = []
    malformed_jsonld = 0

    def collect_products(value: Any) -> None:
        if isinstance(value, list):
            for child in value:
                collect_products(child)
        elif isinstance(value, dict):
            raw_type = value.get("@type", [])
            types = raw_type if isinstance(raw_type, list) else [raw_type]
            if any(isinstance(item, str) and item.lower() == "product" for item in types):
                product_entities.append(value)
            graph = value.get("@graph")
            if graph is not None:
                collect_products(graph)

    for script in parser.jsonld_scripts:
        try:
            payload = json.loads(script)
        except (json.JSONDecodeError, TypeError):
            malformed_jsonld += 1
            continue
        collect_products(payload)

    if malformed_jsonld:
        findings.append(_finding(
            "structured_data", "Malformed JSON-LD structured data", "verified", "medium",
            f"Found {malformed_jsonld} JSON-LD script(s) that could not be parsed as JSON. URL: {final_url}",
            "Malformed JSON prevents parsers from reliably reading that JSON-LD block. Other structured-data blocks may still be valid; this check does not assess every Schema.org rule.",
            "Correct the JSON syntax in each flagged script and validate the resulting structured data with a search-engine testing tool.",
            ["Inspect each application/ld+json script in the raw HTML.", "Parse each block as JSON and validate supported structured-data properties."],
            final_url,
        ))

    products_without_name = sum(
        1 for product in product_entities
        if not (isinstance(product.get("name"), str) and product["name"].strip())
    )
    if products_without_name:
        findings.append(_finding(
            "structured_data", "Product structured data missing name", "verified", "medium",
            f"Found {products_without_name} Product entity/entities without a non-empty name property. URL: {final_url}",
            "A product name is a core descriptive property. Missing names can make product structured data incomplete, but this source check does not determine eligibility for a particular rich result.",
            "Add an accurate name property to each affected Product entity and validate the complete structured-data graph.",
            ["Inspect Product entities in every JSON-LD block.", "Compare structured product names with the visible product title.", "Run a structured-data validator after changes."],
            final_url,
        ))
    # Check price/currency signals only when Product JSON-LD is present. This is
    # a targeted source check, not a full Google rich-result eligibility validator.
    products_with_offers = 0
    offers_missing_price = 0
    offers_missing_currency = 0
    for product in product_entities:
        raw_offers = product.get("offers")
        offers = raw_offers if isinstance(raw_offers, list) else [raw_offers]
        for offer in offers:
            if not isinstance(offer, dict):
                continue
            products_with_offers += 1
            price = offer.get("price")
            price_valid = (
                isinstance(price, (str, int, float))
                and not isinstance(price, bool)
                and bool(str(price).strip())
            )
            if not price_valid:
                offers_missing_price += 1
            currency = offer.get("priceCurrency")
            if not (isinstance(currency, str) and re.fullmatch(r"[A-Za-z]{3}", currency.strip())):
                offers_missing_currency += 1

    if offers_missing_price:
        findings.append(_finding(
            "structured_data", "Product offers missing price", "verified", "medium",
            f"Found {offers_missing_price} Product Offer object(s) without a usable price property. URL: {final_url}",
            "A price is important for product offer information. This check verifies only the source property and does not assess sale-price consistency, availability, or rich-result eligibility.",
            "Provide the current, accurate price in each affected Offer and ensure it matches the visible product page and currency formatting.",
            ["Inspect each Product Offer in JSON-LD.", "Compare structured prices with the visible price and variant selection.", "Validate the page with a structured-data testing tool."],
            final_url,
        ))

    if offers_missing_currency:
        findings.append(_finding(
            "structured_data", "Product offers missing or invalid currency", "verified", "medium",
            f"Found {offers_missing_currency} Product Offer object(s) without a three-letter priceCurrency code. URL: {final_url}",
            "A currency code clarifies the denomination of a structured offer price. This source check does not verify exchange rates or merchant-feed consistency.",
            "Set priceCurrency to the correct three-letter ISO 4217 code, such as USD, GBP, or PKR, and ensure it matches the visible offer.",
            ["Inspect priceCurrency for each Product Offer.", "Confirm the code matches the actual storefront currency.", "Run structured-data validation after changes."],
            final_url,
        ))

    checks = [
        (bool(parser.title_text), "Page title", "The HTML response has no readable <title> element.",
         "Add a unique, descriptive title that accurately reflects this page.",
         ["Open the page source and find the <title> element."]),
        (bool(parser.meta_description), "Meta description", "The HTML response has no meta description.",
         "Add a concise, page-specific meta description; search engines may choose another snippet.",
         ["Inspect the page source for meta name=\"description\"."]),
        (parser.h1_count > 0, "Primary heading (H1)", "No H1 heading was found in the returned HTML.",
         "Provide a clear primary page heading in the page's semantic HTML.",
         ["Inspect the rendered page and heading outline; confirm the main heading is meaningful."]),
    ]
    for passed, title, evidence, recommendation, steps in checks:
        if passed:
            recommendation = {
                "Page title": "Keep the title accurate and specific to this page; review uniqueness and search intent separately because this presence check does not assess title quality.",
                "Meta description": "Keep the description accurate and page-specific; review its usefulness and search snippet separately because this check only confirms presence.",
                "Primary heading (H1)": "Keep a clear primary heading and verify that it accurately describes the page; this check confirms presence, not semantic quality.",
            }.get(title, "Keep this element present and review its quality in context; this check confirms presence only.")
        findings.append(_finding(
            "on_page_seo" if title != "Mobile viewport" else "mobile_ux",
            title,
            "verified",
            "low" if not passed else "info",
            f"{evidence} Final URL: {final_url}" if not passed else
            (f"Found: {parser.title_text[:160]}" if title == "Page title" else
             f"Found {parser.h1_count} H1 heading(s)." if title == "Primary heading (H1)" else
             f"Found: {parser.viewport[:160]}" if title == "Mobile viewport" else
             f"Found meta description ({len(parser.meta_description)} characters)."),
            ("This is a basic source-HTML check, not a complete SEO or responsive-layout assessment."
             if not passed else "The expected element is present in the returned HTML; its quality and rendered behavior were not fully assessed."),
            recommendation, steps, final_url,
        ))
    robots_header = headers.get("x-robots-tag", "")
    robots_directives = f"{parser.meta_robots}, {robots_header}".lower()
    if re.search(r"(?<![a-z0-9_-])noindex(?![a-z0-9_-])", robots_directives):
        sources = []
        if re.search(r"(?<![a-z0-9_-])noindex(?![a-z0-9_-])", parser.meta_robots.lower()):
            sources.append("meta name=robots")
        if re.search(r"(?<![a-z0-9_-])noindex(?![a-z0-9_-])", robots_header.lower()):
            sources.append("X-Robots-Tag response header")
        findings.append(_finding(
            "technical_seo", "Homepage has a noindex directive", "verified", "medium",
            f"Detected noindex in {', '.join(sources)} for {final_url}.",
            "The observed directive asks compliant search engines not to index this URL. It may be intentional for a private, campaign, or staging page, so the source signal alone does not establish a defect.",
            "Confirm that excluding the public homepage from search results is intentional. If the page should be indexed, remove the unintended noindex directive and verify the rendered response and canonical URL.",
            ["Inspect all meta robots elements in the raw HTML.", "Check every X-Robots-Tag response header.", "Confirm the intended indexing policy with the site owner and validate the exact URL in Search Console."],
            final_url,
        ))
    # Duplicate metadata declarations can create conflicting or ambiguous signals.
    if parser.title_count > 1:
        findings.append(_finding(
            "on_page_seo", "Multiple title elements", "verified", "medium",
            f"Found {parser.title_count} title elements in the returned HTML. URL: {final_url}",
            "A document should expose one clear page title. Multiple title elements can make source interpretation and debugging ambiguous; this check does not determine which title a search engine displays.",
            "Keep one intentional title element in the document head and make it specific to this page.",
            ["Inspect the raw HTML and confirm there is exactly one title element.", "Check the browser tab title and compare it with the intended page title."],
            final_url,
        ))
    if parser.meta_description_count > 1:
        findings.append(_finding(
            "on_page_seo", "Multiple meta description elements", "verified", "low",
            f"Found {parser.meta_description_count} meta description elements, including {parser.meta_description_empty_count} empty element(s). URL: {final_url}",
            "Multiple meta descriptions provide conflicting page-summary signals. Search engines may choose a different snippet; this source check does not predict the displayed snippet.",
            "Keep one accurate, page-specific meta description and remove duplicate or empty declarations.",
            ["Inspect the raw HTML and confirm one non-empty meta name=description element remains.", "Review the resulting snippet separately in search-engine tools when available."],
            final_url,
        ))
    # Canonical declarations are easy to misconfigure and were parsed above but
    # previously did not produce a finding. Report only source-verifiable problems.
    if parser.canonical_count > 1:
        findings.append(_finding(
            "technical_seo", "Multiple canonical link elements", "verified", "medium",
            f"Found {parser.canonical_count} canonical link elements in the returned HTML. URL: {final_url}",
            "Multiple canonical declarations can send conflicting canonicalization signals. This source check does not determine which URL search engines will select.",
            "Keep one intentional canonical link element in the document head and ensure its absolute destination matches the preferred indexable URL.",
            [
                "Inspect the raw HTML and confirm there is exactly one canonical link element.",
                "Resolve its href against the final page URL and confirm it points to the intended indexable URL.",
                "Check that redirects, robots directives, and sitemap URLs are consistent with the canonical destination.",
            ], final_url,
        ))
    if parser.canonical_missing_href_count:
        findings.append(_finding(
            "technical_seo", "Canonical link missing href", "verified", "medium",
            f"{parser.canonical_missing_href_count} canonical link element(s) have no usable href attribute. URL: {final_url}",
            "A canonical element without a destination cannot reliably declare the preferred URL.",
            "Add a valid canonical href to the intended indexable URL, or remove the empty canonical element.",
            [
                "Inspect each canonical link element in the raw HTML.",
                "Confirm every retained canonical element has a non-empty href.",
                "Verify the resolved destination is the preferred indexable URL.",
            ], final_url,
        ))
    viewport = parser.viewport.lower().replace(" ", "")
    viewport_steps = [
        "Inspect the page source for meta name=\"viewport\".",
        "Test reflow at 320 CSS px and common mobile widths in a real browser.",
        "Confirm users can zoom without the page preventing magnification.",
    ]
    if not viewport:
        findings.append(_finding(
            "mobile_ux", "Mobile viewport", "verified", "medium",
            f"No meta name=\"viewport\" was found in the returned HTML. URL: {final_url}",
            "Without an appropriate viewport declaration, mobile browsers may lay the page out at a wider virtual width. This source check does not prove how the page actually renders.",
            "Add a responsive declaration such as width=device-width, initial-scale=1. Do not disable user zoom.",
            viewport_steps, final_url,
        ))
    elif "user-scalable=no" in viewport or "user-scalable=0" in viewport or "maximum-scale=1" in viewport:
        findings.append(_finding(
            "mobile_ux", "Viewport may restrict zoom", "verified", "medium",
            f"Viewport declaration may restrict zoom: {parser.viewport[:200]}",
            "Preventing users from zooming can make content harder to use, especially for people with low vision. Browser behavior varies, so verify the rendered experience.",
            "Remove user-scalable=no and restrictive maximum-scale settings unless a documented, accessibility-reviewed exception applies.",
            viewport_steps, final_url,
        ))
    elif "width=device-width" not in viewport:
        findings.append(_finding(
            "mobile_ux", "Viewport may use a fixed layout width", "verified", "medium",
            f"Viewport declaration does not include width=device-width: {parser.viewport[:200]}",
            "A fixed or unusual viewport width can make mobile content appear scaled down or require horizontal scrolling. Actual layout behavior needs browser testing.",
            "Review the responsive viewport declaration; commonly use width=device-width, initial-scale=1 and test the rendered page.",
            viewport_steps, final_url,
        ))
    else:
        findings.append(_finding(
            "mobile_ux", "Mobile viewport declaration", "verified", "info",
            f"Found: {parser.viewport[:200]}",
            "A responsive viewport declaration is present in source HTML. This alone does not prove responsive layout quality or WCAG reflow.",
            "Test the rendered page at 320 CSS px and common phone, tablet, desktop, portrait, landscape, and zoom settings.",
            viewport_steps, final_url,
        ))
    if parser.images_missing_alt:
        findings.append(_finding(
            "aria_alt_text", "Images missing an alt attribute", "verified", "medium",
            f"{parser.images_missing_alt} of {parser.images} image element(s) have no alt attribute in returned HTML.",
            "Alternative text communicates the purpose of meaningful images to people using screen readers. Decorative images can use an empty alt attribute.",
            "Add meaningful alt text to informative images and alt=\"\" to decorative images. Do not stuff keywords.",
            ["Inspect each flagged image in context.", "Use a browser accessibility inspector or an automated accessibility scanner."],
            final_url,
        ))
    findings.append(_finding(
        "on_page_seo", "H1 count", "manual_review_required", "info",
        f"Detected {parser.h1_count} H1 element(s); first readable heading: {parser.h1_text[:160] or 'none'}.",
        "Heading count alone does not determine SEO quality or accessibility; heading purpose and page structure require context.",
        "Review the heading hierarchy and ensure headings describe the sections they introduce.",
        ["Inspect the rendered heading outline and compare it with the page content."], final_url,
    ))
    security_headers = {
        "strict-transport-security": ("HSTS header", "medium"),
        "content-security-policy": ("Content Security Policy", "medium"),
        "x-content-type-options": ("X-Content-Type-Options", "low"),
        "referrer-policy": ("Referrer-Policy", "low"),
    }
    for header, (label, severity) in security_headers.items():
        value = headers.get(header)
        findings.append(_finding(
            "security_headers", label,
            "verified" if value else "manual_review_required",
            "info" if value else severity,
            f"Header value: {value[:240]}" if value else f"Response did not include {header}.",
            "Security headers can reduce certain browser-side risks, but their presence alone does not prove a site is secure.",
            f"Review whether {header} is appropriate for this site and configure it safely; test for compatibility before enforcing restrictive policies.",
            [f"Inspect the response headers with browser DevTools or a reputable header scanner.", "Review configuration and test critical site flows."],
            final_url,
        ))
    return findings


def inspect_discovery_contents(category: str, body: str, source_url: str) -> list[AuditFinding]:
    """Perform bounded semantic checks on robots.txt and sitemap.xml content."""
    if category == "robots_txt":
        directives: list[tuple[str, str]] = []
        for raw_line in body.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            if key and value:
                directives.append((key, value))
        user_agents = sum(1 for key, _ in directives if key == "user-agent")
        disallow_count = sum(1 for key, _ in directives if key == "disallow")
        allow_count = sum(1 for key, _ in directives if key == "allow")
        sitemap_count = sum(1 for key, _ in directives if key == "sitemap")
        return [_finding(
            category,
            "robots.txt directive summary",
            "verified" if user_agents else "manual_review_required",
            "info" if user_agents else "low",
            f"Parsed {len(directives)} non-empty directive(s): {user_agents} User-agent, "
            f"{allow_count} Allow, {disallow_count} Disallow, {sitemap_count} Sitemap.",
            "This is a lightweight directive count, not a complete robots.txt standards validator. "
            "Rules must be reviewed against the site's intended crawl policy and important URL paths.",
            "Check every User-agent group, Allow/Disallow rule, and Sitemap reference. Make sure important public pages are not accidentally blocked.",
            ["Review the file with a robots.txt tester and compare rules against intended crawl behavior.",
             "Check important product and category URLs with the relevant search-engine tools."],
            source_url,
        )]

    if category == "sitemap_xml":
        try:
            root = ET.fromstring(body)
        except ET.ParseError as exc:
            return [_finding(
                category, "Sitemap XML parsing", "verified", "medium",
                f"The response was not well-formed XML: {str(exc)[:180]}",
                "Search engines may not be able to process a malformed sitemap. A successful HTTP status alone does not validate its contents.",
                "Generate valid XML with the correct sitemap namespace and URL entries, then validate the published file.",
                ["Run the sitemap through an XML parser and the search engine's sitemap reporting tool."],
                source_url,
            )]
        root_name = root.tag.rsplit("}", 1)[-1].lower()
        loc_values = [
            (element.text or "").strip()
            for element in root.iter()
            if element.tag.rsplit("}", 1)[-1].lower() == "loc"
        ]
        invalid_locations = 0
        for value in loc_values:
            try:
                parsed = urlsplit(value)
                # Validate explicit ports as well as the absolute HTTP(S) URL shape.
                _ = parsed.port
                valid_location = (
                    parsed.scheme.lower() in {"http", "https"}
                    and bool(parsed.hostname)
                    and parsed.username is None
                    and parsed.password is None
                )
            except (ValueError, UnicodeError):
                valid_location = False
            if not valid_location:
                invalid_locations += 1
        valid_root = root_name in {"urlset", "sitemapindex"}
        if not valid_root or not loc_values or invalid_locations:
            status = "manual_review_required"
            severity = "medium"
        else:
            status = "verified"
            severity = "info"
        return [_finding(
            category, "Sitemap XML structure", status, severity,
            f"Root element: {root_name or 'missing'}; loc entries: {len(loc_values)}; "
            f"entries without an absolute HTTP(S) URL: {invalid_locations}.",
            "This checks basic XML shape and URL format only. It does not prove that listed URLs are canonical, indexable, current, or accepted by a search engine.",
            "Use a urlset for URL entries or sitemapindex for child sitemap locations. Remove invalid entries and verify that listed URLs return the intended canonical pages.",
            ["Validate the XML with a sitemap validator.", "Inspect search-engine sitemap status and sample listed URLs."],
            source_url,
        )]
    return []


async def run_phase_one_checks(target: str) -> AuditCheckResult:
    """Run bounded, unauthenticated checks against a public site's homepage and common files."""
    from datetime import datetime, timezone

    normalized = normalize_target(target)
    parsed = urlsplit(normalized)
    findings: list[AuditFinding] = []
    pages_checked: list[str] = []
    limitations = [
        "Only the public homepage and common discovery files are checked in this phase; this is not a full-site crawl.",
        "HTML source checks do not prove the rendered mobile layout, full accessibility, Google indexing, or legal compliance.",
        "Security-header checks are passive observations and do not constitute penetration testing.",
    ]
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
    connector = aiohttp.TCPConnector(
        resolver=PublicOnlyResolver(),
        use_dns_cache=False,
        family=socket.AF_UNSPEC,
    )
    async with aiohttp.ClientSession(
        timeout=timeout,
        connector=connector,
        headers={"User-Agent": USER_AGENT},
        trust_env=False,
    ) as client:
        try:
            status, html, headers, final_url = await _safe_get(client, normalized)
            pages_checked.append(final_url)
            if status < 200 or status >= 300:
                findings.append(_finding(
                    "crawl", "Homepage HTTP response", "verified", "high" if status >= 500 else "medium",
                    f"Homepage returned HTTP {status}.",
                    "The server did not return a successful homepage response to this audit request.",
                    "Check hosting, redirects, access rules, and server logs; verify the page using a normal browser and search crawler.",
                    ["Repeat the request with a browser and an HTTP status checker."], final_url,
                ))
            else:
                findings.extend(inspect_homepage(html, final_url, headers))
                # Reuse the safely fetched homepage HTML; do not make a second request to the target.
                from dependency_checks import inspect_client_dependency_versions

                dependency_findings, dependency_limitations = await inspect_client_dependency_versions(
                    html, final_url
                )
                findings.extend(dependency_findings)
                limitations.extend(dependency_limitations)
        except Exception as exc:
            findings.append(_finding(
                "crawl", "Homepage could not be inspected", "not_tested", "info",
                f"Check stopped safely: {type(exc).__name__}: {str(exc)[:240]}",
                "The audit could not obtain a reliable homepage response, so downstream page checks were not performed.",
                "Confirm the target is public and reachable, then rerun the audit.",
                ["Open the target in a browser.", "Check DNS, TLS, robots/access restrictions, and server availability."],
                normalized,
            ))
            limitations.append("Homepage checks were skipped because a safe, successful fetch was not completed.")

        origin = f"{parsed.scheme}://{parsed.netloc}"
        for filename, category, description in [
            ("robots.txt", "robots_txt", "robots.txt"),
            ("sitemap.xml", "sitemap_xml", "sitemap.xml"),
            ("llms.txt", "llms_txt", "llms.txt"),
        ]:
            file_url = urljoin(origin + "/", filename)
            try:
                status, body, _, final_url = await _safe_get(client, file_url)
                if 200 <= status < 300:
                    findings.append(_finding(
                        category, f"{description} availability", "verified", "info",
                        f"GET {final_url} returned HTTP {status}; response size {len(body.encode('utf-8'))} bytes.",
                        ("This confirms only that a public response was returned. The file's directives or contents still need semantic validation."
                         if category != "llms_txt" else
                         "llms.txt is a proposed convention; availability does not establish search ranking, crawling, or AI citation benefits."),
                        ("Validate syntax and ensure directives reflect the site's intended crawl policy."
                         if category == "robots_txt" else
                         "Validate sitemap XML, canonical URLs, and that listed URLs are indexable."
                         if category == "sitemap_xml" else
                         "Treat this as an optional convention; keep any content accurate and do not rely on it for guaranteed discovery."),
                        [f"Open {final_url} directly.", "Review the response content and compare it with the intended site configuration."],
                        final_url,
                    ))
                    findings.extend(inspect_discovery_contents(category, body, final_url))
                else:
                    # Only a clear 404 supports a finding that the conventional file is
                    # absent. Access-denied, rate-limit, and server-error responses do
                    # not prove absence and must not trigger a publish-file recommendation.
                    is_not_found = status == 404
                    findings.append(_finding(
                        category, f"{description} availability",
                        "verified" if is_not_found else "not_tested",
                        "low" if is_not_found else "info",
                        f"GET {final_url} returned HTTP {status}.",
                        (f"{description} was not found at the conventional root path. "
                         "Whether that matters depends on the site's setup and intended use."
                         if is_not_found else
                         f"The server returned HTTP {status}; this does not establish whether {description} exists or is configured correctly."),
                        (("Publish and validate this file if the site needs explicit crawl rules."
                          if category == "robots_txt" else
                          "Publish a valid sitemap and reference it from robots.txt if appropriate."
                          if category == "sitemap_xml" else
                          "No action is required solely for missing llms.txt; it is optional and has no guaranteed ranking benefit.")
                         if is_not_found else
                         "Resolve the access, rate-limit, or server response and rerun this check before drawing conclusions."),
                        [f"Open {file_url} directly and check whether an alternative location is intentionally used."],
                        final_url,
                    ))
            except Exception as exc:
                findings.append(_finding(
                    category, f"{description} could not be checked", "not_tested", "info",
                    f"Check stopped safely: {type(exc).__name__}: {str(exc)[:200]}",
                    "A reliable response could not be obtained, so availability and content were not verified.",
                    "Confirm public reachability and rerun; do not treat this result as proof the file is missing.",
                    ["Open the URL directly and check server/network logs."], file_url,
                ))
    # Public HTML directives are useful diagnostics, but they are not an authoritative
    # record of whether Google has indexed a URL. No Search Console property/API
    # authorization is configured in this public audit path, so report that gap plainly.
    findings.append(_finding(
        "technical_seo",
        "Google indexing status not verified",
        "not_tested",
        "info",
        "This audit checks public page and discovery-file signals only; it does not query Google Search Console URL Inspection or an authoritative index-status source.",
        "A reachable page, sitemap entry, or absence of a noindex directive does not prove that Google has indexed the URL. Likewise, this audit cannot prove that a URL is absent from Google's index.",
        "If index status matters, inspect the exact URL in the site's authorized Google Search Console property and review the reason reported there. Treat public source checks as diagnostic signals, not index-status confirmation.",
        [
            "Open Google Search Console for the verified site property.",
            "Use URL Inspection for the exact canonical URL and review the reported indexing state and last crawl.",
            "Compare any reported issue with the page's canonical, robots directives, response status, and sitemap entry.",
        ],
        normalized,
    ))
    limitations.append(
        "Google index status is not queried: Search Console authorization and URL Inspection data are not part of this public audit."
    )
    return AuditCheckResult(
        target_url=normalized,
        checked_at_utc=datetime.now(timezone.utc).isoformat(),
        findings=findings,
        pages_checked=pages_checked,
        limitations=limitations,
    )
