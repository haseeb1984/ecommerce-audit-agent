"""Evidence-first, bounded public website checks for the ecommerce audit engine.

This module intentionally does not claim a full security, accessibility, or SEO audit.
It performs conservative public-page checks and reports limitations explicitly.
"""
from __future__ import annotations

import asyncio
import ipaddress
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
            if response.status in {301, 302, 303, 307, 308}:
                location = headers.get("location")
                if not location:
                    return response.status, "", headers, current
                if redirect_count >= MAX_REDIRECTS:
                    raise ValueError("The website exceeded the redirect limit.")
                current = normalize_target(urljoin(current, location))
                continue
            content_length = headers.get("content-length")
            if content_length:
                try:
                    if int(content_length) > MAX_RESPONSE_BYTES:
                        raise ValueError("Response exceeded the audit's 1 MB size limit.")
                except ValueError as exc:
                    if "size limit" in str(exc):
                        raise
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
        self._in_title = False
        self.meta_description = ""
        self.viewport = ""
        self.h1_count = 0
        self.h1_text = ""
        self._in_h1 = False
        self.images = 0
        self.images_missing_alt = 0
        self.links = 0
        self._title_parts: list[str] = []
        self._h1_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            name = values.get("name", "").strip().lower()
            if name == "description":
                self.meta_description = values.get("content", "").strip()
            elif name == "viewport":
                self.viewport = values.get("content", "").strip()
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
        elif tag.lower() == "h1":
            if self._in_h1:
                text = " ".join("".join(self._h1_parts).split())
                if text and not self.h1_text:
                    self.h1_text = text
            self._in_h1 = False

    def handle_data(self, data: str) -> None:
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
        findings.append(_finding(
            "on_page_seo" if title != "Mobile viewport" else "mobile_ux",
            title,
            "verified" if not passed else "verified",
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
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
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
                    findings.append(_finding(
                        category, f"{description} availability",
                        "verified", "low" if status == 404 else "medium",
                        f"GET {final_url} returned HTTP {status}.",
                        (f"{description} was not served successfully at the conventional root path. "
                         "Whether that is an issue depends on the site's setup and intended use."),
                        ("Publish and validate this file if the site needs explicit crawl rules."
                         if category == "robots_txt" else
                         "Publish a valid sitemap and reference it from robots.txt if appropriate."
                         if category == "sitemap_xml" else
                         "No action is required solely for missing llms.txt; it is optional and has no guaranteed ranking benefit."),
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
    return AuditCheckResult(
        target_url=normalized,
        checked_at_utc=datetime.now(timezone.utc).isoformat(),
        findings=findings,
        pages_checked=pages_checked,
        limitations=limitations,
    )
