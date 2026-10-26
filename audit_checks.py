"""Evidence-first, bounded public website checks for the ecommerce audit engine.

This module intentionally does not claim a full security, accessibility, or SEO audit.
It performs conservative public-page checks and reports limitations explicitly.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import ipaddress
import hashlib
import json
import re
import socket
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from typing import Any, Literal
from urllib.parse import urljoin, urlsplit, urlunsplit

import aiohttp
from pydantic import BaseModel, Field, root_validator


MAX_RESPONSE_BYTES = 1_000_000
MAX_REDIRECTS = 5
REQUEST_TIMEOUT_SECONDS = 10.0
USER_AGENT = "EcommerceAuditBot/1.0 (+https://junctiontools.com)"


class AuditFinding(BaseModel):
    finding_id: str = ""
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
    severity_rationale: str = "Severity is a triage label, not a measured business impact."
    observed_at_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    test_method: str = "Not specified by the individual checker"
    evidence_confidence: str = "limited"
    standard_references: list[str] = Field(default_factory=list)
    estimated_effort: str = "Not estimated"
    effort_basis: str = "No implementation-specific estimate recorded"
    dependencies: list[str] = Field(default_factory=list)

    @root_validator(skip_on_failure=True)
    def ensure_stable_finding_id(cls, values):
        """Every finding, including synthetic unavailable states, gets a stable ID."""
        if not str(values.get("finding_id") or "").strip():
            identity = "|".join((
                str(values.get("category") or "").strip().lower(),
                str(values.get("title") or "").strip().lower(),
                str(values.get("source_url") or "").strip(),
            ))
            values["finding_id"] = "F-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12].upper()
        rationale = str(values.get("severity_rationale") or "").strip()
        if not rationale or rationale == "Severity is a triage label, not a measured business impact.":
            severity = str(values.get("severity") or "").lower()
            rationale_by_severity = {
                "critical": "Highest triage priority under the checker rule because the observed condition may have material impact; verify scope and exploitability before action.",
                "high": "High triage priority under the checker rule because the observed condition may materially affect technical behavior or users; business impact is not measured.",
                "medium": "Moderate triage priority under the checker rule; confirm scope and affected templates before estimating business impact.",
                "low": "Lower triage priority under the checker rule; prioritize against other verified work and site context.",
                "info": "Informational or unavailable state; this label does not by itself recommend remediation.",
            }
            values["severity_rationale"] = rationale_by_severity.get(
                severity, "Severity is a triage label, not a measured business impact."
            )
        dependencies = values.get("dependencies") or []
        if not dependencies:
            category = str(values.get("category") or "").lower()
            dependency_by_category = {
                "technical_seo": ["Confirm the canonical URL/template owner and intended indexable URL."],
                "on_page_seo": ["Confirm the CMS/template owner and intended page metadata."],
                "robots_txt": ["Confirm search-crawl policy with the site owner before changing directives."],
                "sitemap_xml": ["Confirm the sitemap generator and intended canonical/indexable URL set."],
                "performance": ["Identify the theme/app/script owner; retest after each material change."],
                "accessibility": ["Confirm the affected template owner and complete manual keyboard/assistive-technology review."],
                "aria": ["Confirm the interactive component owner and test with keyboard/screen reader."],
                "aria_alt_text": ["Request contextual review from the content owner for meaningful versus decorative images."],
                "security_transport": ["Confirm hosting/DNS control and schedule a TLS configuration retest."],
                "security_headers": ["Confirm application/edge configuration ownership and regression-test security policy changes."],
                "security_exposure": ["Verify the exposure safely before changes; involve the system owner and security lead if confirmed."],
                "mobile_ux": ["Confirm affected template/device scope and retest in real browsers after changes."],
                "ecommerce": ["Confirm product/catalog data ownership and the number of affected templates or SKUs."],
                "structured_data": ["Confirm schema ownership and validate representative product/category templates after changes."],
                "international_seo": ["Confirm supported locales, URL strategy and CMS hreflang generation."],
                "pixel_analytics": ["Obtain authorized analytics/tag-manager access and use a safe test environment."],
                "conversion_paid_traffic": ["Obtain authorized test access and analytics/ad-platform context; never use real customer data or submit real orders."],
                "trust": ["Confirm the accuracy and owner of policy, payment, review and support information before changing presentation."],
                "content_quality": ["Confirm editorial ownership and review affected pages before merging or removing content."],
                "broken_internal_links": ["Confirm whether destinations moved, were intentionally removed, or require a redirect."],
            }
            if category in dependency_by_category:
                values["dependencies"] = dependency_by_category[category]
        effort = str(values.get("estimated_effort") or "").strip()
        if not effort or effort == "Not estimated":
            status = str(values.get("status") or "").lower()
            severity = str(values.get("severity") or "").lower()
            category = str(values.get("category") or "").lower()
            if status != "verified" or severity == "info":
                values["estimated_effort"] = "Not applicable until an actionable issue is confirmed"
                values["effort_basis"] = "This record is informational, unavailable, or requires manual review; no remediation estimate is implied."
            else:
                effort_by_category = {
                    "technical_seo": ("0.5–3 developer hours", "Rough estimate for a single metadata/canonical/link change; template and CMS scope may increase effort."),
                    "on_page_seo": ("0.5–3 developer hours", "Rough estimate for a single on-page change; template and CMS scope may increase effort."),
                    "robots_txt": ("0.5–2 developer hours", "Rough estimate for a scoped robots directive correction, excluding broader indexing analysis."),
                    "sitemap_xml": ("1–4 developer hours", "Rough estimate for a sitemap-generation or URL-inclusion correction; catalog size may increase effort."),
                    "performance": ("2–8 developer hours for initial remediation", "Initial estimate only; root cause, third-party scripts, theme/app constraints and retesting can materially change effort."),
                    "accessibility": ("1–4 developer hours per affected template", "Initial estimate for a bounded template-level fix; manual assistive-technology review and repeated components may increase effort."),
                    "aria": ("1–4 developer hours per affected template", "Initial estimate for a bounded accessible-name/ARIA fix; interaction and screen-reader review may increase effort."),
                    "aria_alt_text": ("0.5–3 content/developer hours", "Initial estimate for a bounded image group; editorial context and catalog size may increase effort."),
                    "security_transport": ("1–4 developer hours for configuration review", "Estimate assumes control of hosting/DNS configuration; certificate or platform issues may require provider work."),
                    "security_headers": ("1–4 developer hours for configuration review", "Estimate assumes control of application or edge configuration; CSP tuning and regression checks may increase effort."),
                    "security_exposure": ("2–8 developer hours for verification and remediation", "Estimate excludes incident response and depends on whether exposure is confirmed and which system owns the path."),
                    "mobile_ux": ("2–8 developer hours per affected template", "Initial estimate for a bounded responsive-layout issue; device/browser coverage and theme complexity may increase effort."),
                    "ecommerce": ("1–6 developer hours per affected template", "Initial estimate for product/category data or navigation changes; catalog-wide changes may require additional work."),
                    "structured_data": ("1–4 developer hours per affected template", "Estimate excludes large-scale catalog migrations and post-deployment validation across all product types."),
                    "international_seo": ("1–6 developer hours per template/locale group", "Estimate depends on the number of locales, URL strategy, and CMS support."),
                    "pixel_analytics": ("1–6 developer hours for instrumentation review", "Estimate excludes ad-platform account access, consent implementation, and conversion-event QA."),
                    "conversion_paid_traffic": ("2–8 developer hours for a bounded review", "Estimate excludes authenticated checkout testing, campaign account analysis, and any platform-specific deployment."),
                    "trust": ("1–4 developer hours per affected template", "Estimate covers a bounded presentation/content change, not verification of business legitimacy or legal policy compliance."),
                    "content_quality": ("1–4 editorial hours per affected page group", "Estimate assumes editorial access and a bounded duplicate/thin-content set; large catalogs require separate scoping."),
                    "broken_internal_links": ("0.5–4 developer hours", "Estimate assumes a bounded set of internal destinations; redirects, CMS data and bulk catalog corrections may increase effort."),
                }
                selected = effort_by_category.get(category)
                if selected:
                    values["estimated_effort"], values["effort_basis"] = selected
                else:
                    values["estimated_effort"] = "Needs technical scoping before a reliable estimate"
                    values["effort_basis"] = "Public evidence does not reveal the implementation owner, codebase, or affected-template count."
        return values


class CheckOutcome(BaseModel):
    """An explicit result from a checker that actually evaluated a page."""
    check_id: str
    category: str
    page_url: str
    outcome: Literal["pass", "issue", "warning", "not_assessed", "error"]
    observed_at_utc: str
    method: str
    evidence: str
    evidence_ref: str | None = None


class AuditCheckResult(BaseModel):
    target_url: str
    checked_at_utc: str
    findings: list[AuditFinding] = Field(default_factory=list)
    pages_checked: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    check_outcomes: list[CheckOutcome] = Field(default_factory=list)


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


async def _safe_get(
    client: aiohttp.ClientSession, url: str, allowed_origin: str | None = None
) -> tuple[int, str, dict[str, str], str]:
    """Fetch a public URL with bounded bytes and safe redirects.

    If allowed_origin is supplied, redirect targets must remain on that origin.
    """
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
                next_url = normalize_target(urljoin(current, location))
                if allowed_origin and not _same_origin(next_url, allowed_origin):
                    raise ValueError("Redirect left the permitted same-origin crawl boundary.")
                current = next_url
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
        self.hreflang_entries: list[tuple[str, str]] = []
        self.hreflang_missing_href_count = 0
        self.h1_count = 0
        self.empty_h1_count = 0
        self.h1_text = ""
        self._in_h1 = False
        self.images = 0
        self.images_missing_alt = 0
        self.images_empty_alt = 0
        self.links = 0
        self.link_hrefs: list[str] = []
        self._title_parts: list[str] = []
        self._h1_parts: list[str] = []
        self.jsonld_scripts: list[str] = []
        self._in_jsonld_script = False
        self._jsonld_parts: list[str] = []
        self.document_language = ""
        self.charset_declarations: list[str] = []
        self.main_landmark_count = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag == "html":
            self.document_language = values.get("lang", "").strip()
        elif tag == "meta":
            charset = values.get("charset", "").strip()
            if charset:
                self.charset_declarations.append(charset)
            elif values.get("http-equiv", "").strip().lower() == "content-type":
                content_type = values.get("content", "")
                match = re.search(r"charset\s*=\s*([a-zA-Z0-9._-]+)", content_type, re.I)
                if match:
                    self.charset_declarations.append(match.group(1))
        elif tag == "main":
            self.main_landmark_count += 1
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
            if "alternate" in rel_tokens and values.get("hreflang", "").strip():
                language = values.get("hreflang", "").strip()
                href = values.get("href", "").strip()
                self.hreflang_entries.append((language, href))
                if not href:
                    self.hreflang_missing_href_count += 1
        elif tag == "h1":
            self.h1_count += 1
            self._in_h1 = True
            self._h1_parts = []
        elif tag == "img":
            self.images += 1
            if "alt" not in values:
                self.images_missing_alt += 1
            elif not values.get("alt", "").strip():
                self.images_empty_alt += 1
        elif tag == "a" and values.get("href"):
            self.links += 1
            self.link_hrefs.append(values.get("href", "").strip())

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
                if not text:
                    self.empty_h1_count += 1
                elif not self.h1_text:
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
    """Build a finding with a stable, evidence-location-specific identifier."""
    identity = "|".join((category.strip().lower(), title.strip().lower(), (source_url or "").strip()))
    finding_id = "F-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12].upper()
    normalized_category = category.strip().lower()
    reference_map = {
        "technical_seo": ["https://developers.google.com/search/docs/crawling-indexing"],
        "on_page_seo": ["https://developers.google.com/search/docs/appearance/title-link"],
        "robots_txt": ["https://developers.google.com/search/docs/crawling-indexing/robots/intro"],
        "sitemap_xml": ["https://www.sitemaps.org/protocol.html"],
        "llms_txt": ["https://llmstxt.org/"],
        "accessibility": ["https://www.w3.org/TR/WCAG22/"],
        "aria": ["https://www.w3.org/WAI/ARIA/apg/"],
        "aria_alt_text": ["https://www.w3.org/WAI/tutorials/images/"],
        "structured_data": ["https://developers.google.com/search/docs/appearance/structured-data/intro-structured-data"],
        "security_transport": ["https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security"],
        "security_headers": ["https://owasp.org/www-project-secure-headers/"],
        "performance": ["https://web.dev/articles/vitals"],
        "mobile_ux": ["https://www.w3.org/TR/WCAG22/#reflow"],
        "international_seo": ["https://developers.google.com/search/docs/specialty/international/localized-versions"],
        "conversion_paid_traffic": ["https://support.google.com/analytics/answer/9322688"],
        "crawlability": ["https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers"],
        "crawl": ["https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers"],
        "indexability": ["https://developers.google.com/search/docs/crawling-indexing/robots-meta-tag"],
        "indexing": ["https://support.google.com/webmasters/answer/9012289"],
        "security_baseline": ["https://owasp.org/www-project-top-ten/"],
        "security": ["https://owasp.org/www-project-top-ten/"],
        "security_exposure": ["https://owasp.org/www-project-top-ten/"],
        "security_cookies": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"],
        "security_api_documentation": ["https://owasp.org/www-project-api-security/"],
        "trust": ["https://www.ftc.gov/business-guidance/advertising-marketing/endorsements-influencers-reviews"],
        "trust_inspector": ["https://www.ftc.gov/business-guidance/advertising-marketing/endorsements-influencers-reviews"],
        "pixel_analytics": ["https://developers.google.com/analytics/devguides/collection/ga4/events"],
        "ecommerce": ["https://developers.google.com/search/docs/appearance/structured-data/product"],
        "ecommerce_category": ["https://developers.google.com/search/docs/appearance/structured-data/product"],
        "content_quality": ["https://developers.google.com/search/docs/fundamentals/creating-helpful-content"],
    }
    confidence = (
        "limited" if status in {"not_tested", "insufficient_data", "manual_review_required"}
        else "moderate" if source_url and evidence.strip()
        else "limited"
    )
    return AuditFinding(
        finding_id=finding_id,
        category=category, title=title, status=status, severity=severity,
        evidence=evidence, explanation=explanation, recommendation=recommendation,
        verification_steps=steps, source_url=source_url,
        observed_at_utc=datetime.now(timezone.utc).isoformat(),
        test_method="Bounded passive public-page check; see finding-specific evidence and limitations",
        evidence_confidence=confidence,
        standard_references=reference_map.get(normalized_category, []),
    )


def record_homepage_outcomes(
    html: str, final_url: str, headers: dict[str, str], observed_at_utc: str
) -> list[CheckOutcome]:
    """Record explicit outcomes only for source checks evaluated successfully."""
    parser = _PageParser()
    parser.feed(html)
    outcomes: list[CheckOutcome] = []

    def record(check_id: str, category: str, outcome: str, evidence: str) -> None:
        outcomes.append(CheckOutcome(
            check_id=check_id,
            category=category,
            page_url=final_url,
            outcome=outcome,
            observed_at_utc=observed_at_utc,
            method="bounded static HTML source inspection",
            evidence=evidence,
            evidence_ref=f"{check_id}:{final_url}",
        ))

    lang_value = parser.document_language.strip()
    if not lang_value:
        lang_outcome = "issue"
        lang_evidence = "Root html lang attribute is missing or empty."
    elif not re.fullmatch(r"[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*", lang_value):
        lang_outcome = "warning"
        lang_evidence = f"Root html lang value {lang_value[:80]!r} does not match the conservative syntax pattern; semantic validity is not established."
    else:
        lang_outcome = "pass"
        lang_evidence = f"Root html lang attribute: {lang_value!r}; syntax pattern matched, but actual page language is not independently verified."
    record("html.document_language", "accessibility", lang_outcome, lang_evidence)
    record("html.title_present", "on_page_seo", "pass" if parser.title_text else "issue",
           f"Title element count: {parser.title_count}; extracted title: {parser.title_text[:160]!r}.")
    record("html.title_count", "on_page_seo", "warning" if parser.title_count > 1 else "pass",
           f"Title element count: {parser.title_count}; multiple title elements can create ambiguous source signals.")
    record("html.meta_description_present", "on_page_seo", "pass" if parser.meta_description else "issue",
           f"Meta description count: {parser.meta_description_count}; non-empty description present: {bool(parser.meta_description)}.")
    record("html.meta_description_count", "on_page_seo", "warning" if parser.meta_description_count > 1 else "pass",
           f"Meta description element count: {parser.meta_description_count}; empty declaration count: {parser.meta_description_empty_count}. This check does not assess snippet selection.")
    empty_description_outcome = (
        "not_assessed" if parser.meta_description_count == 0
        else "issue" if parser.meta_description_empty_count == parser.meta_description_count
        else "warning" if parser.meta_description_empty_count > 0
        else "pass"
    )
    record("html.meta_description_content", "on_page_seo", empty_description_outcome,
           f"Meta description element count: {parser.meta_description_count}; empty declaration count: {parser.meta_description_empty_count}. Non-empty content presence is checked only; quality and search snippet selection are not assessed.")
    record("html.h1_present", "on_page_seo", "pass" if parser.h1_count > parser.empty_h1_count else "issue",
           f"H1 element count: {parser.h1_count}; empty H1 count: {parser.empty_h1_count}.")
    record("html.h1_count", "on_page_seo", "warning" if parser.h1_count > 1 else "pass",
           f"H1 element count: {parser.h1_count}; source inspection does not determine the ideal heading structure for this page.")
    record("html.viewport_present", "mobile_ux", "pass" if parser.viewport else "issue",
           f"Viewport declaration: {parser.viewport[:160]!r}.")
    viewport_tokens = {
        key.strip().lower(): value.strip().lower()
        for token in parser.viewport.split(",")
        if "=" in token
        for key, value in [token.split("=", 1)]
    }
    viewport_config_ok = (
        viewport_tokens.get("width") == "device-width"
        and viewport_tokens.get("initial-scale") == "1"
    )
    viewport_config_outcome = (
        "not_assessed" if not parser.viewport
        else "pass" if viewport_config_ok
        else "warning"
    )
    record(
        "mobile.viewport_configuration", "mobile_ux", viewport_config_outcome,
        f"Viewport declaration: {parser.viewport[:200]!r}; width=device-width: {viewport_tokens.get('width') == 'device-width'}; "
        f"initial-scale=1: {viewport_tokens.get('initial-scale') == '1'}. This source-only check does not test rendered responsiveness or zoom behavior.",
    )
    record("html.main_landmark_present", "accessibility", "pass" if parser.main_landmark_count > 0 else "issue",
           f"Main landmark count in returned HTML: {parser.main_landmark_count}.")

    response_charset = ""
    for key, value in headers.items():
        if key.lower() == "content-type":
            match = re.search(r"charset\s*=\s*([a-zA-Z0-9._-]+)", value, re.I)
            if match:
                response_charset = match.group(1).strip().lower()
            break
    declared_charsets = [value.strip().lower() for value in parser.charset_declarations if value.strip()]
    has_charset = bool(response_charset or declared_charsets)
    charset_mismatch = bool(response_charset and declared_charsets and any(value != response_charset for value in declared_charsets))
    charset_outcome = "warning" if charset_mismatch else "pass" if has_charset else "issue"
    record("html.charset_declared", "technical_seo", charset_outcome,
           f"HTTP charset: {response_charset or 'not declared'}; HTML charset declaration(s): {', '.join(declared_charsets) or 'none'}; declaration mismatch: {charset_mismatch}.")
    record(
        "html.images_alt_attribute", "aria_alt_text",
        "issue" if parser.images_missing_alt else "pass",
        f"Image elements: {parser.images}; elements missing an alt attribute: {parser.images_missing_alt}. "
        "This source check does not determine whether supplied alternative text is meaningful or appropriate.",
    )
    record(
        "html.images_empty_alt_attribute", "aria_alt_text",
        "warning" if parser.images_empty_alt else "pass",
        f"Image elements: {parser.images}; elements with explicitly empty alt attributes: {parser.images_empty_alt}. "
        "Empty alt is appropriate for decorative images, but context is needed to judge product or informative images.",
    )
    if parser.canonical_count == 0:
        canonical_outcome = "warning"
        canonical_evidence = "No canonical link element was found in the returned HTML; some pages intentionally omit it."
    elif parser.canonical_count > 1:
        canonical_outcome = "issue"
        canonical_evidence = f"Canonical link elements: {parser.canonical_count}; multiple declarations may conflict."
    elif parser.canonical_missing_href_count:
        canonical_outcome = "issue"
        canonical_evidence = "A canonical link element was found without a usable href."
    else:
        try:
            canonical_target = urljoin(final_url, parser.canonical_href)
            canonical_parts = urlsplit(canonical_target)
            canonical_valid = (
                canonical_parts.scheme.lower() in {"http", "https"}
                and bool(canonical_parts.hostname)
                and canonical_parts.username is None
                and canonical_parts.password is None
            )
        except ValueError:
            canonical_valid = False
            canonical_target = ""
        canonical_outcome = "pass" if canonical_valid else "issue"
        canonical_evidence = (
            f"Canonical href: {parser.canonical_href!r}; resolved destination: {canonical_target!r}; "
            f"HTTP(S) destination shape valid: {canonical_valid}. This does not prove canonical correctness or search-engine selection."
        )
    record("html.canonical_declaration", "technical_seo", canonical_outcome, canonical_evidence)
    if not parser.hreflang_entries:
        record(
            "international_seo.hreflang_links", "international_seo", "not_assessed",
            "No link rel=alternate hreflang declarations were found in the returned HTML. This does not establish whether the site needs international targeting or uses sitemap/HTTP-header hreflang.",
        )
    else:
        invalid_hreflang = [
            language for language, _ in parser.hreflang_entries
            if not re.fullmatch(r"(?:[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*|x-default)", language)
        ]
        normalized_languages = [language.strip().lower() for language, _ in parser.hreflang_entries]
        duplicate_language_count = len(normalized_languages) - len(set(normalized_languages))
        invalid_href_count = 0
        for _, href in parser.hreflang_entries:
            try:
                href_parts = urlsplit(href)
                href_valid = (
                    href_parts.scheme.lower() in {"http", "https"}
                    and bool(href_parts.hostname)
                    and href_parts.username is None
                    and href_parts.password is None
                )
                _ = href_parts.port
            except (ValueError, UnicodeError):
                href_valid = False
            if not href_valid:
                invalid_href_count += 1
        hreflang_outcome = (
            "issue" if invalid_href_count
            else "warning" if invalid_hreflang or duplicate_language_count
            else "pass"
        )
        record(
            "international_seo.hreflang_links", "international_seo", hreflang_outcome,
            f"HTML hreflang declarations: {len(parser.hreflang_entries)}; missing or non-absolute/invalid HTTP(S) href: {invalid_href_count}; values outside conservative language-tag syntax: {len(invalid_hreflang)}; duplicate language labels: {duplicate_language_count}. This source check does not validate reciprocal links, target status, locale correctness, or Google selection.",
        )
    robots_header = headers.get("x-robots-tag", "")
    robots_signal = f"{parser.meta_robots}, {robots_header}"
    robots_tokens = {
        token.strip().lower()
        for token in re.split(r"[,;\\s]+", robots_signal)
        if token.strip()
    }
    has_meta_noindex = "noindex" in robots_tokens
    record(
        "html.meta_robots_noindex",
        "indexing_signals",
        "warning" if has_meta_noindex else "pass",
        f"HTML meta robots: {parser.meta_robots[:160]!r}; X-Robots-Tag: {robots_header[:160]!r}; "
        f"noindex token present: {has_meta_noindex}. This is a public source/header signal, not proof of actual search-engine index status.",
    )
    if parser.jsonld_scripts:
        malformed_jsonld = 0
        for script in parser.jsonld_scripts:
            try:
                json.loads(script)
            except (json.JSONDecodeError, TypeError):
                malformed_jsonld += 1
        record(
            "structured_data.jsonld_parseability", "structured_data",
            "issue" if malformed_jsonld else "pass",
            f"JSON-LD script blocks: {len(parser.jsonld_scripts)}; blocks that failed JSON parsing: {malformed_jsonld}. "
            "Valid JSON syntax does not establish Schema.org validity or rich-result eligibility.",
        )
    else:
        # No JSON-LD means parseability itself was not testable. Do not treat the
        # absence of structured data as a parseability pass or silently omit it.
        record(
            "structured_data.jsonld_parseability", "structured_data", "not_assessed",
            "No application/ld+json script block was found in the returned HTML; JSON-LD syntax could not be evaluated. "
            "Other structured-data formats and page-specific requirements were not assessed by this check.",
        )
    # Product/Offer outcomes are independent source checks. A missing Product
    # entity is not a failure of a product-specific property check: that check is
    # marked not_assessed because this page may not represent a product.
    product_entities: list[dict[str, Any]] = []

    def collect_product_entities(value: Any) -> None:
        if isinstance(value, list):
            for child in value:
                collect_product_entities(child)
        elif isinstance(value, dict):
            raw_type = value.get("@type", [])
            types = raw_type if isinstance(raw_type, list) else [raw_type]
            if any(
                isinstance(item, str)
                and item.strip().rstrip("/").rsplit("/", 1)[-1].rsplit("#", 1)[-1].lower() == "product"
                for item in types
            ):
                product_entities.append(value)
            if "@graph" in value:
                collect_product_entities(value["@graph"])

    malformed_product_jsonld = 0
    for script in parser.jsonld_scripts:
        try:
            collect_product_entities(json.loads(script))
        except (json.JSONDecodeError, TypeError):
            malformed_product_jsonld += 1

    if not product_entities:
        product_not_assessed = (
            "No parseable Product entity was found in returned HTML JSON-LD. "
            "This may be a non-product page or product markup may be absent, malformed, rendered later, or represented in another format; no positive product-data conclusion is inferred."
        )
        for check_id, description in (
            ("structured_data.product_name", "Product name property"),
            ("structured_data.product_description", "Product description property"),
            ("structured_data.product_image", "Product image property"),
            ("structured_data.product_offers", "Product offer information"),
            ("structured_data.offer_price", "Offer price"),
            ("structured_data.offer_currency", "Offer currency"),
            ("structured_data.offer_availability", "Offer availability"),
        ):
            record(check_id, "structured_data", "not_assessed", f"{description} not assessed. {product_not_assessed}")
    else:
        def product_property_missing(product: dict[str, Any], key: str) -> bool:
            value = product.get(key)
            if key == "image":
                values = value if isinstance(value, list) else [value]
                return not any(
                    (isinstance(item, str) and item.strip())
                    or (isinstance(item, dict) and any(
                        isinstance(item.get(field), str) and item[field].strip()
                        for field in ("url", "contentUrl")
                    ))
                    for item in values
                )
            return not (isinstance(value, str) and value.strip()) if key in {"name", "description"} else False

        for property_name, check_id in (
            ("name", "structured_data.product_name"),
            ("description", "structured_data.product_description"),
            ("image", "structured_data.product_image"),
        ):
            missing_count = sum(product_property_missing(product, property_name) for product in product_entities)
            record(
                check_id, "structured_data", "issue" if missing_count else "pass",
                f"Parseable Product entities: {len(product_entities)}; entities missing a usable {property_name} property: {missing_count}. "
                "This checks source presence/shape only; it does not verify visible-content consistency, image reachability, or rich-result eligibility.",
            )

        offer_objects: list[dict[str, Any]] = []
        products_without_offers = 0
        for product in product_entities:
            raw_offers = product.get("offers")
            offers = raw_offers if isinstance(raw_offers, list) else [raw_offers]
            product_offers = [offer for offer in offers if isinstance(offer, dict) and offer]
            if product_offers:
                offer_objects.extend(product_offers)
            else:
                products_without_offers += 1
        record(
            "structured_data.product_offers", "structured_data",
            "warning" if products_without_offers else "pass",
            f"Parseable Product entities: {len(product_entities)}; entities without a non-empty Offer/AggregateOffer object: {products_without_offers}; offer objects inspected: {len(offer_objects)}. "
            "Some Product markup is used outside merchant listings, so absent offers are not universally invalid.",
        )

        def parse_source_price(value: Any) -> Decimal | None:
            if not isinstance(value, (str, int, float)) or isinstance(value, bool):
                return None
            try:
                parsed = Decimal(str(value).strip())
            except (InvalidOperation, ValueError):
                return None
            return parsed if parsed.is_finite() and parsed >= 0 else None

        missing_price = 0
        missing_currency = 0
        missing_or_invalid_availability = 0
        recognized_availability = {
            "backorder", "discontinued", "instoreonly", "limitedavailability",
            "madetoorder", "onlineonly", "outofstock", "presale", "preorder",
            "instock", "soldout",
        }
        for offer in offer_objects:
            offer_types = offer.get("@type", [])
            offer_types = offer_types if isinstance(offer_types, list) else [offer_types]
            aggregate = any(isinstance(t, str) and t.strip().rstrip("/").rsplit("/", 1)[-1].rsplit("#", 1)[-1].lower() == "aggregateoffer" for t in offer_types)
            if aggregate:
                if parse_source_price(offer.get("lowPrice")) is None and parse_source_price(offer.get("highPrice")) is None:
                    missing_price += 1
            elif parse_source_price(offer.get("price")) is None:
                missing_price += 1
            currency = offer.get("priceCurrency")
            if not (isinstance(currency, str) and re.fullmatch(r"[A-Za-z]{3}", currency.strip())):
                missing_currency += 1
            availability = offer.get("availability")
            if isinstance(availability, str) and availability.strip():
                token = re.sub(r"[^A-Za-z-]", "", availability.strip().rstrip("/").rsplit("/", 1)[-1]).lower()
                if token not in recognized_availability:
                    missing_or_invalid_availability += 1
            else:
                missing_or_invalid_availability += 1

        if not offer_objects:
            for check_id, description in (
                ("structured_data.offer_price", "Offer price"),
                ("structured_data.offer_currency", "Offer currency"),
                ("structured_data.offer_availability", "Offer availability"),
            ):
                record(check_id, "structured_data", "not_assessed",
                       f"{description} not assessed because no non-empty Offer/AggregateOffer object was found. Product entities: {len(product_entities)}; missing offer entities: {products_without_offers}.")
        else:
            record(
                "structured_data.offer_price", "structured_data",
                "issue" if missing_price else "pass",
                f"Offer objects inspected: {len(offer_objects)}; objects missing a usable non-negative finite price (or both aggregate range bounds): {missing_price}. "
                "Visible-price consistency and variant selection are not assessed.",
            )
            record(
                "structured_data.offer_currency", "structured_data",
                "issue" if missing_currency else "pass",
                f"Offer objects inspected: {len(offer_objects)}; objects missing a three-letter priceCurrency code: {missing_currency}. "
                "The code is not verified against the actual storefront currency.",
            )
            record(
                "structured_data.offer_availability", "structured_data",
                "issue" if missing_or_invalid_availability else "pass",
                f"Offer objects inspected: {len(offer_objects)}; objects missing or using an unrecognized availability token: {missing_or_invalid_availability}. "
                "This is a markup-shape check only; real-time inventory, fulfillment, and visible stock consistency are not verified.",
            )

    return outcomes


def inspect_homepage(html: str, final_url: str, headers: dict[str, str]) -> list[AuditFinding]:
    parser = _PageParser()
    parser.feed(html)
    findings: list[AuditFinding] = []

    # Basic document semantics: directly observed source facts, not a conformance claim.
    if not parser.document_language:
        findings.append(_finding(
            "accessibility", "HTML document language is not declared", "verified", "medium",
            f"The root <html> element has no non-empty lang attribute. URL: {final_url}",
            "Assistive technology and language-aware tools use the document language to choose pronunciation and text processing. This source check does not assess language changes within the page.",
            "Set the root html lang attribute to the primary language of the page, using a valid BCP 47 language tag.",
            ["Inspect the root html element in the page source.", "Confirm the declared language matches the page's primary human language."],
            final_url,
        ))
    elif not re.fullmatch(r"[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*", parser.document_language):
        findings.append(_finding(
            "accessibility", "HTML document language tag needs review", "manual_review_required", "low",
            f"The root html lang value is {parser.document_language[:80]!r}. URL: {final_url}",
            "The language attribute is present, but this conservative syntax check cannot confirm that the tag accurately identifies the page language.",
            "Verify the lang value against the page's actual primary language and a BCP 47 language-tag reference.",
            ["Review the visible page language.", "Validate the chosen language tag against BCP 47 guidance."],
            final_url,
        ))

    response_charset = ""
    for header_name, header_value in headers.items():
        if header_name.lower() == "content-type":
            match = re.search(r"charset\s*=\s*([a-zA-Z0-9._-]+)", header_value, re.I)
            if match:
                response_charset = match.group(1).strip().lower()
            break
    declared_charsets = {value.strip().lower() for value in parser.charset_declarations if value.strip()}
    if not response_charset and not declared_charsets:
        findings.append(_finding(
            "technical_seo", "Character encoding is not explicitly declared", "verified", "low",
            f"No charset parameter was found in the HTTP Content-Type header and no meta charset declaration was found in the HTML source. URL: {final_url}",
            "An explicit character encoding helps browsers decode text consistently, especially international product names and symbols.",
            "Serve HTML as UTF-8 and declare the charset in the HTTP Content-Type header or early in the document head.",
            ["Inspect the response Content-Type header.", "Inspect the document head for a meta charset declaration.", "Check international characters in a browser after updating."],
            final_url,
        ))
    elif response_charset and declared_charsets and response_charset not in declared_charsets:
        findings.append(_finding(
            "technical_seo", "HTTP and HTML character encoding declarations differ", "manual_review_required", "medium",
            f"HTTP charset={response_charset}; HTML meta charset value(s)={', '.join(sorted(declared_charsets))}. URL: {final_url}",
            "Different encoding declarations can cause inconsistent text decoding. Browser handling depends on the exact document and response.",
            "Align the HTTP Content-Type charset and HTML declaration, preferably using UTF-8, then inspect international characters in a browser.",
            ["Compare the final HTTP response header with the HTML meta declaration.", "Validate the page after aligning both declarations."],
            final_url,
        ))

    if parser.main_landmark_count == 0:
        findings.append(_finding(
            "accessibility", "Main content landmark not detected", "manual_review_required", "low",
            f"No <main> element was found in the inspected HTML source. URL: {final_url}",
            "A main landmark can help assistive-technology users navigate directly to primary page content. Some pages use other valid landmark patterns, so this observation requires contextual review.",
            "Review the page structure and add one appropriate main landmark around the primary content if no equivalent semantic landmark exists.",
            ["Inspect the page's landmark structure.", "Confirm there is a clear route to primary content for keyboard and screen-reader users."],
            final_url,
        ))

    # Validate embedded JSON-LD structured data syntax and flag Product entities without a name.
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
            if any(
                isinstance(item, str)
                and item.strip().rstrip("/").rsplit("/", 1)[-1].rsplit("#", 1)[-1].lower() == "product"
                for item in types
            ):
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
    products_without_description = sum(
        1 for product in product_entities
        if not (isinstance(product.get("description"), str) and product["description"].strip())
    )
    if products_without_description:
        findings.append(_finding(
            "structured_data", "Product structured data missing description",
            "verified", "low",
            f"Found {products_without_description} Product entity/entities without a non-empty description property. URL: {final_url}",
            "A concise, accurate product description can provide useful context for search systems and product features. This source check does not compare the description with visible page content or guarantee rich-result eligibility.",
            "Add a unique, accurate description to each affected Product entity that reflects the visible product details and avoids promotional or unsupported claims.",
            ["Inspect the description property on each Product entity.",
             "Compare it with the visible product description and selected variant.",
             "Validate the updated structured data."],
            final_url,
        ))
    products_without_image = 0
    for product in product_entities:
        image = product.get("image")
        image_values = image if isinstance(image, list) else [image]
        has_image = any(
            (isinstance(item, str) and item.strip())
            or (isinstance(item, dict) and any(
                isinstance(item.get(key), str) and item[key].strip()
                for key in ("url", "contentUrl")
            ))
            for item in image_values
        )
        if not has_image:
            products_without_image += 1
    if products_without_image:
        findings.append(_finding(
            "structured_data", "Product structured data missing image", "verified", "medium",
            f"Found {products_without_image} Product entity/entities without a usable image property. URL: {final_url}",
            "Product images help search engines understand the item and are part of common product rich-result requirements. This source check does not assess image accessibility, quality, or rich-result eligibility.",
            "Add one or more representative, crawlable product image URLs to each affected Product entity and ensure they show the actual product.",
            ["Inspect the image property on each Product entity in JSON-LD.",
             "Confirm each image URL loads publicly and matches the visible product or selected variant.",
             "Validate the structured data after updating it."],
            final_url,
        ))
    products_without_offers = sum(
        1 for product in product_entities
        if not (
            (isinstance(product.get("offers"), dict) and bool(product.get("offers")))
            or (isinstance(product.get("offers"), list) and any(
                isinstance(offer, dict) and bool(offer) for offer in product["offers"]
            ))
        )
    )
    if products_without_offers:
        findings.append(_finding(
            "structured_data", "Product structured data has no offer information",
            "verified", "low",
            f"Found {products_without_offers} Product entity/entities without an Offer or AggregateOffer object. URL: {final_url}",
            "Offer data can be important for product merchant listings and price-related search features. A Product entity may still be valid for other uses without offers, so this check does not claim that all Product markup requires pricing.",
            "If the page represents a purchasable item and merchant-listing visibility is intended, add an accurate Offer or AggregateOffer with current price and currency. Do not invent prices for products that are not directly offered on the page.",
            ["Inspect each Product entity and determine whether the page offers the item for purchase.",
             "For purchasable products, add accurate Offer or AggregateOffer properties that match the visible page.",
             "Validate the complete structured-data graph after updating it."],
            final_url,
        ))
    # Check price/currency signals only when Product JSON-LD is present. This is
    # a targeted source check, not a full Google rich-result eligibility validator.
    products_with_offers = 0
    offers_missing_price = 0
    offers_invalid_price_range = 0
    offers_missing_currency = 0
    offers_invalid_availability = 0
    offers_missing_availability = 0
    valid_availability = {
        "backorder", "discontinued", "in-store-only", "instoreonly",
        "limitedavailability", "made-to-order", "madetoorder",
        "online-only", "onlineonly", "outofstock", "presale",
        "preorder", "instock", "soldout",
    }
    for product in product_entities:
        raw_offers = product.get("offers")
        offers = raw_offers if isinstance(raw_offers, list) else [raw_offers]
        for offer in offers:
            if not isinstance(offer, dict):
                continue
            products_with_offers += 1
            def parse_price(value: Any) -> Decimal | None:
                # Reject booleans, non-numeric strings, negative values, NaN and infinity.
                if not isinstance(value, (str, int, float)) or isinstance(value, bool):
                    return None
                try:
                    parsed = Decimal(str(value).strip())
                except (InvalidOperation, ValueError):
                    return None
                return parsed if parsed.is_finite() and parsed >= 0 else None

            offer_types = offer.get("@type", [])
            offer_types = offer_types if isinstance(offer_types, list) else [offer_types]
            is_aggregate_offer = any(
                isinstance(value, str) and value.lower() == "aggregateoffer"
                for value in offer_types
            )
            if is_aggregate_offer:
                low_price = parse_price(offer.get("lowPrice"))
                high_price = parse_price(offer.get("highPrice"))
                # AggregateOffer uses a range; do not incorrectly require a scalar price.
                if low_price is None and high_price is None:
                    offers_missing_price += 1
                elif low_price is not None and high_price is not None and low_price > high_price:
                    offers_invalid_price_range += 1
            elif parse_price(offer.get("price")) is None:
                offers_missing_price += 1
            currency = offer.get("priceCurrency")
            if not (isinstance(currency, str) and re.fullmatch(r"[A-Za-z]{3}", currency.strip())):
                offers_missing_currency += 1
            availability = offer.get("availability")
            if availability is None or (isinstance(availability, str) and not availability.strip()):
                offers_missing_availability += 1
            else:
                if isinstance(availability, str):
                    token = availability.strip().rstrip("/").rsplit("/", 1)[-1]
                    token = re.sub(r"[^A-Za-z-]", "", token).lower()
                    if token not in valid_availability:
                        offers_invalid_availability += 1
                else:
                    offers_invalid_availability += 1

    if offers_missing_price:
        findings.append(_finding(
            "structured_data", "Product offers missing price", "verified", "medium",
            f"Found {offers_missing_price} Product Offer object(s) without a usable price property. URL: {final_url}",
            "A price is important for product offer information. This check verifies only the source property and does not assess sale-price consistency, availability, or rich-result eligibility.",
            "Provide the current, accurate price in each affected Offer and ensure it matches the visible product page and currency formatting.",
            ["Inspect each Product Offer in JSON-LD.", "Compare structured prices with the visible price and variant selection.", "Validate the page with a structured-data testing tool."],
            final_url,
        ))

    if offers_invalid_price_range:
        findings.append(_finding(
            "structured_data", "Aggregate product offer has an invalid price range",
            "verified", "medium",
            f"Found {offers_invalid_price_range} AggregateOffer object(s) where lowPrice exceeds highPrice. URL: {final_url}",
            "An aggregate offer's lower price should not exceed its upper price. This source check validates numeric ordering only and does not verify variant pricing or currency consistency.",
            "Correct lowPrice and highPrice so they reflect the actual minimum and maximum prices available on the page, using the same currency and current product variants.",
            ["Inspect lowPrice and highPrice on each AggregateOffer.", "Compare the range with purchasable variants shown on the page.", "Validate the structured data after correcting the range."],
            final_url,
        ))

    if offers_missing_availability:
        findings.append(_finding(
            "structured_data", "Product offers missing availability",
            "verified", "low",
            f"Found {offers_missing_availability} Product Offer object(s) without an availability property. URL: {final_url}",
            "Availability helps communicate whether a product can currently be purchased. This check detects a missing source property only; it does not verify real-time inventory or fulfillment.",
            "If the offer is purchasable, set availability to the accurate current Schema.org item-availability value, such as https://schema.org/InStock or https://schema.org/OutOfStock, and keep it synchronized with inventory.",
            ["Inspect availability on each Product Offer in JSON-LD.",
             "Compare the structured value with the visible stock status and actual inventory.",
             "Validate the updated structured data."],
            final_url,
        ))

    if offers_invalid_availability:
        findings.append(_finding(
            "structured_data", "Product offers have invalid availability",
            "verified", "low",
            f"Found {offers_invalid_availability} Product Offer object(s) with an unrecognized availability value. URL: {final_url}",
            "Availability should use a recognized Schema.org item-availability value so consumers can interpret the offer consistently. This check validates only the value's shape, not real inventory or fulfillment.",
            "Use the correct Schema.org availability value for the current offer, such as https://schema.org/InStock or https://schema.org/OutOfStock, and keep it synchronized with actual stock status.",
            ["Inspect availability on each Product Offer in JSON-LD.",
             "Compare the structured value with the visible stock status and actual inventory.",
             "Validate the updated structured data."],
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

    # Validate aggregate-rating structure only when a page publishes it.
    # This catches obvious source-data errors without claiming review authenticity.
    rating_issues = {"missing_value": 0, "invalid_value": 0, "out_of_range": 0, "invalid_count": 0}
    for product in product_entities:
        if "aggregateRating" not in product:
            continue
        rating = product.get("aggregateRating")
        if not isinstance(rating, dict):
            rating_issues["invalid_value"] += 1
            continue

        def parse_rating_number(value: Any) -> Decimal | None:
            if not isinstance(value, (str, int, float)) or isinstance(value, bool):
                return None
            try:
                number = Decimal(str(value).strip())
            except (InvalidOperation, ValueError):
                return None
            return number if number.is_finite() else None

        rating_value = parse_rating_number(rating.get("ratingValue"))
        if rating_value is None:
            rating_issues["missing_value"] += 1
            continue
        best_declared = "bestRating" in rating
        worst_declared = "worstRating" in rating
        best_rating = parse_rating_number(rating.get("bestRating")) if best_declared else Decimal("5")
        worst_rating = parse_rating_number(rating.get("worstRating")) if worst_declared else Decimal("1")
        # Invalid explicitly supplied bounds must not silently fall back to 1–5.
        if (
            (best_declared and best_rating is None)
            or (worst_declared and worst_rating is None)
            or best_rating is None
            or worst_rating is None
            or worst_rating >= best_rating
            or not (worst_rating <= rating_value <= best_rating)
        ):
            rating_issues["out_of_range"] += 1
        for count_key in ("ratingCount", "reviewCount"):
            if count_key in rating:
                raw_count = rating.get(count_key)
                try:
                    count_value = Decimal(str(raw_count).strip()) if not isinstance(raw_count, bool) else Decimal("-1")
                except (InvalidOperation, ValueError, AttributeError):
                    count_value = Decimal("-1")
                # A published count must describe at least one rating/review.
                if not count_value.is_finite() or count_value < 1 or count_value != count_value.to_integral_value():
                    rating_issues["invalid_count"] += 1
                    break

    rating_issue_count = sum(rating_issues.values())
    if rating_issue_count:
        details = []
        if rating_issues["missing_value"]:
            details.append(f'{rating_issues["missing_value"]} without a numeric ratingValue')
        if rating_issues["invalid_value"]:
            details.append(f'{rating_issues["invalid_value"]} with a non-object AggregateRating')
        if rating_issues["out_of_range"]:
            details.append(f'{rating_issues["out_of_range"]} with ratingValue outside the declared/default range')
        if rating_issues["invalid_count"]:
            details.append(f'{rating_issues["invalid_count"]} with a negative, non-integer, or non-numeric review/rating count')
        findings.append(_finding(
            "structured_data", "Product aggregate rating needs review",
            "verified", "medium" if rating_issues["out_of_range"] else "low",
            "AggregateRating source-data issues detected: " + "; ".join(details) + f". URL: {final_url}",
            "This check validates basic property shape and numeric bounds only. It cannot confirm that reviews are genuine, that the counts match the visible page, or that the page qualifies for a rich result.",
            "Publish AggregateRating only when it reflects genuine, visible review data. Use a numeric ratingValue within the declared worstRating/bestRating range and positive integer reviewCount or ratingCount values.",
            ["Compare the structured rating and counts with review information visible to customers.", "Remove or correct unsupported AggregateRating data.", "Validate the complete JSON-LD graph with a structured-data testing tool."],
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
    viewport_values = {
        key.strip().lower(): value.strip().lower()
        for token in parser.viewport.split(",")
        if "=" in token
        for key, value in [token.split("=", 1)]
    }
    if parser.viewport and (
        viewport_values.get("width") != "device-width"
        or viewport_values.get("initial-scale") != "1"
    ):
        findings.append(_finding(
            "mobile_ux", "Viewport configuration needs review",
            "manual_review_required", "low",
            f"Viewport declaration: {parser.viewport[:200]!r}; width=device-width: {viewport_values.get('width') == 'device-width'}; initial-scale=1: {viewport_values.get('initial-scale') == '1'}. URL: {final_url}",
            "A viewport declaration can influence the initial mobile layout, but this source check does not test responsive rendering, zoom, clipping, or touch usability.",
            "Review the viewport configuration against the site's intended responsive behavior. Do not disable user zoom; test representative narrow, tablet, and desktop widths in a real browser.",
            ["Inspect the page at 320, 360, 375, 390, and 414 CSS-pixel widths.", "Check portrait and landscape layouts, browser zoom, and horizontal overflow.", "Confirm the declaration does not restrict user scaling."],
            final_url,
        ))

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
    if parser.images_missing_alt:
        findings.append(_finding(
            "accessibility", "Images missing alt attributes", "verified", "medium",
            f"Found {parser.images_missing_alt} image(s) without an alt attribute among {parser.images} image(s). URL: {final_url}",
            "Images without alt attributes lack a text alternative in the HTML source. This can reduce accessibility for people using screen readers; decorative images should instead use an explicit empty alt attribute.",
            "Add concise, context-appropriate alt text to informative images and use alt=\"\" for purely decorative images.",
            ["Inspect each image reported in the page source.", "Decide whether each image conveys information or is decorative.", "Recheck the page with an accessibility checker and manual review."],
            final_url,
        ))
    if parser.images_empty_alt:
        findings.append(_finding(
            "accessibility", "Images have empty alt text", "verified", "low",
            f"Found {parser.images_empty_alt} image(s) with an explicitly empty alt attribute among {parser.images} image(s). URL: {final_url}",
            "An empty alt attribute is appropriate for decorative images but can hide meaningful product imagery from assistive technology if used incorrectly. Source inspection alone cannot determine image purpose.",
            "Review each affected image in context. Keep empty alt text for decorative images; provide descriptive alt text for product photos and other informative images.",
            ["Inspect each image with empty alt text in its visual context.", "Confirm product images have meaningful descriptions where needed.", "Recheck with an accessibility tool and manual review."],
            final_url,
        ))
    if parser.meta_robots_count > 1:
        findings.append(_finding(
            "technical_seo", "Multiple meta robots elements", "verified", "medium",
            f"Found {parser.meta_robots_count} meta name=robots elements in the returned HTML. URL: {final_url}",
            "Multiple robots declarations can make indexing directives harder to maintain and may combine restrictive instructions unexpectedly. This source check reports duplication; it does not infer the site's intended indexing policy.",
            "Review all robots meta elements, consolidate the intended directives into one clear declaration, and confirm no unintended noindex or nofollow instruction remains.",
            [
                "Inspect every meta name=robots element in the raw HTML.",
                "Compare the combined directives with the intended indexing policy.",
                "Check X-Robots-Tag response headers separately because they can also affect indexing.",
            ], final_url,
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
    if parser.meta_description_empty_count > 0:
        findings.append(_finding(
            "on_page_seo", "Empty meta description content", "verified", "low",
            f"Found {parser.meta_description_empty_count} empty meta description declaration(s) among {parser.meta_description_count} total on {final_url}.",
            "An empty meta description does not provide a page-specific summary in the source. Search engines may generate a snippet from page content; this check does not predict the displayed snippet.",
            "Remove empty description declarations and retain one accurate, page-specific non-empty description where appropriate.",
            ["Inspect all meta name=description elements in the raw HTML.", "Ensure empty declarations are removed and review the page snippet separately where search data is available."],
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
    canonical_is_valid = False
    canonical_parts = None
    if parser.canonical_href:
        try:
            canonical_target = urljoin(final_url, parser.canonical_href)
            canonical_parts = urlsplit(canonical_target)
            _ = canonical_parts.port
            canonical_is_valid = (
                canonical_parts.scheme.lower() in {"http", "https"}
                and bool(canonical_parts.hostname)
                and canonical_parts.username is None
                and canonical_parts.password is None
                and not canonical_parts.fragment
            )
        except (ValueError, UnicodeError):
            canonical_is_valid = False
        if not canonical_is_valid:
            findings.append(_finding(
                "technical_seo", "Canonical URL is malformed", "verified", "medium",
                f"Canonical href {parser.canonical_href[:200]!r} does not resolve to a clean absolute HTTP(S) URL without credentials or a fragment. Page URL: {final_url}",
                "A malformed canonical destination may be ignored or interpreted inconsistently by crawlers. Relative canonical URLs are allowed when they resolve to a valid absolute URL.",
                "Replace the canonical href with a valid absolute HTTP(S) URL, without embedded credentials or a fragment, and confirm it identifies the intended preferred page.",
                [
                    "Resolve the canonical href against the final page URL.",
                    "Confirm the destination uses HTTP or HTTPS, has a valid hostname, and contains no credentials or fragment.",
                    "Verify the destination is the intended canonical page and returns an appropriate response.",
                ], final_url,
            ))
    # A syntactically valid canonical URL can still point at a different host.
    # Cross-domain canonicals can be intentional, so report this as a review signal.
    if canonical_is_valid and parser.canonical_href:
        try:
            canonical_host = (canonical_parts.hostname or "").lower().rstrip(".")
            page_parts = urlsplit(final_url)
            page_host = (page_parts.hostname or "").lower().rstrip(".")
            canonical_port = canonical_parts.port or (443 if canonical_parts.scheme.lower() == "https" else 80)
            page_port = page_parts.port or (443 if page_parts.scheme.lower() == "https" else 80)
            canonical_is_cross_origin = canonical_host != page_host or canonical_port != page_port
        except (ValueError, UnicodeError):
            canonical_is_cross_origin = False
        if canonical_is_cross_origin:
            findings.append(_finding(
                "technical_seo", "Canonical points to a different origin", "manual_review_required", "medium",
                f"Page host is {page_host or '(unknown)'!r}, while canonical host is {canonical_host or '(unknown)'!r}. Page URL: {final_url}",
                "A cross-origin canonical can be valid for intentionally syndicated or duplicate content, but an accidental host mismatch may consolidate search signals to the wrong site. This source check cannot determine the site's intended canonical strategy.",
                "Confirm that cross-domain canonicalization is intentional. If this page should be canonical to itself or to another page on the same site, correct the href and verify redirects, sitemap entries, and internal links agree.",
                [
                    "Compare the canonical destination with the preferred URL for this page.",
                    "Open the canonical target and confirm it represents the same or intentionally preferred content.",
                    "Check whether cross-domain canonicalization is part of an approved migration or syndication setup.",
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
        "permissions-policy": ("Permissions-Policy", "low"),
    }
    for header, (label, severity) in security_headers.items():
        value = headers.get(header)
        findings.append(_finding(
            "security_headers", label,
            "verified" if value else "manual_review_required",
            "info" if value else severity,
            f"Header value: {value[:240]}" if value else f"Response did not include {header}.",
            (
                f"{label} is present in the sampled response. It is one browser-side control; "
                "overall security also depends on application behavior, deployment configuration, and other controls."
                if value else
                f"{label} was not present in the sampled response. Whether that is a meaningful gap depends "
                "on the site's architecture, required browser behavior, and threat model."
            ),
            f"Review whether {header} is appropriate for this site and configure it safely; test for compatibility before enforcing restrictive policies.",
            [f"Inspect the response headers with browser DevTools or a reputable header scanner.", "Review configuration and test critical site flows."],
            final_url,
        ))
    return findings


def inspect_discovery_contents(category: str, body: str, source_url: str) -> list[AuditFinding]:
    """Perform bounded semantic checks on robots.txt and sitemap.xml content."""
    if category == "robots_txt":
        directives: list[tuple[str, str]] = []
        wildcard_groups: list[dict[str, Any]] = []
        current_agents: list[str] = []
        current_rules: list[tuple[str, str]] = []
        group_has_rule = False

        def save_group() -> None:
            if current_agents:
                wildcard_groups.append({
                    "agents": list(current_agents),
                    "rules": list(current_rules),
                })

        for raw_line in body.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            if not key:
                continue
            if key == "user-agent":
                # Consecutive User-agent lines share a group until a rule
                # has appeared; a later User-agent starts a new group.
                if group_has_rule:
                    save_group()
                    current_agents = []
                    current_rules = []
                    group_has_rule = False
                if value:
                    current_agents.append(value.lower())
                    directives.append((key, value))
                continue
            if not value:
                continue
            directives.append((key, value))
            if key in {"allow", "disallow", "crawl-delay", "sitemap"}:
                if key != "sitemap" and current_agents:
                    current_rules.append((key, value))
                    group_has_rule = True
                elif key == "sitemap":
                    # Sitemap is a global declaration, not a group rule.
                    pass
        save_group()

        user_agents = sum(1 for key, _ in directives if key == "user-agent")
        disallow_count = sum(1 for key, _ in directives if key == "disallow")
        allow_count = sum(1 for key, _ in directives if key == "allow")
        sitemap_count = sum(1 for key, _ in directives if key == "sitemap")
        findings = [_finding(
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
        wildcard_blocks_site = any(
            "*" in group["agents"]
            and any(key == "disallow" and value.strip() == "/" for key, value in group["rules"])
            for group in wildcard_groups
        )
        if wildcard_blocks_site:
            findings.append(_finding(
                category, "robots.txt may block the entire site", "verified", "high",
                f"A User-agent: * group contains Disallow: /. Source: {source_url}",
                "This rule asks compliant crawlers to avoid crawling the site's URL paths. If published on a live storefront unintentionally, product and category pages may become unavailable for crawling. Robots directives do not themselves guarantee deindexing, and the rule may be intentional for staging or private environments.",
                "Confirm the rule is intentional. For a public storefront that should be crawled, remove or narrow the wildcard Disallow rule while preserving any intentional private-path restrictions.",
                [
                    "Inspect the complete robots.txt group and any Allow exceptions.",
                    "Confirm whether the site is production, staging, or intentionally private.",
                    "Use the relevant search-engine robots tester to check representative product and category URLs.",
                ],
                source_url,
            ))
        return findings

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
        findings = [_finding(
            category, "Sitemap XML structure", status, severity,
            f"Root element: {root_name or 'missing'}; loc entries: {len(loc_values)}; "
            f"entries without an absolute HTTP(S) URL: {invalid_locations}.",
            "This checks basic XML shape and URL format only. It does not prove that listed URLs are canonical, indexable, current, or accepted by a search engine.",
            "Use a urlset for URL entries or sitemapindex for child sitemap locations. Remove invalid entries and verify that listed URLs return the intended canonical pages.",
            ["Validate the XML with a sitemap validator.", "Inspect search-engine sitemap status and sample listed URLs."],
            source_url,
        )]
        normalized_locations = [value for value in loc_values if value]
        duplicate_locations = len(normalized_locations) - len(set(normalized_locations))
        if duplicate_locations:
            findings.append(_finding(
                category, "Duplicate URLs in sitemap",
                "verified", "low",
                f"Found {duplicate_locations} duplicate loc entr(y/ies) among {len(normalized_locations)} non-empty sitemap loc entries. Source: {source_url}",
                "Repeated URLs add unnecessary sitemap entries and can obscure the quality of the submitted URL set. Duplicate detection is exact-string based; it does not treat redirects, URL parameters, or canonical equivalents as duplicates.",
                "Remove exact duplicate loc entries and retain the intended canonical URL for each page. Then validate and resubmit the sitemap if appropriate.",
                [
                    "Compare repeated loc values in the published XML.",
                    "Check that each retained URL is canonical and intended for indexing.",
                    "Validate the updated sitemap and review its search-engine processing status.",
                ], source_url,
            ))
        return findings
    return []


MAX_CRAWL_PAGES = 12
MAX_DISCOVERED_LINKS = 250


def _same_origin(left: str, right: str) -> bool:
    """Compare web origins conservatively; scheme, hostname, and effective port must match."""
    try:
        a, b = urlsplit(left), urlsplit(right)
        a_port = a.port or (443 if a.scheme.lower() == "https" else 80)
        b_port = b.port or (443 if b.scheme.lower() == "https" else 80)
        return (
            a.scheme.lower() == b.scheme.lower()
            and (a.hostname or "").lower().rstrip(".") == (b.hostname or "").lower().rstrip(".")
            and a_port == b_port
        )
    except ValueError:
        return False


def _crawl_candidate(href: str, page_url: str, origin_url: str) -> str | None:
    """Resolve a link and keep only bounded, same-origin HTML-page candidates."""
    raw = (href or "").strip()
    if not raw or len(raw) > 2048 or raw.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
        return None
    try:
        absolute = urljoin(page_url, raw)
        parsed = urlsplit(absolute)
        if parsed.scheme.lower() not in {"http", "https"} or not _same_origin(absolute, origin_url):
            return None
        candidate = normalize_target(urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, "")))
        path = urlsplit(candidate).path.lower()
        if path.endswith((
            ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".css", ".js",
            ".pdf", ".zip", ".xml", ".json", ".woff", ".woff2", ".ttf", ".mp4", ".webm",
        )):
            return None
        return candidate
    except (ValueError, UnicodeError):
        return None


def extract_same_origin_sitemap_urls(xml_body: str, sitemap_url: str, origin_url: str) -> tuple[list[str], list[str]]:
    """Extract a bounded set of safe same-origin URLs from a fetched sitemap URL set."""
    urls: list[str] = []
    limitations: list[str] = []
    try:
        root = ET.fromstring(xml_body)
    except (ET.ParseError, ValueError):
        return [], ["Sitemap URL discovery was skipped because the sitemap XML could not be parsed."]
    root_name = root.tag.rsplit("}", 1)[-1].lower()
    if root_name == "sitemapindex":
        return [], ["Sitemap URL discovery found a sitemap index; nested sitemap files are not followed in this bounded crawl."]
    if root_name != "urlset":
        return [], ["Sitemap URL discovery was skipped because the XML root was not a urlset."]
    seen: set[str] = set()
    loc_count = 0
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1].lower() != "loc" or not element.text:
            continue
        loc_count += 1
        if loc_count > MAX_DISCOVERED_LINKS:
            limitations.append(f"Sitemap URL discovery was capped at {MAX_DISCOVERED_LINKS} loc entries.")
            break
        raw_url = element.text.strip()
        try:
            candidate = normalize_target(raw_url)
        except (ValueError, TypeError):
            limitations.append("One or more sitemap locations were excluded because they were not valid supported public HTTP(S) URLs.")
            continue
        if not _same_origin(candidate, origin_url):
            limitations.append("One or more sitemap locations on another origin were excluded from this crawl.")
            continue
        # Sitemap entries are absolute by convention; require the source to be
        # same-origin too, then normalize through the same candidate filter.
        candidate = _crawl_candidate(candidate, sitemap_url, origin_url)
        if candidate and candidate not in seen:
            seen.add(candidate)
            urls.append(candidate)
    return urls, list(dict.fromkeys(limitations))


async def crawl_same_origin_pages(
    client: aiohttp.ClientSession, homepage_url: str, homepage_html: str,
    max_pages: int = MAX_CRAWL_PAGES, seed_urls: list[str] | None = None,
    outcome_records: list[CheckOutcome] | None = None,
) -> tuple[list[str], list[AuditFinding], list[str]]:
    """Crawl a small same-origin HTML sample and report page-specific source findings."""
    checked: list[str] = []
    findings: list[AuditFinding] = []
    limitations: list[str] = []
    origin = homepage_url
    queue: list[tuple[str, str]] = []
    seen = {homepage_url}
    parser = _PageParser()
    try:
        parser.feed(homepage_html)
    except Exception as exc:
        if outcome_records is not None:
            from datetime import datetime, timezone
            outcome_records.append(CheckOutcome(
                check_id="crawl.homepage_link_discovery",
                category="crawlability",
                page_url=homepage_url,
                outcome="error",
                observed_at_utc=datetime.now(timezone.utc).isoformat(),
                method="bounded static HTML link parsing",
                evidence=(
                    f"Homepage link parsing failed with {type(exc).__name__}; "
                    "internal-link discovery and dependent page checks were not completed."
                ),
                evidence_ref="crawl.homepage_link_discovery",
            ))
        return checked, findings, ["Same-origin crawling was skipped because homepage links could not be parsed safely."]
    # Sitemap URLs are lower-priority seeds; the same origin, URL, and page
    # budgets apply to them as to ordinary homepage links.
    for seed in (seed_urls or [])[:MAX_DISCOVERED_LINKS]:
        candidate = _crawl_candidate(seed, homepage_url, origin)
        if candidate and candidate not in seen:
            seen.add(candidate)
            queue.append((candidate, "sitemap"))
    for href in parser.link_hrefs[:MAX_DISCOVERED_LINKS]:
        candidate = _crawl_candidate(href, homepage_url, origin)
        if candidate and candidate not in seen:
            seen.add(candidate)
            queue.append((candidate, homepage_url))

    attempted = 0
    while queue and attempted + 1 < max_pages:
        page_url, _parent = queue.pop(0)
        attempted += 1
        try:
            status, body, headers, final_url = await _safe_get(
                client, page_url, allowed_origin=origin
            )
            if not _same_origin(final_url, origin):
                if outcome_records is not None:
                    from datetime import datetime, timezone
                    outcome_records.append(CheckOutcome(
                        check_id="crawl.discovered_url_redirect_scope",
                        category="crawlability",
                        page_url=page_url,
                        outcome="not_assessed",
                        observed_at_utc=datetime.now(timezone.utc).isoformat(),
                        method="bounded redirect destination origin comparison",
                        evidence=(
                            "A discovered same-origin URL redirected outside the audited origin; "
                            "the destination was excluded from page analysis under the same-origin crawl policy. "
                            "No destination-page outcome is inferred."
                        ),
                        evidence_ref=page_url,
                    ))
                limitations.append("A same-origin link redirected to another origin and was excluded from page analysis.")
                continue
            if final_url in checked or final_url == homepage_url:
                continue
            if not (200 <= status < 300):
                if outcome_records is not None:
                    from datetime import datetime, timezone
                    outcome_records.append(CheckOutcome(
                        check_id=(
                            "discovery.sitemap_xml.listed_url_status"
                            if _parent == "sitemap" else "crawl.discovered_url_http_status"
                        ),
                        category="sitemap_xml" if _parent == "sitemap" else "crawlability",
                        page_url=final_url,
                        outcome="issue",
                        observed_at_utc=datetime.now(timezone.utc).isoformat(),
                        method="bounded same-origin HTTP status inspection",
                        evidence=(
                            f"Discovered URL {page_url} returned HTTP {status}; "
                            "authentication, bot rules, and transient errors can affect this request. "
                            "This is the observed response for this audit request, not proof of search-engine treatment."
                        ),
                        evidence_ref=final_url,
                    ))
                findings.append(_finding(
                    "sitemap_xml" if _parent == "sitemap" else "crawl",
                    "Sitemap-listed URL returned a non-success HTTP status" if _parent == "sitemap"
                    else "Discovered page returned a non-success HTTP status",
                    "verified", "high" if status >= 500 else "medium",
                    f"Same-origin link {page_url} returned HTTP {status}; final URL: {final_url}.",
                    "A discovered internal link did not return a successful response to this audit request. Authentication, bot rules, and transient errors can affect the result.",
                    "Check the URL in a browser, confirm its intended status, and repair internal links or server responses where appropriate.",
                    ["Open the URL without an authenticated session.", "Confirm the intended HTTP status and redirect target."],
                    final_url,
                ))
                checked.append(final_url)
                continue
            content_type = headers.get("content-type", "").lower()
            is_html = "text/html" in content_type or "application/xhtml+xml" in content_type
            if outcome_records is not None and _parent == "sitemap":
                from datetime import datetime, timezone
                outcome_records.append(CheckOutcome(
                    check_id="discovery.sitemap_xml.listed_url_status",
                    category="sitemap_xml", page_url=final_url,
                    outcome="pass" if is_html else "warning",
                    observed_at_utc=datetime.now(timezone.utc).isoformat(),
                    method="bounded HTTP status and content-type inspection of a same-origin sitemap-listed URL",
                    evidence=f"Sitemap-listed URL {page_url} returned HTTP {status}; content type: {content_type or 'not declared'}. A successful response does not prove canonicality or indexability.",
                    evidence_ref=final_url,
                ))
            if not is_html:
                if outcome_records is not None:
                    from datetime import datetime, timezone
                    outcome_records.append(CheckOutcome(
                        check_id="crawl.discovered_url_html_content_type",
                        category="crawlability",
                        page_url=final_url,
                        outcome="warning",
                        observed_at_utc=datetime.now(timezone.utc).isoformat(),
                        method="bounded same-origin HTTP content-type inspection",
                        evidence=(
                            f"Discovered URL returned HTTP {status} with content type "
                            f"{content_type or 'not declared'}; HTML-specific checks were not run. "
                            "Non-HTML responses may be intentional."
                        ),
                        evidence_ref=final_url,
                    ))
                continue
            checked.append(final_url)
            if outcome_records is not None:
                from datetime import datetime, timezone
                outcome_records.extend(record_homepage_outcomes(
                    body, final_url, headers, datetime.now(timezone.utc).isoformat()
                ))
            page_findings = inspect_homepage(body, final_url, headers)
            # Reuse source checks on internal pages, but label findings accurately.
            for finding in page_findings:
                if "Homepage" in finding.title:
                    finding.title = finding.title.replace("Homepage", "Page")
            findings.extend(page_findings)
            page_parser = _PageParser()
            try:
                page_parser.feed(body)
            except Exception:
                limitations.append(f"Links on {final_url} could not be parsed; that page was still counted as fetched.")
                continue
            for href in page_parser.link_hrefs[:MAX_DISCOVERED_LINKS]:
                candidate = _crawl_candidate(href, final_url, origin)
                if candidate and candidate not in seen and len(seen) < MAX_DISCOVERED_LINKS:
                    seen.add(candidate)
                    queue.append((candidate, final_url))
        except Exception as exc:
            if outcome_records is not None:
                from datetime import datetime, timezone
                outcome_records.append(CheckOutcome(
                    check_id=(
                        "discovery.sitemap_xml.listed_url_status"
                        if _parent == "sitemap" else "crawl.discovered_url_fetch"
                    ),
                    category="sitemap_xml" if _parent == "sitemap" else "crawlability",
                    page_url=page_url,
                    outcome="error",
                    observed_at_utc=datetime.now(timezone.utc).isoformat(),
                    method="bounded same-origin page fetch failed before reliable status evaluation",
                    evidence=f"Request failed with {type(exc).__name__}; no URL status, HTML quality, or indexability conclusion is inferred.",
                    evidence_ref=page_url,
                ))
            findings.append(_finding(
                "crawl", "Discovered page could not be inspected", "not_tested", "info",
                f"Safe fetch of {page_url} stopped: {type(exc).__name__}: {str(exc)[:180]}",
                "The page was discovered in a same-origin link but could not be fetched reliably; this is not proof that the page is broken for normal visitors.",
                "Check the URL and server response, then rerun the audit.",
                ["Open the URL in a browser.", "Review redirect, TLS, DNS, and access-control behavior."],
                page_url,
            ))
    if queue:
        limitations.append(f"Same-origin crawl budget reached: inspected at most {max_pages} page responses including the homepage; remaining discovered URLs were not checked.")
    limitations.append("Crawl coverage is a bounded sample of discoverable same-origin links, not a complete inventory of product, category, checkout, or JavaScript-rendered routes.")
    return checked, findings, limitations


async def run_phase_one_checks(target: str) -> AuditCheckResult:
    """Run bounded, unauthenticated checks against a public site's homepage and common files."""
    from datetime import datetime, timezone

    normalized = normalize_target(target)
    parsed = urlsplit(normalized)
    findings: list[AuditFinding] = []
    pages_checked: list[str] = []
    check_outcomes: list[CheckOutcome] = []
    limitations = [
        "A bounded same-origin sample of up to 12 page responses is checked alongside common discovery files; this is not a full-site crawl.",
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
        sitemap_cache: tuple[int, str, dict[str, str], str] | None = None
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
                observed_at_utc = datetime.now(timezone.utc).isoformat()
                check_outcomes.extend(record_homepage_outcomes(html, final_url, headers, observed_at_utc))
                findings.extend(inspect_homepage(html, final_url, headers))
                # Fetch the conventional sitemap once and reuse its response both for
                # semantic reporting and as bounded seeds for the page crawl.
                sitemap_url = urljoin(f"{urlsplit(final_url).scheme}://{urlsplit(final_url).netloc}/", "sitemap.xml")
                sitemap_seeds: list[str] = []
                try:
                    sitemap_cache = await _safe_get(client, sitemap_url, allowed_origin=final_url)
                    sitemap_status, sitemap_body, sitemap_headers, sitemap_final_url = sitemap_cache
                    if 200 <= sitemap_status < 300:
                        sitemap_type = sitemap_headers.get("content-type", "").lower()
                        if not sitemap_type or "xml" in sitemap_type or "text/plain" in sitemap_type:
                            sitemap_seeds, sitemap_seed_limits = extract_same_origin_sitemap_urls(
                                sitemap_body, sitemap_final_url, final_url
                            )
                            limitations.extend(sitemap_seed_limits)
                        else:
                            limitations.append("Sitemap URL discovery was skipped because the sitemap response did not advertise an XML-compatible content type.")
                except Exception as sitemap_exc:
                    limitations.append(f"Sitemap URL discovery could not fetch the conventional sitemap safely ({type(sitemap_exc).__name__}).")
                # Crawl a small same-origin sample; sitemap seeds share the same strict page budget.
                crawled_pages, crawl_findings, crawl_limitations = await crawl_same_origin_pages(
                    client, final_url, html, max_pages=MAX_CRAWL_PAGES,
                    seed_urls=sitemap_seeds, outcome_records=check_outcomes,
                )
                pages_checked.extend(crawled_pages)
                findings.extend(crawl_findings)
                limitations.extend(crawl_limitations)
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
                if filename == "sitemap.xml" and sitemap_cache is not None:
                    status, body, _, final_url = sitemap_cache
                else:
                    status, body, _, final_url = await _safe_get(client, file_url)
                observed_at_utc = datetime.now(timezone.utc).isoformat()
                check_id = "discovery." + category + ".availability"
                if 200 <= status < 300:
                    check_outcomes.append(CheckOutcome(
                        check_id=check_id, category=category, page_url=final_url,
                        outcome="pass", observed_at_utc=observed_at_utc,
                        method="bounded public HTTP GET and status inspection",
                        evidence=f"GET {final_url} returned HTTP {status}; response size {len(body.encode('utf-8'))} bytes.",
                        evidence_ref=final_url,
                    ))
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
                    content_findings = inspect_discovery_contents(category, body, final_url)
                    findings.extend(content_findings)
                    # Record content-level outcomes separately from HTTP availability.
                    # A successful GET must never be treated as proof that file content is valid.
                    if category == "robots_txt":
                        summary = next((item for item in content_findings if item.title == "robots.txt directive summary"), None)
                        if summary is not None:
                            agent_match = re.search(r":\s*(\d+)\s+User-agent\b", summary.evidence)
                            has_agents = bool(agent_match and int(agent_match.group(1)) > 0)
                            check_outcomes.append(CheckOutcome(
                                check_id="discovery.robots_txt.directives",
                                category=category, page_url=final_url,
                                outcome="pass" if has_agents else "warning",
                                observed_at_utc=observed_at_utc,
                                method="bounded line-based robots.txt directive inspection",
                                evidence=summary.evidence + " This is a lightweight syntax signal, not a complete robots protocol validation.",
                                evidence_ref=final_url,
                            ))
                        blocking = next((item for item in content_findings if item.title == "robots.txt may block the entire site"), None)
                        check_outcomes.append(CheckOutcome(
                            check_id="discovery.robots_txt.wildcard_block",
                            category=category, page_url=final_url,
                            outcome="issue" if blocking is not None else "pass",
                            observed_at_utc=observed_at_utc,
                            method="inspection of parsed User-agent: * group and Disallow: / directive",
                            evidence=(
                                blocking.evidence if blocking is not None else
                                "No parsed User-agent: * group with an exact Disallow: / directive was detected. "
                                "This does not validate every robots rule or prove that important URLs are crawlable."
                            ),
                            evidence_ref=final_url,
                        ))
                    elif category == "sitemap_xml":
                        parse_finding = next((item for item in content_findings if item.title == "Sitemap XML parsing"), None)
                        structure = next((item for item in content_findings if item.title == "Sitemap XML structure"), None)
                        duplicate = next((item for item in content_findings if item.title == "Duplicate URLs in sitemap"), None)
                        if parse_finding is not None:
                            check_outcomes.append(CheckOutcome(
                                check_id="discovery.sitemap_xml.parseability",
                                category=category, page_url=final_url, outcome="issue",
                                observed_at_utc=observed_at_utc,
                                method="Python XML parser on bounded fetched sitemap response",
                                evidence=parse_finding.evidence,
                                evidence_ref=final_url,
                            ))
                        else:
                            # Reaching the structure finding means XML parsing completed;
                            # keep parseability separate from semantic sitemap quality.
                            check_outcomes.append(CheckOutcome(
                                check_id="discovery.sitemap_xml.parseability",
                                category=category, page_url=final_url, outcome="pass",
                                observed_at_utc=observed_at_utc,
                                method="Python XML parser on bounded fetched sitemap response",
                                evidence="The response parsed as well-formed XML. Sitemap semantics and search-engine acceptance are assessed separately.",
                                evidence_ref=final_url,
                            ))
                        if structure is not None:
                            structure_outcome = "pass" if structure.status == "verified" else "warning"
                            check_outcomes.append(CheckOutcome(
                                check_id="discovery.sitemap_xml.structure",
                                category=category, page_url=final_url, outcome=structure_outcome,
                                observed_at_utc=observed_at_utc,
                                method="XML root, loc-entry presence, and absolute HTTP(S) URL shape inspection",
                                evidence=structure.evidence + " Canonicality, indexability, and search-engine acceptance are not established.",
                                evidence_ref=final_url,
                            ))
                        if duplicate is not None:
                            check_outcomes.append(CheckOutcome(
                                check_id="discovery.sitemap_xml.duplicate_urls",
                                category=category, page_url=final_url, outcome="issue",
                                observed_at_utc=observed_at_utc,
                                method="exact-string duplicate detection over non-empty sitemap loc entries",
                                evidence=duplicate.evidence,
                                evidence_ref=final_url,
                            ))
                        elif structure is not None:
                            check_outcomes.append(CheckOutcome(
                                check_id="discovery.sitemap_xml.duplicate_urls",
                                category=category, page_url=final_url, outcome="pass",
                                observed_at_utc=observed_at_utc,
                                method="exact-string duplicate detection over non-empty sitemap loc entries",
                                evidence="No exact-string duplicate non-empty loc entries were detected. This does not establish URL canonicality or indexability.",
                                evidence_ref=final_url,
                            ))
                    elif category == "llms_txt":
                        text_lines = [line.strip() for line in body.splitlines() if line.strip()]
                        looks_like_markdown = bool(text_lines) and any(line.startswith("#") for line in text_lines)
                        format_evidence = (
                            f"Non-empty lines: {len(text_lines)}; Markdown heading present: {looks_like_markdown}. "
                            "This is only a lightweight format signal for a proposed convention, not a ranking or discovery assessment."
                        )
                        check_outcomes.append(CheckOutcome(
                            check_id="discovery.llms_txt.basic_format",
                            category=category, page_url=final_url,
                            outcome="pass" if looks_like_markdown else "warning",
                            observed_at_utc=observed_at_utc,
                            method="basic non-empty text and Markdown heading signal inspection",
                            evidence=format_evidence,
                            evidence_ref=final_url,
                        ))
                        if not looks_like_markdown:
                            findings.append(_finding(
                                category, "llms.txt basic format needs review",
                                "manual_review_required", "low",
                                format_evidence + f" Source: {final_url}",
                                "llms.txt is a proposed convention rather than a guaranteed indexing, ranking, or AI-citation control. This simple check only looks for a non-empty response with a Markdown heading.",
                                "If you choose to publish llms.txt, review its content for accuracy and consider using a concise Markdown structure with a heading and relevant public resources. Do not publish confidential or access-restricted URLs.",
                                ["Review the public file content.", "Confirm all listed resources are accurate, intended to be public, and current."],
                                final_url,
                            ))
                else:
                    # Only a clear 404 supports a finding that the conventional file is
                    # absent. Access-denied, rate-limit, and server-error responses do
                    # not prove absence and must not trigger a publish-file recommendation.
                    is_not_found = status == 404
                    check_outcomes.append(CheckOutcome(
                        check_id="discovery." + category + ".availability",
                        category=category, page_url=final_url,
                        outcome=("issue" if is_not_found and category != "llms_txt" else "warning"),
                        observed_at_utc=datetime.now(timezone.utc).isoformat(),
                        method="bounded public HTTP GET and status inspection",
                        evidence=f"GET {final_url} returned HTTP {status}; status alone does not establish configuration correctness.",
                        evidence_ref=final_url,
                    ))
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
                check_outcomes.append(CheckOutcome(
                    check_id="discovery." + category + ".availability",
                    category=category, page_url=file_url, outcome="error",
                    observed_at_utc=datetime.now(timezone.utc).isoformat(),
                    method="bounded public HTTP GET; request failed before reliable status/content evaluation",
                    evidence=f"Request failed safely with {type(exc).__name__}; no availability conclusion is inferred.",
                    evidence_ref=file_url,
                ))
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
        "indexing",
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
        check_outcomes=check_outcomes,
    )
