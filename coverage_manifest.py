"""Transparent audit coverage summaries; never treat absent findings as successful checks."""
from __future__ import annotations

from collections import Counter
import hashlib
from typing import Any
from urllib.parse import urlsplit, urlunsplit

# Mirrors the agreed requirements categories. A category counts as observed only when
# this run emits at least one finding in that category. This is deliberately conservative:
# one signal does not mean every check within the category was executed.
REQUIRED_AUDIT_CATEGORIES: tuple[tuple[str, str], ...] = (
    ("technical_seo", "Technical SEO and on-page signals"),
    ("robots_txt", "robots.txt"),
    ("sitemap_xml", "XML sitemap"),
    ("llms_txt", "llms.txt convention"),
    ("indexing", "Google indexing status"),
    ("security_transport", "SSL/TLS and transport"),
    ("security_headers", "Security headers"),
    ("security_exposure", "Public exposure probes"),
    ("performance", "Performance / PageSpeed"),
    ("accessibility", "Accessibility / WCAG signals"),
    ("aria", "ARIA and accessible names"),
    ("trust", "Trust signals"),
    ("pixel_analytics", "Pixel and analytics diagnostics"),
    ("mobile_ux", "Mobile UX"),
    ("ecommerce", "E-commerce product/category signals"),
    ("structured_data", "Structured data"),
    ("international_seo", "International SEO / hreflang"),
    ("backlink_competitor", "Backlink and competitor datasets"),
    ("content_quality", "Content quality"),
    ("conversion_paid_traffic", "Conversion and paid-traffic waste"),
    ("dependency_advisory", "Target-side dependency advisories"),
)

CATEGORY_ALIASES: dict[str, tuple[str, ...]] = {
    "technical_seo": ("technical_seo", "on_page_seo", "indexability"),
    "indexing": ("indexing",),
    "aria": ("aria_alt_text",),
    "trust": ("trust_inspector",),
    "ecommerce": ("ecommerce_category",),
    "dependency_advisory": ("security_dependency",),
    "content_quality": ("duplicate_content",),
}


def build_coverage_manifest(
    *,
    target_url: str,
    pages_checked: list[str],
    findings: list[Any],
    limitations: list[str],
) -> dict[str, Any]:
    """Build category-level evidence coverage, not a false per-check success percentage."""
    raw_counts = Counter(str(getattr(item, "category", "unknown")) for item in findings)
    observed: list[dict[str, Any]] = []
    not_proven: list[dict[str, Any]] = []
    for category, label in REQUIRED_AUDIT_CATEGORIES:
        accepted = CATEGORY_ALIASES.get(category, (category,))
        count = sum(raw_counts.get(name, 0) for name in accepted)
        entry = {
            "category": category,
            "label": label,
            "status": "observed" if count else "not_proven",
            "findings_in_category": count,
        }
        (observed if count else not_proven).append(entry)

    total = len(REQUIRED_AUDIT_CATEGORIES)
    recorded_observations = []
    for finding in findings:
        category = str(getattr(finding, "category", "unknown"))
        title = str(getattr(finding, "title", "Untitled check"))
        source_url = getattr(finding, "source_url", None)
        safe_source_url = None
        if source_url:
            try:
                parts = urlsplit(str(source_url))
                if parts.scheme in {"http", "https"} and parts.hostname:
                    host = parts.hostname.lower()
                    if ":" in host and not host.startswith("["):
                        host = f"[{host}]"
                    port = parts.port
                    if port and port not in (80, 443):
                        host = f"{host}:{port}"
                    safe_source_url = urlunsplit((parts.scheme.lower(), host, parts.path or "/", "", ""))
            except ValueError:
                safe_source_url = None
        identity = "|".join((category, title, safe_source_url or ""))
        recorded_observations.append({
            "check_id": hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16],
            "category": category,
            "title": title,
            "status": str(getattr(finding, "status", "unknown")),
            "severity": str(getattr(finding, "severity", "info")),
            "source_url": safe_source_url,
        })

    return {
        "schema_version": 1,
        "coverage_level": "category_signal_coverage_not_individual_check_coverage",
        "target_url": target_url,
        "pages_checked": list(dict.fromkeys(pages_checked)),
        "pages_checked_count": len(set(pages_checked)),
        "findings_total": len(findings),
        "finding_status_counts": dict(Counter(str(getattr(item, "status", "unknown")) for item in findings)),
        "finding_category_counts": dict(raw_counts),
        "recorded_observations": recorded_observations,
        "recorded_observations_count": len(recorded_observations),
        "required_categories": total,
        "categories_with_observed_evidence": len(observed),
        "categories_not_proven": len(not_proven),
        "category_signal_coverage_pct": round(100 * len(observed) / total, 1) if total else None,
        "observed_categories": observed,
        "not_proven_categories": not_proven,
        "limitations": list(dict.fromkeys(limitations)),
        "important_note": (
            "This percentage measures categories with at least one recorded signal only. "
            "It does not prove that every check inside a category ran or passed. "
            "Categories without findings are not counted as passes. Google indexing, "
            "field Core Web Vitals, full WCAG conformance, complete software composition "
            "analysis, live event attribution, and measured CPC/ROAS/revenue impact require "
            "additional authorized data or separate testing."
        ),
    }
