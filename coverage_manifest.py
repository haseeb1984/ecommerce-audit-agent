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
    ("crawlability", "Bounded crawl and discovery"),
    ("broken_internal_links", "Internal-link response checks"),
    ("robots_txt", "robots.txt"),
    ("sitemap_xml", "XML sitemap"),
    ("llms_txt", "llms.txt convention"),
    ("indexability", "Public indexability signals"),
    ("indexing", "Google indexing status"),
    ("security_transport", "SSL/TLS and transport"),
    ("security_headers", "Security headers"),
    ("security_exposure", "Public exposure probes"),
    ("security_cookies", "Cookie security attributes"),
    ("security_api_documentation", "Public API/documentation exposure"),
    ("security_baseline", "General passive security signals"),
    ("performance", "Performance / PageSpeed"),
    ("accessibility", "Accessibility / WCAG signals"),
    ("aria", "ARIA and accessible names"),
    ("aria_alt_text", "ARIA and image-alt source signals"),
    ("trust", "Trust signals"),
    ("pixel_analytics", "Pixel and analytics diagnostics"),
    ("mobile_ux", "Mobile UX"),
    ("ecommerce", "E-commerce product/category signals"),
    ("structured_data", "Structured data"),
    ("international_seo", "International SEO / hreflang"),
    ("backlink_competitor", "Backlink and competitor datasets"),
    ("content_quality", "Content quality / duplicate-content signals"),
    ("conversion_paid_traffic", "Conversion and paid-traffic waste"),
    ("dependency_advisory", "Target-side dependency advisories"),
)

CATEGORY_ALIASES: dict[str, tuple[str, ...]] = {
    "technical_seo": ("technical_seo", "on_page_seo"),
    "crawlability": ("crawl",),
    "indexing": ("indexing",),
    "trust": ("trust_inspector",),
    "ecommerce": ("ecommerce_category",),
    "security_baseline": ("security",),
    "dependency_advisory": ("security_dependency",),
    "content_quality": ("duplicate_content",),
}


def build_coverage_manifest(
    *,
    target_url: str,
    pages_checked: list[str],
    findings: list[Any],
    limitations: list[str],
    executed_categories: list[str] | tuple[str, ...] = (),
) -> dict[str, Any]:
    """Build coverage from findings plus explicit records of successfully run check groups.

    A category can have no findings because its checks found no signal. It is only
    marked checked_no_findings when the caller confirms the corresponding checker ran;
    otherwise it remains not_proven. This is category-level, not individual-check coverage.
    """
    raw_counts = Counter(str(getattr(item, "category", "unknown")) for item in findings)
    executed = set(executed_categories)
    observed: list[dict[str, Any]] = []
    checked_without_findings: list[dict[str, Any]] = []
    not_proven: list[dict[str, Any]] = []
    for category, label in REQUIRED_AUDIT_CATEGORIES:
        accepted = CATEGORY_ALIASES.get(category, (category,))
        count = sum(raw_counts.get(name, 0) for name in accepted)
        is_executed = category in executed or any(alias in executed for alias in accepted)
        status = "recorded" if count else "checked_no_findings" if is_executed else "not_proven"
        entry = {
            "category": category,
            "label": label,
            "status": status,
            "findings_in_category": count,
            "checker_group_executed": is_executed,
        }
        if count:
            observed.append(entry)
        elif is_executed:
            checked_without_findings.append(entry)
        else:
            not_proven.append(entry)

    total = len(REQUIRED_AUDIT_CATEGORIES)
    categories_checked = len(observed) + len(checked_without_findings)
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
        "categories_with_recorded_findings": len(observed),
        "categories_checked_without_findings": len(checked_without_findings),
        "categories_checked": categories_checked,
        "categories_not_proven": len(not_proven),
        "category_signal_coverage_pct": round(100 * len(observed) / total, 1) if total else None,
        "category_execution_coverage_pct": round(100 * categories_checked / total, 1) if total else None,
        "observed_categories": observed,
        "checked_without_findings_categories": checked_without_findings,
        "not_proven_categories": not_proven,
        "limitations": list(dict.fromkeys(limitations)),
        "important_note": (
            "category_signal_coverage_pct measures categories with at least one recorded finding. "
            "category_execution_coverage_pct measures category groups whose checker completed, "
            "including groups that found no issue; this does not prove every individual "
            "check ran or passed. Categories not explicitly marked as executed remain not proven. "
            "Google indexing,             "field Core Web Vitals, full WCAG conformance, complete software composition "
            "analysis, live event attribution, and measured CPC/ROAS/revenue impact require "
            "additional authorized data or separate testing."
        ),
    }
