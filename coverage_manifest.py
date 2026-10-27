"""Transparent audit coverage summaries; never treat absent findings as successful checks."""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import re
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

def _safe_evidence_url(value: object) -> str | None:
    """Keep public URL evidence useful without persisting credentials or query secrets."""
    try:
        parts = urlsplit(str(value))
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"} or not parts.hostname:
            return None
        if parts.username is not None or parts.password is not None:
            return None
        host = parts.hostname.lower()
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = parts.port
        default_port = 80 if scheme == "http" else 443
        netloc = f"{host}:{port}" if port and port != default_port else host
        return urlunsplit((scheme, netloc, parts.path or "/", "", ""))
    except (TypeError, ValueError):
        return None


CATEGORY_ALIASES: dict[str, tuple[str, ...]] = {
    # Keep ARIA, general accessibility, and image-alt coverage independent; one signal in one group must not imply the others ran.
    "technical_seo": ("technical_seo", "on_page_seo"),
    "crawlability": ("crawl",),
    "indexing": ("indexing",),
    "trust": ("trust_inspector",),
    "ecommerce": ("ecommerce_category", "ecommerce_catalog"),
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
    check_outcomes: list[Any] | tuple[Any, ...] = (),
    run_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build coverage from findings plus explicit records of successfully run check groups.

    A category can have no findings because its checks found no signal. It is only
    marked checked_no_findings when the caller confirms the corresponding checker ran;
    otherwise it remains not_proven. This is category-level, not individual-check coverage.
    """
    raw_counts = Counter(str(getattr(item, "category", "unknown")) for item in findings)
    # Individual-check summaries use recorded outcomes only. They never infer passes
    # from absent findings and expose the observed-page denominator for each check.
    outcomes_by_check: dict[str, list[Any]] = defaultdict(list)
    for outcome in check_outcomes:
        check_id = str(getattr(outcome, "check_id", "") or "").strip()
        outcome_value = str(getattr(outcome, "outcome", "") or "").strip().lower()
        if check_id and outcome_value in {"pass", "issue", "warning", "not_assessed", "error"}:
            outcomes_by_check[check_id].append(outcome)
    check_outcome_summaries = []
    for check_id, records in sorted(outcomes_by_check.items()):
        # One page must contribute at most once to a check's denominator. If duplicate
        # records disagree, use the most conservative state for that page.
        severity_order = {"error": 5, "not_assessed": 4, "issue": 3, "warning": 2, "pass": 1}
        page_outcomes: dict[str, str] = {}
        unscoped_counts = Counter()
        for record in records:
            value = str(getattr(record, "outcome", "unknown")).lower()
            safe_url = _safe_evidence_url(getattr(record, "page_url", None))
            if safe_url is None:
                unscoped_counts[value] += 1
                continue
            previous = page_outcomes.get(safe_url)
            if previous is None or severity_order.get(value, 0) > severity_order.get(previous, 0):
                page_outcomes[safe_url] = value
        counts = Counter(page_outcomes.values())
        # Records without a safe, attributable URL remain visible as unscoped outcomes,
        # but are excluded from the tested-page denominator.
        assessed = counts.get("pass", 0) + counts.get("issue", 0) + counts.get("warning", 0)
        check_outcome_summaries.append({
            "check_id": check_id,
            "outcome_counts": {
                "pass": counts.get("pass", 0) + unscoped_counts.get("pass", 0),
                "issue": counts.get("issue", 0) + unscoped_counts.get("issue", 0),
                "warning": counts.get("warning", 0) + unscoped_counts.get("warning", 0),
                "not_assessed": counts.get("not_assessed", 0) + unscoped_counts.get("not_assessed", 0),
                "error": counts.get("error", 0) + unscoped_counts.get("error", 0),
            },
            "outcome_records": len(records),
            "tested_page_denominator": len(page_outcomes),
            "assessed_page_count": assessed,
            "not_assessed_record_count": counts.get("not_assessed", 0) + unscoped_counts.get("not_assessed", 0),
            "error_record_count": counts.get("error", 0) + unscoped_counts.get("error", 0),
            "pass_pct_of_assessed_records": round(100 * counts.get("pass", 0) / assessed, 1) if assessed else None,
            "unscoped_outcome_records": sum(unscoped_counts.values()),
            "note": "Per-page counts deduplicate repeated records by sanitized URL and use the most conservative outcome when duplicate states conflict; unscoped records are shown separately.",
        })
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
        category = str(getattr(finding, "category", "unknown"))[:100]
        title = str(getattr(finding, "title", "Untitled check"))[:300]
        safe_source_url = _safe_evidence_url(getattr(finding, "source_url", None))
        identity = "|".join((category, title, safe_source_url or ""))
        generated_id = "F-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12].upper()
        finding_id = str(getattr(finding, "finding_id", "") or "").strip()
        if not re.fullmatch(r"F-[A-F0-9]{12}", finding_id):
            finding_id = generated_id
        def safe_text(value: object, limit: int = 1200) -> str | None:
            if not isinstance(value, str):
                return None
            cleaned = " ".join(value.split())
            cleaned = re.sub(
                r"(?i)\b(authorization\s*:\s*bearer|bearer)\s+[A-Za-z0-9._~+/=-]+",
                r"\1 [REDACTED]",
                cleaned,
            )
            cleaned = re.sub(
                r"""(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|session(?:id)?|password|secret)\s*[:=]\s*["']?[^&\s,"']+""",
                r"\1=[REDACTED]",
                cleaned,
            )
            cleaned = re.sub(
                r"""https?://[^\s<>"']+""",
                lambda match: _safe_evidence_url(match.group(0).rstrip(".,);]")) or "[URL REDACTED]",
                cleaned,
            )
            return cleaned[:limit] or None
        raw_steps = getattr(finding, "verification_steps", [])
        verification_steps = [
            safe_text(step, 500) for step in raw_steps[:12]
            if isinstance(step, str) and safe_text(step, 500)
        ] if isinstance(raw_steps, list) else []
        raw_references = getattr(finding, "standard_references", [])
        standard_references = [
            safe_text(reference, 500) for reference in raw_references[:10]
            if isinstance(reference, str) and safe_text(reference, 500)
        ] if isinstance(raw_references, list) else []
        raw_dependencies = getattr(finding, "dependencies", [])
        dependencies = [
            safe_text(item, 300) for item in raw_dependencies[:10]
            if isinstance(item, str) and safe_text(item, 300)
        ] if isinstance(raw_dependencies, list) else []
        recorded_observations.append({
            "finding_id": finding_id,
            "check_id": finding_id,
            "category": category,
            "title": title,
            "status": str(getattr(finding, "status", "unknown"))[:80],
            "severity": str(getattr(finding, "severity", "info"))[:40],
            "severity_rationale": safe_text(getattr(finding, "severity_rationale", None), 800),
            "source_url": safe_source_url,
            "observed_at_utc": safe_text(getattr(finding, "observed_at_utc", None), 40),
            "test_method": safe_text(getattr(finding, "test_method", None), 300),
            "evidence_confidence": safe_text(getattr(finding, "evidence_confidence", None), 80),
            "evidence": safe_text(getattr(finding, "evidence", None), 1200),
            "explanation": safe_text(getattr(finding, "explanation", None), 1200),
            "recommendation": safe_text(getattr(finding, "recommendation", None), 1200),
            "verification_steps": verification_steps,
            "standard_references": standard_references,
            "potential_benefit": safe_text(getattr(finding, "potential_benefit", None), 500),
            "risk_if_unresolved": safe_text(getattr(finding, "risk_if_unresolved", None), 500),
            "estimated_effort": safe_text(getattr(finding, "estimated_effort", None), 120),
            "effort_basis": safe_text(getattr(finding, "effort_basis", None), 500),
            "dependencies": dependencies,
        })

    safe_target_url = _safe_evidence_url(target_url)
    safe_pages_checked = list(dict.fromkeys(
        safe_url for page_url in pages_checked
        if (safe_url := _safe_evidence_url(page_url)) is not None
    ))
    context = run_context if isinstance(run_context, dict) else {}
    raw_limits = context.get("limits") if isinstance(context.get("limits"), dict) else {}
    limits = {
        key: value for key, value in raw_limits.items()
        if isinstance(key, str) and isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 10_000_000
    }
    raw_module_statuses = context.get("module_statuses") if isinstance(context.get("module_statuses"), dict) else {}
    allowed_module_states = {"not_started", "running", "completed", "unavailable", "error"}
    module_statuses = {
        str(key)[:80]: value
        for key, value in raw_module_statuses.items()
        if isinstance(key, str) and value in allowed_module_states
    }
    safe_run_context = {
        "started_at_utc": str(context.get("started_at_utc") or "")[:40] or None,
        "completed_at_utc": str(context.get("completed_at_utc") or "")[:40] or None,
        "target_scope": str(context.get("target_scope") or "Public-site audit; authentication and active testing are not assumed.")[:500],
        "user_agent": str(context.get("user_agent") or "")[:200] or None,
        "module_statuses": module_statuses,
        "limits": limits,
        "measurement_context": {
            str(key)[:80]: str(value)[:500]
            for key, value in (context.get("measurement_context") or {}).items()
            if isinstance(key, str) and isinstance(value, (str, int, float, bool))
        } if isinstance(context.get("measurement_context"), dict) else {},
        "check_ids_recorded": sorted(outcomes_by_check.keys())[:500],
        "check_outcome_record_count": sum(len(records) for records in outcomes_by_check.values()),
        "check_outcome_state_counts": dict(Counter(
            str(getattr(outcome, "outcome", "unknown")).lower()
            for outcome in check_outcomes
            if str(getattr(outcome, "outcome", "unknown")).lower() in {"pass", "issue", "warning", "not_assessed", "error"}
        )),
        "limitations_count": len(list(dict.fromkeys(limitations))),
    }
    return {
        "schema_version": 4,
        "audit_run_context": safe_run_context,
        "coverage_level": "category_signal_coverage_not_individual_check_coverage",
        "target_url": safe_target_url,
        "pages_checked": safe_pages_checked,
        "pages_checked_count": len(safe_pages_checked),
        "findings_total": len(findings),
        "finding_status_counts": dict(Counter(str(getattr(item, "status", "unknown")) for item in findings)),
        "finding_category_counts": dict(raw_counts),
        "recorded_observations": recorded_observations,
        "recorded_observations_count": len(recorded_observations),
        "individual_check_outcomes": check_outcome_summaries,
        "individual_check_outcomes_count": len(check_outcome_summaries),
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
            "Google indexing, field Core Web Vitals, full WCAG conformance, complete software composition "
            "analysis, backlink/competitor datasets, rendered-browser console/network diagnostics, "
            "authenticated checkout behavior, live event attribution, and measured CPC/ROAS/revenue impact "
            "require additional authorized data or separate testing."
        ),
    }
