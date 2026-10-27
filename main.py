import asyncio
import hashlib
import hmac
import secrets
import time
import logging
import os
import smtplib
import json
from email.message import EmailMessage
from pathlib import Path
from datetime import datetime, timezone
import re
from urllib.parse import urlsplit

# Configure credential redaction before importing application or framework modules,
# because imports can emit logs as a side effect.
logging.basicConfig(level=logging.INFO)
from log_safety import CredentialRedactionFilter

_redaction_filter = CredentialRedactionFilter()
_seen_handlers = set()
for _logger in [logging.getLogger(), *[
    item for item in logging.Logger.manager.loggerDict.values()
    if isinstance(item, logging.Logger)
]]:
    for _handler in _logger.handlers:
        if id(_handler) not in _seen_handlers:
            _handler.addFilter(_redaction_filter)
            _seen_handlers.add(id(_handler))

from fastapi import FastAPI, Depends, HTTPException, Query, Response, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, text
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_async_db
from ecommerce_agent import UniversalEcommerceAgent, LeadDossier
from models import SoftwareLicense, APIKey, AuditLead, AuditQuotaReservation, AuditReport, PaymentWebhookEvent, SaaSOperationEvent
from auth import verify_license_or_api_key, verify_account_credentials_for_key_revocation, verify_account_credentials_for_billing
from quota import reserve_audit_slot, release_audit_reservation
from audit_checks import AuditCheckResult, AuditFinding, CheckOutcome, MAX_RESPONSE_BYTES, USER_AGENT, normalize_target, run_phase_one_checks
from report_generator import render_audit_pdf
from crawl_checks import run_bounded_site_crawl
from conversion_checks import run_conversion_paid_traffic_checks
from coverage_manifest import build_coverage_manifest
from unavailable_checks import append_unavailable_check_outcomes

logger = logging.getLogger("audit_service")

app = FastAPI(
    title="AI E-Commerce Audit Engine - Commercial Edition",
    description="Multi-model API serving SaaS, Managed Services, White-Label, and Enterprise integrations.",
    swagger_ui_parameters={"persistAuthorization": True}
)

agent = UniversalEcommerceAgent()


@app.middleware("http")
async def apply_response_security_headers(request: Request, call_next):
    """Apply baseline browser protections and prevent caching authenticated/private responses."""
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

    private_paths = (
        "/api/v1/admin/",
        "/api/v1/account/",
        "/api/v1/reports",
        "/admin",
        "/app",
    )
    if request.url.path.startswith(private_paths):
        response.headers["Cache-Control"] = "no-store, private"
        response.headers["Pragma"] = "no-cache"
    return response


class ReportEmailRequest(BaseModel):
    recipient_email: str
    recipient_confirmed: bool = False


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version="1.0.0",
        description=app.description,
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "APIKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "Enter your X-API-Key"
        },
        "LicenseKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "X-License-Key",
            "description": "Enter your X-License-Key"
        }
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


@app.get("/")
def read_root():
    return {"status": "AI Agent Commercial Engine Operational"}


@app.get("/health-check")
async def health_check(db: AsyncSession = Depends(get_async_db)):
    try:
        result = await db.execute(text("SELECT 1"))
        return {"status": "success", "db_connected": True, "result": result.scalar()}
    except Exception as exc:
        logger.error("Health check failed (error_type=%s)", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Database connection error")


@app.post("/api/v1/audit-lead", response_model=LeadDossier)
@app.post("/api/v1/audit-lead/", response_model=LeadDossier, include_in_schema=False)
async def audit_lead(
    domain: str = Query(..., min_length=1, max_length=255, description="E-commerce store URL/domain"),
    email: str = Query("", max_length=255, description="User email for audit copy"),
    source: str = Query("web_audit", max_length=50, description="Traffic source tag"),
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_async_db)
):
    # Validate and canonicalize before reserving quota or calling any external provider.
    # This keeps rejected input free of billable audit work and avoids inconsistent URL handling.
    try:
        target_url = normalize_target(domain)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    license_id = license_obj.id
    reservation_id = None
    try:
        # Reserve quota in a short transaction. No row lock is held during external API calls.
        reservation_id, reserved_at = await reserve_audit_slot(db, license_id)

        dossier = await agent.process_lead(domain=target_url, user_email=email, source=source)

        db_lead = AuditLead(
            license_id=license_id,
            domain=dossier.audit.domain,
            mobile_score=dossier.audit.mobile_score,
            speed_index_sec=dossier.audit.speed_index_sec,
            contact_email=dossier.contact.email,
            revenue_leak_hypothesis=dossier.pitch.revenue_leak_hypothesis,
            email_subject=dossier.pitch.email_subject,
            email_body=dossier.pitch.email_body,
            source_channel=source,
            # Attribute usage to the month in which its quota slot was reserved.
            created_at=reserved_at,
        )
        db.add(db_lead)
        await db.execute(
            delete(AuditQuotaReservation).where(AuditQuotaReservation.id == reservation_id)
        )
        await db.commit()
        reservation_id = None
        return dossier
    except HTTPException as exc:
        await db.rollback()
        if reservation_id is not None:
            try:
                await release_audit_reservation(db, reservation_id)
            except Exception as release_exc:
                logger.error("Failed to release quota reservation (error_type=%s)", type(release_exc).__name__)
        await _record_operation_event(db, "quota_denied" if exc.status_code == 429 else "audit_rejected",
                                      license_id, _safe_diagnostic_host(domain), f"HTTP_{exc.status_code}")
        raise
    except Exception as exc:
        await db.rollback()
        if reservation_id is not None:
            try:
                await release_audit_reservation(db, reservation_id)
            except Exception as release_exc:
                logger.error("Failed to release quota reservation (error_type=%s)", type(release_exc).__name__)
        await _record_operation_event(db, "audit_failed", license_id, _safe_diagnostic_host(domain), type(exc).__name__)
        logger.error("Audit execution failed (error_type=%s)", type(exc).__name__)
        raise HTTPException(
            status_code=500,
            detail="Audit execution failed. Check server logs for diagnostic details."
        )


@app.post("/api/v1/comprehensive-audit", response_class=Response)
async def comprehensive_audit_pdf(
    domain: str = Query(..., min_length=1, max_length=2048, description="Public website URL or domain"),
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_async_db),
):
    """Create a phase-one evidence report as a PDF, using the existing license quota."""
    try:
        target_url = normalize_target(domain)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    license_id = license_obj.id
    reservation_id = None
    try:
        audit_started_at_utc = datetime.now(timezone.utc).isoformat()
        module_statuses = {
            "core_homepage_discovery": "running",
            "pagespeed": "not_started",
            "bounded_crawl": "not_started",
            "conversion_paid_traffic": "not_started",
        }
        reservation_id, reserved_at = await reserve_audit_slot(db, license_id)

        # Run audit families independently. A failure in the phase-one checker must not
        # discard findings from the bounded crawl, conversion checks, or PageSpeed.
        try:
            result = await run_phase_one_checks(target_url)
            module_statuses["core_homepage_discovery"] = "completed"
        except Exception as phase_one_exc:
            module_statuses["core_homepage_discovery"] = "error"
            result = AuditCheckResult(
                target_url=target_url,
                checked_at_utc=datetime.now(timezone.utc).isoformat(),
                findings=[],
                pages_checked=[],
                limitations=[
                    f"Core homepage/discovery checks were unavailable ({type(phase_one_exc).__name__}); other audit families were attempted independently."
                ],
                check_outcomes=[],
            )
            result.check_outcomes.append(CheckOutcome(
                check_id="phase_one.core",
                category="technical_seo",
                page_url=target_url,
                outcome="error",
                observed_at_utc=datetime.now(timezone.utc).isoformat(),
                method="bounded homepage and discovery-file checks",
                evidence=f"The phase-one checker stopped with {type(phase_one_exc).__name__}; no pass or issue is inferred.",
                evidence_ref="phase_one.core",
            ))
            result.findings.append(AuditFinding(
                category="technical_seo",
                title="Core homepage and discovery checks could not be completed",
                status="not_tested",
                severity="info",
                evidence=f"The core checker stopped with {type(phase_one_exc).__name__}; no homepage SEO or discovery-file result is inferred.",
                explanation="The audit will retain results from independent checker families where available. This failure does not imply that the site passed or failed the skipped checks.",
                recommendation="Retry the audit. If the failure persists, review public endpoint availability and the audit service's bounded request logs.",
                verification_steps=["Retry the audit.", "Check the public homepage and robots.txt/sitemap responses independently."],
                source_url=target_url,
            ))
        metrics = None
        module_statuses["pagespeed"] = "running"
        try:
            metrics = await agent.run_audit(target_url)
            module_statuses["pagespeed"] = "completed" if metrics is not None else "unavailable"
        except Exception as pagespeed_exc:
            module_statuses["pagespeed"] = "error"
            result.limitations.append(
                f"Google PageSpeed metrics were unavailable for this run ({type(pagespeed_exc).__name__}); "
                "performance measurements are not inferred and other audit modules continue."
            )

        # Keep the audit modular: a failure in an additional checker must not erase
        # valid results already collected by the core page/discovery checks.
        crawl_completed = False
        conversion_completed = False
        module_statuses["bounded_crawl"] = "running"
        try:
            crawl_findings, crawl_pages, crawl_limitations = await run_bounded_site_crawl(
                target_url, outcome_records=result.check_outcomes
            )
            # A normal return can still mean the homepage was non-HTML/unavailable;
            # count the bounded crawl as completed only when it recorded a page.
            crawl_completed = bool(crawl_pages)
            module_statuses["bounded_crawl"] = "completed" if crawl_completed else "unavailable"
            result.findings.extend(crawl_findings)
            result.pages_checked = list(dict.fromkeys([*result.pages_checked, *crawl_pages]))
            result.limitations.extend(crawl_limitations)
        except Exception as crawl_exc:
            module_statuses["bounded_crawl"] = "error"
            result.check_outcomes.append(CheckOutcome(
                check_id="crawl.bounded_crawl",
                category="crawlability",
                page_url=target_url,
                outcome="error",
                observed_at_utc=datetime.now(timezone.utc).isoformat(),
                method="bounded same-origin crawl",
                evidence=f"The crawler stopped with {type(crawl_exc).__name__}; no page-level pass or issue is inferred.",
                evidence_ref="crawl.bounded_crawl",
            ))
            result.findings.append(AuditFinding(
                category="crawl",
                title="Bounded crawl could not be completed",
                status="not_tested",
                severity="info",
                evidence=f"The optional bounded crawl stopped with {type(crawl_exc).__name__}; no crawl result is inferred.",
                explanation="The core audit may still contain valid homepage and discovery-file observations, but the additional page crawl did not complete.",
                recommendation="Retry the audit and review the site's availability, response limits, and crawl restrictions if the issue persists.",
                verification_steps=["Retry the audit.", "Review the affected public URLs and HTTP responses."],
                source_url=target_url,
            ))
            result.limitations.append(
                f"Bounded same-origin crawl results are unavailable for this run ({type(crawl_exc).__name__}); other completed checks are retained."
            )

        module_statuses["conversion_paid_traffic"] = "running"
        try:
            conversion_findings, conversion_pages, conversion_limitations = await run_conversion_paid_traffic_checks(target_url)
            conversion_completed = True
            module_statuses["conversion_paid_traffic"] = "completed"
            result.findings.extend(conversion_findings)
            result.pages_checked = list(dict.fromkeys([*result.pages_checked, *conversion_pages]))
            result.limitations.extend(conversion_limitations)
        except Exception as conversion_exc:
            module_statuses["conversion_paid_traffic"] = "error"
            result.check_outcomes.append(CheckOutcome(
                check_id="conversion_paid_traffic.checker",
                category="conversion_paid_traffic",
                page_url=target_url,
                outcome="error",
                observed_at_utc=datetime.now(timezone.utc).isoformat(),
                method="bounded public HTML conversion/paid-traffic checks",
                evidence=f"The checker stopped with {type(conversion_exc).__name__}; checkout success and attribution are not inferred.",
                evidence_ref="conversion_paid_traffic.checker",
            ))
            result.findings.append(AuditFinding(
                category="conversion_paid_traffic",
                title="Conversion and paid-traffic checks could not be completed",
                status="not_tested",
                severity="info",
                evidence=f"The conversion/paid-traffic checker stopped with {type(conversion_exc).__name__}; no campaign or checkout outcome is inferred.",
                explanation="This module could not complete, so its absence of findings must not be interpreted as a healthy checkout, working analytics, or efficient campaigns.",
                recommendation="Retry the audit. Use authorized test access for checkout and event-flow verification; public tag detection alone cannot confirm attribution.",
                verification_steps=["Retry the audit.", "Where authorized, verify checkout and analytics events in a test environment without submitting real orders."],
                source_url=target_url,
            ))
            result.limitations.append(
                f"Conversion and paid-traffic checks are unavailable for this run ({type(conversion_exc).__name__}); other completed checks are retained."
            )
        performance_completed = metrics is not None
        if metrics is not None:
            # PageSpeed successfully returned a lab result. Record an explicit
            # outcome instead of relying on the presence of a summary finding.
            # These thresholds describe the measured Lighthouse score only; they
            # do not establish field Core Web Vitals or business outcomes.
            score = getattr(metrics, "mobile_score", None)
            if isinstance(score, (int, float)) and not isinstance(score, bool):
                performance_outcome = "issue" if score < 50 else "warning" if score < 90 else "pass"
                performance_evidence = (
                    f"Google PageSpeed Insights returned a mobile Lighthouse score of {score}/100. "
                    "This is a lab measurement, not a field Core Web Vitals result or a business-impact measurement."
                )
            else:
                performance_outcome = "not_assessed"
                performance_evidence = (
                    "PageSpeed returned a response, but its mobile Lighthouse score was missing or invalid; "
                    "no pass or issue is inferred."
                )
            result.check_outcomes.append(CheckOutcome(
                check_id="performance.pagespeed_api",
                category="performance",
                page_url=target_url,
                outcome=performance_outcome,
                observed_at_utc=datetime.now(timezone.utc).isoformat(),
                method="Google PageSpeed Insights API mobile Lighthouse lab run",
                evidence=performance_evidence,
                evidence_ref="performance.pagespeed_api",
            ))
            lab_metric_parts = [
                f"Mobile Lighthouse performance score: {metrics.mobile_score}/100",
                f"Speed Index: {metrics.speed_index_sec} seconds",
            ]
            for metric_label, metric_value, unit in (
                ("Largest Contentful Paint (LCP)", getattr(metrics, "lcp_sec", None), "seconds"),
                ("Cumulative Layout Shift (CLS)", getattr(metrics, "cls_score", None), ""),
                ("Total Blocking Time (TBT)", getattr(metrics, "tbt_ms", None), "ms"),
                ("Time to First Byte (TTFB)", getattr(metrics, "ttfb_ms", None), "ms"),
            ):
                if isinstance(metric_value, (int, float)):
                    lab_metric_parts.append(f"{metric_label}: {metric_value}{(' ' + unit) if unit else ''}")
            field_metric_parts = []
            field_data_context = getattr(metrics, "field_data_context", {}) or {}
            if isinstance(field_data_context, dict):
                for context_name, context_value in field_data_context.items():
                    if context_name.endswith("_overall_category") and isinstance(context_value, str):
                        field_metric_parts.append(f"{context_name}: {context_value}")
            field_metrics = getattr(metrics, "field_metrics", {}) or {}
            if isinstance(field_metrics, dict):
                for metric_name, metric_data in field_metrics.items():
                    if not isinstance(metric_data, dict):
                        continue
                    percentile = metric_data.get("percentile")
                    normalized_value = metric_data.get("normalized_value", percentile)
                    unit = metric_data.get("unit")
                    category = metric_data.get("category")
                    if isinstance(percentile, (int, float)):
                        field_metric_parts.append(
                            f"{metric_name}: p75={normalized_value}"
                            + (f" {unit}" if isinstance(unit, str) else "")
                            + (f", category={category}" if isinstance(category, str) else "")
                        )
            performance_evidence = (
                "Google PageSpeed Insights lab measurements: " + "; ".join(lab_metric_parts) + ". "
                + (
                    "Available URL-level and/or origin-level PageSpeed field metrics: " + "; ".join(field_metric_parts) + ". "
                    "These are provider-reported field percentiles/categories; the response does not include a precise sample count or collection-window boundaries in this report. "
                    if field_metric_parts else
                    "No PageSpeed loadingExperience field metrics were returned for this URL/origin in this run. "
                )
                + (
                    f"Lighthouse version: {getattr(metrics, 'lighthouse_version', None)}; "
                    f"fetch time: {getattr(metrics, 'page_fetch_time', None)}; "
                    f"form factor: {getattr(metrics, 'form_factor', None)}; "
                    f"final displayed URL: {_safe_audit_metadata_url(getattr(metrics, 'final_url', None)) or 'not available'}. "
                    if getattr(metrics, "lighthouse_version", None) or getattr(metrics, "page_fetch_time", None)
                    else ""
                )
                + "Lab measurements are not field measurements; unavailable field metrics must not be inferred."
            )
            score_is_valid = isinstance(getattr(metrics, "mobile_score", None), (int, float)) and not isinstance(getattr(metrics, "mobile_score", None), bool)
            result.findings.insert(0, AuditFinding(
                category="performance",
                title=(
                    "Google PageSpeed mobile performance snapshot"
                    if score_is_valid else
                    "Google PageSpeed performance score unavailable"
                ),
                status="verified" if score_is_valid else "not_tested",
                severity=(
                    "medium" if metrics.mobile_score < 50 else "low" if metrics.mobile_score < 90 else "info"
                ) if score_is_valid else "info",
                evidence=performance_evidence,
                explanation=(
                    "The performance score summarizes a Lighthouse lab run and is not a direct "
                    "measurement of revenue, conversion rate, or search ranking."
                ),
                recommendation=(
                    "Review the full PageSpeed Insights report for opportunities relevant to this page, "
                    "then prioritize changes based on measured diagnostics and retest."
                ),
                verification_steps=[
                    "Open https://pagespeed.web.dev/ and test the exact target URL.",
                    "Compare the mobile strategy, test time, score, Speed Index, and available field data.",
                ],
                source_url=target_url,
                test_method="Google PageSpeed Insights API mobile Lighthouse lab run",
                evidence_confidence="moderate",
                standard_references=["https://web.dev/articles/vitals", "https://pagespeed.web.dev/"],
            ))
            if not metrics.screenshot_data_uri:
                result.limitations.append(
                    "No usable actual-page screenshot was supplied by the Google PageSpeed response for this run; "
                    "the report uses explanatory vector illustrations only and does not fabricate website screenshots."
                )
        else:
            result.check_outcomes.append(CheckOutcome(
                check_id="performance.pagespeed_api",
                category="performance",
                page_url=target_url,
                outcome="error",
                observed_at_utc=datetime.now(timezone.utc).isoformat(),
                method="Google PageSpeed Insights API request",
                evidence="No usable Lighthouse measurement was returned; no performance score or Core Web Vital is inferred.",
                evidence_ref="performance.pagespeed_api",
            ))
            result.findings.insert(0, AuditFinding(
                category="performance",
                title="Google PageSpeed performance measurements unavailable",
                status="not_tested",
                severity="info",
                evidence="The PageSpeed provider did not return a usable Lighthouse measurement for this run. No score, Core Web Vital, or speed value is inferred.",
                explanation="Performance results are unavailable for this run. Other completed audit modules remain valid within their stated scope.",
                recommendation="Retry PageSpeed Insights for the same URL and compare lab results with available URL-level and origin-level field data.",
                verification_steps=[
                    "Open https://pagespeed.web.dev/ and test the exact target URL.",
                    "Check provider availability and API quota if the failure persists.",
                ],
                source_url=target_url,
                test_method="PageSpeed API request attempted; no usable metrics returned",
                evidence_confidence="limited",
                standard_references=["https://web.dev/articles/vitals", "https://pagespeed.web.dev/"],
            ))
        # Explicitly disclose verification modes unavailable in this deployment; absence of
        # browser/authorized/external data must never read as a pass.
        append_unavailable_check_outcomes(result)

        # Convert each emitted finding into a durable explicit outcome record. This
        # records observed issues/review-needed/not-assessed states only; absence of a
        # finding is never converted into a pass. Checker-specific positive outcomes
        # must still be emitted by the checker that actually evaluated that condition.
        existing_finding_outcome_refs = {
            outcome.evidence_ref for outcome in result.check_outcomes if outcome.evidence_ref
        }
        for finding in result.findings:
            outcome_ref = f"finding.{finding.finding_id}"
            if outcome_ref in existing_finding_outcome_refs:
                continue
            # The PageSpeed summary already has a checker-authored outcome above.
            # Do not add a second inferred outcome for the same summary finding,
            # which would otherwise count one measured score twice in coverage.
            if (
                finding.title in {
                    "Google PageSpeed mobile performance snapshot",
                    "Google PageSpeed performance score unavailable",
                }
                and any(
                    outcome.check_id == "performance.pagespeed_api"
                    and outcome.page_url == (finding.source_url or target_url)
                    for outcome in result.check_outcomes
                )
            ):
                continue
            finding_status = str(finding.status or "").casefold()
            finding_severity = str(finding.severity or "").casefold()
            if finding_status in {"not_tested", "not tested", "insufficient_data"}:
                explicit_outcome = "not_assessed"
            elif finding_status == "manual_review_required" or finding_severity == "info":
                explicit_outcome = "warning"
            else:
                explicit_outcome = "issue"
            result.check_outcomes.append(CheckOutcome(
                check_id=outcome_ref,
                category=finding.category or "uncategorized",
                page_url=finding.source_url or target_url,
                outcome=explicit_outcome,
                observed_at_utc=finding.observed_at_utc or datetime.now(timezone.utc).isoformat(),
                method=finding.test_method or "finding evidence emitted by the responsible audit checker",
                evidence=(finding.evidence or "Finding emitted without additional evidence text.")[:2000],
                evidence_ref=outcome_ref,
            ))
            existing_finding_outcome_refs.add(outcome_ref)

        # Calculate coverage before PDF rendering so the same manifest appears in the PDF,
        # the saved report metadata, and the customer dashboard.
        # Derive completed coverage only from explicit outcome records and checker
        # calls that returned successfully. A recorded outcome proves that category
        # was evaluated; it does not imply every check in that category passed.
        executed_categories = {
            outcome.category for outcome in result.check_outcomes
            if outcome.category and outcome.outcome not in {"error", "not_assessed"}
        }
        # These functions returned normally above, so their bounded checker groups
        # completed. Keep their coverage labels separate from unrelated audit groups.
        if performance_completed:
            executed_categories.add("performance")
        if crawl_completed:
            executed_categories.add("crawlability")
        if conversion_completed:
            executed_categories.add("conversion_paid_traffic")
        if crawl_completed:
            # The dependency version checker is invoked as part of the successful
            # homepage crawl even when no advisory signal is found.
            executed_categories.add("dependency_advisory")
        elif any(
            finding.category in {"dependency_advisory", "security_dependency"}
            for finding in result.findings
        ):
            executed_categories.add("dependency_advisory")
        coverage_manifest = build_coverage_manifest(
            target_url=target_url,
            pages_checked=result.pages_checked,
            findings=result.findings,
            limitations=result.limitations,
            executed_categories=sorted(executed_categories),
            check_outcomes=result.check_outcomes,
            run_context={
                "started_at_utc": audit_started_at_utc,
                "completed_at_utc": datetime.now(timezone.utc).isoformat(),
                "target_scope": "Public unauthenticated HTTP(S) audit; bounded same-origin crawl; no active penetration testing or authenticated checkout actions.",
                "user_agent": USER_AGENT,
                "module_statuses": module_statuses,
                "limits": {
                    "max_crawl_pages": 12,
                    "max_links_from_homepage": 100,
                    "max_response_bytes": MAX_RESPONSE_BYTES,
                    "max_saved_check_outcomes": 500,
                    "max_saved_findings": 150,
                },
                "measurement_context": {
                    "performance": "PageSpeed Insights lab metrics and any provider-returned field data are reported separately; absent field data is not inferred.",
                    "rendered_browser": "Not available in this server-side audit path unless explicitly recorded by a checker outcome.",
                    "authorization": "Only unauthenticated public checks are attempted by default.",
                },
            },
        )
        pdf_bytes = render_audit_pdf(
            result,
            screenshot_data_uri=getattr(metrics, "screenshot_data_uri", None),
            coverage_manifest=coverage_manifest,
        )
        # Persist the explicit bounded outcome records beside the conservative
        # coverage manifest so saved-report history retains the evidence behind PDF counts.
        report_metadata = {
            **coverage_manifest,
            "check_outcomes": [
                {
                    **outcome.dict(),
                    "page_url": _safe_audit_metadata_url(outcome.page_url),
                    "evidence": _redact_audit_metadata_text(outcome.evidence, limit=2000),
                    "evidence_ref": _redact_audit_metadata_text(outcome.evidence_ref, limit=300),
                }
                for outcome in result.check_outcomes[:500]
            ],
            "findings": [
                {
                    "finding_id": finding.finding_id,
                    "category": finding.category,
                    "title": _redact_audit_metadata_text(finding.title, limit=240),
                    "status": finding.status,
                    "severity": finding.severity,
                    "severity_rationale": _redact_audit_metadata_text(finding.severity_rationale, limit=500),
                    "evidence": _redact_audit_metadata_text(finding.evidence, limit=2000),
                    "explanation": _redact_audit_metadata_text(finding.explanation, limit=1200),
                    "recommendation": _redact_audit_metadata_text(finding.recommendation, limit=1200),
                    "potential_benefit": _redact_audit_metadata_text(finding.potential_benefit, limit=1000),
                    "risk_if_unresolved": _redact_audit_metadata_text(finding.risk_if_unresolved, limit=1000),
                    "verification_steps": [
                        _redact_audit_metadata_text(step, limit=500)
                        for step in finding.verification_steps[:12]
                    ],
                    "source_url": _safe_audit_metadata_url(finding.source_url),
                    "observed_at_utc": finding.observed_at_utc,
                    "test_method": _redact_audit_metadata_text(finding.test_method, limit=300),
                    "evidence_confidence": finding.evidence_confidence,
                    "standard_references": [
                        _safe_audit_metadata_url(reference)
                        for reference in finding.standard_references[:8]
                        if _safe_audit_metadata_url(reference)
                    ],
                    "estimated_effort": finding.estimated_effort,
                    "effort_basis": _redact_audit_metadata_text(finding.effort_basis, limit=300),
                    "dependencies": [
                        _redact_audit_metadata_text(dependency, limit=500)
                        for dependency in finding.dependencies[:8]
                    ],
                }
                for finding in result.findings[:150]
            ],
            "evidence_storage_limits": {
                "max_check_outcomes": 500,
                "max_findings": 150,
                "max_evidence_text_chars": 2000,
                "query_strings_and_fragments_removed_from_evidence_urls": True,
            },
        }
        report = AuditReport(
            license_id=license_id,
            domain=urlsplit(target_url).hostname or (metrics.domain if metrics else "website"),
            pdf_bytes=pdf_bytes,
            coverage_json=json.dumps(report_metadata, separators=(",", ":")),
            finding_count=len(result.findings),
            created_at=reserved_at,
        )
        db.add(report)
        await db.flush()
        report_id = report.id

        db.add(AuditLead(
            license_id=license_id,
            domain=urlsplit(target_url).hostname or (metrics.domain if metrics else "website"),
            mobile_score=metrics.mobile_score if metrics is not None else None,
            speed_index_sec=metrics.speed_index_sec if metrics is not None else None,
            contact_email=None,
            revenue_leak_hypothesis=None,
            email_subject=None,
            email_body=None,
            source_channel="comprehensive_audit",
            created_at=reserved_at,
        ))
        await db.execute(
            delete(AuditQuotaReservation).where(AuditQuotaReservation.id == reservation_id)
        )
        await db.commit()
        reservation_id = None

        hostname = urlsplit(target_url).hostname or "website"
        safe_hostname = re.sub(r"[^a-zA-Z0-9.-]", "-", hostname)[:180]
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="ecommerce-audit-{safe_hostname}.pdf"',
                "X-Audit-Report-ID": str(report_id),
                "Cache-Control": "no-store, private",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
            },
        )
    except HTTPException as exc:
        await db.rollback()
        if reservation_id is not None:
            try:
                await release_audit_reservation(db, reservation_id)
            except Exception as release_exc:
                logger.error("Failed to release quota reservation (error_type=%s)", type(release_exc).__name__)
        await _record_operation_event(db, "quota_denied" if exc.status_code == 429 else "audit_rejected",
                                      license_id, _safe_diagnostic_host(target_url), f"HTTP_{exc.status_code}")
        raise
    except Exception as exc:
        await db.rollback()
        if reservation_id is not None:
            try:
                await release_audit_reservation(db, reservation_id)
            except Exception as release_exc:
                logger.error("Failed to release quota reservation (error_type=%s)", type(release_exc).__name__)
        await _record_operation_event(db, "audit_failed", license_id, _safe_diagnostic_host(target_url), type(exc).__name__)
        logger.error("Comprehensive audit report generation failed (error_type=%s)", type(exc).__name__)
        raise HTTPException(
            status_code=500,
            detail="Comprehensive audit report generation failed. Check server logs for diagnostics.",
        ) from exc

 

@app.get("/checkout", response_class=HTMLResponse, include_in_schema=False)
async def paddle_checkout_page(request: Request):
    """Launch a Paddle-hosted transaction from the configured payment link."""
    client_token = os.getenv("PADDLE_CLIENT_TOKEN", "").strip()
    environment = os.getenv("PADDLE_ENVIRONMENT", "sandbox").strip().lower()
    if environment not in {"sandbox", "production"}:
        environment = "sandbox"
    token_json = json.dumps(client_token)
    environment_js = "Paddle.Environment.set('sandbox');" if environment == "sandbox" else ""
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure checkout | E-Commerce Audit Agent</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;background:#f5f7fb;color:#172033;min-height:100vh;display:grid;place-items:center}}
main{{background:#fff;padding:2rem;border-radius:16px;max-width:520px;margin:1rem;box-shadow:0 12px 40px #17203312}}
h1{{margin-top:0}}p{{line-height:1.6;color:#46536a}}#status{{font-weight:600}}
</style>
<script src="https://cdn.paddle.com/paddle/v2/paddle.js"></script>
</head><body><main>
<h1>Secure checkout</h1><p id="status">Preparing your secure Paddle checkout…</p>
<p>You will complete payment on Paddle's secure checkout. Do not refresh this page while checkout opens.</p>
</main>
<script>
(async function() {{
  const status = document.getElementById("status");
  const token = {token_json};
  const params = new URLSearchParams(window.location.search);
  const transactionId = params.get("_ptxn") || params.get("transaction_id");
  if (!token) {{ status.textContent = "Checkout is not configured yet. Please contact support."; return; }}
  if (!transactionId || !/^txn_[A-Za-z0-9]+$/.test(transactionId)) {{
    status.textContent = "No valid checkout transaction was supplied. Please return to the plans page and try again.";
    return;
  }}
  try {{
    {environment_js}
    Paddle.Initialize({{ token: token }});
    status.textContent = "Opening secure checkout…";
    Paddle.Checkout.open({{ transactionId: transactionId }});
  }} catch (error) {{
    status.textContent = "Checkout could not be opened. Please return to the plans page and try again.";
  }}
}})();
</script></body></html>"""
    return HTMLResponse(content=html)

@app.get("/app", include_in_schema=False)
async def customer_portal():
    """Serve the lightweight, API-backed customer portal bundled with this repository."""
    return FileResponse(Path(__file__).resolve().parent / "customer_portal.html")


@app.get("/api/v1/account/usage")
async def get_account_usage(
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_async_db),
):
    """Return the authenticated license's monthly quota status without exposing its key."""
    from sqlalchemy import select, func as sql_func

    now = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if month_start.month == 12:
        next_month = month_start.replace(year=month_start.year + 1, month=1)
    else:
        next_month = month_start.replace(month=month_start.month + 1)

    used = int((await db.execute(
        select(sql_func.count(AuditLead.id)).where(
            AuditLead.license_id == license_obj.id,
            AuditLead.created_at >= month_start,
        )
    )).scalar_one() or 0)
    pending = int((await db.execute(
        select(sql_func.count(AuditQuotaReservation.id)).where(
            AuditQuotaReservation.license_id == license_obj.id,
            AuditQuotaReservation.created_at >= month_start,
            AuditQuotaReservation.expires_at > now,
        )
    )).scalar_one() or 0)
    # Show the same operator-managed allowance that quota enforcement uses.
    # Retain the license column as a migration fallback for older/unlisted tiers.
    package_result = await db.execute(text("""
        SELECT monthly_audit_allowance FROM saas_plan_packages WHERE tier=:tier
    """), {"tier": str(license_obj.tier or "starter").strip().lower()})
    package_limit = package_result.scalar_one_or_none()
    limit = max(0, int(
        package_limit if package_limit is not None else (license_obj.max_monthly_audits or 0)
    ))
    consumed = used + pending
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "tier": str(license_obj.tier or "starter"),
        "monthly_limit": limit,
        "used": used,
        "in_progress": pending,
        "remaining": max(0, limit - consumed),
        "usage_percent": min(100, round(consumed * 100 / limit, 1)) if limit else 0,
        "period_resets_at": next_month.isoformat(),
        "is_active": bool(license_obj.is_active),
        "expires_at": license_obj.expires_at.isoformat() if license_obj.expires_at else None,
    }


@app.get("/api/v1/account/billing-history")
async def account_billing_history(
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_account_credentials_for_billing),
    db: AsyncSession = Depends(get_async_db),
):
    """Return a bounded billing-event history scoped to the authenticated license."""
    from sqlalchemy import select

    events = (await db.execute(
        select(PaymentWebhookEvent)
        .where(PaymentWebhookEvent.license_id == license_obj.id)
        .order_by(PaymentWebhookEvent.created_at.desc(), PaymentWebhookEvent.event_id.desc())
        .limit(50)
    )).scalars().all()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "account": {
            "client_name": license_obj.client_name,
            "tier": license_obj.tier,
            "is_active": bool(license_obj.is_active),
            "expires_at": license_obj.expires_at.isoformat() if license_obj.expires_at else None,
        },
        "items": [
            {
                "event_id": item.event_id,
                "status": item.status,
                "transaction_id": item.transaction_id,
                "subscription_id": item.subscription_id,
                "created_at": item.created_at.isoformat() if item.created_at else None,
                "updated_at": item.updated_at.isoformat() if item.updated_at else None,
            }
            for item in events
        ],
        "limit": 50,
    }


@app.post("/api/v1/account/billing-portal")
async def create_account_billing_portal(
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_account_credentials_for_billing),
    db: AsyncSession = Depends(get_async_db),
):
    """Create a short-lived Paddle customer portal session for the authenticated license."""
    from sqlalchemy import select

    if not os.getenv("PADDLE_API_KEY", "").strip():
        raise HTTPException(status_code=503, detail="Self-service billing is not configured.")
    events = (await db.execute(
        select(PaymentWebhookEvent)
        .where(
            PaymentWebhookEvent.license_id == license_obj.id,
            PaymentWebhookEvent.paddle_customer_id.is_not(None),
        )
        .order_by(PaymentWebhookEvent.updated_at.desc(), PaymentWebhookEvent.event_id.desc())
        .limit(20)
    )).scalars().all()
    customer_id = next((item.paddle_customer_id for item in events if item.paddle_customer_id), None)
    if not customer_id or not re.fullmatch(r"ctm_[A-Za-z0-9]+", customer_id):
        raise HTTPException(status_code=409, detail="No linked Paddle customer is available for this account yet.")
    subscription_ids = list(dict.fromkeys(
        item.subscription_id for item in events
        if item.subscription_id and re.fullmatch(r"sub_[A-Za-z0-9]+", item.subscription_id)
    ))
    payload = {"subscription_ids": subscription_ids} if subscription_ids else {}
    try:
        result = await asyncio.to_thread(
            _paddle_api_request,
            f"/customers/{customer_id}/portal-sessions",
            "POST",
            payload,
        )
        data = result.get("data") or {}
        urls = data.get("urls") or {}
        general = urls.get("general") or {}
        portal_url = general.get("overview") or data.get("url")
        parsed = urlsplit(portal_url or "")
        if parsed.scheme != "https" or not parsed.hostname or not (
            parsed.hostname == "paddle.com" or parsed.hostname.endswith(".paddle.com")
        ):
            raise RuntimeError("Paddle did not return a valid customer portal URL")
    except Exception as exc:
        logger.error("Paddle customer portal creation failed (error_type=%s)", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Unable to open self-service billing. Please retry later.") from None
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {"portal_url": portal_url, "expires_in_seconds": 900}


@app.get("/api/v1/account/api-keys")
async def list_account_api_keys(
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_async_db),
):
    """List metadata for this account's API keys; never return stored key material."""
    from sqlalchemy import select

    rows = (await db.execute(
        select(APIKey)
        .where(APIKey.license_id == license_obj.id)
        .order_by(APIKey.created_at.desc(), APIKey.id.desc())
        .limit(100)
    )).scalars().all()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "items": [
            {
                "id": item.id,
                "key_prefix": item.key_prefix,
                "created_at": item.created_at.isoformat() if item.created_at else None,
            }
            for item in rows
        ],
        "limit": 100,
        "note": "Full API keys are shown only once when created.",
    }


@app.post("/api/v1/account/api-keys", status_code=201)
async def create_account_api_key(
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_async_db),
):
    """Create a customer-owned API key and reveal its secret exactly once."""
    from sqlalchemy import select, func as sql_func

    # Serialize key creation per license on databases that support row locks. Without
    # this lock, simultaneous requests can both observe nine keys and create an
    # eleventh key despite the per-account cap.
    await db.execute(
        select(SoftwareLicense.id)
        .where(SoftwareLicense.id == license_obj.id)
        .with_for_update()
    )
    current_count = int((await db.execute(
        select(sql_func.count(APIKey.id)).where(APIKey.license_id == license_obj.id)
    )).scalar_one() or 0)
    if current_count >= 10:
        raise HTTPException(
            status_code=409,
            detail="This account already has 10 API keys. Revoke an unused key before creating another.",
        )

    raw_key = "eaa_" + secrets.token_urlsafe(32)
    key_hash = APIKey.hash_key(raw_key)
    item = APIKey(
        license_id=license_obj.id,
        api_key_hash=key_hash,
        key_prefix=raw_key[:10],
    )
    db.add(item)
    try:
        await db.commit()
        await db.refresh(item)
    except Exception:
        await db.rollback()
        logger.error("Customer API key creation failed (license_id=%s)", license_obj.id)
        raise HTTPException(status_code=503, detail="API key could not be created. Please retry.") from None

    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "id": item.id,
        "key": raw_key,
        "key_prefix": item.key_prefix,
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "warning": "Copy this key now. It cannot be retrieved again.",
    }


@app.delete("/api/v1/account/api-keys/{key_id}")
async def revoke_account_api_key(
    key_id: int,
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_account_credentials_for_key_revocation),
    db: AsyncSession = Depends(get_async_db),
):
    """Revoke an account-owned API key, including after the license expires.

    The dedicated dependency grants no audit/report access and is used only for
    this revocation action so expired customers can invalidate compromised keys.
    """
    from sqlalchemy import delete

    result = await db.execute(
        delete(APIKey).where(
            APIKey.id == key_id,
            APIKey.license_id == license_obj.id,
        )
    )
    if not result.rowcount:
        await db.rollback()
        raise HTTPException(status_code=404, detail="API key not found for this account.")
    await db.commit()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {"status": "revoked", "key_id": key_id}


def _load_saved_report_coverage(coverage_json: str | None) -> dict:
    """Load persisted coverage defensively; a damaged legacy row must not break report history."""
    try:
        payload = json.loads(coverage_json or "{}")
    except (TypeError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _sanitize_saved_evidence_records(records: list, offset: int, limit: int) -> list[dict]:
    """Return a bounded, allowlisted, redacted slice of persisted report evidence."""
    allowed = {
        "check_id", "check_name", "category", "page_url", "source_url", "outcome",
        "observed_at_utc", "method", "test_method", "evidence", "evidence_ref",
        "title", "status", "severity", "finding_id", "description", "recommendation",
        "message", "detail", "notes", "evidence_confidence", "standard_reference",
        "affected_urls", "observed_value", "limitation", "reason", "tool_version",
    }
    result = []
    for record in records[offset:offset + limit]:
        if not isinstance(record, dict):
            continue
        safe = {}
        for field in allowed:
            if field not in record:
                continue
            value = record[field]
            if isinstance(value, str):
                safe[field] = _redact_audit_metadata_text(value, limit=2000)
            elif isinstance(value, (int, float, bool)) or value is None:
                safe[field] = value
            elif field == "affected_urls" and isinstance(value, list):
                safe[field] = [_redact_audit_metadata_text(item, limit=1000) for item in value[:50] if isinstance(item, str)]
        result.append(safe)
    return result


def _saved_report_outcome_summary(coverage_json: str | None) -> dict:
    """Summarize only persisted explicit outcomes; never infer missing checks as passes."""
    states = ("pass", "issue", "warning", "not_assessed", "error")
    counts = {state: 0 for state in states}
    payload = _load_saved_report_coverage(coverage_json)
    outcomes = payload.get("check_outcomes", [])
    if not isinstance(outcomes, list):
        outcomes = []
    for item in outcomes:
        if not isinstance(item, dict):
            continue
        state = item.get("outcome")
        if state in counts:
            counts[state] += 1
    denominator = sum(counts.values())
    return {
        "counts": counts,
        "denominator": denominator,
        "percentages": {
            state: round(count / denominator * 100, 1) if denominator else None
            for state, count in counts.items()
        },
        "scope_note": (
            "Counts include only saved explicit outcomes; missing outcomes are not passes."
        ),
    }


@app.get("/api/v1/reports")
async def list_audit_reports(
    response: Response,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_async_db),
):
    """List only reports owned by the authenticated license; never expose PDF bytes here."""
    from sqlalchemy import select, func as sql_func
    total = (await db.execute(
        select(sql_func.count(AuditReport.id)).where(AuditReport.license_id == license_obj.id)
    )).scalar_one()
    rows = (await db.execute(
        select(AuditReport).where(AuditReport.license_id == license_obj.id)
        .order_by(AuditReport.created_at.desc(), AuditReport.id.desc())
        .offset(offset).limit(limit)
    )).scalars().all()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "reports": [
            {
                "id": row.id,
                "domain": row.domain,
                "finding_count": row.finding_count,
                "created_at": row.created_at.isoformat(),
                "check_outcome_summary": _saved_report_outcome_summary(row.coverage_json),
                "download_url": f"/api/v1/reports/{row.id}/pdf",
                "coverage_url": f"/api/v1/reports/{row.id}/coverage",
            }
            for row in rows
        ],
    }


@app.get("/api/v1/reports/{report_id}/pdf", response_class=Response)
async def download_audit_report(
    report_id: int,
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_async_db),
):
    """Download a stored report only when it belongs to the authenticated license."""
    from sqlalchemy import select
    row = (await db.execute(select(AuditReport).where(
        AuditReport.id == report_id,
        AuditReport.license_id == license_obj.id,
    ))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Audit report not found")
    safe_hostname = re.sub(r"[^a-zA-Z0-9.-]", "-", row.domain)[:180] or "website"
    return Response(
        content=row.pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="ecommerce-audit-{safe_hostname}-{row.id}.pdf"',
            "Cache-Control": "no-store, private",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/api/v1/reports/{report_id}/coverage")
async def get_audit_report_coverage(
    report_id: int,
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_async_db),
):
    """Return the run's recorded evidence manifest, scoped to the owning license."""
    from sqlalchemy import select
    row = (await db.execute(select(AuditReport).where(
        AuditReport.id == report_id,
        AuditReport.license_id == license_obj.id,
    ))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Audit report not found")
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    payload = _load_saved_report_coverage(row.coverage_json)
    # Keep the common coverage request small. Detailed evidence is separately paginated
    # so large crawls do not flood the customer dashboard or serverless response body.
    findings = payload.pop("findings", [])
    outcomes = payload.pop("check_outcomes", [])
    payload["stored_findings_count"] = len(findings) if isinstance(findings, list) else 0
    payload["stored_check_outcomes_count"] = len(outcomes) if isinstance(outcomes, list) else 0
    payload["evidence_endpoint"] = f"/api/v1/reports/{report_id}/evidence"
    return payload


@app.get("/api/v1/reports/{report_id}/evidence")
async def get_audit_report_evidence(
    report_id: int,
    response: Response,
    kind: str = Query("findings", pattern="^(findings|check_outcomes)$"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_async_db),
):
    """Return a bounded page of saved evidence, isolated to the owning license."""
    from sqlalchemy import select
    row = (await db.execute(select(AuditReport).where(
        AuditReport.id == report_id,
        AuditReport.license_id == license_obj.id,
    ))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Audit report not found")
    metadata = _load_saved_report_coverage(row.coverage_json)
    collection = metadata.get("findings" if kind == "findings" else "check_outcomes", [])
    if not isinstance(collection, list):
        collection = []
    # Only object records are meaningful outcomes; malformed entries are not checks.
    collection = [item for item in collection if isinstance(item, dict)]
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    outcome_summary = None
    if kind == "check_outcomes":
        # Count only stored explicit outcome records. These counts describe saved
        # evidence, not every possible check on the website.
        states = ("pass", "issue", "warning", "not_assessed", "error")
        counts = {
            state: sum(
                1 for item in collection
                if isinstance(item, dict) and item.get("outcome") == state
            )
            for state in states
        }
        denominator = len(collection)
        outcome_summary = {
            "denominator": denominator,
            "counts": counts,
            "percentages": {
                state: round(count / denominator * 100, 1) if denominator else None
                for state, count in counts.items()
            },
            "scope_note": "Only saved explicit outcomes are counted; missing outcomes are not passes and this is not full-site coverage.",
        }
    return {
        "report_id": report_id,
        "kind": kind,
        "outcome_summary": outcome_summary,
        "total": len(collection),
        "limit": limit,
        "offset": offset,
        "items": _sanitize_saved_evidence_records(collection, offset, limit),
    }




def _smtp_configuration_status() -> dict:
    """Describe SMTP readiness without returning configured values or secrets."""
    issues = []
    if not os.getenv("SMTP_HOST", "").strip():
        issues.append("SMTP_HOST missing")
    if not os.getenv("SMTP_FROM", "").strip():
        issues.append("SMTP_FROM missing")
    try:
        port = int(os.getenv("SMTP_PORT", "587").strip())
        if not 1 <= port <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        issues.append("SMTP_PORT must be an integer from 1 to 65535")
    mode = os.getenv("SMTP_TLS_MODE", "starttls").strip().lower()
    if mode not in {"starttls", "ssl"}:
        issues.append("SMTP_TLS_MODE must be starttls or ssl")
    username = os.getenv("SMTP_USERNAME", "").strip()
    password = os.getenv("SMTP_PASSWORD", "")
    if bool(username) != bool(password):
        issues.append("SMTP_USERNAME and SMTP_PASSWORD must both be set or both be empty")
    return {"configured": not issues, "issues": issues}


def _configured_smtp_port() -> int:
    """Validate SMTP port configuration before opening a network connection."""
    raw_port = os.getenv("SMTP_PORT", "587").strip()
    try:
        port = int(raw_port)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("SMTP port configuration is invalid") from exc
    if not 1 <= port <= 65535:
        raise RuntimeError("SMTP port configuration is invalid")
    return port


def _send_license_email(recipient: str, license_key: str, tier: str, quota: int) -> None:
    """Deliver a newly provisioned license using SMTP secrets from the runtime environment."""
    host = os.getenv("SMTP_HOST", "").strip()
    sender = os.getenv("SMTP_FROM", "").strip()
    if not host or not sender:
        raise RuntimeError("Email delivery is not configured")
    port = _configured_smtp_port()
    username = os.getenv("SMTP_USERNAME", "")
    password = os.getenv("SMTP_PASSWORD", "")
    mode = os.getenv("SMTP_TLS_MODE", "starttls").strip().lower()
    if mode not in {"starttls", "ssl"}:
        raise RuntimeError("Unsupported SMTP TLS mode")
    message = EmailMessage()
    message["Subject"] = "Your E-commerce Audit Agent license"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        "Your payment has been confirmed and your audit license is ready.\n\n"
        f"License key: {license_key}\nPlan: {tier}\nMonthly audit allowance: {quota}\n\n"
        "Open the customer dashboard, choose License key, and paste this key to access your reports. "
        "Keep this key private; it authorizes use of your account allowance."
    )
    if mode == "ssl":
        with smtplib.SMTP_SSL(host, port, timeout=15) as server:
            if username:
                server.login(username, password)
            server.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            if username:
                server.login(username, password)
            server.send_message(message)


def _paddle_api_base() -> str:
    environment = os.getenv("PADDLE_ENVIRONMENT", "sandbox").strip().lower()
    if environment == "production": return "https://api.paddle.com"
    if environment == "sandbox": return "https://sandbox-api.paddle.com"
    raise RuntimeError("PADDLE_ENVIRONMENT must be sandbox or production")


def _paddle_api_request(path: str, method: str = "GET", payload: dict | None = None) -> dict:
    """Call Paddle Billing with server-side credentials; never log tokens or request bodies."""
    import urllib.request
    import urllib.error
    api_key = os.getenv("PADDLE_API_KEY", "").strip()
    if not api_key: raise RuntimeError("Paddle API is not configured")
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(_paddle_api_base() + path, data=body, method=method,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Paddle API request failed (HTTP {exc.code})") from exc
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise RuntimeError(f"Paddle API request failed ({type(exc).__name__})") from exc


def _configured_payment_plans() -> list[dict]:
    plans = []
    for tier, label, default_quota in (("STARTER", "Starter", 100), ("PRO", "Pro", 500), ("BUSINESS", "Business", 2000)):
        price_id = os.getenv(f"PADDLE_PRICE_ID_{tier}", "").strip()
        if not re.fullmatch(r"pri_[a-z0-9]+", price_id): continue
        try: quota = int(os.getenv(f"LICENSE_MONTHLY_AUDITS_{tier}", str(default_quota)))
        except ValueError: continue
        if quota < 1: continue
        plans.append({"tier": tier.lower(), "label": label, "monthly_audit_allowance": quota, "price_id": price_id})
    return plans


class PaddleCheckoutRequest(BaseModel):
    tier: str


@app.get("/api/v1/billing/plans")
async def public_billing_plans(db: AsyncSession = Depends(get_async_db)):
    """Expose active operator-managed plans only when payment delivery is configured."""
    ready = bool(os.getenv("PADDLE_API_KEY", "").strip() and os.getenv("PADDLE_WEBHOOK_SECRET", "").strip()
                 and os.getenv("SMTP_HOST", "").strip() and os.getenv("SMTP_FROM", "").strip())
    plans = await _db_payment_plans(db, active_only=True) if ready else []
    plans = [p for p in plans if p.get("price_id")]
    return {"checkout_provider": "Paddle", "configured": bool(plans),
        "plans": [{"tier": p["tier"], "label": p["label"],
                   "monthly_audit_allowance": p["monthly_audit_allowance"],
                   "max_concurrent_audits": p["max_concurrent_audits"]} for p in plans],
        "configuration_needed": [] if plans else ["Paddle API key", "Paddle notification destination secret",
            "SMTP host and sender", "Paddle price ID for each enabled plan"]}


@app.post("/api/v1/billing/checkout")
async def create_paddle_checkout(payload: PaddleCheckoutRequest, db: AsyncSession = Depends(get_async_db)):
    """Create a transaction using an active server-managed package price; the client cannot set amounts."""
    tier = payload.tier.strip().lower()
    plans = await _db_payment_plans(db, active_only=True)
    plan = next((p for p in plans if p["tier"] == tier), None)
    if plan is None:
        raise HTTPException(status_code=422, detail="The selected package is unavailable.")
    if not plan.get("price_id") or not os.getenv("PADDLE_API_KEY", "").strip():
        raise HTTPException(status_code=503, detail="This Paddle plan is not configured.")
    transaction = {"items": [{"price_id": plan["price_id"], "quantity": 1}],
                   "custom_data": {"license_tier": plan["tier"]}}
    checkout_url = os.getenv("PADDLE_CHECKOUT_URL", "").strip()
    if checkout_url:
        parsed = urlsplit(checkout_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise HTTPException(status_code=503, detail="Paddle checkout URL configuration is invalid.")
        transaction["checkout"] = {"url": checkout_url}
    try:
        response = await asyncio.to_thread(_paddle_api_request, "/transactions", "POST", transaction)
        url = response.get("data", {}).get("checkout", {}).get("url")
        parsed = urlsplit(url or "")
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or not (
                parsed.hostname.lower() == "paddle.com"
                or parsed.hostname.lower().endswith(".paddle.com")
            )
        ):
            raise RuntimeError("Paddle did not return a valid checkout URL")
        transaction_id = response.get("data", {}).get("id")
        if not isinstance(transaction_id, str) or not re.fullmatch(r"txn_[A-Za-z0-9]+", transaction_id):
            raise RuntimeError("Paddle did not return a valid transaction ID")
        return {"checkout_url": url, "transaction_id": transaction_id}
    except Exception as exc:
        logger.error("Paddle checkout creation failed (error_type=%s)", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Unable to start Paddle checkout; verify billing configuration.") from exc


@app.post("/api/v1/billing/paddle-webhook")
async def paddle_webhook(request: Request, db: AsyncSession = Depends(get_async_db)):
    """Verify Paddle signatures and provision licenses idempotently after transaction completion."""
    secret = os.getenv("PADDLE_WEBHOOK_SECRET", "").strip()
    signature = request.headers.get("paddle-signature", "")
    if not secret or not signature:
        raise HTTPException(status_code=503 if not secret else 400, detail="Paddle webhook is not configured or signature is missing.")
    # Webhook payloads are small JSON documents. Bound streamed input before
    # buffering it so an oversized request cannot consume unbounded function memory.
    max_webhook_body_bytes = 1024 * 1024
    content_length = request.headers.get("content-length", "").strip()
    if content_length:
        try:
            if int(content_length) > max_webhook_body_bytes:
                raise HTTPException(status_code=413, detail="Paddle webhook payload is too large.")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Paddle webhook content length.")
    body_chunks = []
    body_size = 0
    async for chunk in request.stream():
        body_size += len(chunk)
        if body_size > max_webhook_body_bytes:
            raise HTTPException(status_code=413, detail="Paddle webhook payload is too large.")
        body_chunks.append(chunk)
    raw_body = b"".join(body_chunks)
    try:
        parts = {}
        for item in signature.split(";"):
            key, value = item.split("=", 1)
            parts.setdefault(key, []).append(value)
        timestamp = int(parts["ts"][0])
        signatures = parts.get("h1", [])
    except (KeyError, ValueError, IndexError):
        raise HTTPException(status_code=400, detail="Malformed Paddle signature.")
    if abs(int(time.time()) - timestamp) > 300:
        raise HTTPException(status_code=400, detail="Paddle signature timestamp is outside the allowed window.")
    expected = hmac.new(secret.encode(), str(timestamp).encode() + b":" + raw_body, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, candidate) for candidate in signatures):
        raise HTTPException(status_code=400, detail="Invalid Paddle signature.")
    try: event = json.loads(raw_body)
    except (ValueError, UnicodeDecodeError): raise HTTPException(status_code=400, detail="Invalid Paddle event JSON.")
    event_id = str(event.get("event_id") or event.get("id") or "")
    event_type = str(event.get("event_type") or event.get("type") or "")
    if not event_id: raise HTTPException(status_code=400, detail="Paddle event ID is missing.")
    transaction = event.get("data") or {}

    # Subscription lifecycle events must not be silently discarded: a confirmed
    # cancellation revokes future access for the license provisioned by its purchase.
    if event_type == "subscription.canceled":
        subscription_id = str(transaction.get("id") or "")[:100]
        if not subscription_id:
            raise HTTPException(status_code=400, detail="Paddle cancellation event has no subscription ID.")
        from sqlalchemy import select, update
        # Serialize lifecycle transitions for this subscription. The advisory lock
        # is transaction-scoped and avoids a late renewal racing a cancellation.
        await db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:subscription_id))"),
            {"subscription_id": subscription_id},
        )
        linked_event = (await db.execute(
            select(PaymentWebhookEvent)
            .where(PaymentWebhookEvent.subscription_id == subscription_id)
            .order_by(PaymentWebhookEvent.updated_at.desc())
            .limit(1)
        )).scalar_one_or_none()
        if linked_event is None or linked_event.license_id is None:
            logger.warning("Paddle cancellation cannot yet be linked (event_id=%s)", event_id[:80])
            raise HTTPException(status_code=503, detail="Subscription cancellation is awaiting license reconciliation.")
        license_obj = (await db.execute(
            select(SoftwareLicense).where(SoftwareLicense.id == linked_event.license_id)
        )).scalar_one_or_none()
        if license_obj is None:
            raise HTTPException(status_code=503, detail="Subscription cancellation is awaiting license reconciliation.")
        changed = bool(license_obj.is_active)
        license_obj.is_active = False
        # Persist a sticky lifecycle marker on the latest subscription event.
        # A delayed transaction.completed webhook must not reactivate access after
        # a cancellation has already been applied.
        linked_event.status = "subscription_canceled"
        linked_event.updated_at = datetime.now(timezone.utc)
        await db.commit()
        if changed:
            await _record_operation_event(db, "subscription_canceled", license_obj.id, None, None)
            logger.info("Paddle subscription cancellation applied (license_id=%s)", license_obj.id)
        return {"status": "cancellation_applied" if changed else "already_canceled", "event_id": event_id}

    if event_type != "transaction.completed":
        return {"status": "ignored", "event_id": event_id}
    if transaction.get("status") != "completed": return {"status": "payment_not_complete", "event_id": event_id}
    custom_data = transaction.get("custom_data") or {}
    tier = str(custom_data.get("license_tier", "")).strip().lower()
    price_ids = {item.get("price", {}).get("id") for item in (transaction.get("items") or []) if isinstance(item, dict)}
    configured_plans = await _db_payment_plans(db, active_only=False)
    plans_by_tier = {p["tier"]: p for p in configured_plans}
    plan = plans_by_tier.get(tier)
    if plan is None or plan.get("price_id") not in price_ids:
        plan = next((candidate for candidate in configured_plans
                     if candidate.get("price_id") in price_ids), None)
    if plan is None or not plan.get("price_id"):
        raise HTTPException(status_code=400, detail="Completed Paddle transaction does not match a configured price.")

    from sqlalchemy import select
    # Resolve subscription renewals to the original account before provisioning.
    # Recurring transactions have new transaction IDs; treating each as a new purchase
    # would otherwise mint a fresh license and send duplicate credentials every month.
    transaction_id = str(transaction.get("id") or "")[:100] or None
    subscription_id = str(transaction.get("subscription_id") or "")[:100] or None
    if subscription_id:
        # Use the same subscription-scoped lock as cancellation so lifecycle state
        # transitions are serialized in PostgreSQL.
        await db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:subscription_id))"),
            {"subscription_id": subscription_id},
        )
        linked_subscription_event = (await db.execute(
            select(PaymentWebhookEvent)
            .where(PaymentWebhookEvent.subscription_id == subscription_id)
            .order_by(PaymentWebhookEvent.updated_at.desc())
            .limit(1)
        )).scalar_one_or_none()
        if linked_subscription_event is not None and linked_subscription_event.status == "subscription_canceled":
            # A late/replayed payment event is not proof that a canceled subscription
            # has been reinstated. Require a separately verified lifecycle/reconcile
            # action instead of silently restoring account access.
            return {"status": "subscription_canceled", "event_id": event_id}
        if linked_subscription_event is not None and linked_subscription_event.license_id is not None:
            linked_license = (await db.execute(
                select(SoftwareLicense).where(SoftwareLicense.id == linked_subscription_event.license_id)
            )).scalar_one_or_none()
            if linked_license is not None:
                existing_event = (await db.execute(
                    select(PaymentWebhookEvent).where(PaymentWebhookEvent.event_id == event_id)
                )).scalar_one_or_none()
                if existing_event is not None:
                    if existing_event.status == "delivered":
                        return {"status": "already_processed", "event_id": event_id}
                    return {"status": "delivery_in_progress", "event_id": event_id}
                if transaction_id:
                    prior_renewal = (await db.execute(
                        select(PaymentWebhookEvent).where(PaymentWebhookEvent.transaction_id == transaction_id)
                    )).scalar_one_or_none()
                    if prior_renewal is not None:
                        return {"status": "already_processed", "event_id": prior_renewal.event_id}
                linked_license.tier = plan["tier"]
                linked_license.max_monthly_audits = plan["monthly_audit_allowance"]
                linked_license.is_active = True
                renewal_customer = transaction.get("customer") or {}
                renewal_customer_id = str(
                    transaction.get("customer_id") or renewal_customer.get("id") or ""
                ).strip()
                renewal_event = PaymentWebhookEvent(
                    event_id=event_id,
                    status="delivered",
                    license_id=linked_license.id,
                    recipient_email=linked_subscription_event.recipient_email,
                    transaction_id=transaction_id,
                    subscription_id=subscription_id,
                    paddle_customer_id=(renewal_customer_id[:100] or linked_subscription_event.paddle_customer_id),
                )
                db.add(renewal_event)
                await db.commit()
                await _record_operation_event(db, "subscription_renewed", linked_license.id, None, None)
                return {"status": "subscription_renewed", "event_id": event_id, "license_id": linked_license.id}

    # Paddle retries normally reuse event_id, but a transaction can also be
    # delivered under a distinct event ID. Reuse the original provisioning record
    # by transaction ID so a second notification cannot mint another license.
    if transaction_id:
        # Serialize provisioning for this purchase before looking up its event.
        # This closes the race where distinct event IDs arrive simultaneously
        # before either request inserts a webhook record.
        await db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:transaction_id))"),
            {"transaction_id": transaction_id},
        )
        prior_transaction_event = (await db.execute(
            select(PaymentWebhookEvent)
            .where(PaymentWebhookEvent.transaction_id == transaction_id)
            .order_by(PaymentWebhookEvent.updated_at.desc())
            .limit(1)
        )).scalar_one_or_none()
        if prior_transaction_event is not None:
            event_id = prior_transaction_event.event_id
    webhook_event = (await db.execute(select(PaymentWebhookEvent).where(PaymentWebhookEvent.event_id == event_id))).scalar_one_or_none()
    if webhook_event is None:
        customer = transaction.get("customer") or {}
        recipient = str(customer.get("email") or "").strip()
        customer_name = str(customer.get("name") or "").strip()
        customer_id = str(transaction.get("customer_id") or customer.get("id") or "").strip()
        if not recipient and customer_id and os.getenv("PADDLE_API_KEY", "").strip():
            try:
                customer_response = await asyncio.to_thread(_paddle_api_request, f"/customers/{customer_id}")
                customer = customer_response.get("data") or {}
                recipient = str(customer.get("email") or "").strip()
                customer_name = str(customer.get("name") or "").strip()
            except Exception as exc:
                logger.error("Paddle customer lookup failed (error_type=%s)", type(exc).__name__)
                raise HTTPException(status_code=502, detail="Paddle customer details could not be retrieved; webhook can retry.") from exc
        if len(recipient) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", recipient):
            raise HTTPException(status_code=400, detail="Completed Paddle transaction has no valid customer email.")
        license_obj = SoftwareLicense(license_key=secrets.token_urlsafe(32), client_name=(customer_name or recipient)[:255],
            tier=plan["tier"], max_monthly_audits=plan["monthly_audit_allowance"], is_active=True)
        db.add(license_obj)
        await db.flush()
        webhook_event = PaymentWebhookEvent(
            event_id=event_id, status="email_pending", license_id=license_obj.id,
            recipient_email=recipient, transaction_id=str(transaction.get("id") or "")[:100] or None,
            subscription_id=str(transaction.get("subscription_id") or "")[:100] or None,
            paddle_customer_id=customer_id[:100] or None,
        )
        db.add(webhook_event)
        await db.commit()
    elif webhook_event.status == "delivered":
        return {"status": "already_processed", "event_id": event_id}
    if not webhook_event.transaction_id:
        webhook_event.transaction_id = str(transaction.get("id") or "")[:100] or None
    if not webhook_event.subscription_id:
        webhook_event.subscription_id = str(transaction.get("subscription_id") or "")[:100] or None
    if not webhook_event.paddle_customer_id:
        event_customer = transaction.get("customer") or {}
        event_customer_id = str(transaction.get("customer_id") or event_customer.get("id") or "").strip()
        webhook_event.paddle_customer_id = event_customer_id[:100] or None
    await db.commit()

    # Claim email delivery atomically so simultaneous Paddle retries cannot send
    # the same license email twice. A stale claim can be recovered after a worker
    # crash; normal SMTP retries remain immediately available after a failed send.
    from datetime import timedelta
    from sqlalchemy import or_, update
    now = datetime.now(timezone.utc)
    stale_before = now - timedelta(minutes=5)
    claimed = await db.execute(
        update(PaymentWebhookEvent)
        .where(
            PaymentWebhookEvent.event_id == event_id,
            or_(
                PaymentWebhookEvent.status == "email_pending",
                (PaymentWebhookEvent.status == "email_sending")
                & (PaymentWebhookEvent.updated_at < stale_before),
            ),
        )
        .values(status="email_sending", updated_at=now)
        .returning(PaymentWebhookEvent.event_id)
    )
    if claimed.scalar_one_or_none() is None:
        current = (await db.execute(
            select(PaymentWebhookEvent).where(PaymentWebhookEvent.event_id == event_id)
        )).scalar_one_or_none()
        if current is not None and current.status == "delivered":
            return {"status": "already_processed", "event_id": event_id}
        return {"status": "delivery_in_progress", "event_id": event_id}
    await db.commit()

    license_obj = (await db.execute(select(SoftwareLicense).where(SoftwareLicense.id == webhook_event.license_id))).scalar_one_or_none()
    if license_obj is None:
        webhook_event.status = "email_pending"
        webhook_event.updated_at = datetime.now(timezone.utc)
        await db.commit()
        raise HTTPException(status_code=500, detail="The provisioned license record is unavailable.")
    try:
        await asyncio.to_thread(_send_license_email, webhook_event.recipient_email, license_obj.license_key,
            license_obj.tier, license_obj.max_monthly_audits)
    except Exception as exc:
        logger.error("License email delivery failed (error_type=%s)", type(exc).__name__)
        webhook_event.status = "email_pending"
        webhook_event.updated_at = datetime.now(timezone.utc)
        await db.commit()
        raise HTTPException(status_code=502, detail="Payment was recorded; license email is pending SMTP delivery retry.") from exc
    webhook_event.status = "delivered"
    webhook_event.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return {"status": "provisioned", "event_id": event_id}

def _send_pdf_email(recipient: str, domain: str, report_id: int, pdf_bytes: bytes) -> None:
    """Send a user-requested report using SMTP configuration supplied only via environment."""
    host = os.getenv("SMTP_HOST", "").strip()
    sender = os.getenv("SMTP_FROM", "").strip()
    if not host or not sender:
        raise RuntimeError("Email delivery is not configured")
    port = _configured_smtp_port()
    username = os.getenv("SMTP_USERNAME", "")
    password = os.getenv("SMTP_PASSWORD", "")
    mode = os.getenv("SMTP_TLS_MODE", "starttls").strip().lower()
    if mode not in {"starttls", "ssl"}:
        raise RuntimeError("Unsupported SMTP TLS mode")

    message = EmailMessage()
    message["Subject"] = f"Your e-commerce audit report for {domain}"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        f"Your requested e-commerce audit report for {domain} is attached.\n\n"
        "The report describes observed public signals and limitations. It does not claim "
        "complete security, WCAG conformance, Google indexing, or measured revenue impact.\n"
        f"Report reference: {report_id}\n"
    )
    message.add_attachment(
        pdf_bytes,
        maintype="application",
        subtype="pdf",
        filename=f"ecommerce-audit-{report_id}.pdf",
    )
    if mode == "ssl":
        with smtplib.SMTP_SSL(host, port, timeout=15) as server:
            if username:
                server.login(username, password)
            server.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            if username:
                server.login(username, password)
            server.send_message(message)


@app.post("/api/v1/reports/{report_id}/email")
async def email_audit_report(
    report_id: int,
    payload: ReportEmailRequest,
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_async_db),
):
    """Email a saved PDF only on explicit request and only for a report owned by this license."""
    from sqlalchemy import select
    recipient = payload.recipient_email.strip()
    if not payload.recipient_confirmed:
        raise HTTPException(status_code=422, detail="Confirm that the recipient requested this report.")
    if len(recipient) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", recipient):
        raise HTTPException(status_code=422, detail="Provide a valid recipient email address.")
    row = (await db.execute(select(AuditReport).where(
        AuditReport.id == report_id,
        AuditReport.license_id == license_obj.id,
    ))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Audit report not found")
    if len(row.pdf_bytes) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Report exceeds the email attachment size limit.")
    try:
        await asyncio.to_thread(
            _send_pdf_email, recipient, row.domain, row.id, row.pdf_bytes
        )
    except RuntimeError as exc:
        if str(exc) == "Email delivery is not configured":
            raise HTTPException(status_code=503, detail="Email delivery is not configured on this deployment.") from exc
        logger.error("Report email configuration rejected (error_type=%s)", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Email delivery configuration is invalid.") from exc
    except Exception as exc:
        logger.error("Report email delivery failed (error_type=%s)", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Email delivery failed; verify SMTP configuration and retry.") from exc
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {"status": "sent", "report_id": row.id}



async def _ensure_admin_tables(db: AsyncSession) -> None:
    """Create admin tables and bootstrap plans while serializing concurrent schema setup."""
    # Multiple cold-start requests can enter this lazy initializer simultaneously.
    # Serialize DDL + plan seeding within PostgreSQL; the transaction lock is released
    # by the caller's commit/rollback, preventing CREATE INDEX / INSERT deadlocks.
    await db.execute(text(
        "SELECT pg_advisory_xact_lock(hashtext('ecommerce_audit_admin_schema_v1'))"
    ))
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS saas_plan_packages (
            tier VARCHAR(50) PRIMARY KEY,
            label VARCHAR(100) NOT NULL,
            monthly_audit_allowance INTEGER NOT NULL CHECK (monthly_audit_allowance BETWEEN 1 AND 10000000),
            max_concurrent_audits INTEGER NOT NULL CHECK (max_concurrent_audits BETWEEN 1 AND 10000),
            paddle_price_id VARCHAR(100),
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """))
    await db.execute(text("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_saas_plan_packages_paddle_price_id
        ON saas_plan_packages (paddle_price_id) WHERE paddle_price_id IS NOT NULL
    """))
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS saas_operation_events (
            id BIGSERIAL PRIMARY KEY,
            event_type VARCHAR(80) NOT NULL,
            license_id INTEGER REFERENCES software_licenses(id) ON DELETE SET NULL,
            domain VARCHAR(255),
            error_type VARCHAR(120),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_saas_operation_events_created
        ON saas_operation_events (created_at DESC, id DESC)
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_saas_operation_events_type_created
        ON saas_operation_events (event_type, created_at DESC)
    """))
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS saas_admin_action_logs (
            id BIGSERIAL PRIMARY KEY,
            action VARCHAR(80) NOT NULL,
            entity_type VARCHAR(50) NOT NULL,
            entity_id VARCHAR(255),
            details_json TEXT NOT NULL DEFAULT '{}',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_saas_admin_action_logs_created
        ON saas_admin_action_logs (created_at DESC, id DESC)
    """))
    # Keep billing references available when this code is upgraded against an existing database.
    await db.execute(text("ALTER TABLE payment_webhook_events ADD COLUMN IF NOT EXISTS transaction_id VARCHAR(100)"))
    await db.execute(text("ALTER TABLE payment_webhook_events ADD COLUMN IF NOT EXISTS subscription_id VARCHAR(100)"))
    await db.execute(text("CREATE INDEX IF NOT EXISTS ix_payment_webhook_events_transaction_id ON payment_webhook_events (transaction_id)"))
    await db.execute(text("CREATE INDEX IF NOT EXISTS ix_payment_webhook_events_subscription_id ON payment_webhook_events (subscription_id)"))
    # Migrate configured legacy plans without overwriting operator-managed values.
    for plan in _configured_payment_plans():
        tier = plan["tier"]
        env_suffix = tier.upper()
        # Safe product defaults must match the published plan tiers even when
        # optional per-tier environment overrides have not been configured.
        default_concurrency = {"starter": 1, "pro": 3, "business": 10}.get(tier, 1)
        try:
            concurrency = int(os.getenv(
                f"LICENSE_MAX_CONCURRENT_AUDITS_{env_suffix}",
                str(default_concurrency),
            ))
        except ValueError:
            concurrency = default_concurrency
        concurrency = min(10000, max(1, concurrency))
        await db.execute(text("""
            INSERT INTO saas_plan_packages
                (tier, label, monthly_audit_allowance, max_concurrent_audits, paddle_price_id, is_active)
            VALUES (:tier, :label, :allowance, :concurrency, :price_id, TRUE)
            ON CONFLICT (tier) DO NOTHING
        """), {"tier": tier, "label": plan["label"], "allowance": plan["monthly_audit_allowance"],
               "concurrency": concurrency, "price_id": plan["price_id"]})
        # Repair only the legacy default (1) when the explicit environment setting
        # requests a higher limit. Preserve non-default values set in the admin UI.
        if concurrency > 1:
            await db.execute(text("""
                UPDATE saas_plan_packages
                SET max_concurrent_audits=:concurrency, updated_at=NOW()
                WHERE tier=:tier AND max_concurrent_audits=1
            """), {"tier": tier, "concurrency": concurrency})
    await db.commit()


def _sanitize_admin_log_value(value, *, depth: int = 0):
    """Bound and redact admin-log payloads before they reach persistent storage."""
    if depth > 5:
        return "[nested value omitted]"
    if isinstance(value, dict):
        cleaned = {}
        for key, item in list(value.items())[:100]:
            name = str(key)[:100]
            if re.search(r"(?i)(secret|password|passwd|token|credential|authorization|api.?key|license.?key|private.?key)", name):
                cleaned[name] = "[REDACTED]"
            else:
                cleaned[name] = _sanitize_admin_log_value(item, depth=depth + 1)
        return cleaned
    if isinstance(value, (list, tuple)):
        return [_sanitize_admin_log_value(item, depth=depth + 1) for item in value[:100]]
    if isinstance(value, str):
        # Redact secret-shaped assignments even when a caller accidentally places
        # a credential in an otherwise ordinary diagnostic string.
        from log_safety import redact_secrets
        return redact_secrets(value[:2000])
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:500]


async def _write_admin_log(db: AsyncSession, action: str, entity_type: str,
                           entity_id: str | int | None, details: dict | None = None) -> None:
    # Defense in depth: do not trust each caller to sanitize the audit metadata.
    safe_details = _sanitize_admin_log_value(details or {})
    await db.execute(text("""
        INSERT INTO saas_admin_action_logs (action, entity_type, entity_id, details_json)
        VALUES (:action, :entity_type, :entity_id, :details_json)
    """), {"action": action[:80], "entity_type": entity_type[:50],
           "entity_id": str(entity_id)[:255] if entity_id is not None else None,
           "details_json": json.dumps(safe_details, separators=(",", ":"), ensure_ascii=True)})


def _safe_audit_metadata_url(value: str | None) -> str | None:
    """Persist only public HTTP(S) URLs without userinfo, query strings or fragments."""
    if not value:
        return None
    try:
        parts = urlsplit(str(value))
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return None
        if parts.username is not None or parts.password is not None:
            return None
        host = parts.hostname.lower()
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = parts.port
        default_port = 80 if parts.scheme.lower() == "http" else 443
        netloc = f"{host}:{port}" if port and port != default_port else host
        return parts._replace(scheme=parts.scheme.lower(), netloc=netloc, query="", fragment="").geturl()
    except (TypeError, ValueError, UnicodeError):
        return None


def _redact_audit_metadata_text(value: object, *, limit: int = 2000) -> str:
    """Bound stored evidence and remove common credential-like assignments."""
    import re
    text_value = str(value or "")[:limit]
    text_value = re.sub(
        r"(?i)(authorization|cookie|set-cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret)(\s*[:=]\s*)([^\s,;]+)",
        r"\1\2[REDACTED]",
        text_value,
    )
    # Evidence excerpts may contain full request URLs. Keep useful path context but
    # never persist query parameters, fragments, or credential-bearing URLs.
    text_value = re.sub(
        r"https?://[^\s\"'<>]+",
        lambda match: _safe_audit_metadata_url(match.group(0).rstrip(".,;")) or "[URL OMITTED]",
        text_value,
        flags=re.IGNORECASE,
    )
    return text_value


def _safe_diagnostic_host(value: str | None) -> str | None:
    try:
        raw = (value or "").strip()
        if not raw:
            return None
        parsed = urlsplit(raw if "://" in raw else "https://" + raw)
        return (parsed.hostname or "")[:255] or None
    except Exception:
        return None


async def _record_operation_event(db: AsyncSession, event_type: str, license_id: int | None,
                                domain: str | None, error_type: str | None) -> None:
    """Best-effort diagnostic write with only a hostname and exception class; never store traceback/secrets."""
    try:
        await db.execute(text("""
            CREATE TABLE IF NOT EXISTS saas_operation_events (
                id BIGSERIAL PRIMARY KEY,
                event_type VARCHAR(80) NOT NULL,
                license_id INTEGER REFERENCES software_licenses(id) ON DELETE SET NULL,
                domain VARCHAR(255),
                error_type VARCHAR(120),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """))
        await db.execute(text("""
            INSERT INTO saas_operation_events (event_type, license_id, domain, error_type)
            VALUES (:event_type, :license_id, :domain, :error_type)
        """), {"event_type": event_type[:80], "license_id": license_id,
               "domain": (domain or "")[:255] or None, "error_type": (error_type or "")[:120] or None})
        await db.commit()
    except Exception as log_exc:
        await db.rollback()
        logger.warning("Operation diagnostic write failed (error_type=%s)", type(log_exc).__name__)


async def _db_payment_plans(db: AsyncSession, active_only: bool = True) -> list[dict]:
    await _ensure_admin_tables(db)
    query = "SELECT tier, label, monthly_audit_allowance, max_concurrent_audits, paddle_price_id, is_active FROM saas_plan_packages"
    if active_only:
        query += " WHERE is_active = TRUE"
    query += " ORDER BY monthly_audit_allowance ASC, tier ASC"
    rows = (await db.execute(text(query))).mappings().all()
    return [{
        "tier": row["tier"], "label": row["label"],
        "monthly_audit_allowance": int(row["monthly_audit_allowance"]),
        "max_concurrent_audits": int(row["max_concurrent_audits"]),
        "price_id": row["paddle_price_id"], "is_active": bool(row["is_active"])
    } for row in rows]


class AdminPackageInput(BaseModel):
    tier: str
    label: str
    monthly_audit_allowance: int
    max_concurrent_audits: int = 1
    paddle_price_id: str | None = None
    is_active: bool = True


def _validate_admin_package(payload: AdminPackageInput) -> dict:
    tier = payload.tier.strip().lower()
    label = payload.label.strip()
    price_id = (payload.paddle_price_id or "").strip() or None
    if not re.fullmatch(r"[a-z0-9_-]{2,50}", tier):
        raise HTTPException(status_code=422, detail="Package tier must be 2-50 lowercase letters, numbers, underscores or hyphens.")
    if not label or len(label) > 100:
        raise HTTPException(status_code=422, detail="Package label must be 1-100 characters.")
    if not 1 <= payload.monthly_audit_allowance <= 10000000:
        raise HTTPException(status_code=422, detail="Monthly audit allowance must be between 1 and 10,000,000.")
    if not 1 <= payload.max_concurrent_audits <= 10000:
        raise HTTPException(status_code=422, detail="Concurrent audit limit must be between 1 and 10,000.")
    if price_id and not re.fullmatch(r"pri_[A-Za-z0-9]+", price_id):
        raise HTTPException(status_code=422, detail="Paddle price ID format is invalid.")
    return {"tier": tier, "label": label, "monthly_audit_allowance": payload.monthly_audit_allowance,
            "max_concurrent_audits": payload.max_concurrent_audits,
            "paddle_price_id": price_id, "is_active": payload.is_active}


@app.get("/api/v1/admin/packages")
async def admin_list_packages(request: Request, db: AsyncSession = Depends(get_async_db)):
    _require_admin_key(request)
    return {"packages": await _db_payment_plans(db, active_only=False)}


@app.post("/api/v1/admin/packages")
async def admin_create_package(payload: AdminPackageInput, request: Request,
                               db: AsyncSession = Depends(get_async_db)):
    _require_admin_key(request)
    values = _validate_admin_package(payload)
    await _ensure_admin_tables(db)
    if values["paddle_price_id"]:
        duplicate = (await db.execute(text("""
            SELECT tier FROM saas_plan_packages WHERE paddle_price_id=:price_id
        """), {"price_id": values["paddle_price_id"]})).scalar_one_or_none()
        if duplicate:
            raise HTTPException(status_code=409, detail="That Paddle price is already assigned to another package.")
    try:
        await db.execute(text("""
            INSERT INTO saas_plan_packages
                (tier, label, monthly_audit_allowance, max_concurrent_audits, paddle_price_id, is_active)
            VALUES (:tier, :label, :monthly_audit_allowance, :max_concurrent_audits, :paddle_price_id, :is_active)
        """), values)
        # Creating a package must not silently mutate pre-existing license
        # entitlements that happen to use the same tier identifier (for example,
        # legacy/manual licenses). New defaults apply to future assignments;
        # existing entitlements are changed explicitly through client management.
        await _write_admin_log(db, "package.created", "package", values["tier"], {
            "monthly_audit_allowance": values["monthly_audit_allowance"],
            "max_concurrent_audits": values["max_concurrent_audits"], "is_active": values["is_active"]})
        await db.commit()
    except Exception as exc:
        await db.rollback()
        if "IntegrityError" in type(exc).__name__:
            raise HTTPException(status_code=409, detail="A package with this tier already exists.") from exc
        logger.error("Admin package creation failed (error_type=%s)", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Unable to create package.") from exc
    return {"status": "created", "tier": values["tier"]}


@app.patch("/api/v1/admin/packages/{tier}")
async def admin_update_package(tier: str, payload: AdminPackageInput, request: Request,
                               db: AsyncSession = Depends(get_async_db)):
    _require_admin_key(request)
    values = _validate_admin_package(payload)
    tier = tier.strip().lower()
    if values["tier"] != tier:
        raise HTTPException(status_code=422, detail="Package tier is immutable; create a new package to use a different identifier.")
    await _ensure_admin_tables(db)
    if values["paddle_price_id"]:
        duplicate = (await db.execute(text("""
            SELECT tier FROM saas_plan_packages WHERE paddle_price_id=:price_id AND tier<>:tier
        """), {"price_id": values["paddle_price_id"], "tier": tier})).scalar_one_or_none()
        if duplicate:
            raise HTTPException(status_code=409, detail="That Paddle price is already assigned to another package.")
    previous_allowance = (await db.execute(text("""
        SELECT monthly_audit_allowance FROM saas_plan_packages WHERE tier=:tier
    """), {"tier": tier})).scalar_one_or_none()
    result = await db.execute(text("""
        UPDATE saas_plan_packages SET label=:label,
          monthly_audit_allowance=:monthly_audit_allowance,
          max_concurrent_audits=:max_concurrent_audits,
          paddle_price_id=:paddle_price_id, is_active=:is_active, updated_at=NOW()
        WHERE tier=:tier
    """), values)
    if result.rowcount == 0:
        await db.rollback()
        raise HTTPException(status_code=404, detail="Package not found.")
    # Update inherited quotas only. Preserve per-client overrides configured by
    # an operator through the client-management endpoint.
    if previous_allowance is not None and int(previous_allowance) != values["monthly_audit_allowance"]:
        await db.execute(text("""
            UPDATE software_licenses SET max_monthly_audits=:allowance
            WHERE LOWER(tier)=:tier AND max_monthly_audits=:previous_allowance
        """), {
            "allowance": values["monthly_audit_allowance"],
            "tier": tier,
            "previous_allowance": int(previous_allowance),
        })
    await _write_admin_log(db, "package.updated", "package", tier, {
        "monthly_audit_allowance": values["monthly_audit_allowance"],
        "max_concurrent_audits": values["max_concurrent_audits"], "is_active": values["is_active"]})
    await db.commit()
    return {"status": "updated", "tier": tier}


@app.delete("/api/v1/admin/packages/{tier}")
async def admin_deactivate_package(tier: str, request: Request, db: AsyncSession = Depends(get_async_db)):
    """Soft-delete packages to preserve subscription/account history."""
    _require_admin_key(request)
    tier = tier.strip().lower()
    await _ensure_admin_tables(db)
    result = await db.execute(text("""
        UPDATE saas_plan_packages SET is_active=FALSE, updated_at=NOW() WHERE tier=:tier
    """), {"tier": tier})
    if result.rowcount == 0:
        await db.rollback()
        raise HTTPException(status_code=404, detail="Package not found.")
    await _write_admin_log(db, "package.deactivated", "package", tier)
    await db.commit()
    return {"status": "deactivated", "tier": tier}


@app.get("/api/v1/admin/actions")
async def admin_action_history(request: Request, limit: int = Query(100, ge=1, le=500),
                              db: AsyncSession = Depends(get_async_db)):
    _require_admin_key(request)
    await _ensure_admin_tables(db)
    rows = (await db.execute(text("""
        SELECT id, action, entity_type, entity_id, details_json, created_at
        FROM saas_admin_action_logs ORDER BY created_at DESC, id DESC LIMIT :limit
    """), {"limit": limit})).mappings().all()
    return {"actions": [{
        "id": row["id"], "action": row["action"], "entity_type": row["entity_type"],
        "entity_id": row["entity_id"], "details": json.loads(row["details_json"] or "{}"),
        "created_at": row["created_at"].isoformat() if row["created_at"] else None
    } for row in rows]}


# ----------------------- Admin operations dashboard -----------------------
# Fail closed: configure ADMIN_API_KEY as a deployment secret. Never log its value.
def _require_admin_key(request: Request) -> None:
    expected = os.getenv("ADMIN_API_KEY", "").strip()
    supplied = request.headers.get("x-admin-key", "")
    if not expected:
        raise HTTPException(status_code=503, detail="Admin access is not configured.")
    if not supplied or not hmac.compare_digest(expected, supplied):
        raise HTTPException(status_code=403, detail="Admin authentication failed.")


@app.get("/admin", response_class=HTMLResponse, include_in_schema=False)
async def admin_dashboard_page():
    """Serve the operator-only dashboard shell; every data endpoint independently authenticates."""
    return FileResponse(Path(__file__).resolve().parent / "admin_portal.html")



@app.post("/api/v1/admin/payment-events/{event_id}/reconcile")
async def admin_reconcile_payment(event_id: str, request: Request,
                                  db: AsyncSession = Depends(get_async_db)):
    """Reconcile a recorded payment and safely backfill missing provider identifiers."""
    _require_admin_key(request)
    await _ensure_admin_tables(db)
    from sqlalchemy import select
    event = (await db.execute(select(PaymentWebhookEvent).where(
        PaymentWebhookEvent.event_id == event_id
    ))).scalar_one_or_none()
    if event is None:
        raise HTTPException(status_code=404, detail="Payment event not found.")
    if not event.transaction_id:
        raise HTTPException(status_code=409, detail="This event has no recorded Paddle transaction ID; automatic reconciliation is unavailable.")
    if not os.getenv("PADDLE_API_KEY", "").strip():
        raise HTTPException(status_code=503, detail="Paddle API is not configured.")
    try:
        response = await asyncio.to_thread(_paddle_api_request, f"/transactions/{event.transaction_id}")
        data = response.get("data") or {}
        provider_transaction_id = str(data.get("id") or "").strip()
        if not provider_transaction_id or not hmac.compare_digest(provider_transaction_id, event.transaction_id):
            raise HTTPException(status_code=502, detail="Paddle returned a transaction that does not match the recorded payment.")
        details = data.get("details") or {}
        totals = details.get("totals") or {}
        subscription_id = str(data.get("subscription_id") or "").strip()
        customer_id = str(data.get("customer_id") or "").strip()
        # Backfill only missing IDs from the authenticated Paddle API response.
        # Never overwrite an existing link or change license/payment entitlement here.
        backfilled = []
        if not event.subscription_id and re.fullmatch(r"sub_[A-Za-z0-9]+", subscription_id):
            event.subscription_id = subscription_id[:100]
            backfilled.append("subscription_id")
        if not event.paddle_customer_id and re.fullmatch(r"ctm_[A-Za-z0-9]+", customer_id):
            event.paddle_customer_id = customer_id[:100]
            backfilled.append("paddle_customer_id")
        result = {
            "event_id": event.event_id,
            "recorded_email_status": event.status,
            "recorded_transaction_id": event.transaction_id,
            "paddle_transaction_id": provider_transaction_id,
            "paddle_status": data.get("status"),
            "subscription_id": subscription_id or event.subscription_id,
            "currency_code": data.get("currency_code"),
            "total_minor_units": totals.get("total"),
            "customer_id": customer_id or event.paddle_customer_id,
            "backfilled_identifiers": backfilled,
            "entitlement_changed": False,
        }
        await _write_admin_log(db, "payment.reconciled", "payment_event", event.event_id, {
            "transaction_id": event.transaction_id, "paddle_status": str(data.get("status") or "")[:40],
            "backfilled_identifiers": backfilled})
        await db.commit()
        return result
    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        logger.error("Admin payment reconciliation failed (error_type=%s)", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Paddle transaction reconciliation failed; verify the API configuration.") from exc


@app.post("/api/v1/admin/payment-events/{event_id}/retry-email")
async def admin_retry_license_email(event_id: str, request: Request,
                                    db: AsyncSession = Depends(get_async_db)):
    """Manually retry a failed license email for an already-recorded payment event."""
    _require_admin_key(request)
    await _ensure_admin_tables(db)
    from sqlalchemy import select

    now = datetime.now(timezone.utc)
    event = (await db.execute(
        select(PaymentWebhookEvent)
        .where(PaymentWebhookEvent.event_id == event_id)
        .with_for_update()
    )).scalar_one_or_none()
    if event is None:
        raise HTTPException(status_code=404, detail="Payment event not found.")
    if event.status == "delivered":
        return {"status": "already_delivered", "event_id": event.event_id}
    if event.status == "email_sending":
        updated_at = event.updated_at
        if updated_at is not None:
            if updated_at.tzinfo is None:
                updated_at = updated_at.replace(tzinfo=timezone.utc)
            if (now - updated_at).total_seconds() < 600:
                raise HTTPException(status_code=409, detail="A license email delivery attempt is already in progress.")
        # Recover a stale in-progress marker left by a timed-out server process.
    if not event.license_id:
        raise HTTPException(status_code=409, detail="This payment event has no linked license to deliver.")
    license_obj = (await db.execute(
        select(SoftwareLicense).where(SoftwareLicense.id == event.license_id)
    )).scalar_one_or_none()
    if license_obj is None:
        raise HTTPException(status_code=409, detail="The license linked to this payment event is unavailable.")

    event.status = "email_sending"
    event.updated_at = now
    await db.commit()
    try:
        await asyncio.to_thread(
            _send_license_email, event.recipient_email, license_obj.license_key,
            license_obj.tier, license_obj.max_monthly_audits,
        )
    except Exception as exc:
        event.status = "email_pending"
        event.updated_at = datetime.now(timezone.utc)
        await db.commit()
        logger.error("Admin license email retry failed (error_type=%s)", type(exc).__name__)
        raise HTTPException(status_code=502, detail="License email retry failed; the event remains pending.") from exc

    event.status = "delivered"
    event.updated_at = datetime.now(timezone.utc)
    await _write_admin_log(
        db, "payment.license_email_retried", "payment_event", event.event_id,
        {"license_id": event.license_id, "delivery_status": "delivered"},
    )
    await db.commit()
    return {"status": "delivered", "event_id": event.event_id}


@app.get("/api/v1/admin/operations")
async def admin_operations(request: Request, db: AsyncSession = Depends(get_async_db)):
    """Private operational diagnostics without exposing environment values or customer secrets."""
    _require_admin_key(request)
    await _ensure_admin_tables(db)
    from sqlalchemy import select, func as sql_func
    now = datetime.now(timezone.utc)
    # Probe DB with a harmless query and return only health state, never connection details.
    try:
        await db.execute(text("SELECT 1"))
        database_status = "healthy"
    except Exception as exc:
        logger.error("Admin database diagnostic failed (error_type=%s)", type(exc).__name__)
        database_status = "unavailable"

    pending_email = (await db.execute(select(sql_func.count(PaymentWebhookEvent.event_id)).where(
        PaymentWebhookEvent.status != "delivered"
    ))).scalar_one()
    payment_events = (await db.execute(
        select(PaymentWebhookEvent).where(PaymentWebhookEvent.status != "delivered")
        .order_by(PaymentWebhookEvent.updated_at.asc()).limit(50)
    )).scalars().all()
    expired_reservation_count = (await db.execute(select(sql_func.count(AuditQuotaReservation.id)).where(
        AuditQuotaReservation.expires_at <= now
    ))).scalar_one()
    expired_reservations = (await db.execute(
        select(AuditQuotaReservation).where(AuditQuotaReservation.expires_at <= now)
        .order_by(AuditQuotaReservation.expires_at.asc()).limit(100)
    )).scalars().all()
    active_reservations = (await db.execute(select(sql_func.count(AuditQuotaReservation.id)).where(
        AuditQuotaReservation.expires_at > now
    ))).scalar_one()
    recent_failures = (await db.execute(text("""
        SELECT id, event_type, license_id, domain, error_type, created_at
        FROM saas_operation_events
        WHERE created_at >= NOW() - INTERVAL '24 hours'
        ORDER BY created_at DESC, id DESC LIMIT 100
    """))).mappings().all()
    failures_24h = (await db.execute(text("""
        SELECT COUNT(*) FROM saas_operation_events
        WHERE created_at >= NOW() - INTERVAL '24 hours'
    """))).scalar_one()
    smtp_status = _smtp_configuration_status()
    return {
        "generated_at": now.isoformat(),
        "health": {
            "database": database_status,
            "paddle_api_key_configured": bool(os.getenv("PADDLE_API_KEY", "").strip()),
            "paddle_webhook_secret_configured": bool(os.getenv("PADDLE_WEBHOOK_SECRET", "").strip()),
            "smtp_configured": smtp_status["configured"],
            "smtp_configuration_issues": smtp_status["issues"],
            "admin_key_configured": bool(os.getenv("ADMIN_API_KEY", "").strip()),
        },
        "counts": {
            "pending_payment_email_events": int(pending_email or 0),
            "expired_quota_reservations": int(expired_reservation_count or 0),
            "active_quota_reservations": int(active_reservations or 0),
            "audit_and_operation_failures_24h": int(failures_24h or 0),
        },
        "recent_failures": [{
            "id": row["id"], "event_type": row["event_type"], "license_id": row["license_id"],
            "domain": row["domain"], "error_type": row["error_type"],
            "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        } for row in recent_failures],
        "pending_payment_events": [{
            "event_id": item.event_id,
            "transaction_id": item.transaction_id,
            "subscription_id": item.subscription_id,
            "status": item.status,
            "license_id": item.license_id,
            "recipient_email": item.recipient_email,
            "created_at": item.created_at.isoformat() if item.created_at else None,
            "updated_at": item.updated_at.isoformat() if item.updated_at else None,
        } for item in payment_events],
        "expired_reservations": [{
            "id": item.id,
            "license_id": item.license_id,
            "created_at": item.created_at.isoformat() if item.created_at else None,
            "expires_at": item.expires_at.isoformat() if item.expires_at else None,
        } for item in expired_reservations],
    }


@app.get("/api/v1/admin/overview")
async def admin_overview(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=10000000),
    search: str = Query(default="", max_length=100),
    db: AsyncSession = Depends(get_async_db),
):
    """Return global platform metrics plus a bounded, searchable client page."""
    _require_admin_key(request)
    from sqlalchemy import select, func as sql_func, or_, cast, String
    now = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    normalized_search = search.strip()
    client_filter = None
    if normalized_search:
        literal_search = normalized_search.replace("%", "").replace("_", "")
        pattern = f"%{literal_search}%"
        client_filter = or_(
            SoftwareLicense.client_name.ilike(pattern),
            SoftwareLicense.tier.ilike(pattern),
            cast(SoftwareLicense.id, String).ilike(pattern),
        )
    count_query = select(sql_func.count(SoftwareLicense.id))
    filtered_query = select(SoftwareLicense)
    if client_filter is not None:
        count_query = count_query.where(client_filter)
        filtered_query = filtered_query.where(client_filter)
    filtered_total = int((await db.execute(count_query)).scalar_one() or 0)
    licenses = (await db.execute(
        filtered_query.order_by(SoftwareLicense.created_at.desc(), SoftwareLicense.id.desc())
        .offset(offset).limit(limit)
    )).scalars().all()
    total_clients = int((await db.execute(select(sql_func.count(SoftwareLicense.id)))).scalar_one() or 0)
    active_clients = int((await db.execute(
        select(sql_func.count(SoftwareLicense.id)).where(
            SoftwareLicense.is_active.is_(True),
            (SoftwareLicense.expires_at.is_(None)) | (SoftwareLicense.expires_at >= now),
        )
    )).scalar_one() or 0)
    total_leads = (await db.execute(select(sql_func.count(AuditLead.id)))).scalar_one()
    total_reports = (await db.execute(select(sql_func.count(AuditReport.id)))).scalar_one()
    total_reservations = (await db.execute(select(sql_func.count(AuditQuotaReservation.id)).where(
        AuditQuotaReservation.expires_at > now
    ))).scalar_one()
    total_webhooks = (await db.execute(select(sql_func.count(PaymentWebhookEvent.event_id)))).scalar_one()
    monthly_leads = (await db.execute(select(sql_func.count(AuditLead.id)).where(
        AuditLead.created_at >= month_start
    ))).scalar_one()
    # Aggregate per-license metrics in bounded queries instead of issuing several
    # round trips for every client. This keeps the operator overview responsive as
    # the SaaS customer count grows and avoids an N+1 query pattern.
    monthly_rows = (await db.execute(
        select(AuditLead.license_id, sql_func.count(AuditLead.id))
        .where(AuditLead.created_at >= month_start)
        .group_by(AuditLead.license_id)
    )).all()
    audit_rows = (await db.execute(
        select(AuditLead.license_id, sql_func.count(AuditLead.id), sql_func.max(AuditLead.created_at))
        .group_by(AuditLead.license_id)
    )).all()
    report_rows = (await db.execute(
        select(AuditReport.license_id, sql_func.count(AuditReport.id))
        .group_by(AuditReport.license_id)
    )).all()
    reservation_rows = (await db.execute(
        select(AuditQuotaReservation.license_id, sql_func.count(AuditQuotaReservation.id))
        .where(AuditQuotaReservation.expires_at > now)
        .group_by(AuditQuotaReservation.license_id)
    )).all()
    monthly_by_license = {row[0]: int(row[1] or 0) for row in monthly_rows}
    audits_by_license = {row[0]: (int(row[1] or 0), row[2]) for row in audit_rows}
    reports_by_license = {row[0]: int(row[1] or 0) for row in report_rows}
    reservations_by_license = {row[0]: int(row[1] or 0) for row in reservation_rows}

    client_rows = []
    for item in licenses:
        used_month = monthly_by_license.get(item.id, 0)
        total_audits, latest_audit = audits_by_license.get(item.id, (0, None))
        report_count = reports_by_license.get(item.id, 0)
        active_runs = reservations_by_license.get(item.id, 0)
        client_rows.append({
            "id": item.id, "client_name": item.client_name, "tier": item.tier,
            "is_active": bool(item.is_active),
            "expired": bool(item.expires_at and (item.expires_at.replace(tzinfo=timezone.utc) if item.expires_at.tzinfo is None else item.expires_at) < now),
            "created_at": item.created_at.isoformat() if item.created_at else None,
            "expires_at": item.expires_at.isoformat() if item.expires_at else None,
            "monthly_limit": int(item.max_monthly_audits or 0),
            "monthly_used": used_month,
            "monthly_remaining": max(0, int(item.max_monthly_audits or 0) - used_month),
            "usage_percent": round(100 * used_month / int(item.max_monthly_audits), 1) if item.max_monthly_audits else 0,
            "total_audits": total_audits,
            "reports_saved": report_count,
            "active_audit_reservations": active_runs,
            "last_audit_at": latest_audit.isoformat() if latest_audit else None,
        })
    return {
        "generated_at": now.isoformat(), "month_start": month_start.isoformat(),
        "summary": {
            "clients_total": total_clients, "clients_active": active_clients,
            "clients_inactive_or_expired": total_clients - active_clients,
            "audits_this_month": int(monthly_leads or 0), "audits_all_time": int(total_leads or 0),
            "reports_saved": int(total_reports or 0), "active_audit_reservations": int(total_reservations or 0),
            "payment_webhook_events": int(total_webhooks or 0),
        },
        "clients": client_rows,
        "client_page": {"limit": limit, "offset": offset, "total": filtered_total, "search": normalized_search, "has_more": offset + len(client_rows) < filtered_total},
    }


@app.get("/api/v1/admin/reports/{report_id}/pdf", response_class=Response)
async def admin_download_audit_report(report_id: int, request: Request,
                                      db: AsyncSession = Depends(get_async_db)):
    """Allow authenticated operators to retrieve a saved customer report for support."""
    _require_admin_key(request)
    from sqlalchemy import select
    report = (await db.execute(select(AuditReport).where(AuditReport.id == report_id))).scalar_one_or_none()
    if report is None:
        raise HTTPException(status_code=404, detail="Audit report not found.")
    safe_hostname = re.sub(r"[^a-zA-Z0-9.-]", "-", report.domain)[:180] or "website"
    return Response(
        content=report.pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="ecommerce-audit-{safe_hostname}-{report.id}.pdf"',
            "Cache-Control": "no-store, private",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/api/v1/admin/reports/{report_id}/evidence")
async def admin_report_evidence(
    report_id: int,
    request: Request,
    response: Response,
    kind: str = Query("check_outcomes", pattern="^(findings|check_outcomes)$"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_async_db),
):
    """Return bounded persisted report evidence for operators, without exposing PDF bytes."""
    _require_admin_key(request)
    from sqlalchemy import select

    report = (await db.execute(
        select(AuditReport).where(AuditReport.id == report_id)
    )).scalar_one_or_none()
    if report is None:
        raise HTTPException(status_code=404, detail="Audit report not found.")
    metadata = _load_saved_report_coverage(report.coverage_json)
    key = "findings" if kind == "findings" else "check_outcomes"
    records = metadata.get(key, [])
    if not isinstance(records, list):
        records = []
    records = [item for item in records if isinstance(item, dict)]
    states = ("pass", "issue", "warning", "not_assessed", "error")
    counts = {
        state: sum(
            1 for item in records
            if isinstance(item, dict) and item.get("outcome") == state
        )
        for state in states
    }
    denominator = len(records)
    items = _sanitize_saved_evidence_records(records, offset, limit)
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "report_id": report.id,
        "domain": report.domain,
        "kind": kind,
        "total": denominator,
        "limit": limit,
        "offset": offset,
        "counts": counts if kind == "check_outcomes" else None,
        "items": items,
    }


@app.get("/api/v1/admin/clients/{license_id}/history")
async def admin_client_history(license_id: int, request: Request, limit: int = Query(100, ge=1, le=500),
                              db: AsyncSession = Depends(get_async_db)):
    """Return a single client's audit, report, reservation and payment-provisioning history."""
    _require_admin_key(request)
    from sqlalchemy import select
    client = (await db.execute(select(SoftwareLicense).where(SoftwareLicense.id == license_id))).scalar_one_or_none()
    if client is None:
        raise HTTPException(status_code=404, detail="Client not found.")
    audits = (await db.execute(select(AuditLead).where(AuditLead.license_id == license_id)
        .order_by(AuditLead.created_at.desc(), AuditLead.id.desc()).limit(limit))).scalars().all()
    reports = (await db.execute(select(AuditReport).where(AuditReport.license_id == license_id)
        .order_by(AuditReport.created_at.desc(), AuditReport.id.desc()).limit(limit))).scalars().all()
    reservations = (await db.execute(select(AuditQuotaReservation).where(AuditQuotaReservation.license_id == license_id)
        .order_by(AuditQuotaReservation.created_at.desc(), AuditQuotaReservation.id.desc()).limit(limit))).scalars().all()
    payments = (await db.execute(select(PaymentWebhookEvent).where(PaymentWebhookEvent.license_id == license_id)
        .order_by(PaymentWebhookEvent.created_at.desc()).limit(limit))).scalars().all()
    return {
        "client": {"id": client.id, "client_name": client.client_name, "tier": client.tier,
                   "is_active": bool(client.is_active), "monthly_limit": client.max_monthly_audits,
                   "created_at": client.created_at.isoformat() if client.created_at else None,
                   "expires_at": client.expires_at.isoformat() if client.expires_at else None},
        "audits": [{"id": a.id, "domain": a.domain, "mobile_score": a.mobile_score,
                    "speed_index_sec": a.speed_index_sec, "source": a.source_channel,
                    "created_at": a.created_at.isoformat() if a.created_at else None} for a in audits],
        "reports": [{"id": r.id, "domain": r.domain, "finding_count": r.finding_count,
                     "created_at": r.created_at.isoformat() if r.created_at else None} for r in reports],
        "reservations": [{"id": r.id, "created_at": r.created_at.isoformat(),
                          "expires_at": r.expires_at.isoformat(),
                          "status": "active" if (r.expires_at.replace(tzinfo=timezone.utc) if r.expires_at.tzinfo is None else r.expires_at) > datetime.now(timezone.utc) else "expired"}
                         for r in reservations],
        "payments": [{"event_id": p.event_id, "license_id": p.license_id, "status": p.status, "recipient_email": p.recipient_email,
                      "transaction_id": p.transaction_id, "subscription_id": p.subscription_id,
                      "created_at": p.created_at.isoformat() if p.created_at else None,
                      "updated_at": p.updated_at.isoformat() if p.updated_at else None} for p in payments],
    }


class AdminClientUpdate(BaseModel):
    client_name: str | None = None
    tier: str | None = None
    max_monthly_audits: int | None = None
    is_active: bool | None = None
    expires_at: datetime | None = None


class AdminAPIKeyCreate(BaseModel):
    client_id: int = Field(..., ge=1)
    label: str = Field(default="Admin-created key", min_length=1, max_length=100)


class AdminAPIKeyRevoke(BaseModel):
    reason: str = Field(default="operator revocation", min_length=1, max_length=200)


@app.get("/api/v1/admin/clients/{license_id}/api-keys")
async def admin_list_client_api_keys(
    license_id: int,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
):
    """Return key metadata for a selected client without exposing key secrets."""
    _require_admin_key(request)
    from sqlalchemy import select

    client = (await db.execute(
        select(SoftwareLicense).where(SoftwareLicense.id == license_id)
    )).scalar_one_or_none()
    if client is None:
        raise HTTPException(status_code=404, detail="Client not found.")
    rows = (await db.execute(
        select(APIKey).where(APIKey.license_id == license_id)
        .order_by(APIKey.created_at.desc(), APIKey.id.desc()).limit(100)
    )).scalars().all()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "client_id": license_id,
        "items": [
            {
                "id": item.id,
                "key_prefix": item.key_prefix,
                "created_at": item.created_at.isoformat() if item.created_at else None,
            }
            for item in rows
        ],
        "limit": 100,
    }


@app.post("/api/v1/admin/clients/{license_id}/api-keys", status_code=201)
async def admin_create_client_api_key(
    license_id: int,
    payload: AdminAPIKeyCreate,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
):
    """Create a customer integration key as an explicitly authorized admin action."""
    _require_admin_key(request)
    from sqlalchemy import select, func as sql_func

    if payload.client_id != license_id:
        raise HTTPException(status_code=422, detail="Client ID in the path and body must match.")
    # Serialize admin-issued key creation on the owning license row as well;
    # otherwise parallel operator requests could bypass the account's 10-key cap.
    client = (await db.execute(
        select(SoftwareLicense).where(SoftwareLicense.id == license_id).with_for_update()
    )).scalar_one_or_none()
    if client is None:
        raise HTTPException(status_code=404, detail="Client not found.")
    current_count = int((await db.execute(
        select(sql_func.count(APIKey.id)).where(APIKey.license_id == license_id)
    )).scalar_one() or 0)
    if current_count >= 10:
        await db.rollback()
        raise HTTPException(status_code=409, detail="This account already has 10 API keys.")
    raw_key = "eaa_" + secrets.token_urlsafe(32)
    item = APIKey(
        license_id=license_id,
        api_key_hash=APIKey.hash_key(raw_key),
        key_prefix=raw_key[:10],
    )
    db.add(item)
    try:
        await db.flush()
        await _write_admin_log(db, "client.api_key_created", "client", license_id, {
            "api_key_id": item.id, "key_prefix": item.key_prefix, "label": payload.label,
        })
        await db.commit()
        await db.refresh(item)
    except Exception:
        await db.rollback()
        logger.error("Admin API key creation failed (client_id=%s)", license_id)
        raise HTTPException(status_code=503, detail="API key could not be created. Please retry.") from None
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "id": item.id,
        "client_id": license_id,
        "key": raw_key,
        "key_prefix": item.key_prefix,
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "warning": "Copy this key now. It cannot be retrieved again.",
    }


@app.delete("/api/v1/admin/clients/{license_id}/api-keys/{key_id}")
async def admin_revoke_client_api_key(
    license_id: int,
    key_id: int,
    payload: AdminAPIKeyRevoke,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
):
    """Revoke one client API key with an auditable, account-scoped admin action."""
    _require_admin_key(request)
    from sqlalchemy import delete, select

    client = (await db.execute(
        select(SoftwareLicense).where(SoftwareLicense.id == license_id)
    )).scalar_one_or_none()
    if client is None:
        raise HTTPException(status_code=404, detail="Client not found.")
    item = (await db.execute(
        select(APIKey).where(APIKey.id == key_id, APIKey.license_id == license_id)
    )).scalar_one_or_none()
    if item is None:
        raise HTTPException(status_code=404, detail="API key not found for this client.")
    prefix = item.key_prefix
    await db.execute(delete(APIKey).where(APIKey.id == key_id, APIKey.license_id == license_id))
    await _write_admin_log(db, "client.api_key_revoked", "client", license_id, {
        "api_key_id": key_id, "key_prefix": prefix, "reason": payload.reason.strip(),
    })
    await db.commit()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {"status": "revoked", "client_id": license_id, "key_id": key_id}


@app.patch("/api/v1/admin/clients/{license_id}")
async def admin_update_client(license_id: int, payload: AdminClientUpdate, request: Request,
                              db: AsyncSession = Depends(get_async_db)):
    """Allow an authenticated operator to adjust a customer's entitlement and account status."""
    _require_admin_key(request)
    await _ensure_admin_tables(db)
    from sqlalchemy import select
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=422, detail="Provide at least one field to update.")
    if "client_name" in changes:
        value = (changes["client_name"] or "").strip()
        if not value or len(value) > 255:
            raise HTTPException(status_code=422, detail="Client name must be between 1 and 255 characters.")
        changes["client_name"] = value
    if "tier" in changes:
        value = (changes["tier"] or "").strip().lower()
        if not value or len(value) > 50 or not re.fullmatch(r"[a-z0-9_-]+", value):
            raise HTTPException(status_code=422, detail="Package tier identifier is invalid.")
        changes["tier"] = value
    if "max_monthly_audits" in changes:
        value = changes["max_monthly_audits"]
        if value is None or value < 1 or value > 10000000:
            raise HTTPException(status_code=422, detail="Monthly audit limit must be between 1 and 10,000,000.")
    if "expires_at" in changes and changes["expires_at"] is not None:
        if changes["expires_at"].tzinfo is None:
            changes["expires_at"] = changes["expires_at"].replace(tzinfo=timezone.utc)
    client = (await db.execute(select(SoftwareLicense).where(SoftwareLicense.id == license_id))).scalar_one_or_none()
    if client is None:
        raise HTTPException(status_code=404, detail="Client not found.")
    if "tier" in changes:
        package = (await db.execute(text("""
            SELECT monthly_audit_allowance, is_active
            FROM saas_plan_packages WHERE tier=:tier
        """), {"tier": changes["tier"]})).mappings().first()
        if package is None:
            raise HTTPException(status_code=422, detail="Select a package that exists in admin package management.")
        if not bool(package["is_active"]):
            raise HTTPException(status_code=422, detail="Cannot assign a deactivated package. Reactivate it first or choose an active package.")
        if "max_monthly_audits" not in changes:
            changes["max_monthly_audits"] = int(package["monthly_audit_allowance"])
    allowed = {"client_name", "tier", "max_monthly_audits", "is_active", "expires_at"}
    for key, value in changes.items():
        if key not in allowed:
            raise HTTPException(status_code=422, detail="Unsupported client update field.")
        setattr(client, key, value)
    await _write_admin_log(db, "client.updated", "client", client.id, {
        "fields": sorted(changes),
        "tier": client.tier,
        "max_monthly_audits": client.max_monthly_audits,
        "is_active": bool(client.is_active),
    })
    await db.commit()
    await db.refresh(client)
    # Deliberately log only the client ID and field names, never license keys or credentials.
    logger.info("Admin updated client account (client_id=%s, fields=%s)", client.id, ",".join(sorted(changes)))
    return {
        "status": "updated", "client": {
            "id": client.id, "client_name": client.client_name, "tier": client.tier,
            "is_active": bool(client.is_active), "monthly_limit": client.max_monthly_audits,
            "expires_at": client.expires_at.isoformat() if client.expires_at else None,
        }
    }

