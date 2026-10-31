import asyncio
import ipaddress
import hashlib
import hmac
import secrets
import time
import logging
import os
import smtplib
import json
import io
import zipfile
from email.message import EmailMessage
from pathlib import Path
from datetime import datetime, timezone, timedelta
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

from database import Base, get_async_db
from scan_api import router as scan_router
from scan_worker_api import router as scan_worker_router
from ecommerce_agent import UniversalEcommerceAgent, LeadDossier
from models import SoftwareLicense, APIKey, AuditLead, AuditQuotaReservation, AuditReport, PaymentWebhookEvent, SaaSOperationEvent
from auth import verify_license_or_api_key, verify_customer_account, verify_account_credentials_for_key_revocation, CUSTOMER_BEARER
from quota import reserve_audit_slot, release_audit_reservation
from audit_checks import AuditCheckResult, AuditFinding, CheckOutcome, MAX_RESPONSE_BYTES, USER_AGENT, run_phase_one_checks
from report_generator import render_audit_pdf
from crawl_checks import run_bounded_site_crawl
from conversion_checks import run_conversion_paid_traffic_checks
from coverage_manifest import build_coverage_manifest
from unavailable_checks import append_unavailable_check_outcomes
from plan_features import plan_features
from hostinger_database import get_hostinger_db, HostingerBase, HostingerAsyncSessionLocal
from hostinger_models import CustomerAccount, CustomerLoginChallenge, CustomerSession, CustomerEmailChangeChallenge, CustomerBranding, WordPressInstallation, CustomerUsageEvent, CustomerActivityEvent, WebsiteScanResult, AdminCustomerNote, AdminActionLog, CustomerBillingEvent, OperationalDiagnosticEvent

logger = logging.getLogger("audit_service")

app = FastAPI(
    title="AI E-Commerce Audit Engine - Commercial Edition",
    description="Multi-model API serving SaaS, Managed Services, White-Label, and Enterprise integrations.",
    swagger_ui_parameters={"persistAuthorization": True}
)

agent = UniversalEcommerceAgent()
app.include_router(scan_router)
app.include_router(scan_worker_router)


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
    # Checkout URLs may carry a short-lived Paddle transaction identifier in the
    # query string. Do not let browsers or shared caches retain that launch URL.
    if request.url.path == "/checkout" or request.url.path.startswith(private_paths):
        response.headers["Cache-Control"] = "no-store, private"
        response.headers["Pragma"] = "no-cache"
    return response



class WordPressSiteRegister(BaseModel):
    site_url: str = Field(..., min_length=8, max_length=2048)
    admin_email: str = Field(..., min_length=3, max_length=254)
    wordpress_version: str = Field(default="", max_length=30)
    woocommerce_version: str = Field(default="", max_length=30)
    plugin_version: str = Field(..., min_length=1, max_length=30)


class WordPressSiteAction(BaseModel):
    site_id: str = Field(..., min_length=20, max_length=64)


class ReportEmailRequest(BaseModel):
    # Bound untrusted request data before the route performs DB lookup or SMTP work.
    recipient_email: str = Field(..., min_length=3, max_length=254)
    recipient_confirmed: bool = False


class WhiteLabelBrandingUpdate(BaseModel):
    brand_name: str = Field(..., min_length=1, max_length=100)
    logo_url: str | None = Field(default=None, max_length=2048)
    primary_color: str = Field(default="#155a8a", min_length=7, max_length=7)


class AccountProfileUpdate(BaseModel):
    """Customer-editable account display name; billing identity stays with the payment provider."""
    client_name: str = Field(..., min_length=1, max_length=255)


class AccountLoginRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)


class AccountLoginVerify(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    code: str = Field(..., min_length=6, max_length=6)


class AccountEmailChangeRequest(BaseModel):
    new_email: str = Field(..., min_length=3, max_length=254)


class AccountEmailChangeVerify(BaseModel):
    challenge_id: str = Field(..., min_length=20, max_length=64)
    code: str = Field(..., min_length=6, max_length=6)


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
        },
        "CustomerSessionAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "opaque session token",
            "description": "Passwordless customer account session"
        }
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


@app.get("/")
def read_root():
    return {"status": "AI Agent Commercial Engine Operational"}


@app.get("/health-check")
async def health_check(
    db: AsyncSession = Depends(get_async_db),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Check licensing/audit PostgreSQL and SaaS operational MySQL independently."""
    licensing_tables = {
        "software_licenses",
        "api_keys",
        "audit_leads",
        "audit_quota_reservations",
        "audit_reports",
        "saas_plan_packages",
        "payment_webhook_events",
    }
    try:
        pg_ping = await db.execute(text("SELECT 1"))
        pg_table_result = await db.execute(text(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = current_schema()"
        ))
        pg_existing_tables = set(pg_table_result.scalars().all())
        pg_missing_tables = sorted(licensing_tables - pg_existing_tables)
        pg_missing_columns = {}
        pg_missing_indexes = []

        if not pg_missing_tables:
            pg_column_result = await db.execute(text(
                "SELECT table_name, column_name FROM information_schema.columns "
                "WHERE table_schema = current_schema()"
            ))
            pg_existing_columns = {
                (row[0], row[1]) for row in pg_column_result.all()
            }
            pg_missing_columns = {
                table_name: sorted(
                    column.name
                    for column in Base.metadata.tables[table_name].columns
                    if (table_name, column.name) not in pg_existing_columns
                )
                for table_name in sorted(licensing_tables)
            }
            pg_missing_columns = {
                name: columns for name, columns in pg_missing_columns.items() if columns
            }

            pg_index_result = await db.execute(text(
                "SELECT indexname FROM pg_indexes WHERE schemaname = current_schema()"
            ))
            pg_existing_indexes = set(pg_index_result.scalars().all())
            pg_required_indexes = {
                index.name
                for table_name in licensing_tables
                for index in Base.metadata.tables[table_name].indexes
                if index.name
            }
            pg_required_indexes.add("uq_saas_plan_packages_paddle_price_id")
            pg_missing_indexes = sorted(pg_required_indexes - pg_existing_indexes)

        mysql_ping = await operational_db.execute(text("SELECT 1"))
        mysql_table_result = await operational_db.execute(text(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = DATABASE()"
        ))
        mysql_existing_tables = set(mysql_table_result.scalars().all())
        operational_tables = set(HostingerBase.metadata.tables)
        mysql_missing_tables = sorted(operational_tables - mysql_existing_tables)
        mysql_missing_columns = {}

        if not mysql_missing_tables:
            mysql_column_result = await operational_db.execute(text(
                "SELECT table_name, column_name FROM information_schema.columns "
                "WHERE table_schema = DATABASE()"
            ))
            mysql_existing_columns = {
                (row[0], row[1]) for row in mysql_column_result.all()
            }
            mysql_missing_columns = {
                table_name: sorted(
                    column.name
                    for column in HostingerBase.metadata.tables[table_name].columns
                    if (table_name, column.name) not in mysql_existing_columns
                )
                for table_name in sorted(operational_tables)
            }
            mysql_missing_columns = {
                name: columns for name, columns in mysql_missing_columns.items() if columns
            }

        licensing_ready = not (
            pg_missing_tables or pg_missing_columns or pg_missing_indexes
        )
        operational_ready = not (
            mysql_missing_tables or mysql_missing_columns
        )
        overall_ready = licensing_ready and operational_ready

        if not overall_ready:
            logger.error(
                "Database readiness failed (licensing_missing_tables=%s, operational_missing_tables=%s)",
                len(pg_missing_tables),
                len(mysql_missing_tables),
            )
            raise HTTPException(
                status_code=503,
                detail={
                    "status": "not_ready",
                    "licensing_database": {
                        "engine": "postgresql",
                        "connected": True,
                        "schema_ready": licensing_ready,
                        "missing_tables": pg_missing_tables,
                        "missing_columns": pg_missing_columns,
                        "missing_indexes": pg_missing_indexes,
                    },
                    "operational_database": {
                        "engine": "mysql",
                        "connected": True,
                        "schema_ready": operational_ready,
                        "missing_tables": mysql_missing_tables,
                        "missing_columns": mysql_missing_columns,
                    },
                },
            )

        return {
            "status": "success",
            "licensing_database": {
                "engine": "postgresql",
                "connected": True,
                "schema_ready": True,
                "result": pg_ping.scalar(),
            },
            "operational_database": {
                "engine": "mysql",
                "connected": True,
                "schema_ready": True,
                "result": mysql_ping.scalar(),
            },
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Health check failed (error_type=%s)", type(exc).__name__)
        raise HTTPException(
            status_code=503,
            detail={
                "status": "not_ready",
                "message": "One or more required databases are unavailable.",
            },
        )

def _normalize_request_audit_target(domain: str) -> str:
    """Reject parameterized targets at API boundaries before reserving quota."""
    raw_target = domain.strip()
    candidate_target = raw_target if "://" in raw_target else "https://" + raw_target
    # Query parameters can contain tokens or customer data. API callers must submit
    # a clean public page URL instead of having the service silently change intent.
    if urlsplit(candidate_target).query:
        raise ValueError(
            "Query strings are not accepted for audit targets; submit the public page URL without parameters."
        )
    return agent._normalize_audit_target(domain)


@app.post("/api/v1/audit-lead", response_model=LeadDossier)
@app.post("/api/v1/audit-lead/", response_model=LeadDossier, include_in_schema=False)
async def audit_lead(
    domain: str = Query(..., min_length=1, max_length=255, description="E-commerce store URL/domain"),
    email: str = Query("", max_length=255, description="User email for audit copy"),
    source: str = Query("web_audit", max_length=50, description="Traffic source tag"),
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_async_db),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    # Conversion dossiers are a premium entitlement; reject before quota reservation or provider calls.
    if not plan_features(license_obj.tier)["conversion_dossier"]:
        raise HTTPException(status_code=403, detail="Conversion dossiers require a Pro, Agency, or Business plan.")
    # Validate and canonicalize before reserving quota or calling any external provider.
    # This keeps rejected input free of billable audit work and avoids inconsistent URL handling.
    try:
        target_url = _normalize_request_audit_target(domain)
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

        # PostgreSQL owns quota and the canonical lead; Hostinger owns customer
        # usage/activity history. Keep the audit successful if the secondary
        # operational event write is temporarily unavailable.
        try:
            usage_key = f"legacy-audit:{db_lead.id}"
            operational_db.add(CustomerUsageEvent(
                license_key=license_obj.license_key,
                job_id=None,
                event_key=usage_key,
                event_type="audit_completed",
                quantity=1,
                package_tier=license_obj.tier,
                details_json=json.dumps({
                    "audit_lead_id": db_lead.id,
                    "domain": dossier.audit.domain,
                    "source": source[:50],
                }, separators=(",", ":"), ensure_ascii=True),
                created_at=reserved_at,
            ))
            operational_db.add(CustomerActivityEvent(
                license_key=license_obj.license_key,
                actor_email=email.strip().lower()[:254] or None,
                event_type="audit_completed",
                entity_type="audit_lead",
                entity_id=str(db_lead.id),
                details_json=json.dumps({
                    "domain": dossier.audit.domain,
                    "source": source[:50],
                }, separators=(",", ":"), ensure_ascii=True),
                created_at=reserved_at,
            ))
            await operational_db.commit()
        except Exception as history_exc:
            await operational_db.rollback()
            logger.warning(
                "Customer audit history write failed (error_type=%s, audit_lead_id=%s)",
                type(history_exc).__name__,
                db_lead.id,
            )
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


async def verify_license_with_optional_wordpress_site(
    request: Request,
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_async_db), operational_db: AsyncSession = Depends(get_hostinger_db),
) -> SoftwareLicense:
    """Authenticate normal SaaS clients and additionally enforce a supplied WordPress site identity."""
    site_id = request.headers.get("X-WordPress-Site-ID", "").strip()
    if site_id:
        if not re.fullmatch(r"[A-Za-z0-9_-]{20,64}", site_id):
            raise HTTPException(status_code=403, detail="Invalid WordPress site connection.")
        from sqlalchemy import select
        site = (await operational_db.execute(select(WordPressInstallation.id).where(
            WordPressInstallation.id == site_id,
            WordPressInstallation.license_key == license_obj.license_key,
            WordPressInstallation.status == "active",
        ))).scalar_one_or_none()
        if site is None:
            raise HTTPException(status_code=403, detail="This WordPress site is disconnected or not linked to the authenticated license.")
    return license_obj


@app.post("/api/v1/comprehensive-audit", response_class=Response)
async def comprehensive_audit_pdf(
    domain: str = Query(..., min_length=1, max_length=2048, description="Public website URL or domain"),
    license_obj: SoftwareLicense = Depends(verify_license_with_optional_wordpress_site),
    db: AsyncSession = Depends(get_async_db),
):
    """Create an evidence report as a PDF, using the existing license quota."""
    if not plan_features(license_obj.tier)["standard_audits"]:
        raise HTTPException(status_code=403, detail="Standard audits are not included in this plan.")
    try:
        target_url = _normalize_request_audit_target(domain)
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
            content=pdf_bytes,            media_type="application/pdf",
            headers={                "Content-Disposition": f'attachment; filename="ecommerce-audit-{safe_hostname}.pdf"',
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


@app.post("/api/v1/account/auth/request-code", status_code=202)
async def request_account_login_code(payload: AccountLoginRequest, response: Response, db: AsyncSession = Depends(get_async_db), operational_db: AsyncSession = Depends(get_hostinger_db)):
    """Send a short-lived sign-in code without disclosing whether an email owns an account."""
    from sqlalchemy import select, func
    email = payload.email.strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(status_code=422, detail="Enter a valid email address.")
    now = datetime.now(timezone.utc)
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    recent_count = int((await operational_db.execute(select(func.count(CustomerLoginChallenge.id)).where(
        CustomerLoginChallenge.email == email,
        CustomerLoginChallenge.created_at >= now - timedelta(hours=1),
    ))).scalar_one() or 0)
    latest = (await operational_db.execute(select(CustomerLoginChallenge).where(
        CustomerLoginChallenge.email == email,
    ).order_by(CustomerLoginChallenge.created_at.desc()).limit(1))).scalar_one_or_none()
    if recent_count >= 5 or (latest is not None and latest.created_at >= now - timedelta(seconds=60)):
        return {"status": "accepted", "message": "If an account exists for this email, a sign-in code will be sent."}

    linked = (await operational_db.execute(select(CustomerBillingEvent).where(
        func.lower(CustomerBillingEvent.recipient_email) == email,
    ).order_by(CustomerBillingEvent.updated_at.desc(), CustomerBillingEvent.created_at.desc()).limit(1))).scalar_one_or_none()
    linked_license_key = linked.license_key if linked is not None else None
    if linked_license_key is None:
        # Compatibility fallback while existing PostgreSQL billing events are
        # being copied to Hostinger; new billing history is mirrored operationally.
        legacy_link = (await db.execute(select(PaymentWebhookEvent).where(
            func.lower(PaymentWebhookEvent.recipient_email) == email,
            PaymentWebhookEvent.license_id.is_not(None),
        ).order_by(PaymentWebhookEvent.updated_at.desc(), PaymentWebhookEvent.created_at.desc()).limit(1))).scalar_one_or_none()
        if legacy_link is not None:
            linked_license_key = await db.scalar(
                select(SoftwareLicense.license_key).where(SoftwareLicense.id == legacy_link.license_id)
            )
    if linked_license_key is None:
        return {"status": "accepted", "message": "If an account exists for this email, a sign-in code will be sent."}

    auth_secret = os.getenv("ACCOUNT_AUTH_SECRET", "").strip()
    if len(auth_secret) < 32:
        logger.error("Customer account sign-in is unavailable because ACCOUNT_AUTH_SECRET is not configured.")
        raise HTTPException(status_code=503, detail="Customer sign-in is temporarily unavailable.")
    # A newly issued code supersedes every older outstanding code for this email.
    from sqlalchemy import update
    await operational_db.execute(update(CustomerLoginChallenge).where(
        CustomerLoginChallenge.email == email,
        CustomerLoginChallenge.consumed_at.is_(None),
    ).values(consumed_at=now))
    code = f"{secrets.randbelow(1000000):06d}"
    challenge_id = secrets.token_urlsafe(24)
    digest = hmac.new(auth_secret.encode(), f"{challenge_id}:{email}:{code}".encode(), hashlib.sha256).hexdigest()
    linked_license = await db.scalar(select(SoftwareLicense).where(SoftwareLicense.license_key == linked_license_key))
    if linked_license is None:
        return {"status": "accepted", "message": "If an account exists for this email, a sign-in code will be sent."}
    challenge = CustomerLoginChallenge(
        id=challenge_id, email=email, license_key=linked_license.license_key, code_hash=digest,
        expires_at=now + timedelta(minutes=10), attempts=0, created_at=now,
    )
    operational_db.add(challenge)
    await operational_db.commit()
    try:
        _send_account_login_code(email, code)
    except Exception as exc:
        challenge.consumed_at = datetime.now(timezone.utc)
        await operational_db.commit()
        logger.warning("Customer sign-in email delivery failed (%s)", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Unable to deliver a sign-in code right now.") from exc
    return {"status": "accepted", "message": "If an account exists for this email, a sign-in code will be sent."}


@app.post("/api/v1/account/auth/verify-code")
async def verify_account_login_code(payload: AccountLoginVerify, request: Request, response: Response, db: AsyncSession = Depends(get_async_db), operational_db: AsyncSession = Depends(get_hostinger_db)):
    """Consume a one-time code and issue an opaque 30-day customer session."""
    from sqlalchemy import select
    email = payload.email.strip().lower()
    if not re.fullmatch(r"\d{6}", payload.code):
        raise HTTPException(status_code=422, detail="Sign-in code must contain six digits.")
    auth_secret = os.getenv("ACCOUNT_AUTH_SECRET", "").strip()
    if len(auth_secret) < 32:
        raise HTTPException(status_code=503, detail="Customer sign-in is temporarily unavailable.")
    now = datetime.now(timezone.utc)
    challenge = (await operational_db.execute(select(CustomerLoginChallenge).where(
        CustomerLoginChallenge.email == email,
        CustomerLoginChallenge.consumed_at.is_(None),
    ).order_by(CustomerLoginChallenge.created_at.desc()).limit(1).with_for_update())).scalar_one_or_none()
    if challenge is None:
        raise HTTPException(status_code=401, detail="Sign-in code is invalid or expired.")
    expiry = challenge.expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if expiry <= now or challenge.attempts >= 5:
        challenge.consumed_at = now
        await operational_db.commit()
        raise HTTPException(status_code=401, detail="Sign-in code is invalid or expired.")
    expected = hmac.new(auth_secret.encode(), f"{challenge.id}:{email}:{payload.code}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, challenge.code_hash):
        challenge.attempts += 1
        if challenge.attempts >= 5:
            challenge.consumed_at = now
        await operational_db.commit()
        raise HTTPException(status_code=401, detail="Sign-in code is invalid or expired.")
    license_obj = (await db.execute(select(SoftwareLicense).where(
        SoftwareLicense.license_key == challenge.license_key,
    ))).scalar_one_or_none()
    if license_obj is None:
        challenge.consumed_at = now
        await operational_db.commit()
        raise HTTPException(status_code=401, detail="Customer account is unavailable.")
    challenge.consumed_at = now
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    session = CustomerSession(
        token_hash=token_hash, license_key=license_obj.license_key, email=email,
        expires_at=now + timedelta(days=30), created_at=now,
        public_id=secrets.token_urlsafe(24),
        user_agent=(request.headers.get("user-agent") or "")[:500],
    )
    operational_db.add(session)
    existing_account = await operational_db.scalar(select(CustomerAccount).where(
        CustomerAccount.license_key == license_obj.license_key,
        CustomerAccount.email == email,
    ))
    if existing_account is None:
        operational_db.add(CustomerAccount(
            id=secrets.token_urlsafe(24), license_key=license_obj.license_key,
            email=email, display_name=license_obj.client_name, status="active",
            created_at=now, updated_at=now,
        ))
    await operational_db.commit()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "status": "authenticated",
        "access_token": raw_token,
        "token_type": "Bearer",
        "expires_at": session.expires_at.isoformat(),
        "account": {"client_name": license_obj.client_name, "tier": license_obj.tier},
    }



@app.post("/api/v1/account/auth/email-change/request-code", status_code=202)
async def request_customer_email_change(
    payload: AccountEmailChangeRequest,
    response: Response,
    credentials=Depends(CUSTOMER_BEARER),
    db: AsyncSession = Depends(get_async_db),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Challenge a proposed address without changing the existing verified account identity."""
    from sqlalchemy import select, func, update
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Customer session is required.")
    new_email = payload.new_email.strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", new_email):
        raise HTTPException(status_code=422, detail="Enter a valid email address.")
    token_hash = hashlib.sha256(credentials.credentials.encode()).hexdigest()
    current = (await operational_db.execute(select(CustomerSession).where(
        CustomerSession.token_hash == token_hash,
        CustomerSession.revoked_at.is_(None),
    ).with_for_update())).scalar_one_or_none()
    if current is None:
        raise HTTPException(status_code=401, detail="Customer session is invalid.")
    old_email = current.email.strip().lower()
    if hmac.compare_digest(old_email, new_email):
        raise HTTPException(status_code=422, detail="The new email must be different from the current email.")
    now = datetime.now(timezone.utc)
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    old_license_ids = await _billing_license_ids_for_email(db, operational_db, old_email)
    new_license_ids = await _billing_license_ids_for_email(db, operational_db, new_email)
    if new_license_ids - old_license_ids:
        raise HTTPException(status_code=409, detail="That email is already linked to a different customer account.")
    recent_count = int((await operational_db.execute(select(func.count(CustomerEmailChangeChallenge.id)).where(
        CustomerEmailChangeChallenge.old_email == old_email,
        CustomerEmailChangeChallenge.created_at >= now - timedelta(hours=1),
    ))).scalar_one() or 0)
    latest = (await operational_db.execute(select(CustomerEmailChangeChallenge).where(
        CustomerEmailChangeChallenge.old_email == old_email,
    ).order_by(CustomerEmailChangeChallenge.created_at.desc()).limit(1))).scalar_one_or_none()
    if recent_count >= 5 or (latest is not None and latest.created_at >= now - timedelta(seconds=60)):
        raise HTTPException(status_code=429, detail="Please wait before requesting another email verification code.")
    auth_secret = os.getenv("ACCOUNT_AUTH_SECRET", "").strip()
    if len(auth_secret) < 32:
        raise HTTPException(status_code=503, detail="Customer account security is temporarily unavailable.")
    await operational_db.execute(update(CustomerEmailChangeChallenge).where(
        CustomerEmailChangeChallenge.old_email == old_email,
        CustomerEmailChangeChallenge.consumed_at.is_(None),
    ).values(consumed_at=now))
    code = f"{secrets.randbelow(1000000):06d}"
    challenge_id = secrets.token_urlsafe(24)
    digest = hmac.new(auth_secret.encode(), f"email-change:{challenge_id}:{old_email}:{new_email}:{code}".encode(), hashlib.sha256).hexdigest()
    challenge = CustomerEmailChangeChallenge(
        id=challenge_id, license_key=current.license_key, old_email=old_email, new_email=new_email,
        code_hash=digest, expires_at=now + timedelta(minutes=10), attempts=0, created_at=now,
    )
    operational_db.add(challenge)
    await operational_db.commit()
    try:
        _send_account_email_change_code(new_email, code)
    except Exception as exc:
        challenge.consumed_at = datetime.now(timezone.utc)
        await operational_db.commit()
        logger.warning("Customer email-change verification delivery failed (%s)", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Unable to deliver an email verification code right now.") from exc
    return {
        "status": "verification_sent",
        "challenge_id": challenge_id,
        "message": "A verification code was sent to the new email. Your current account email remains unchanged until verification succeeds.",
        "expires_in_seconds": 600,
    }


@app.post("/api/v1/account/auth/email-change/verify-code")
async def verify_customer_email_change(
    payload: AccountEmailChangeVerify,
    response: Response,
    credentials=Depends(CUSTOMER_BEARER),
    db: AsyncSession = Depends(get_async_db),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Atomically move the verified customer email and revoke every other device session."""
    from sqlalchemy import select, update, func
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Customer session is required.")
    if not re.fullmatch(r"\d{6}", payload.code):
        raise HTTPException(status_code=422, detail="Verification code must contain six digits.")
    auth_secret = os.getenv("ACCOUNT_AUTH_SECRET", "").strip()
    if len(auth_secret) < 32:
        raise HTTPException(status_code=503, detail="Customer account security is temporarily unavailable.")
    token_hash = hashlib.sha256(credentials.credentials.encode()).hexdigest()
    now = datetime.now(timezone.utc)
    current = (await operational_db.execute(select(CustomerSession).where(
        CustomerSession.token_hash == token_hash,
        CustomerSession.revoked_at.is_(None),
    ).with_for_update())).scalar_one_or_none()
    if current is None:
        raise HTTPException(status_code=401, detail="Customer session is invalid.")
    old_email = current.email.strip().lower()
    challenge = (await operational_db.execute(select(CustomerEmailChangeChallenge).where(
        CustomerEmailChangeChallenge.id == payload.challenge_id,
        CustomerEmailChangeChallenge.old_email == old_email,
        CustomerEmailChangeChallenge.consumed_at.is_(None),
    ).with_for_update())).scalar_one_or_none()
    if challenge is None:
        raise HTTPException(status_code=401, detail="Verification code is invalid or expired.")
    expiry = challenge.expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if expiry <= now or challenge.attempts >= 5:
        challenge.consumed_at = now
        await operational_db.commit()
        raise HTTPException(status_code=401, detail="Verification code is invalid or expired.")
    expected = hmac.new(
        auth_secret.encode(),
        f"email-change:{challenge.id}:{old_email}:{challenge.new_email}:{payload.code}".encode(),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, challenge.code_hash):
        challenge.attempts += 1
        if challenge.attempts >= 5:
            challenge.consumed_at = now
        await operational_db.commit()
        raise HTTPException(status_code=401, detail="Verification code is invalid or expired.")
    # Serialize claims for the same proposed address so two different accounts
    # cannot both pass the collision check concurrently on PostgreSQL.
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:email))"), {"email": challenge.new_email})
    old_license_ids = await _billing_license_ids_for_email(db, operational_db, old_email)
    new_license_ids = await _billing_license_ids_for_email(db, operational_db, challenge.new_email)
    if new_license_ids - old_license_ids:
        challenge.consumed_at = now
        await operational_db.commit()
        raise HTTPException(status_code=409, detail="That email is now linked to a different customer account.")
    linked_license_keys = list((await db.execute(
        select(SoftwareLicense.license_key).where(SoftwareLicense.id.in_(old_license_ids))
    )).scalars().all()) if old_license_ids else []
    if linked_license_keys:
        await operational_db.execute(update(CustomerAccount).where(
            CustomerAccount.license_key.in_(linked_license_keys),
            CustomerAccount.email == old_email,
        ).values(email=challenge.new_email, updated_at=now))
    await db.execute(update(PaymentWebhookEvent).where(
        func.lower(PaymentWebhookEvent.recipient_email) == old_email,
    ).values(recipient_email=challenge.new_email))
    await operational_db.execute(update(CustomerBillingEvent).where(
        func.lower(CustomerBillingEvent.recipient_email) == old_email,
    ).values(recipient_email=challenge.new_email))
    # Keep the linked WordPress customer identity synchronized with the verified
    # SaaS email change in the same transaction as the billing identity records.
    await operational_db.execute(update(WordPressInstallation).where(
        func.lower(WordPressInstallation.customer_email) == old_email,
    ).values(customer_email=challenge.new_email))
    await operational_db.execute(update(CustomerLoginChallenge).where(
        CustomerLoginChallenge.email == old_email,
        CustomerLoginChallenge.consumed_at.is_(None),
    ).values(consumed_at=now))
    await operational_db.execute(update(CustomerSession).where(
        CustomerSession.email == old_email,
        CustomerSession.token_hash != token_hash,
        CustomerSession.revoked_at.is_(None),
    ).values(revoked_at=now))
    current.email = challenge.new_email
    current.last_seen_at = now
    challenge.consumed_at = now
    await operational_db.commit()
    await db.commit()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "status": "email_updated",
        "email": challenge.new_email,
        "sessions_revoked": True,
        "message": "Your verified account email has been updated. Other device sessions were signed out.",
    }


@app.get("/api/v1/account/auth/sessions")
async def list_customer_device_sessions(
    response: Response,
    credentials=Depends(CUSTOMER_BEARER),
    db: AsyncSession = Depends(get_async_db),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """List active Hostinger-backed devices without exposing token digests."""
    from sqlalchemy import select
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Customer session is required.")
    token_hash = hashlib.sha256(credentials.credentials.encode()).hexdigest()
    current = await operational_db.scalar(select(CustomerSession).where(
        CustomerSession.token_hash == token_hash,
        CustomerSession.revoked_at.is_(None),
    ))
    if current is None:
        raise HTTPException(status_code=401, detail="Customer session is invalid.")
    now = datetime.now(timezone.utc)
    sessions = (await operational_db.execute(
        select(CustomerSession).where(
            CustomerSession.email == current.email,
            CustomerSession.revoked_at.is_(None),
            CustomerSession.expires_at > now,
            CustomerSession.public_id.is_not(None),
        ).order_by(CustomerSession.last_seen_at.desc().nullslast(), CustomerSession.created_at.desc())
        .limit(100)
    )).scalars().all()
    license_keys = list({item.license_key for item in sessions})
    licenses = (await db.execute(select(SoftwareLicense).where(
        SoftwareLicense.license_key.in_(license_keys)
    ))).scalars().all() if license_keys else []
    names = {item.license_key: item.client_name for item in licenses}
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {"items": [{
        "id": session.public_id,
        "client_name": names.get(session.license_key, "Customer account"),
        "user_agent": session.user_agent or "Unknown device",
        "created_at": session.created_at.isoformat() if session.created_at else None,
        "last_seen_at": session.last_seen_at.isoformat() if session.last_seen_at else None,
        "expires_at": session.expires_at.isoformat() if session.expires_at else None,
        "current": session.token_hash == token_hash,
    } for session in sessions]}


@app.delete("/api/v1/account/auth/sessions/{session_id}")
async def revoke_customer_device_session(
    session_id: str,
    response: Response,
    credentials=Depends(CUSTOMER_BEARER),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Revoke one other active device belonging to the same verified customer email."""
    from sqlalchemy import select
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Customer session is required.")
    token_hash = hashlib.sha256(credentials.credentials.encode()).hexdigest()
    current = await operational_db.scalar(select(CustomerSession).where(
        CustomerSession.token_hash == token_hash,
        CustomerSession.revoked_at.is_(None),
    ))
    if current is None:
        raise HTTPException(status_code=401, detail="Customer session is invalid.")
    target = await operational_db.scalar(select(CustomerSession).where(
        CustomerSession.public_id == session_id,
        CustomerSession.email == current.email,
        CustomerSession.revoked_at.is_(None),
    ).with_for_update())
    if target is None:
        raise HTTPException(status_code=404, detail="Active customer device was not found.")
    if target.token_hash == token_hash:
        raise HTTPException(status_code=422, detail="Use sign out to end the current device session.")
    target.revoked_at = datetime.now(timezone.utc)
    await operational_db.commit()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {"status": "revoked", "session_id": target.public_id}


@app.post("/api/v1/account/auth/logout")
async def logout_account_session(
    response: Response,
    credentials=Depends(CUSTOMER_BEARER),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Revoke the current Hostinger-backed customer session immediately."""
    from sqlalchemy import select
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Customer session is required.")
    digest = hashlib.sha256(credentials.credentials.encode()).hexdigest()
    session = await operational_db.scalar(select(CustomerSession).where(CustomerSession.token_hash == digest))
    if session is not None and session.revoked_at is None:
        session.revoked_at = datetime.now(timezone.utc)
        await operational_db.commit()
    response.headers["Cache-Control"] = "no-store, private"
    return {"status": "logged_out"}


@app.post("/api/v1/account/auth/logout-all")
async def logout_all_account_sessions(
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_customer_account),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Revoke every active browser session for the authenticated customer account."""
    from sqlalchemy import update
    now = datetime.now(timezone.utc)
    result = await operational_db.execute(update(CustomerSession).where(
        CustomerSession.license_key == license_obj.license_key,
        CustomerSession.revoked_at.is_(None),
    ).values(revoked_at=now))
    await operational_db.commit()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {"status": "sessions_revoked", "revoked_count": int(result.rowcount or 0)}


@app.get("/api/v1/account/licenses")
async def list_customer_account_licenses(
    response: Response,
    credentials=Depends(CUSTOMER_BEARER),
    license_obj: SoftwareLicense = Depends(verify_customer_account),
    db: AsyncSession = Depends(get_async_db),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """List every license linked to the verified checkout email on this browser session."""
    from sqlalchemy import func, select
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Email sign-in is required to manage linked licenses.")
    token_hash = hashlib.sha256(credentials.credentials.encode()).hexdigest()
    session = (await operational_db.execute(select(CustomerSession).where(
        CustomerSession.token_hash == token_hash,
        CustomerSession.revoked_at.is_(None),
    ))).scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=401, detail="Customer session is invalid.")
    linked_license_keys = set((await operational_db.execute(
        select(CustomerBillingEvent.license_key).where(
            func.lower(CustomerBillingEvent.recipient_email) == session.email.lower()
        ).distinct()
    )).scalars().all())
    linked_ids = (await db.execute(
        select(SoftwareLicense.id).where(SoftwareLicense.license_key.in_(linked_license_keys))
    )).scalars().all() if linked_license_keys else []
    if not linked_ids:
        # Compatibility path for accounts whose billing history has not yet been migrated.
        linked_ids = (await db.execute(
            select(SoftwareLicense.id).join(
                PaymentWebhookEvent, PaymentWebhookEvent.license_id == SoftwareLicense.id
            ).where(
                func.lower(PaymentWebhookEvent.recipient_email) == session.email.lower(),
                SoftwareLicense.id.is_not(None),
            ).distinct()
        )).scalars().all()
    licenses = (await db.execute(select(SoftwareLicense).where(
        SoftwareLicense.id.in_(linked_ids)
    ).order_by(SoftwareLicense.created_at.desc(), SoftwareLicense.id.desc()))).scalars().all() if linked_ids else []
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "items": [{
            "id": item.id,
            "client_name": item.client_name,
            "tier": item.tier,
            "is_active": bool(item.is_active),
            "expires_at": item.expires_at.isoformat() if item.expires_at else None,
            "selected": item.license_key == session.license_key,
        } for item in licenses],
        "selected_license_key": session.license_key,
    }


@app.post("/api/v1/account/licenses/switch")
async def switch_customer_account_license(
    request: Request,
    response: Response,
    credentials=Depends(CUSTOMER_BEARER),
    license_obj: SoftwareLicense = Depends(verify_customer_account),
    db: AsyncSession = Depends(get_async_db),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Switch the current browser session only to a license linked to its verified email."""
    from sqlalchemy import func, select
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Email sign-in is required to switch linked licenses.")
    try:
        payload = await request.json()
        target_id = int(payload.get("license_id"))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(status_code=422, detail="A valid license_id is required.")
    token_hash = hashlib.sha256(credentials.credentials.encode()).hexdigest()
    session = (await operational_db.execute(select(CustomerSession).where(
        CustomerSession.token_hash == token_hash,
        CustomerSession.revoked_at.is_(None),
    ).with_for_update())).scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=401, detail="Customer session is invalid.")
    target_license_key = await db.scalar(
        select(SoftwareLicense.license_key).where(SoftwareLicense.id == target_id)
    )
    allowed = await operational_db.scalar(select(CustomerBillingEvent.event_id).where(
        CustomerBillingEvent.license_key == target_license_key,
        func.lower(CustomerBillingEvent.recipient_email) == session.email.lower(),
    ).limit(1)) if target_license_key else None
    if allowed is None:
        allowed = (await db.execute(select(PaymentWebhookEvent.event_id).where(
            PaymentWebhookEvent.license_id == target_id,
            func.lower(PaymentWebhookEvent.recipient_email) == session.email.lower(),
        ).limit(1))).scalar_one_or_none()
    if allowed is None:
        raise HTTPException(status_code=403, detail="That license is not linked to this verified customer email.")
    target = (await db.execute(select(SoftwareLicense).where(
        SoftwareLicense.id == target_id
    ))).scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Linked license was not found.")
    session.license_key = target.license_key
    session.last_seen_at = datetime.now(timezone.utc)
    await operational_db.commit()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {"status": "switched", "account": {
        "client_name": target.client_name, "tier": target.tier,
        "license_id": target.id, "is_active": bool(target.is_active),
    }}



@app.post("/api/v1/integrations/wordpress/sites/register", status_code=201)
async def register_wordpress_site(
    payload: WordPressSiteRegister,
    request: Request,
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_async_db),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Register or refresh one WordPress installation in Hostinger."""
    from sqlalchemy import select, func as sql_func
    raw_url = payload.site_url.strip()
    parsed = urlsplit(raw_url)
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(status_code=422, detail="WordPress site URL must be a valid HTTPS URL.")
    if parsed.query or parsed.fragment or len(parsed.hostname) > 253:
        raise HTTPException(status_code=422, detail="WordPress site URL contains unsupported components.")
    host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    if not re.fullmatch(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host) or ".." in host:
        raise HTTPException(status_code=422, detail="WordPress site hostname is invalid.")
    admin_email = payload.admin_email.strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", admin_email):
        raise HTTPException(status_code=422, detail="WordPress administrator email is invalid.")
    site_url = f"https://{parsed.netloc.lower()}{parsed.path.rstrip('/')}/" if parsed.path else f"https://{parsed.netloc.lower()}/"
    now = datetime.now(timezone.utc)
    owner_email = await operational_db.scalar(select(CustomerBillingEvent.recipient_email).where(
        CustomerBillingEvent.license_key == license_obj.license_key,
    ).order_by(CustomerBillingEvent.updated_at.desc()).limit(1))
    if not owner_email:
        owner_email = await db.scalar(select(PaymentWebhookEvent.recipient_email).where(
            PaymentWebhookEvent.license_id == license_obj.id,
            PaymentWebhookEvent.recipient_email.is_not(None),
        ).order_by(PaymentWebhookEvent.updated_at.desc()).limit(1))
    account = await operational_db.scalar(select(CustomerAccount).where(
        CustomerAccount.license_key == license_obj.license_key
    ).with_for_update())
    if account is None:
        account = CustomerAccount(
            id=secrets.token_urlsafe(24), license_key=license_obj.license_key,
            email=(owner_email or admin_email).strip().lower(),
            display_name=license_obj.client_name, status="active",
            created_at=now, updated_at=now,
        )
        operational_db.add(account)
        await operational_db.flush()
    existing = await operational_db.scalar(select(WordPressInstallation).where(
        WordPressInstallation.license_key == license_obj.license_key,
        WordPressInstallation.site_host == host,
    ).with_for_update())
    active_count = int((await operational_db.execute(select(sql_func.count(WordPressInstallation.id)).where(
        WordPressInstallation.license_key == license_obj.license_key,
        WordPressInstallation.status == "active",
    ))).scalar_one() or 0)
    if existing is None:
        if active_count >= 10:
            raise HTTPException(status_code=409, detail="This license already has the maximum of 10 connected WordPress sites.")
        existing = WordPressInstallation(
            id=secrets.token_urlsafe(24), license_key=license_obj.license_key,
            site_url=site_url, site_host=host, admin_email=admin_email,
            customer_email=owner_email.strip().lower() if owner_email else None,
            plugin_version=payload.plugin_version.strip(),
            wordpress_version=payload.wordpress_version.strip() or None,
            woocommerce_version=payload.woocommerce_version.strip() or None,
            status="active", created_at=now, last_seen_at=now,
        )
        operational_db.add(existing)
    else:
        if existing.status != "active" and active_count >= 10:
            raise HTTPException(status_code=409, detail="This license already has the maximum of 10 connected WordPress sites.")
        existing.site_url = site_url
        existing.admin_email = admin_email
        existing.customer_email = owner_email.strip().lower() if owner_email else None
        existing.plugin_version = payload.plugin_version.strip()
        existing.wordpress_version = payload.wordpress_version.strip() or None
        existing.woocommerce_version = payload.woocommerce_version.strip() or None
        existing.status = "active"
        existing.disconnected_at = None
        existing.last_seen_at = now
    await operational_db.commit()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "status": "connected",
        "site_id": existing.id,
        "site_url": existing.site_url,
        "site_host": existing.site_host,
        "customer_email": existing.customer_email,
        "license": {"id": license_obj.id, "client_name": license_obj.client_name, "tier": license_obj.tier},
        "connected_at": existing.created_at.isoformat() if existing.created_at else None,
    }


@app.get("/api/v1/integrations/wordpress/sites/status")
async def wordpress_site_status(
    response: Response,
    site_id: str = Query(..., min_length=20, max_length=64),
    license_obj: SoftwareLicense = Depends(verify_account_credentials_for_key_revocation),
    db: AsyncSession = Depends(get_async_db), operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Return the connected site's current license entitlement without revealing secrets."""
    from sqlalchemy import select
    site = (await operational_db.execute(select(WordPressInstallation).where(
        WordPressInstallation.id == site_id,
        WordPressInstallation.license_key == license_obj.license_key,
        WordPressInstallation.status == "active",
    ))).scalar_one_or_none()
    if site is None:
        raise HTTPException(status_code=404, detail="WordPress site connection not found.")
    site.last_seen_at = datetime.now(timezone.utc)
    await operational_db.commit()
    expires_at = license_obj.expires_at
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "status": "connected",
        "site_id": site.id,
        "site_url": site.site_url,
        "site_host": site.site_host,
        "license": {
            "id": license_obj.id,
            "client_name": license_obj.client_name,
            "tier": license_obj.tier,
            "is_active": bool(license_obj.is_active),
            "expires_at": expires_at.isoformat() if expires_at else None,
            "billing_period_ends_at": license_obj.billing_period_ends_at.isoformat() if license_obj.billing_period_ends_at else None,
            "entitlement_state": "inactive" if not license_obj.is_active else ("expired" if expires_at and expires_at <= now else "active"),
        },
        "last_seen_at": site.last_seen_at.isoformat() if site.last_seen_at else None,
        "plugin_version": site.plugin_version,
        "wordpress_version": site.wordpress_version,
        "woocommerce_version": site.woocommerce_version,
    }


@app.post("/api/v1/integrations/wordpress/sites/disconnect")
async def disconnect_wordpress_site(
    payload: WordPressInstallationAction,
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_account_credentials_for_key_revocation),
    db: AsyncSession = Depends(get_async_db), operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Disconnect a site without deleting license, customer, billing, or audit history."""
    from sqlalchemy import select
    site = (await operational_db.execute(select(WordPressInstallation).where(
        WordPressInstallation.id == payload.site_id,
        WordPressInstallation.license_key == license_obj.license_key,
        WordPressInstallation.status == "active",
    ).with_for_update())).scalar_one_or_none()
    if site is None:
        raise HTTPException(status_code=404, detail="WordPress site connection not found.")
    site.status = "disconnected"
    site.disconnected_at = datetime.now(timezone.utc)
    await operational_db.commit()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {"status": "disconnected", "site_id": site.id}


@app.get("/wordpress-plugin-guide", response_class=HTMLResponse)
async def wordpress_plugin_guide():
    """Public installation guide for the downloadable WordPress integration."""
    return HTMLResponse("""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WordPress Plugin Setup · Ecommerce Audit Agent</title>
<style>body{font:16px/1.6 system-ui,sans-serif;color:#172334;background:#f4f7fb;margin:0}.wrap{max-width:820px;margin:36px auto;padding:28px;background:white;border:1px solid #dce5ef;border-radius:14px}h1,h2{line-height:1.2}a.button{display:inline-block;background:#155a8a;color:white;padding:12px 18px;border-radius:8px;text-decoration:none;font-weight:700}.muted{color:#586b7e}li{margin:8px 0}</style></head>
<body><main class="wrap"><h1>Connect WordPress or WooCommerce</h1>
<p class="muted">Install the official Ecommerce Audit Agent plugin, connect your SaaS license, and manage audits from WordPress.</p>
<p><a class="button" href="/wordpress-plugin.zip">Download WordPress plugin (.zip)</a></p>
<h2>Requirements</h2><ul><li>WordPress 6.2 or newer</li><li>PHP 7.4 or newer with OpenSSL enabled</li><li>HTTPS configured on your WordPress site</li><li>Outbound HTTPS requests allowed by your hosting provider</li><li>A valid Ecommerce Audit Agent SaaS license</li><li>WooCommerce is optional</li></ul>
<h2>Installation</h2><ol><li>Download the plugin ZIP above.</li><li>In WordPress, open Plugins → Add New Plugin → Upload Plugin.</li><li>Choose the ZIP, install it, and activate Ecommerce Audit Agent.</li><li>Open Ecommerce Audit in the WordPress admin menu.</li><li>Paste your SaaS license key and save. The plugin registers this WordPress site with your license.</li><li>View your entitlement and monthly quota, run an audit, download saved reports, or open the Paddle billing portal from the plugin dashboard.</li></ol>
<h2>Account management</h2><p>Sign in to your SaaS customer portal to view all connected WordPress installations and disconnect a site. Disconnecting a site does not delete your license, billing history, or saved audit reports.</p>
<p class="muted">The plugin sends its license credential only from your WordPress server to the configured HTTPS SaaS API. It encrypts the saved key at rest and never exposes it to public storefront visitors.</p>
</main></body></html>""", headers={"Cache-Control":"public, max-age=300"})


@app.get("/wordpress-plugin.zip")
async def download_wordpress_plugin():
    """Build a WordPress-installable ZIP with the expected top-level plugin folder."""
    plugin_dir = Path(__file__).resolve().parent / "wordpress-plugin" / "ecommerce-audit-agent"
    required_files = ("ecommerce-audit-agent.php", "readme.txt", "uninstall.php")
    if any(not (plugin_dir / filename).is_file() for filename in required_files):
        raise HTTPException(status_code=503, detail="The WordPress plugin package is not available on this deployment.")
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, mode="w", compression=zipfile.ZIP_DEFLATED) as package:
        for filename in required_files:
            package.write(plugin_dir / filename, arcname=f"ecommerce-audit-agent/{filename}")
    return Response(
        content=archive.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="ecommerce-audit-agent.zip"',
            "Cache-Control": "public, max-age=300",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/api/v1/account/wordpress-sites")
async def list_account_wordpress_sites(
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_customer_account),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """List WordPress installations linked to the currently selected customer license."""
    from sqlalchemy import select
    rows = (await operational_db.execute(
        select(WordPressInstallation).where(WordPressInstallation.license_key == license_obj.license_key)
        .order_by(WordPressInstallation.created_at.desc(), WordPressInstallation.id.desc()).limit(100)
    )).scalars().all()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {"items": [{
        "site_id": row.id, "site_url": row.site_url, "site_host": row.site_host,
        "admin_email": row.admin_email, "wordpress_version": row.wordpress_version,
        "woocommerce_version": row.woocommerce_version, "plugin_version": row.plugin_version,
        "status": row.status, "created_at": row.created_at.isoformat() if row.created_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
        "disconnected_at": row.disconnected_at.isoformat() if row.disconnected_at else None,
    } for row in rows]}


@app.post("/api/v1/account/wordpress-sites/{site_id}/disconnect")
async def customer_disconnect_wordpress_site(
    site_id: str,
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_customer_account),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Let an authenticated customer disconnect only a site owned by the selected license."""
    from sqlalchemy import select
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,64}", site_id):
        raise HTTPException(status_code=422, detail="Invalid WordPress site identifier.")
    site = (await operational_db.execute(select(WordPressInstallation).where(
        WordPressInstallation.id == site_id,
        WordPressInstallation.license_key == license_obj.license_key,
        WordPressInstallation.status == "active",
    ).with_for_update())).scalar_one_or_none()
    if site is None:
        raise HTTPException(status_code=404, detail="Connected WordPress site not found.")
    site.status = "disconnected"
    site.disconnected_at = datetime.now(timezone.utc)
    await operational_db.commit()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {"status": "disconnected", "site_id": site.id}


@app.get("/api/v1/account/profile")
async def get_account_profile(
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_customer_account),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Return customer profile from Hostinger and licensing status from Supabase."""
    from sqlalchemy import select
    profile = await operational_db.scalar(select(CustomerAccount).where(
        CustomerAccount.license_key == license_obj.license_key,
        CustomerAccount.status == "active",
    ))
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    now = datetime.now(timezone.utc)
    expires_at = license_obj.expires_at
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at is None:
        account_status = "active" if license_obj.is_active else "inactive"
    elif expires_at <= now:
        account_status = "expired"
    else:
        account_status = "active" if license_obj.is_active else "inactive"
    return {
        "client_name": profile.display_name if profile and profile.display_name else license_obj.client_name,
        "email": profile.email if profile else None,
        "tier": license_obj.tier,
        "account_status": account_status,
        "created_at": profile.created_at.isoformat() if profile and profile.created_at else None,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "billing_period_ends_at": license_obj.billing_period_ends_at.isoformat() if license_obj.billing_period_ends_at else None,
    }


@app.patch("/api/v1/account/profile")
async def update_account_profile(
    payload: AccountProfileUpdate,
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_customer_account),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Update the operational customer display name in Hostinger."""
    from sqlalchemy import select
    client_name = payload.client_name.strip()
    if not client_name:
        raise HTTPException(status_code=422, detail="Account name cannot be blank.")
    if len(client_name) > 255:
        raise HTTPException(status_code=422, detail="Account name must be 255 characters or fewer.")
    profile = await operational_db.scalar(select(CustomerAccount).where(
        CustomerAccount.license_key == license_obj.license_key,
    ).with_for_update())
    if profile is None:
        raise HTTPException(status_code=404, detail="Customer profile was not found.")
    profile.display_name = client_name
    profile.updated_at = datetime.now(timezone.utc)
    await operational_db.commit()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {"client_name": profile.display_name, "updated": True}


@app.get("/api/v1/account/branding")
async def get_account_branding(
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_customer_account),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    if not plan_features(license_obj.tier)["white_label_branding"]:
        raise HTTPException(status_code=403, detail="White-label branding is not included in this plan.")
    from sqlalchemy import select
    item = await operational_db.scalar(select(CustomerBranding).where(
        CustomerBranding.license_key == license_obj.license_key
    ))
    response.headers["Cache-Control"] = "no-store, private"
    return {
        "brand_name": item.brand_name if item else license_obj.client_name,
        "logo_url": item.logo_url if item else None,
        "primary_color": item.primary_color if item else "#155a8a",
        "configured": item is not None,
        "updated_at": item.updated_at.isoformat() if item and item.updated_at else None,
    }


@app.put("/api/v1/account/branding")
async def update_account_branding(
    payload: WhiteLabelBrandingUpdate,
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_customer_account),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    if not plan_features(license_obj.tier)["white_label_branding"]:
        raise HTTPException(status_code=403, detail="White-label branding is not included in this plan.")
    brand_name = payload.brand_name.strip()
    logo_url = payload.logo_url.strip() if payload.logo_url else None
    color = payload.primary_color.strip()
    if not brand_name or not re.fullmatch(r"#[0-9a-fA-F]{6}", color):
        raise HTTPException(status_code=422, detail="Provide a brand name and a six-digit hex color.")
    if logo_url:
        parsed = urlsplit(logo_url)
        if parsed.scheme.lower() != "https" or not parsed.netloc or parsed.username or parsed.password:
            raise HTTPException(status_code=422, detail="Logo URL must be a valid HTTPS URL without embedded credentials.")
    from sqlalchemy import select
    item = await operational_db.scalar(select(CustomerBranding).where(
        CustomerBranding.license_key == license_obj.license_key
    ).with_for_update())
    now = datetime.now(timezone.utc)
    if item is None:
        item = CustomerBranding(
            license_key=license_obj.license_key,
            brand_name=brand_name,
            logo_url=logo_url,
            primary_color=color,
            updated_at=now,
        )
        operational_db.add(item)
    else:
        item.brand_name, item.logo_url, item.primary_color = brand_name, logo_url, color
        item.updated_at = now
    await operational_db.commit()
    response.headers["Cache-Control"] = "no-store, private"
    return {"brand_name": brand_name, "logo_url": logo_url, "primary_color": color, "updated": True}


@app.get("/api/v1/account/usage")
async def get_account_usage(
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_async_db),
    operational_db: AsyncSession = Depends(get_hostinger_db),
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
        SELECT label, monthly_audit_allowance, max_concurrent_audits, is_active
        FROM saas_plan_packages WHERE tier=:tier
    """), {"tier": str(license_obj.tier or "starter").strip().lower()})
    package_row = package_result.mappings().first()
    package_limit = package_row["monthly_audit_allowance"] if package_row is not None else None
    limit = max(0, int(
        package_limit if package_limit is not None else (license_obj.max_monthly_audits or 0)
    ))
    consumed = used + pending
    remaining = max(0, limit - consumed)
    usage_percent = min(100, round(consumed * 100 / limit, 1)) if limit else 0
    expires_at = license_obj.expires_at
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if not license_obj.is_active:
        entitlement_state = "inactive"
    elif expires_at is not None and expires_at <= now:
        entitlement_state = "expired"
    elif package_row is not None and not bool(package_row["is_active"]):
        entitlement_state = "plan_inactive"
    elif limit <= 0:
        entitlement_state = "quota_unavailable"
    elif remaining <= 0:
        entitlement_state = "quota_exhausted"
    else:
        entitlement_state = "active"
    usage_events = (await operational_db.execute(
        select(CustomerUsageEvent).where(
            CustomerUsageEvent.license_key == license_obj.license_key,
            CustomerUsageEvent.created_at >= month_start,
        ).order_by(CustomerUsageEvent.created_at.desc()).limit(100)
    )).scalars().all()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "tier": str(license_obj.tier or "starter"),
        "features": plan_features(license_obj.tier),
        "plan_label": str(package_row["label"]) if package_row is not None else str(license_obj.tier or "starter"),
        "plan_available": bool(package_row["is_active"]) if package_row is not None else None,
        "monthly_limit": limit,
        "used": used,
        "in_progress": pending,
        "consumed": consumed,
        "remaining": remaining,
        "usage_percent": usage_percent,
        "quota_state": "exhausted" if limit > 0 and remaining <= 0 else ("near_limit" if usage_percent >= 80 else "available"),
        "entitlement_state": entitlement_state,
        "max_concurrent_audits": int(package_row["max_concurrent_audits"]) if package_row is not None else None,
        "history": [{
            "event_key": item.event_key, "event_type": item.event_type,
            "quantity": item.quantity,
            "created_at": item.created_at.isoformat() if item.created_at else None,
            "details": json.loads(item.details_json or "{}"),
        } for item in usage_events],
        "period_resets_at": next_month.isoformat(),
        "is_active": bool(license_obj.is_active),
        "expires_at": expires_at.isoformat() if expires_at else None,
    }


@app.get("/api/v1/account/activity")
async def account_audit_activity(
    response: Response,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=10000000),
    domain: str = Query(default="", max_length=253),
    license_obj: SoftwareLicense = Depends(verify_customer_account),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Return customer scan history from Hostinger without exposing lead-contact data."""
    from sqlalchemy import select, func as sql_func
    normalized_domain = domain.strip().lower().replace("%", "").replace("_", "")
    filters = [WebsiteScanResult.license_key == license_obj.license_key]
    if normalized_domain:
        filters.append(WebsiteScanResult.target_url.ilike(f"%{normalized_domain}%"))
    total = int((await operational_db.execute(
        select(sql_func.count(WebsiteScanResult.id)).where(*filters)
    )).scalar_one() or 0)
    rows = (await operational_db.execute(
        select(WebsiteScanResult).where(*filters)
        .order_by(WebsiteScanResult.created_at.desc(), WebsiteScanResult.id.desc())
        .offset(offset).limit(limit)
    )).scalars().all()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "items": [{
            "id": row.id,
            "domain": urlsplit(row.target_url).hostname or row.target_url,
            "mobile_score": (json.loads(row.summary_json or "{}").get("pagespeed") or {}).get("mobile_score"),
            "speed_index_sec": (json.loads(row.summary_json or "{}").get("pagespeed") or {}).get("speed_index_sec"),
            "source": "bulk_scan",
            "created_at": row.created_at.isoformat() if row.created_at else None,
        } for row in rows],
        "page": {
            "limit": limit, "offset": offset, "total": total,
            "has_more": offset + len(rows) < total, "domain": normalized_domain,
        },
    }


@app.get("/api/v1/account/billing-history")
async def account_billing_history(
    response: Response,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0, le=10000000),
    license_obj: SoftwareLicense = Depends(verify_customer_account),
    db: AsyncSession = Depends(get_async_db),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Return customer billing history from Hostinger, with legacy PostgreSQL fallback."""
    from sqlalchemy import select, func as sql_func

    ownership_filter = CustomerBillingEvent.license_key == license_obj.license_key
    total = int((await operational_db.execute(
        select(sql_func.count(CustomerBillingEvent.event_id)).where(ownership_filter)
    )).scalar_one() or 0)
    events = (await operational_db.execute(
        select(CustomerBillingEvent)
        .where(ownership_filter)
        .order_by(CustomerBillingEvent.created_at.desc(), CustomerBillingEvent.event_id.desc())
        .offset(offset)
        .limit(limit)
    )).scalars().all()
    attention_statuses = (
        "payment_failed", "subscription_past_due", "subscription_canceled",
        "email_pending", "email_sending",
    )
    attention_events = (await operational_db.execute(
        select(CustomerBillingEvent)
        .where(ownership_filter, CustomerBillingEvent.status.in_(attention_statuses))
        .order_by(CustomerBillingEvent.updated_at.desc(), CustomerBillingEvent.event_id.desc())
        .limit(10)
    )).scalars().all()

    # Existing accounts remain readable until the one-time Hostinger data copy
    # has been applied. New webhook events are mirrored after their PG commit.
    if total == 0:
        legacy_filter = PaymentWebhookEvent.license_id == license_obj.id
        total = int((await db.execute(
            select(sql_func.count(PaymentWebhookEvent.event_id)).where(legacy_filter)
        )).scalar_one() or 0)
        events = (await db.execute(
            select(PaymentWebhookEvent)
            .where(legacy_filter)
            .order_by(PaymentWebhookEvent.created_at.desc(), PaymentWebhookEvent.event_id.desc())
            .offset(offset).limit(limit)
        )).scalars().all()
        attention_events = (await db.execute(
            select(PaymentWebhookEvent)
            .where(legacy_filter, PaymentWebhookEvent.status.in_(attention_statuses))
            .order_by(PaymentWebhookEvent.updated_at.desc(), PaymentWebhookEvent.event_id.desc())
            .limit(10)
        )).scalars().all()

    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "account": {
            "client_name": license_obj.client_name,
            "tier": license_obj.tier,
            "is_active": bool(license_obj.is_active),
            "expires_at": license_obj.expires_at.isoformat() if license_obj.expires_at else None,
            "billing_period_ends_at": license_obj.billing_period_ends_at.isoformat() if license_obj.billing_period_ends_at else None,
        },
        "items": [{
            "event_id": item.event_id,
            "status": item.status,
            "transaction_id": item.transaction_id,
            "subscription_id": item.subscription_id,
            "created_at": item.created_at.isoformat() if item.created_at else None,
            "updated_at": item.updated_at.isoformat() if item.updated_at else None,
        } for item in events],
        "attention_items": [{
            "event_id": item.event_id,
            "status": item.status,
            "subscription_id": item.subscription_id,
            "updated_at": item.updated_at.isoformat() if item.updated_at else None,
        } for item in attention_events],
        "page": {"limit": limit, "offset": offset, "total": total, "has_more": offset + len(events) < total},
    }

@app.post("/api/v1/account/billing-portal")
async def create_account_billing_portal(
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_customer_account),
    db: AsyncSession = Depends(get_async_db),
):
    """Create a short-lived Paddle customer portal session for the authenticated license."""
    from sqlalchemy import select

    if not os.getenv("PADDLE_API_KEY", "").strip():
        raise HTTPException(status_code=503, detail="Self-service billing is not configured.")
    # Stream only the identifier columns so long billing histories do not
    # materialize every webhook ORM object in application memory.
    customer_links = await db.stream(
        select(PaymentWebhookEvent.paddle_customer_id, PaymentWebhookEvent.subscription_id)
        .where(
            PaymentWebhookEvent.license_id == license_obj.id,
            PaymentWebhookEvent.paddle_customer_id.is_not(None),
        )
        .order_by(PaymentWebhookEvent.updated_at.desc(), PaymentWebhookEvent.event_id.desc())
    )
    # Preserve the valid subscription links used to preselect subscriptions in
    # the Paddle portal while skipping malformed customer IDs.
    customer_id = None
    subscription_ids = []
    async for row in customer_links:
        candidate, subscription_id = row
        if customer_id is None and candidate and re.fullmatch(r"ctm_[A-Za-z0-9]+", candidate):
            customer_id = candidate
        if subscription_id and re.fullmatch(r"sub_[A-Za-z0-9]+", subscription_id):
            if subscription_id not in subscription_ids:
                subscription_ids.append(subscription_id)
    if not customer_id:
        raise HTTPException(status_code=409, detail="No linked Paddle customer is available for this account yet.")
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
        if not _is_valid_paddle_hosted_url(portal_url):
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
    license_obj: SoftwareLicense = Depends(verify_customer_account),
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
    now = datetime.now(timezone.utc)
    expires_at = license_obj.expires_at
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    is_expired = expires_at is not None and expires_at <= now
    if not plan_features(license_obj.tier)["direct_api_access"]:
        can_create_reason = "plan_not_eligible"
    elif len(rows) >= 10:
        can_create_reason = "key_limit_reached"
    elif is_expired:
        can_create_reason = "account_expired"
    elif not license_obj.is_active:
        can_create_reason = "account_inactive"
    else:
        can_create_reason = "available"
    can_create = can_create_reason == "available"
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
        "max_keys": 10,
        "key_count": len(rows),
        "keys_remaining": max(0, 10 - len(rows)),
        "can_create": can_create,
        "can_create_reason": can_create_reason,
        "note": "Full API keys are shown only once when created.",
    }


@app.post("/api/v1/account/api-keys", status_code=201)
async def create_account_api_key(
    response: Response,
    license_obj: SoftwareLicense = Depends(verify_customer_account),
    db: AsyncSession = Depends(get_async_db),
):
    """Create a customer-owned API key and reveal its secret exactly once.

    Account ownership is resolved even after expiry so the API can return a clear
    payment-required response for expired subscriptions, while revoked accounts
    remain forbidden. This dependency does not grant audit or report access.
    """
    from sqlalchemy import select, func as sql_func

    if not plan_features(license_obj.tier)["direct_api_access"]:
        raise HTTPException(status_code=403, detail="Direct API access is not included in this plan.")
    expires_at = license_obj.expires_at
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at is not None and expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=402, detail="License expired. Renewal required.")
    if not license_obj.is_active:
        raise HTTPException(status_code=403, detail="License is inactive or revoked.")

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
    license_obj: SoftwareLicense = Depends(verify_customer_account),
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
    offset: int = Query(0, ge=0, le=10000000),
    domain: str = Query(default="", max_length=253),
    license_obj: SoftwareLicense = Depends(verify_license_with_optional_wordpress_site),
    db: AsyncSession = Depends(get_async_db),
):
    """List only reports owned by the authenticated license; never expose PDF bytes here."""
    from sqlalchemy import select, func as sql_func
    filters = [AuditReport.license_id == license_obj.id]
    normalized_domain = domain.strip().lower().replace("%", "").replace("_", "")
    if normalized_domain:
        filters.append(AuditReport.domain.ilike(f"%{normalized_domain}%"))
    total = (await db.execute(
        select(sql_func.count(AuditReport.id)).where(*filters)
    )).scalar_one()
    rows = (await db.execute(
        select(AuditReport).where(*filters)
        .order_by(AuditReport.created_at.desc(), AuditReport.id.desc())
        .offset(offset).limit(limit)
    )).scalars().all()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "domain": normalized_domain,
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
    license_obj: SoftwareLicense = Depends(verify_license_with_optional_wordpress_site),
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
    license_obj: SoftwareLicense = Depends(verify_license_with_optional_wordpress_site),
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
    offset: int = Query(0, ge=0, le=10000000),
    license_obj: SoftwareLicense = Depends(verify_license_with_optional_wordpress_site),
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


def _send_account_login_code(recipient: str, code: str) -> None:
    """Send a short-lived passwordless sign-in code through the configured SMTP relay."""
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
    message["Subject"] = "Your E-commerce Audit Agent sign-in code"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        f"Your customer account sign-in code is: {code}\n\n"
        "This code expires in 10 minutes and can be used once. "
        "If you did not request it, you can ignore this email."
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


def _send_account_email_change_code(recipient: str, code: str) -> None:
    """Deliver a new-address ownership challenge using the configured SMTP relay."""
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
    message["Subject"] = "Verify your new E-commerce Audit Agent account email"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        f"Your new customer account email verification code is: {code}\n\n"
        "This code expires in 10 minutes and can be used once. "
        "Your existing account email remains active until this code is verified. "
        "If you did not request this change, ignore this message and your account will remain unchanged."
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


def _is_valid_paddle_hosted_url(value: object) -> bool:
    """Accept only credential-free HTTPS URLs on Paddle's actual hosted domain."""
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    try:
        parsed = urlsplit(value)
        hostname = (parsed.hostname or "").lower()
        # Accessing .port also validates malformed port syntax.
        _ = parsed.port
    except (TypeError, ValueError):
        return False
    return bool(
        parsed.scheme.lower() == "https"
        and hostname
        and parsed.username is None
        and parsed.password is None
        and (hostname == "paddle.com" or hostname.endswith(".paddle.com"))
    )


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
            # Provider responses should be small metadata objects. Bound reads so an
            # unexpected/compromised upstream response cannot consume unbounded memory.
            raw_body = response.read(2 * 1024 * 1024 + 1)
            if len(raw_body) > 2 * 1024 * 1024:
                raise RuntimeError("Paddle API response exceeded the allowed size")
            result = json.loads(raw_body.decode("utf-8"))
            if not isinstance(result, dict):
                raise RuntimeError("Paddle API returned an invalid JSON object")
            return result
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Paddle API request failed (HTTP {exc.code})") from exc
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise RuntimeError(f"Paddle API request failed ({type(exc).__name__})") from exc


def _configured_payment_plans() -> list[dict]:
    plans = []
    for tier, label, default_quota in (("STARTER", "Starter", 100), ("PRO", "Pro", 500), ("BUSINESS", "Business", 2000)):
        price_id = os.getenv(f"PADDLE_PRICE_ID_{tier}", "").strip()
        if not re.fullmatch(r"pri_[A-Za-z0-9]+", price_id): continue
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
    ready = bool(
        os.getenv("PADDLE_API_KEY", "").strip()
        and os.getenv("PADDLE_WEBHOOK_SECRET", "").strip()
        and _smtp_configuration_status()["configured"]
    )
    plans = await _db_payment_plans(db, active_only=True) if ready else []
    plans = [p for p in plans if p.get("price_id")]
    return {"checkout_provider": "Paddle", "configured": bool(plans),
        "plans": [{"tier": p["tier"], "label": p["label"],
                   "monthly_audit_allowance": p["monthly_audit_allowance"],
                   "max_concurrent_audits": p["max_concurrent_audits"]} for p in plans],
        "configuration_needed": [] if plans else ["Paddle API key", "Paddle notification destination secret",
            "SMTP host and sender", "Paddle price ID for each enabled plan"]}


@app.post("/api/v1/billing/checkout")
async def create_paddle_checkout(
    payload: PaddleCheckoutRequest,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
):
    """Create a transaction using an active server-managed package price; the client cannot set amounts."""
    tier = payload.tier.strip().lower()
    plans = await _db_payment_plans(db, active_only=True)
    plan = next((p for p in plans if p["tier"] == tier), None)
    if plan is None:
        raise HTTPException(status_code=422, detail="The selected package is unavailable.")
    if not plan.get("price_id") or not os.getenv("PADDLE_API_KEY", "").strip():
        raise HTTPException(status_code=503, detail="This Paddle plan is not configured.")
    # Do not accept money for a purchase that cannot be verified and provisioned.
    # The public catalogue applies the same readiness gate; the checkout endpoint
    # must enforce it independently because clients can call it directly.
    if not os.getenv("PADDLE_WEBHOOK_SECRET", "").strip():
        raise HTTPException(status_code=503, detail="Paddle webhook verification is not configured.")
    smtp_status = _smtp_configuration_status()
    if not smtp_status["configured"]:        raise HTTPException(status_code=503, detail="License delivery is not configured.")    transaction = {"items": [{"price_id": plan["price_id"], "quantity": 1}],
                   "custom_data": {"license_tier": plan["tier"]}}
    checkout_url = os.getenv("PADDLE_CHECKOUT_URL", "").strip()
    if checkout_url:
        # Only forward configured hosted-checkout destinations on Paddle domains.
        if not _is_valid_paddle_hosted_url(checkout_url):
            raise HTTPException(status_code=503, detail="Paddle checkout URL configuration is invalid.")
        transaction["checkout"] = {"url": checkout_url}
    try:
        provider_response = await asyncio.to_thread(_paddle_api_request, "/transactions", "POST", transaction)
        url = provider_response.get("data", {}).get("checkout", {}).get("url")
        if not _is_valid_paddle_hosted_url(url):
            raise RuntimeError("Paddle did not return a valid checkout URL")
        transaction_id = provider_response.get("data", {}).get("id")
        if not isinstance(transaction_id, str) or not re.fullmatch(r"txn_[A-Za-z0-9]+", transaction_id):
            raise RuntimeError("Paddle did not return a valid transaction ID")
        response.headers["Cache-Control"] = "no-store, private"
        response.headers["Pragma"] = "no-cache"
        return {"checkout_url": url, "transaction_id": transaction_id}
    except Exception as exc:
        logger.error("Paddle checkout creation failed (error_type=%s)", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Unable to start Paddle checkout; verify billing configuration.") from exc


def _paddle_billing_period_end(payload: dict) -> datetime | None:
    """Read Paddle's billing-period end from transaction or subscription payloads."""
    candidates = []
    for key in ("current_billing_period", "billing_period"):
        period = payload.get(key)
        if isinstance(period, dict):
            candidates.extend((period.get("ends_at"), period.get("end_at")))
    for raw in candidates:
        if raw is None:
            continue
        if not isinstance(raw, str) or len(raw) > 80:
            raise HTTPException(status_code=400, detail="Paddle billing period end is invalid.")
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail="Paddle billing period end is invalid.")
        if parsed.tzinfo is None:
            raise HTTPException(status_code=400, detail="Paddle billing period end must include a timezone.")
        return parsed.astimezone(timezone.utc)
    return None


async def _lock_paddle_webhook_resource(db: AsyncSession, resource_id: str, parameter_name: str = "subscription_id") -> None:
    """Serialize Paddle lifecycle work on PostgreSQL while supporting SQLite test/dev databases."""
    bind = db.get_bind()
    if bind.dialect.name != "postgresql":
        # SQLite has no advisory-lock function. Production uses PostgreSQL, where
        # the transaction-scoped lock protects against concurrent webhook races.
        return
    await db.execute(
        text(f"SELECT pg_advisory_xact_lock(hashtext(:{parameter_name}))"),
        {parameter_name: resource_id},
    )


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
    try:
        event = json.loads(raw_body)
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Invalid Paddle event JSON.")
    # Valid JSON can still have an unexpected shape; reject it as a client error.
    if not isinstance(event, dict):
        raise HTTPException(status_code=400, detail="Paddle event must be a JSON object.")
    event_id = str(event.get("event_id") or event.get("id") or "").strip()
    event_type = str(event.get("event_type") or event.get("type") or "").strip()
    if not event_id or len(event_id) > 255:
        raise HTTPException(status_code=400, detail="Paddle event ID is missing or invalid.")
    if not event_type or len(event_type) > 120:
        raise HTTPException(status_code=400, detail="Paddle event type is missing or invalid.")
    transaction = event.get("data") or {}
    if not isinstance(transaction, dict):
        raise HTTPException(status_code=400, detail="Paddle event data must be a JSON object.")

# Persist payment-failure lifecycle events for customer-visible billing history.
    # Paddle's retry/dunning policy remains authoritative: a single failed transaction
    # does not by itself revoke access, but the event must not disappear silently.
    if event_type in {"transaction.payment_failed", "subscription.past_due"}:
        subscription_id = str(
            transaction.get("subscription_id") or
            (transaction.get("id") if event_type == "subscription.past_due" else "") or ""
        )[:100]
        if not subscription_id:
            raise HTTPException(status_code=400, detail="Paddle payment-failure event has no subscription ID.")
        from sqlalchemy import select
        await _lock_paddle_webhook_resource(db, subscription_id)
        duplicate = (await db.execute(
            select(PaymentWebhookEvent).where(PaymentWebhookEvent.event_id == event_id)
        )).scalar_one_or_none()
        if duplicate is not None:
            return {"status": "already_processed", "event_id": event_id}
        # A provider can redeliver the same failed transaction under a different
        # event ID. Transaction-level idempotency prevents duplicate customer
        # history/operation events while preserving separate retry attempts,
        # which have their own transaction IDs.
        failed_transaction_id = str(transaction.get("id") or "").strip()[:100]
        if event_type == "transaction.payment_failed" and failed_transaction_id:
            prior_failure = (await db.execute(
                select(PaymentWebhookEvent)
                .where(
                    PaymentWebhookEvent.transaction_id == failed_transaction_id,
                    PaymentWebhookEvent.status == "payment_failed",
                )
                .order_by(PaymentWebhookEvent.updated_at.desc())
                .limit(1)
            )).scalar_one_or_none()
            if prior_failure is not None:
                return {"status": "already_processed", "event_id": prior_failure.event_id}
        linked_event = (await db.execute(
            select(PaymentWebhookEvent)
            .where(
                PaymentWebhookEvent.subscription_id == subscription_id,
                PaymentWebhookEvent.license_id.is_not(None),
            )
            .order_by(PaymentWebhookEvent.updated_at.desc())
            .limit(1)
        )).scalar_one_or_none()
        if linked_event is None:
            # Do not acknowledge an unlinked event permanently; Paddle may retry after
            # the original purchase event is reconciled and the subscription is linked.
            raise HTTPException(status_code=503, detail="Payment-failure event is awaiting subscription reconciliation.")
        customer = transaction.get("customer") or {}
        if not isinstance(customer, dict):
            raise HTTPException(status_code=400, detail="Paddle lifecycle event customer must be a JSON object.")
        customer_id = str(transaction.get("customer_id") or customer.get("id") or "").strip()
        status = "payment_failed" if event_type == "transaction.payment_failed" else "subscription_past_due"
        db.add(PaymentWebhookEvent(
            event_id=event_id,
            status=status,
            license_id=linked_event.license_id,
            recipient_email=linked_event.recipient_email,
            transaction_id=(str(transaction.get("id") or "")[:100] or None)
                if event_type == "transaction.payment_failed" else None,
            subscription_id=subscription_id,
            paddle_customer_id=(customer_id[:100] or linked_event.paddle_customer_id),
        ))
        await db.commit()
        await _sync_billing_event_to_hostinger(db, event_id)
        await _record_operation_event(db, status, linked_event.license_id, None, None)
        return {"status": status, "event_id": event_id, "license_id": linked_event.license_id}

    # Keep non-cancellation subscription state transitions attached to the existing
    # license instead of silently acknowledging pause/resume/activation events.
    # Payment failure alone does not revoke access; explicit pause does. Resume and
    # activation only restore access when the license has not expired.
    if event_type in {"subscription.paused", "subscription.resumed", "subscription.activated"}:
        subscription_id = str(transaction.get("id") or "").strip()[:100]
        if not subscription_id:
            raise HTTPException(status_code=400, detail="Paddle subscription lifecycle event has no subscription ID.")
        from sqlalchemy import select
        await _lock_paddle_webhook_resource(db, subscription_id)
        duplicate = (await db.execute(
            select(PaymentWebhookEvent).where(PaymentWebhookEvent.event_id == event_id)
        )).scalar_one_or_none()
        if duplicate is not None:
            return {"status": "already_processed", "event_id": event_id}
        # A previously confirmed cancellation is sticky. A delayed activation/resume
        # notification must not restore access; only a separately verified renewal
        # flow may resolve the account's billing state.
        canceled = (await db.execute(
            select(PaymentWebhookEvent)
            .where(
                PaymentWebhookEvent.subscription_id == subscription_id,
                PaymentWebhookEvent.status == "subscription_canceled",
            ).limit(1)
        )).scalar_one_or_none()
        if canceled is not None:
            return {"status": "ignored_after_cancellation", "event_id": event_id}
        linked_event = (await db.execute(
            select(PaymentWebhookEvent)
            .where(
                PaymentWebhookEvent.subscription_id == subscription_id,
                PaymentWebhookEvent.license_id.is_not(None),
            )
            .order_by(PaymentWebhookEvent.updated_at.desc())
            .limit(1)
        )).scalar_one_or_none()
        if linked_event is None or linked_event.license_id is None:
            raise HTTPException(status_code=503, detail="Subscription lifecycle event is awaiting license reconciliation.")
        license_obj = (await db.execute(
            select(SoftwareLicense).where(SoftwareLicense.id == linked_event.license_id)
        )).scalar_one_or_none()
        if license_obj is None:
            raise HTTPException(status_code=503, detail="Subscription lifecycle event is awaiting license reconciliation.")
        lifecycle_status = {
            "subscription.paused": "subscription_paused",
            "subscription.resumed": "subscription_resumed",
            "subscription.activated": "subscription_activated",
        }[event_type]
        now = datetime.now(timezone.utc)
        was_active = bool(license_obj.is_active)
        if event_type == "subscription.paused":
            license_obj.is_active = False
        elif license_obj.expires_at is None:
            license_obj.is_active = True
        else:
            expiry = license_obj.expires_at
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            license_obj.is_active = expiry > now
        db.add(PaymentWebhookEvent(
            event_id=event_id,
            status=lifecycle_status,
            license_id=license_obj.id,
            recipient_email=linked_event.recipient_email,
            subscription_id=subscription_id,
            paddle_customer_id=linked_event.paddle_customer_id,
            created_at=now,
            updated_at=now,
        ))
        await db.commit()
        await _sync_billing_event_to_hostinger(db, event_id)
        if was_active != bool(license_obj.is_active):
            await _record_operation_event(db, lifecycle_status, license_obj.id, None, None)
        return {"status": lifecycle_status, "event_id": event_id, "license_id": license_obj.id}

    # Subscription lifecycle events must not be silently discarded: a confirmed
    # cancellation revokes future access for the license provisioned by its purchase.
    if event_type == "subscription.canceled":
        subscription_id = str(transaction.get("id") or "")[:100]
        if not subscription_id:
            raise HTTPException(status_code=400, detail="Paddle cancellation event has no subscription ID.")
        from sqlalchemy import select, update
        # Serialize lifecycle transitions for this subscription. The advisory lock
        # is transaction-scoped and avoids a late renewal racing a cancellation.
        await _lock_paddle_webhook_resource(db, subscription_id)
        duplicate_cancellation = (await db.execute(
            select(PaymentWebhookEvent).where(PaymentWebhookEvent.event_id == event_id)
        )).scalar_one_or_none()
        if duplicate_cancellation is not None:
            return {"status": "already_canceled", "event_id": event_id}
        linked_event = (await db.execute(
            select(PaymentWebhookEvent)
            .where(
                PaymentWebhookEvent.subscription_id == subscription_id,
                PaymentWebhookEvent.license_id.is_not(None),
            )
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
        # Keep the original purchase/renewal event intact for billing history and
        # store cancellation as its own idempotent lifecycle event. The new event
        # is the latest subscription record, so late payment events see the sticky
        # canceled state without erasing the original payment's delivery status.
        now = datetime.now(timezone.utc)
        db.add(PaymentWebhookEvent(
            event_id=event_id,
            status="subscription_canceled",
            license_id=license_obj.id,
            recipient_email=linked_event.recipient_email,
            subscription_id=subscription_id,
            paddle_customer_id=linked_event.paddle_customer_id,
            created_at=now,
            updated_at=now,
        ))
        await db.commit()
        await _sync_billing_event_to_hostinger(db, event_id)
        if changed:
            await _record_operation_event(db, "subscription_canceled", license_obj.id, None, None)
            logger.info("Paddle subscription cancellation applied (license_id=%s)", license_obj.id)
        return {"status": "cancellation_applied" if changed else "already_canceled", "event_id": event_id}

    # Reconcile verified subscription price and lifecycle state from Paddle's
    # authoritative subscription.updated snapshot.
    if event_type == "subscription.updated":
        subscription_id = str(transaction.get("id") or "").strip()[:100]
        if not subscription_id:
            raise HTTPException(status_code=400, detail="Paddle subscription update has no subscription ID.")
        from sqlalchemy import select
        await _lock_paddle_webhook_resource(db, subscription_id)
        duplicate = (await db.execute(
            select(PaymentWebhookEvent).where(PaymentWebhookEvent.event_id == event_id)
        )).scalar_one_or_none()
        if duplicate is not None:
            return {"status": "already_processed", "event_id": event_id}
        canceled = (await db.execute(
            select(PaymentWebhookEvent).where(
                PaymentWebhookEvent.subscription_id == subscription_id,
                PaymentWebhookEvent.status == "subscription_canceled",
            ).limit(1)
        )).scalar_one_or_none()
        linked_event = (await db.execute(
            select(PaymentWebhookEvent).where(
                PaymentWebhookEvent.subscription_id == subscription_id,
                PaymentWebhookEvent.license_id.is_not(None),
            ).order_by(PaymentWebhookEvent.updated_at.desc(), PaymentWebhookEvent.created_at.desc(), PaymentWebhookEvent.event_id.desc()).limit(1)
        )).scalar_one_or_none()
        if linked_event is None or linked_event.license_id is None:
            raise HTTPException(status_code=503, detail="Subscription update is awaiting license reconciliation.")
        license_obj = (await db.execute(
            select(SoftwareLicense).where(SoftwareLicense.id == linked_event.license_id)
        )).scalar_one_or_none()
        if license_obj is None:
            raise HTTPException(status_code=503, detail="Subscription update is awaiting license reconciliation.")

        provider_status = transaction.get("status")
        if provider_status is not None and not isinstance(provider_status, str):
            raise HTTPException(status_code=400, detail="Paddle subscription status must be a string.")
        provider_status = (provider_status or "").strip().lower()
        if provider_status and provider_status not in {"active", "trialing", "paused", "past_due", "canceled", "cancelled"}:
            logger.info("Paddle subscription update has an unrecognized status (subscription_id=%s)", subscription_id)

        items = transaction.get("items") or []
        if not isinstance(items, list):
            raise HTTPException(status_code=400, detail="Paddle subscription items must be a JSON array.")
        price_ids = set()
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("price"), dict):
                price_id = item["price"].get("id")
                if isinstance(price_id, str) and price_id.strip():
                    price_ids.add(price_id.strip())
        plans = await _db_payment_plans(db, active_only=False)
        plan = next((p for p in plans if p.get("price_id") and p["price_id"] in price_ids), None)
        customer = transaction.get("customer") or {}
        if not isinstance(customer, dict):
            raise HTTPException(status_code=400, detail="Paddle subscription customer must be a JSON object.")
        customer_id = str(transaction.get("customer_id") or customer.get("id") or "").strip()
        now = datetime.now(timezone.utc)
        was_active = bool(license_obj.is_active)
        provider_canceled = provider_status in {"canceled", "cancelled"}
        is_canceled = canceled is not None or provider_canceled

        if is_canceled:
            # Both a newly reported cancellation and a previously confirmed
            # cancellation must leave the linked license disabled.
            license_obj.is_active = False
        else:
            if plan is not None:
                license_obj.tier = plan["tier"]
                license_obj.max_monthly_audits = plan["monthly_audit_allowance"]
            billing_period_end = _paddle_billing_period_end(transaction)
            if billing_period_end is not None:
                license_obj.billing_period_ends_at = billing_period_end

            if provider_status == "paused":
                license_obj.is_active = False
            elif provider_status in {"active", "trialing"} and linked_event.status == "subscription_paused":
                expiry = license_obj.expires_at
                if expiry is not None and expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                license_obj.is_active = expiry is None or expiry > now

        if is_canceled:
            event_status = "subscription_canceled"
        elif provider_status == "paused":
            event_status = "subscription_paused"
        elif provider_status == "past_due":
            # Paddle's retry/dunning policy remains authoritative; past_due alone
            # does not revoke access while the provider retries payment.
            event_status = "subscription_updated_past_due"
        elif provider_status in {"active", "trialing"}:
            event_status = "subscription_updated_active"
        else:
            event_status = "subscription_updated" if plan is not None else "subscription_update_unmapped_price"

        db.add(PaymentWebhookEvent(
            event_id=event_id, status=event_status, license_id=license_obj.id,
            recipient_email=linked_event.recipient_email, subscription_id=subscription_id,
            paddle_customer_id=(customer_id[:100] or linked_event.paddle_customer_id),
            created_at=now, updated_at=now,
        ))
        await db.commit()
        await _sync_billing_event_to_hostinger(db, event_id)
        if was_active != bool(license_obj.is_active) or (plan is not None and not is_canceled):
            await _record_operation_event(db, event_status, license_obj.id, None, None)
        if is_canceled:
            return {"status": "ignored_after_cancellation" if canceled is not None else "cancellation_applied",
                    "event_id": event_id, "license_id": license_obj.id}
        if provider_status == "paused":
            return {"status": "subscription_paused", "event_id": event_id, "license_id": license_obj.id}
        if provider_status == "past_due":
            return {"status": "subscription_past_due", "event_id": event_id, "license_id": license_obj.id}
        if provider_status in {"active", "trialing"}:
            return {"status": "plan_reconciled" if plan is not None else "subscription_active_unmapped_price",
                    "event_id": event_id, "license_id": license_obj.id}
        return {"status": "plan_reconciled" if plan is not None else "unmapped_price_ignored",
                "event_id": event_id, "license_id": license_obj.id}

    if event_type != "transaction.completed":
        return {"status": "ignored", "event_id": event_id}
    if transaction.get("status") != "completed":
        return {"status": "payment_not_complete", "event_id": event_id}
    customer = transaction.get("customer") or {}
    if not isinstance(customer, dict):
        raise HTTPException(status_code=400, detail="Paddle transaction customer must be a JSON object.")
    custom_data = transaction.get("custom_data") or {}
    if not isinstance(custom_data, dict):
        raise HTTPException(status_code=400, detail="Paddle transaction custom_data must be a JSON object.")
    items = transaction.get("items") or []
    if not isinstance(items, list):
        raise HTTPException(status_code=400, detail="Paddle transaction items must be a JSON array.")
    tier = str(custom_data.get("license_tier", "")).strip().lower()
    price_ids = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        price = item.get("price") or {}
        if not isinstance(price, dict):
            continue
        price_id = price.get("id")
        if isinstance(price_id, str) and price_id.strip():
            price_ids.add(price_id.strip())
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
        await _lock_paddle_webhook_resource(db, subscription_id)
        linked_subscription_event = (await db.execute(
            select(PaymentWebhookEvent)
            .where(PaymentWebhookEvent.subscription_id == subscription_id)
            .order_by(PaymentWebhookEvent.updated_at.desc())
            .limit(1)
        )).scalar_one_or_none()
        # Cancellation is sticky across later payment-failure/past-due events.
        # Checking only the newest event would let a later failure record hide the
        # cancellation and make a delayed transaction.completed event reactivate access.
        cancellation_event = (await db.execute(
            select(PaymentWebhookEvent)
            .where(
                PaymentWebhookEvent.subscription_id == subscription_id,
                PaymentWebhookEvent.status == "subscription_canceled",
            )
            .limit(1)
        )).scalar_one_or_none()
        if cancellation_event is not None:
            # A payment event is not proof that a canceled subscription was resumed.
            # Require a separately verified lifecycle/reconciliation action.
            # Still persist the late transaction as an ignored lifecycle event so
            # billing history and webhook idempotency remain complete.
            prior_event = (await db.execute(
                select(PaymentWebhookEvent).where(PaymentWebhookEvent.event_id == event_id)
            )).scalar_one_or_none()
            if prior_event is not None:
                return {"status": "already_processed", "event_id": event_id}
            if transaction_id:
                prior_transaction = (await db.execute(
                    select(PaymentWebhookEvent)
                    .where(PaymentWebhookEvent.transaction_id == transaction_id)
                    .limit(1)
                )).scalar_one_or_none()
                if prior_transaction is not None:
                    return {"status": "already_processed", "event_id": prior_transaction.event_id}
            customer_id = str(
                transaction.get("customer_id") or customer.get("id") or ""
            ).strip()
            db.add(PaymentWebhookEvent(
                event_id=event_id,
                status="subscription_canceled",
                license_id=cancellation_event.license_id,
                recipient_email=cancellation_event.recipient_email,
                transaction_id=transaction_id,
                subscription_id=subscription_id,
                paddle_customer_id=(customer_id[:100] or cancellation_event.paddle_customer_id),
            ))
            await db.commit()
            await _sync_billing_event_to_hostinger(db, event_id)
            return {"status": "subscription_canceled", "event_id": event_id,
                    "license_id": cancellation_event.license_id}
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
                billing_period_end = _paddle_billing_period_end(transaction)
                if billing_period_end is not None:
                    linked_license.billing_period_ends_at = billing_period_end
                renewal_customer_id = str(
                    transaction.get("customer_id") or customer.get("id") or ""
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
                await _sync_billing_event_to_hostinger(db, event_id)
                await _record_operation_event(db, "subscription_renewed", linked_license.id, None, None)
                return {"status": "subscription_renewed", "event_id": event_id, "license_id": linked_license.id}

    # Paddle retries normally reuse event_id, but a transaction can also be
    # delivered under a distinct event ID. Reuse the original provisioning record
    # by transaction ID so a second notification cannot mint another license.
    if transaction_id:
        # Serialize provisioning for this purchase before looking up its event.
        # This closes the race where distinct event IDs arrive simultaneously
        # before either request inserts a webhook record.
        await _lock_paddle_webhook_resource(db, transaction_id, "transaction_id")
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
        recipient = str(customer.get("email") or "").strip()
        customer_name = str(customer.get("name") or "").strip()
        customer_id = str(transaction.get("customer_id") or customer.get("id") or "").strip()
        if not recipient and customer_id and os.getenv("PADDLE_API_KEY", "").strip():
            try:
                customer_response = await asyncio.to_thread(_paddle_api_request, f"/customers/{customer_id}")
                if not isinstance(customer_response, dict):
                    raise ValueError("Paddle customer response is not a JSON object")
                customer = customer_response.get("data") or {}
                if not isinstance(customer, dict):
                    raise ValueError("Paddle customer data is not a JSON object")
                recipient = str(customer.get("email") or "").strip()
                customer_name = str(customer.get("name") or "").strip()
            except Exception as exc:
                logger.error("Paddle customer lookup failed (error_type=%s)", type(exc).__name__)
                raise HTTPException(status_code=502, detail="Paddle customer details could not be retrieved; webhook can retry.") from exc
        if len(recipient) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", recipient):
            raise HTTPException(status_code=400, detail="Completed Paddle transaction has no valid customer email.")
        license_obj = SoftwareLicense(license_key=secrets.token_urlsafe(32), client_name=(customer_name or recipient)[:255],
            tier=plan["tier"], max_monthly_audits=plan["monthly_audit_allowance"], is_active=True,
            billing_period_ends_at=_paddle_billing_period_end(transaction))
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
        await _sync_billing_event_to_hostinger(db, event_id)
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
    await _sync_billing_event_to_hostinger(db, event_id)

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
    await _sync_billing_event_to_hostinger(db, event_id)

    license_obj = (await db.execute(select(SoftwareLicense).where(SoftwareLicense.id == webhook_event.license_id))).scalar_one_or_none()
    if license_obj is None:
        webhook_event.status = "email_pending"
        webhook_event.updated_at = datetime.now(timezone.utc)
        await db.commit()
        await _sync_billing_event_to_hostinger(db, event_id)
        raise HTTPException(status_code=500, detail="The provisioned license record is unavailable.")
    try:
        await asyncio.to_thread(_send_license_email, webhook_event.recipient_email, license_obj.license_key,
            license_obj.tier, license_obj.max_monthly_audits)
    except Exception as exc:
        logger.error("License email delivery failed (error_type=%s)", type(exc).__name__)
        webhook_event.status = "email_pending"
        webhook_event.updated_at = datetime.now(timezone.utc)
        await db.commit()
        await _sync_billing_event_to_hostinger(db, event_id)
        raise HTTPException(status_code=502, detail="Payment was recorded; license email is pending SMTP delivery retry.") from exc
    webhook_event.status = "delivered"
    webhook_event.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await _sync_billing_event_to_hostinger(db, event_id)
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
    dialect_name = db.get_bind().dialect.name
    if dialect_name == "postgresql":
        await db.execute(text(
            "SELECT pg_advisory_xact_lock(hashtext('ecommerce_audit_admin_schema_v1'))"
        ))
    timestamp_type = "TIMESTAMPTZ" if dialect_name == "postgresql" else "DATETIME"
    timestamp_default = "NOW()" if dialect_name == "postgresql" else "CURRENT_TIMESTAMP"
    id_type = "BIGSERIAL PRIMARY KEY" if dialect_name == "postgresql" else "INTEGER PRIMARY KEY AUTOINCREMENT"
    await db.execute(text(f"""
        CREATE TABLE IF NOT EXISTS saas_plan_packages (
            tier VARCHAR(50) PRIMARY KEY,
            label VARCHAR(100) NOT NULL,
            monthly_audit_allowance INTEGER NOT NULL CHECK (monthly_audit_allowance BETWEEN 1 AND 10000000),
            max_concurrent_audits INTEGER NOT NULL CHECK (max_concurrent_audits BETWEEN 1 AND 10000),
            paddle_price_id VARCHAR(100),
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at {timestamp_type} NOT NULL DEFAULT {timestamp_default},
            updated_at {timestamp_type} NOT NULL DEFAULT {timestamp_default}
        )
    """))
    await db.execute(text("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_saas_plan_packages_paddle_price_id
        ON saas_plan_packages (paddle_price_id) WHERE paddle_price_id IS NOT NULL
    """))
    await db.execute(text(f"""
        CREATE TABLE IF NOT EXISTS saas_operation_events (
            id {id_type},
            event_type VARCHAR(80) NOT NULL,
            license_id INTEGER REFERENCES software_licenses(id) ON DELETE SET NULL,
            domain VARCHAR(255),
            error_type VARCHAR(120),
            created_at {timestamp_type} NOT NULL DEFAULT {timestamp_default}
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
    await db.execute(text(f"""
        CREATE TABLE IF NOT EXISTS saas_admin_action_logs (
            id {id_type},
            action VARCHAR(80) NOT NULL,
            entity_type VARCHAR(50) NOT NULL,
            entity_id VARCHAR(255),
            details_json TEXT NOT NULL DEFAULT '{{}}',
            created_at {timestamp_type} NOT NULL DEFAULT {timestamp_default}
        )
    """))
    await db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_saas_admin_action_logs_created
        ON saas_admin_action_logs (created_at DESC, id DESC)
    """))
    # Keep billing references available when this code is upgraded against an existing database.
    if dialect_name == "postgresql":
        await db.execute(text("ALTER TABLE payment_webhook_events ADD COLUMN IF NOT EXISTS transaction_id VARCHAR(100)"))
        await db.execute(text("ALTER TABLE payment_webhook_events ADD COLUMN IF NOT EXISTS subscription_id VARCHAR(100)"))
    elif dialect_name == "sqlite":
        columns = (await db.execute(text("PRAGMA table_info(payment_webhook_events)"))).all()
        column_names = {row[1] for row in columns}
        if "transaction_id" not in column_names:
            await db.execute(text("ALTER TABLE payment_webhook_events ADD COLUMN transaction_id VARCHAR(100)"))
        if "subscription_id" not in column_names:
            await db.execute(text("ALTER TABLE payment_webhook_events ADD COLUMN subscription_id VARCHAR(100)"))
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
                SET max_concurrent_audits=:concurrency, updated_at=:updated_at
                WHERE tier=:tier AND max_concurrent_audits=1
            """), {"tier": tier, "concurrency": concurrency, "updated_at": datetime.now(timezone.utc)})
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


async def _billing_license_ids_for_email(
    db: AsyncSession, operational_db: AsyncSession, email: str
) -> set[int]:
    """Resolve account links from Hostinger billing history with legacy PG fallback."""
    from sqlalchemy import select, func
    normalized = email.strip().lower()
    license_keys = set((await operational_db.execute(
        select(CustomerBillingEvent.license_key).where(
            func.lower(CustomerBillingEvent.recipient_email) == normalized
        )
    )).scalars().all())
    ids = set((await db.execute(
        select(SoftwareLicense.id).where(SoftwareLicense.license_key.in_(license_keys))
    )).scalars().all()) if license_keys else set()
    # Retain compatibility until the one-time operational data copy is applied.
    legacy_ids = set((await db.execute(
        select(PaymentWebhookEvent.license_id).where(
            func.lower(PaymentWebhookEvent.recipient_email) == normalized,
            PaymentWebhookEvent.license_id.is_not(None),
        )
    )).scalars().all())
    return ids | legacy_ids


async def _sync_billing_event_to_hostinger(db: AsyncSession, event_id: str) -> bool:
    """Mirror a committed billing event to Hostinger without moving entitlement authority."""
    if HostingerAsyncSessionLocal is None:
        logger.warning("Billing history mirror skipped because Hostinger is unavailable.")
        return False
    from sqlalchemy import select
    try:
        event = (await db.execute(
            select(PaymentWebhookEvent).where(PaymentWebhookEvent.event_id == event_id)
        )).scalar_one_or_none()
        if event is None or event.license_id is None:
            return False
        license_key = await db.scalar(
            select(SoftwareLicense.license_key).where(SoftwareLicense.id == event.license_id)
        )
        if not license_key:
            return False
        async with HostingerAsyncSessionLocal() as operational_db:
            stored = await operational_db.get(CustomerBillingEvent, event.event_id)
            if stored is None:
                stored = CustomerBillingEvent(
                    event_id=event.event_id,
                    license_key=license_key,
                    recipient_email=event.recipient_email[:254],
                    status=event.status[:40],
                    transaction_id=event.transaction_id,
                    subscription_id=event.subscription_id,
                    paddle_customer_id=event.paddle_customer_id,
                    created_at=event.created_at,
                    updated_at=event.updated_at,
                )
                operational_db.add(stored)
            else:
                stored.license_key = license_key
                stored.recipient_email = event.recipient_email[:254]
                stored.status = event.status[:40]
                stored.transaction_id = event.transaction_id
                stored.subscription_id = event.subscription_id
                stored.paddle_customer_id = event.paddle_customer_id
                stored.updated_at = event.updated_at
            await operational_db.commit()
        return True
    except Exception as exc:
        logger.warning(
            "Billing history mirror failed (error_type=%s, event_id_hash=%s)",
            type(exc).__name__,
            hashlib.sha256(event_id.encode()).hexdigest()[:12],
        )
        return False


async def _write_admin_log(db: AsyncSession, action: str, entity_type: str,
                           entity_id: str | int | None, details: dict | None = None) -> None:
    """Persist sanitized admin activity in Hostinger, not the licensing database."""
    if HostingerAsyncSessionLocal is None:
        logger.warning("Admin activity log was not persisted because Hostinger is unavailable.")
        return
    safe_details = _sanitize_admin_log_value(details or {})
    try:
        async with HostingerAsyncSessionLocal() as operational_db:
            operational_db.add(AdminActionLog(
                action=action[:80],
                entity_type=entity_type[:50],
                entity_id=str(entity_id)[:255] if entity_id is not None else None,
                details_json=json.dumps(safe_details, separators=(",", ":"), ensure_ascii=True),
            ))
            await operational_db.commit()
    except Exception as exc:
        # Logging must not prevent an otherwise valid license/admin transaction.
        logger.warning("Admin activity log write failed (error_type=%s)", type(exc).__name__)


def _safe_audit_metadata_url(value: str | None) -> str | None:    """Persist only public HTTP(S) URLs without credentials, private hosts, queries or fragments."""
    if not value:        return None
    try:
        parts = urlsplit(str(value))
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return None
        if parts.username is not None or parts.password is not None:
            return None
        host = parts.hostname.rstrip(".").lower()
        if not host or host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".test", ".invalid")):
            return None
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None and not address.is_global:
            return None
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
    """Write sanitized diagnostics to Hostinger; PostgreSQL remains license authority."""
    if HostingerAsyncSessionLocal is None:
        logger.warning("Operational diagnostic event was not persisted because Hostinger is unavailable.")
        return
    try:
        from sqlalchemy import select
        license_key = None
        if license_id is not None:
            license_key = await db.scalar(
                select(SoftwareLicense.license_key).where(SoftwareLicense.id == license_id)
            )
        async with HostingerAsyncSessionLocal() as operational_db:
            operational_db.add(OperationalDiagnosticEvent(
                event_type=event_type[:80],
                license_key=license_key,
                domain=(domain or "")[:255] or None,
                error_type=(error_type or "")[:120] or None,
            ))
            await operational_db.commit()
    except Exception as log_exc:
        logger.warning(
            "Operational diagnostic write failed (error_type=%s)",
            type(log_exc).__name__,
        )


async def _db_payment_plans(db: AsyncSession, active_only: bool = True) -> list[dict]:
    await _ensure_admin_tables(db)
    query = "SELECT tier, label, monthly_audit_allowance, max_concurrent_audits, paddle_price_id, is_active FROM saas_plan_packages"
    if active_only:
        query += " WHERE is_active = TRUE"
    query += " ORDER BY monthly_audit_allowance ASC, tier ASC"
    rows = (await db.execute(text(query))).mappings().all()
    if not rows:
        # Preserve environment-configured plans for installations that have not
        # populated the operator catalogue yet. Once any catalogue rows exist,
        # the database remains authoritative and disabled tiers are not revived.
        return _configured_payment_plans()
    plans = []
    for row in rows:
        tier = str(row["tier"] or "").strip().lower()
        # Database package settings are authoritative when they contain a price ID.
        # For existing installations whose package row has no price yet, retain the
        # documented environment-based configuration path used by deployment setups.
        price_id = str(row["paddle_price_id"] or "").strip()
        # Never pass malformed persisted operator data through to Paddle. Treat
        # invalid legacy values as unconfigured so checkout fails closed; a valid
        # environment fallback remains available only when the DB value is absent
        # or malformed, and never changes the stored package record.
        if price_id and not re.fullmatch(r"pri_[A-Za-z0-9]+", price_id):
            logger.warning("Ignoring malformed Paddle price ID for package tier=%s", tier)
            price_id = ""
        if not price_id and tier:
            candidate = os.getenv(f"PADDLE_PRICE_ID_{tier.upper()}", "").strip()
            if re.fullmatch(r"pri_[A-Za-z0-9]+", candidate):
                price_id = candidate
        plans.append({
            "tier": tier, "label": row["label"],
            "monthly_audit_allowance": int(row["monthly_audit_allowance"]),
            "max_concurrent_audits": int(row["max_concurrent_audits"]),
            "price_id": price_id or None, "is_active": bool(row["is_active"])
        })
    return plans


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
            # A concurrent admin request can pass the preflight lookup and still
            # collide with the database unique index. Return the actionable conflict
            # rather than misreporting every uniqueness violation as a duplicate tier.
            if values["paddle_price_id"]:
                duplicate_price = (await db.execute(text("""
                    SELECT tier FROM saas_plan_packages WHERE paddle_price_id=:price_id
                """), {"price_id": values["paddle_price_id"]})).scalar_one_or_none()
                if duplicate_price:
                    raise HTTPException(
                        status_code=409,
                        detail="That Paddle price is already assigned to another package.",
                    ) from exc
            duplicate_tier = (await db.execute(text("""
                SELECT tier FROM saas_plan_packages WHERE tier=:tier
            """), {"tier": values["tier"]})).scalar_one_or_none()
            if duplicate_tier:
                raise HTTPException(status_code=409, detail="A package with this tier already exists.") from exc
            raise HTTPException(status_code=409, detail="Package conflicts with an existing unique value.") from exc
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
          paddle_price_id=:paddle_price_id, is_active=:is_active, updated_at=CURRENT_TIMESTAMP
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
        UPDATE saas_plan_packages SET is_active=FALSE, updated_at=CURRENT_TIMESTAMP WHERE tier=:tier
    """), {"tier": tier})
    if result.rowcount == 0:
        await db.rollback()
        raise HTTPException(status_code=404, detail="Package not found.")
    await _write_admin_log(db, "package.deactivated", "package", tier)
    await db.commit()
    return {"status": "deactivated", "tier": tier}



@app.post("/api/v1/admin/billing/reconcile")
async def admin_reconcile_billing_history(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=1000000),
    db: AsyncSession = Depends(get_async_db),
):
    """Repair a bounded page of Hostinger billing mirrors from canonical webhook records."""
    _require_admin_key(request)
    if HostingerAsyncSessionLocal is None:
        raise HTTPException(status_code=503, detail="Operational billing storage is unavailable.")
    from sqlalchemy import select, func
    total = int((await db.execute(
        select(func.count(PaymentWebhookEvent.event_id)).where(
            PaymentWebhookEvent.license_id.is_not(None)
        )
    )).scalar_one() or 0)
    events = (await db.execute(
        select(PaymentWebhookEvent.event_id)
        .where(PaymentWebhookEvent.license_id.is_not(None))
        .order_by(PaymentWebhookEvent.created_at.desc(), PaymentWebhookEvent.event_id.desc())
        .offset(offset)
        .limit(limit)
    )).scalars().all()
    repaired = 0
    failed = 0
    for event_id in events:
        if await _sync_billing_event_to_hostinger(db, event_id):
            repaired += 1
        else:
            failed += 1
    await _write_admin_log(db, "billing.history_reconciled", "billing_history", None, {
        "offset": offset, "page_count": len(events), "repaired": repaired, "failed": failed,
    })
    return {
        "status": "completed" if failed == 0 else "partial",
        "total_source_events": total,
        "page_count": len(events),
        "repaired": repaired,
        "failed": failed,
        "next_offset": offset + len(events) if offset + len(events) < total else None,
    }


@app.get("/api/v1/admin/actions")
async def admin_action_history(
    request: Request,
    response: Response,
    limit: int = Query(100, ge=1, le=200),
    offset: int = Query(0, ge=0, le=1000000),
    db: AsyncSession = Depends(get_async_db),
):
    """Return a bounded, newest-first page of sanitized administrator activity."""
    _require_admin_key(request)
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    if HostingerAsyncSessionLocal is None:
        raise HTTPException(status_code=503, detail="Operational activity storage is unavailable.")
    from sqlalchemy import select, func
    async with HostingerAsyncSessionLocal() as operational_db:
        total = int((await operational_db.execute(
            select(func.count(AdminActionLog.id))
        )).scalar_one() or 0)
        rows = (await operational_db.execute(
            select(AdminActionLog)
            .order_by(AdminActionLog.created_at.desc(), AdminActionLog.id.desc())
            .offset(offset)
            .limit(limit)
        )).scalars().all()
    actions = []
    for row in rows:
        # Older rows may predate write-time sanitization or may have been manually
        # edited. Never let one malformed payload break the whole activity page.
        try:
            parsed_details = json.loads(row.details_json or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            parsed_details = {"_warning": "Stored activity details were invalid and have been omitted."}
        if not isinstance(parsed_details, dict):
            parsed_details = {"_warning": "Stored activity details were not an object and have been omitted."}
        safe_details = _sanitize_admin_log_value(parsed_details)
        actions.append({
            "id": row.id, "action": row.action, "entity_type": row.entity_type,
            "entity_id": row.entity_id, "details": safe_details,
            "created_at": row.created_at.isoformat() if row.created_at else None
        })
    return {
        "actions": actions,
        "page": {"limit": limit, "offset": offset, "total": total, "has_more": offset + len(actions) < total},
    }


# ----------------------- Admin operations dashboard -----------------------
# Fail closed: configure ADMIN_API_KEY as a deployment secret. Never log its value.
def _require_admin_key(request: Request) -> None:
    expected = os.getenv("ADMIN_API_KEY", "").strip()
    supplied = request.headers.get("x-admin-key", "")
    if not expected:
        raise HTTPException(status_code=503, detail="Admin access is not configured.")
    if not supplied:
        raise HTTPException(status_code=401, detail="Admin authentication required.")
    if not hmac.compare_digest(expected, supplied):
        raise HTTPException(status_code=403, detail="Admin authentication failed.")


@app.get("/admin", response_class=HTMLResponse, include_in_schema=False)
async def admin_dashboard_page():
    """Serve the operator-only dashboard shell; every data endpoint independently authenticates."""
    return FileResponse(Path(__file__).resolve().parent / "admin_portal.html")



@app.get("/api/v1/admin/payment-events")
async def admin_payment_events(
    request: Request,
    response: Response,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100000),
    status: str | None = Query(None, min_length=1, max_length=40),
    db: AsyncSession = Depends(get_async_db),
):
    """Merge operational and canonical billing events so partial migration never hides history."""
    _require_admin_key(request)
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    if HostingerAsyncSessionLocal is None:
        raise HTTPException(status_code=503, detail="Operational billing history is unavailable.")
    from sqlalchemy import select, func as sql_func

    pg_statement = select(PaymentWebhookEvent)
    host_statement = select(CustomerBillingEvent)
    if status:
        pg_statement = pg_statement.where(PaymentWebhookEvent.status == status)
        host_statement = host_statement.where(CustomerBillingEvent.status == status)
    pg_count = int((await db.execute(
        select(sql_func.count(PaymentWebhookEvent.event_id)).where(
            PaymentWebhookEvent.status == status if status else True
        )
    )).scalar_one() or 0)
    async with HostingerAsyncSessionLocal() as operational_db:
        host_count_statement = select(sql_func.count(CustomerBillingEvent.event_id))
        if status:
            host_count_statement = host_count_statement.where(CustomerBillingEvent.status == status)
        host_count = int((await operational_db.execute(host_count_statement)).scalar_one() or 0)
        candidate_limit = offset + limit
        host_rows = (await operational_db.execute(
            host_statement.order_by(
                CustomerBillingEvent.created_at.desc(), CustomerBillingEvent.event_id.desc()
            ).limit(candidate_limit)
        )).scalars().all()
    pg_rows = (await db.execute(
        pg_statement.order_by(
            PaymentWebhookEvent.created_at.desc(), PaymentWebhookEvent.event_id.desc()
        ).limit(candidate_limit)
    )).scalars().all()

    # PostgreSQL is the canonical webhook/entitlement record; Hostinger is its
    # operational mirror. Prefer canonical values for duplicate event IDs.
    merged = {}
    for item in host_rows:
        merged[item.event_id] = item
    for item in pg_rows:
        merged[item.event_id] = item
    events = sorted(
        merged.values(),
        key=lambda item: (
            item.created_at.replace(tzinfo=timezone.utc) if item.created_at and item.created_at.tzinfo is None
            else item.created_at or datetime.min.replace(tzinfo=timezone.utc),
            item.event_id,
        ),
        reverse=True,
    )[offset:offset + limit]
    # Both stores contain the same webhook stream during migration; max avoids
    # double-counting mirrored rows while still exposing partially copied rows.
    total = max(pg_count, host_count)
    license_keys = {event.license_key for event in events if hasattr(event, "license_key")}
    license_ids = {}
    if license_keys:
        rows = (await db.execute(
            select(SoftwareLicense.id, SoftwareLicense.license_key)
            .where(SoftwareLicense.license_key.in_(license_keys))
        )).all()
        license_ids = {key: license_id for license_id, key in rows}
    event_license_ids = {event.id: event.license_id for event in events if hasattr(event, "license_id")}
    return {
        "items": [
            {
                "event_id": event.event_id,
                "status": event.status,
                "license_id": (
                    event_license_ids.get(event.event_id)
                    or license_ids.get(getattr(event, "license_key", None))
                ),
                "transaction_id": event.transaction_id,
                "subscription_id": event.subscription_id,
                "paddle_customer_id": event.paddle_customer_id,
                "created_at": event.created_at.isoformat() if event.created_at else None,
                "updated_at": event.updated_at.isoformat() if event.updated_at else None,
            }
            for event in events
        ],
        "page": {
            "limit": limit, "offset": offset, "total": total,
            "has_more": offset + len(events) < total,
        },
    }

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
        if not isinstance(response, dict):
            raise HTTPException(status_code=502, detail="Paddle returned an invalid transaction response.")
        data = response.get("data")
        if not isinstance(data, dict):
            raise HTTPException(status_code=502, detail="Paddle returned an invalid transaction payload.")
        provider_transaction_id = str(data.get("id") or "").strip()
        if not provider_transaction_id or not hmac.compare_digest(provider_transaction_id, event.transaction_id):
            raise HTTPException(status_code=502, detail="Paddle returned a transaction that does not match the recorded payment.")
        details = data.get("details", {})
        if details is None:
            details = {}
        if not isinstance(details, dict):
            raise HTTPException(status_code=502, detail="Paddle returned invalid transaction details.")
        totals = details.get("totals", {})
        if totals is None:
            totals = {}
        if not isinstance(totals, dict):
            raise HTTPException(status_code=502, detail="Paddle returned invalid transaction totals.")
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
        await _sync_billing_event_to_hostinger(db, event.event_id)
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
    # Only provisioning events that explicitly require license-email delivery are
    # retryable. Payment failures, cancellations, and renewal records can reference
    # the same license but must never trigger a fresh credential email.
    if event.status not in {"email_pending", "email_sending"}:
        raise HTTPException(
            status_code=409,
            detail="This payment event is not awaiting license email delivery.",
        )
    recipient = str(event.recipient_email or "").strip()
    if len(recipient) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", recipient):
        raise HTTPException(
            status_code=409,
            detail="This payment event has no valid recipient email for delivery.",
        )
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

    event.recipient_email = recipient
    event.status = "email_sending"
    event.updated_at = now
    await db.commit()
    await _sync_billing_event_to_hostinger(db, event.event_id)
    try:
        await asyncio.to_thread(
            _send_license_email, recipient, license_obj.license_key,
            license_obj.tier, license_obj.max_monthly_audits,
        )
    except Exception as exc:
        event.status = "email_pending"
        event.updated_at = datetime.now(timezone.utc)
        await db.commit()
        await _sync_billing_event_to_hostinger(db, event.event_id)
        logger.error("Admin license email retry failed (error_type=%s)", type(exc).__name__)
        raise HTTPException(status_code=502, detail="License email retry failed; the event remains pending.") from exc

    event.status = "delivered"
    event.updated_at = datetime.now(timezone.utc)
    await _write_admin_log(
        db, "payment.license_email_retried", "payment_event", event.event_id,
        {"license_id": event.license_id, "delivery_status": "delivered"},
    )
    await db.commit()
    await _sync_billing_event_to_hostinger(db, event.event_id)
    return {"status": "delivered", "event_id": event.event_id}


@app.get("/api/v1/admin/operations")
async def admin_operations(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Private operational diagnostics without exposing environment values or customer secrets."""
    _require_admin_key(request)
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    await _ensure_admin_tables(db)
    from sqlalchemy import select, func as sql_func, or_
    now = datetime.now(timezone.utc)
    expiry_horizon = now + timedelta(days=7)
    # Read-only account lifecycle and entitlement diagnostics; never mutate access here.
    license_counts = {
        "total_licenses": int((await db.execute(select(sql_func.count(SoftwareLicense.id)))).scalar_one() or 0),
        "inactive_licenses": int((await db.execute(select(sql_func.count(SoftwareLicense.id)).where(SoftwareLicense.is_active.is_(False)))).scalar_one() or 0),
        "expired_licenses": int((await db.execute(select(sql_func.count(SoftwareLicense.id)).where(SoftwareLicense.expires_at.is_not(None), SoftwareLicense.expires_at <= now))).scalar_one() or 0),
        "expiring_within_7_days": int((await db.execute(select(sql_func.count(SoftwareLicense.id)).where(SoftwareLicense.is_active.is_(True), SoftwareLicense.expires_at > now, SoftwareLicense.expires_at <= expiry_horizon))).scalar_one() or 0),
        "licenses_without_expiry": int((await db.execute(select(sql_func.count(SoftwareLicense.id)).where(SoftwareLicense.expires_at.is_(None)))).scalar_one() or 0),
        "zero_or_negative_quota_licenses": int((await db.execute(select(sql_func.count(SoftwareLicense.id)).where(SoftwareLicense.max_monthly_audits <= 0))).scalar_one() or 0),
        "active_but_expired_licenses": int((await db.execute(select(sql_func.count(SoftwareLicense.id)).where(SoftwareLicense.is_active.is_(True), SoftwareLicense.expires_at.is_not(None), SoftwareLicense.expires_at <= now))).scalar_one() or 0),
        "active_without_expiry": int((await db.execute(select(sql_func.count(SoftwareLicense.id)).where(SoftwareLicense.is_active.is_(True), SoftwareLicense.expires_at.is_(None)))).scalar_one() or 0),
        "inactive_with_future_expiry": int((await db.execute(select(sql_func.count(SoftwareLicense.id)).where(SoftwareLicense.is_active.is_(False), SoftwareLicense.expires_at > now))).scalar_one() or 0),
        "licenses_missing_tier": int((await db.execute(select(sql_func.count(SoftwareLicense.id)).where(or_(SoftwareLicense.tier.is_(None), SoftwareLicense.tier == "")))).scalar_one() or 0),
    }
    lifecycle_rows = (await db.execute(
        select(SoftwareLicense).where(or_(
            SoftwareLicense.expires_at <= expiry_horizon,
            SoftwareLicense.expires_at.is_(None),
            SoftwareLicense.is_active.is_(False),
            SoftwareLicense.max_monthly_audits <= 0,
            SoftwareLicense.tier.is_(None),
            SoftwareLicense.tier == "",
        )).order_by(SoftwareLicense.expires_at.asc().nulls_last(), SoftwareLicense.id.asc()).limit(100)
    )).scalars().all()
    license_attention = []
    for license_row in lifecycle_rows:
        expiry = license_row.expires_at
        if expiry and expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        flags = []
        if not license_row.is_active:
            flags.append("inactive")
        if expiry and expiry <= now:
            flags.append("expired")
        elif expiry and expiry <= expiry_horizon:
            flags.append("expiring_within_7_days")
        if expiry is None:
            flags.append("no_expiry")
        if int(license_row.max_monthly_audits or 0) <= 0:
            flags.append("invalid_monthly_quota")
        if not str(license_row.tier or "").strip():
            flags.append("missing_tier")
        if not license_row.is_active and expiry and expiry > now:
            flags.append("inactive_with_future_expiry")
        if license_row.is_active and expiry is None:
            flags.append("active_without_expiry")
        if license_row.is_active and expiry and expiry <= now:
            flags.append("active_but_expired")
        license_attention.append({
            "license_id": license_row.id, "client_name": license_row.client_name,
            "tier": license_row.tier, "is_active": bool(license_row.is_active),
            "expires_at": license_row.expires_at.isoformat() if license_row.expires_at else None,
            "max_monthly_audits": license_row.max_monthly_audits, "flags": flags,
        })
    # Probe both database responsibilities independently; never expose connection details.
    try:
        await db.execute(text("SELECT 1"))
        database_status = "healthy"
    except Exception as exc:
        logger.error("Licensing database diagnostic failed (error_type=%s)", type(exc).__name__)
        database_status = "unavailable"
    try:
        await operational_db.execute(text("SELECT 1"))
        operational_database_status = "healthy"
    except Exception as exc:
        logger.error("Operational database diagnostic failed (error_type=%s)", type(exc).__name__)
        operational_database_status = "unavailable"

    # Keep delivery recovery metrics separate from ordinary subscription lifecycle
    # events; a payment failure or cancellation is not a pending license email.
    email_recovery_statuses = ("email_pending", "email_sending")
    pending_email = int((await operational_db.execute(
        select(sql_func.count(CustomerBillingEvent.event_id)).where(
            CustomerBillingEvent.status.in_(email_recovery_statuses)
        )
    )).scalar_one() or 0)
    payment_events = (await operational_db.execute(
        select(CustomerBillingEvent)
        .where(CustomerBillingEvent.status.in_(email_recovery_statuses))
        .order_by(CustomerBillingEvent.updated_at.asc()).limit(50)
    )).scalars().all()
    billing_attention_statuses = ("payment_failed", "subscription_past_due", "subscription_canceled")
    billing_attention_counts = {}
    for lifecycle_status in billing_attention_statuses:
        billing_attention_counts[lifecycle_status] = int((await operational_db.execute(
            select(sql_func.count(CustomerBillingEvent.event_id)).where(
                CustomerBillingEvent.status == lifecycle_status
            )
        )).scalar_one() or 0)
    billing_attention_events = (await operational_db.execute(
        select(CustomerBillingEvent)
        .where(CustomerBillingEvent.status.in_(billing_attention_statuses))
        .order_by(CustomerBillingEvent.updated_at.desc(), CustomerBillingEvent.event_id.desc())
        .limit(50)
    )).scalars().all()
    stale_email_sending_count = int((await operational_db.execute(
        select(sql_func.count(CustomerBillingEvent.event_id)).where(
            CustomerBillingEvent.status == "email_sending",
            CustomerBillingEvent.updated_at <= now - timedelta(minutes=10),
        )
    )).scalar_one() or 0)
    billing_license_keys = {item.license_key for item in [*payment_events, *billing_attention_events]}
    billing_license_ids = {}
    if billing_license_keys:
        billing_license_ids = {
            key: license_id for license_id, key in (await db.execute(
                select(SoftwareLicense.id, SoftwareLicense.license_key)
                .where(SoftwareLicense.license_key.in_(billing_license_keys))
            )).all()
        }
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
    recent_failures = (await operational_db.execute(
        select(OperationalDiagnosticEvent)
        .where(OperationalDiagnosticEvent.created_at >= now - timedelta(hours=24))
        .order_by(OperationalDiagnosticEvent.created_at.desc(), OperationalDiagnosticEvent.id.desc())
        .limit(100)
    )).scalars().all()
    failures_24h = int((await operational_db.execute(
        select(sql_func.count(OperationalDiagnosticEvent.id)).where(
            OperationalDiagnosticEvent.created_at >= now - timedelta(hours=24)
        )
    )).scalar_one() or 0)
    diagnostic_license_keys = {
        row.license_key for row in recent_failures if row.license_key
    }
    diagnostic_license_ids = {}
    if diagnostic_license_keys:
        diagnostic_license_ids = {
            key: license_id for license_id, key in (await db.execute(
                select(SoftwareLicense.id, SoftwareLicense.license_key)
                .where(SoftwareLicense.license_key.in_(diagnostic_license_keys))
            )).all()
        }
    smtp_status = _smtp_configuration_status()
    return {
        "generated_at": now.isoformat(),
        "health": {
            "database": database_status,
            "operational_database": operational_database_status,
            "paddle_api_key_configured": bool(os.getenv("PADDLE_API_KEY", "").strip()),
            "paddle_webhook_secret_configured": bool(os.getenv("PADDLE_WEBHOOK_SECRET", "").strip()),
            "smtp_configured": smtp_status["configured"],
            "smtp_configuration_issues": smtp_status["issues"],
            "admin_key_configured": bool(os.getenv("ADMIN_API_KEY", "").strip()),
        },
        "counts": {
            "pending_payment_email_events": int(pending_email or 0),
            "stale_payment_email_attempts": stale_email_sending_count,
            "billing_attention_events": sum(billing_attention_counts.values()),
            "payment_failed_events": billing_attention_counts["payment_failed"],
            "subscription_past_due_events": billing_attention_counts["subscription_past_due"],
            "subscription_canceled_events": billing_attention_counts["subscription_canceled"],
            "expired_quota_reservations": int(expired_reservation_count or 0),
            "active_quota_reservations": int(active_reservations or 0),
            "audit_and_operation_failures_24h": int(failures_24h or 0),
            **license_counts,
        },
        "license_attention": license_attention,
        "recent_failures": [{
            "id": row.id, "event_type": row.event_type,
            "license_id": diagnostic_license_ids.get(row.license_key),
            "domain": row.domain, "error_type": row.error_type,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        } for row in recent_failures],
        "pending_payment_events": [{
            "event_id": item.event_id,
            "transaction_id": item.transaction_id,
            "subscription_id": item.subscription_id,
            "status": item.status,
            "license_id": billing_license_ids.get(item.license_key),
            "recipient_email": item.recipient_email,
            "created_at": item.created_at.isoformat() if item.created_at else None,
            "updated_at": item.updated_at.isoformat() if item.updated_at else None,
        } for item in payment_events],
        "billing_attention_events": [{
            "event_id": item.event_id,
            "transaction_id": item.transaction_id,
            "subscription_id": item.subscription_id,
            "status": item.status,
            "license_id": billing_license_ids.get(item.license_key),
            "created_at": item.created_at.isoformat() if item.created_at else None,
            "updated_at": item.updated_at.isoformat() if item.updated_at else None,
        } for item in billing_attention_events],
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
    client_status: str = Query(default="all", pattern="^(all|active|inactive|expired|expiring_7d|expiring_30d|no_expiry)$"),
    tier_filter: str = Query(default="", max_length=50),
    db: AsyncSession = Depends(get_async_db),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Return global platform metrics plus a bounded, searchable and filterable client page."""
    _require_admin_key(request)
    from sqlalchemy import select, func as sql_func, or_, cast, String
    now = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    normalized_search = search.strip()
    client_filter = None
    if normalized_search:
        literal_search = normalized_search.replace("%", "").replace("_", "")
        pattern = f"%{literal_search}%"
        matching_license_keys = set((await operational_db.execute(
            select(CustomerBillingEvent.license_key).where(
                sql_func.lower(CustomerBillingEvent.recipient_email).ilike(pattern.lower())
            ).distinct()
        )).scalars().all())
        matching_license_ids = set((await db.execute(
            select(SoftwareLicense.id).where(SoftwareLicense.license_key.in_(matching_license_keys))
        )).scalars().all()) if matching_license_keys else set()
        if not matching_license_ids:
            matching_license_ids = set((await db.execute(
                select(PaymentWebhookEvent.license_id).where(
                    sql_func.lower(PaymentWebhookEvent.recipient_email).ilike(pattern.lower()),
                    PaymentWebhookEvent.license_id.is_not(None),
                ).distinct()
            )).scalars().all())
        client_filter = or_(
            SoftwareLicense.client_name.ilike(pattern),
            SoftwareLicense.tier.ilike(pattern),
            cast(SoftwareLicense.id, String).ilike(pattern),
            SoftwareLicense.id.in_(matching_license_ids),
        )
    count_query = select(sql_func.count(SoftwareLicense.id))
    filtered_query = select(SoftwareLicense)
    filters = []
    if client_filter is not None:
        filters.append(client_filter)
    normalized_tier = tier_filter.strip().lower()
    if normalized_tier:
        # The operator UI describes this as an exact tier filter; do not let
        # percent/underscore input broaden the query through SQL wildcard rules.
        filters.append(sql_func.lower(SoftwareLicense.tier) == normalized_tier)
    # Expiry takes precedence over the active flag: an expired but still-enabled
    # record must not be shown as active in the operator's recovery workflow.
    if client_status == "active":
        filters.append(SoftwareLicense.is_active.is_(True))
        filters.append((SoftwareLicense.expires_at.is_(None)) | (SoftwareLicense.expires_at >= now))
    elif client_status == "inactive":
        filters.append(SoftwareLicense.is_active.is_(False))
        filters.append((SoftwareLicense.expires_at.is_(None)) | (SoftwareLicense.expires_at >= now))
    elif client_status == "expired":
        filters.append(SoftwareLicense.expires_at.is_not(None))
        filters.append(SoftwareLicense.expires_at < now)
    elif client_status == "expiring_7d":
        filters.extend([SoftwareLicense.is_active.is_(True), SoftwareLicense.expires_at > now, SoftwareLicense.expires_at <= now + timedelta(days=7)])
    elif client_status == "expiring_30d":
        filters.extend([SoftwareLicense.is_active.is_(True), SoftwareLicense.expires_at > now, SoftwareLicense.expires_at <= now + timedelta(days=30)])
    elif client_status == "no_expiry":
        filters.append(SoftwareLicense.expires_at.is_(None))
    if filters:
        count_query = count_query.where(*filters)
        filtered_query = filtered_query.where(*filters)
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
    expired_clients = int((await db.execute(select(sql_func.count(SoftwareLicense.id)).where(SoftwareLicense.expires_at.is_not(None), SoftwareLicense.expires_at < now))).scalar_one() or 0)
    expiring_7d_clients = int((await db.execute(select(sql_func.count(SoftwareLicense.id)).where(SoftwareLicense.is_active.is_(True), SoftwareLicense.expires_at > now, SoftwareLicense.expires_at <= now + timedelta(days=7)))).scalar_one() or 0)
    expiring_30d_clients = int((await db.execute(select(sql_func.count(SoftwareLicense.id)).where(SoftwareLicense.is_active.is_(True), SoftwareLicense.expires_at > now, SoftwareLicense.expires_at <= now + timedelta(days=30)))).scalar_one() or 0)
    no_expiry_clients = int((await db.execute(select(sql_func.count(SoftwareLicense.id)).where(SoftwareLicense.expires_at.is_(None)))).scalar_one() or 0)
    inactive_flag_clients = int((await db.execute(select(sql_func.count(SoftwareLicense.id)).where(SoftwareLicense.is_active.is_(False)))).scalar_one() or 0)
    total_leads = (await db.execute(select(sql_func.count(AuditLead.id)))).scalar_one()
    total_reports = (await db.execute(select(sql_func.count(AuditReport.id)))).scalar_one()
    total_reservations = (await db.execute(select(sql_func.count(AuditQuotaReservation.id)).where(
        AuditQuotaReservation.expires_at > now
    ))).scalar_one()
    total_webhooks = int((await operational_db.execute(
        select(sql_func.count(CustomerBillingEvent.event_id))
    )).scalar_one() or 0)
    if total_webhooks == 0:
        total_webhooks = int((await db.execute(
            select(sql_func.count(PaymentWebhookEvent.event_id))
        )).scalar_one() or 0)
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

    # Fetch the most recently verified checkout email per visible license in one
    # bounded query. This field is only returned by the admin-key-protected overview.
    contact_email_by_license = {}
    if licenses:
        visible_license_keys = [item.license_key for item in licenses]
        contact_email_rows = (await operational_db.execute(
            select(CustomerBillingEvent.license_key, CustomerBillingEvent.recipient_email)
            .where(CustomerBillingEvent.license_key.in_(visible_license_keys))
            .order_by(
                CustomerBillingEvent.updated_at.desc(),
                CustomerBillingEvent.created_at.desc(),
                CustomerBillingEvent.event_id.desc(),
            )
        )).all()
        license_id_by_key = {item.license_key: item.id for item in licenses}
        for license_key, recipient_email in contact_email_rows:
            license_id = license_id_by_key.get(license_key)
            if license_id is not None:
                contact_email_by_license.setdefault(license_id, recipient_email)
        missing_contact_ids = [item.id for item in licenses if item.id not in contact_email_by_license]
        if missing_contact_ids:
            legacy_contacts = (await db.execute(
                select(PaymentWebhookEvent.license_id, PaymentWebhookEvent.recipient_email)
                .where(PaymentWebhookEvent.license_id.in_(missing_contact_ids))
                .order_by(PaymentWebhookEvent.updated_at.desc(), PaymentWebhookEvent.created_at.desc())
            )).all()
            for license_id, recipient_email in legacy_contacts:
                contact_email_by_license.setdefault(license_id, recipient_email)

    client_rows = []
    for item in licenses:
        used_month = monthly_by_license.get(item.id, 0)
        total_audits, latest_audit = audits_by_license.get(item.id, (0, None))
        report_count = reports_by_license.get(item.id, 0)
        active_runs = reservations_by_license.get(item.id, 0)
        client_rows.append({
            "id": item.id, "client_name": item.client_name, "tier": item.tier,
            "contact_email": contact_email_by_license.get(item.id),
            "is_active": bool(item.is_active),
            "expired": bool(item.expires_at and (item.expires_at.replace(tzinfo=timezone.utc) if item.expires_at.tzinfo is None else item.expires_at) < now),
            "created_at": item.created_at.isoformat() if item.created_at else None,
            "expires_at": item.expires_at.isoformat() if item.expires_at else None,
            "expires_in_days": max(0, int((((item.expires_at.replace(tzinfo=timezone.utc) if item.expires_at.tzinfo is None else item.expires_at) - now).total_seconds()) // 86400)) if item.expires_at and (item.expires_at.replace(tzinfo=timezone.utc) if item.expires_at.tzinfo is None else item.expires_at) >= now else None,
            "expiry_attention": "expired" if item.expires_at and (item.expires_at.replace(tzinfo=timezone.utc) if item.expires_at.tzinfo is None else item.expires_at) < now else ("expiring_7d" if item.expires_at and (item.expires_at.replace(tzinfo=timezone.utc) if item.expires_at.tzinfo is None else item.expires_at) <= now + timedelta(days=7) else ("expiring_30d" if item.expires_at and (item.expires_at.replace(tzinfo=timezone.utc) if item.expires_at.tzinfo is None else item.expires_at) <= now + timedelta(days=30) else ("no_expiry" if item.expires_at is None else "ok"))),
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
            "clients_expired": expired_clients,
            "clients_expiring_7_days": expiring_7d_clients,
            "clients_expiring_30_days": expiring_30d_clients,
            "clients_without_expiry": no_expiry_clients,
            "clients_inactive_flag": inactive_flag_clients,
            "audits_this_month": int(monthly_leads or 0), "audits_all_time": int(total_leads or 0),
            "reports_saved": int(total_reports or 0), "active_audit_reservations": int(total_reservations or 0),
            "payment_webhook_events": int(total_webhooks or 0),
        },
        "clients": client_rows,
        "client_page": {"limit": limit, "offset": offset, "total": filtered_total, "search": normalized_search, "status": client_status, "tier": normalized_tier, "has_more": offset + len(client_rows) < filtered_total},
    }


@app.get("/api/v1/admin/reports/{report_id}/pdf", response_class=Response)
async def admin_download_audit_report(report_id: int, request: Request,
                                      db: AsyncSession = Depends(get_async_db)):
    """Allow authenticated operators to retrieve a saved customer report for support."""
    _require_admin_key(request)
    from sqlalchemy import select
    report = (await db.execute(select(AuditReport).where(AuditReport.id == report_id))).scalar_one_or_none()
    if report is None:        raise HTTPException(status_code=404, detail="Audit report not found.")
    safe_hostname = re.sub(r"[^a-zA-Z0-9.-]", "-", report.domain)[:180] or "website"
    return Response(        content=report.pdf_bytes,
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
    offset: int = Query(0, ge=0, le=10000000),
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
async def admin_client_history(license_id: int, request: Request, response: Response, limit: int = Query(100, ge=1, le=500),
                              db: AsyncSession = Depends(get_async_db),
                              operational_db: AsyncSession = Depends(get_hostinger_db)):
    """Return a single client's audit, report, reservation and payment-provisioning history."""
    _require_admin_key(request)
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
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
    payments = (await operational_db.execute(
        select(CustomerBillingEvent).where(CustomerBillingEvent.license_key == client.license_key)
        .order_by(CustomerBillingEvent.created_at.desc(), CustomerBillingEvent.event_id.desc()).limit(limit)
    )).scalars().all()
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
        "payments": [{"event_id": p.event_id, "license_id": client.id, "status": p.status, "recipient_email": p.recipient_email,
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


class AdminCustomerAccountAction(BaseModel):
    action: str = Field(..., pattern="^(suspend|reactivate|revoke_sessions)$")
    reason: str = Field(..., min_length=3, max_length=500)
    confirm_email: str = Field(..., min_length=3, max_length=254)


class AdminSubscriptionCancel(BaseModel):
    subscription_id: str = Field(..., min_length=8, max_length=100)
    effective_from: str = Field(default="next_billing_period", pattern="^(next_billing_period|immediately)$")
    confirm_subscription_id: str = Field(..., min_length=8, max_length=100)
    reason: str = Field(..., min_length=3, max_length=500)


class AdminCustomerNoteInput(BaseModel):
    note: str = Field(..., min_length=3, max_length=4000)


class AdminAPIKeyCreate(BaseModel):
    client_id: int = Field(..., ge=1)
    label: str = Field(default="Admin-created key", min_length=1, max_length=100)


class AdminAPIKeyRevoke(BaseModel):
    reason: str = Field(default="operator revocation", min_length=1, max_length=200)




@app.post("/api/v1/admin/subscriptions/cancel")
async def admin_cancel_subscription(
    payload: AdminSubscriptionCancel,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
):
    """Request cancellation through Paddle; provider webhook remains authoritative for entitlement state."""
    _require_admin_key(request)
    subscription_id = payload.subscription_id.strip()
    if not re.fullmatch(r"sub_[A-Za-z0-9]+", subscription_id):
        raise HTTPException(status_code=422, detail="Paddle subscription identifier is invalid.")
    if not hmac.compare_digest(subscription_id, payload.confirm_subscription_id.strip()):
        raise HTTPException(status_code=422, detail="Subscription confirmation does not match.")
    from sqlalchemy import select
    event = (await db.execute(select(PaymentWebhookEvent).where(
        PaymentWebhookEvent.subscription_id == subscription_id
    ).order_by(PaymentWebhookEvent.updated_at.desc()).limit(1))).scalar_one_or_none()
    if event is None:
        raise HTTPException(status_code=404, detail="Subscription is not linked to a recorded customer billing event.")
    if not os.getenv("PADDLE_API_KEY", "").strip():
        raise HTTPException(status_code=503, detail="Paddle API is not configured.")
    try:
        provider = await asyncio.to_thread(
            _paddle_api_request,
            f"/subscriptions/{subscription_id}/cancel",
            "POST",
            {"effective_from": payload.effective_from},
        )
        data = provider.get("data") if isinstance(provider, dict) else None
        if not isinstance(data, dict) or data.get("id") != subscription_id:
            raise RuntimeError("Paddle returned an unexpected subscription response")
    except Exception as exc:
        logger.warning("Admin Paddle cancellation request failed (error_type=%s)", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Paddle did not confirm the subscription cancellation request.") from None
    await _write_admin_log(db, "subscription.cancellation_requested", "subscription", subscription_id, {
        "effective_from": payload.effective_from,
        "provider_status": str(data.get("status") or "")[:40],
        "license_id": event.license_id,
        "reason": payload.reason.strip(),
    })
    await db.commit()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "status": "cancellation_requested",
        "subscription_id": subscription_id,
        "effective_from": payload.effective_from,
        "provider_status": data.get("status"),
        "message": "Paddle accepted the cancellation request. Local access changes only when the verified subscription webhook is processed.",
    }


@app.get("/api/v1/admin/customers")
async def admin_customer_directory(
    request: Request,
    response: Response,
    search: str = Query(default="", max_length=254),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=1000000),
    db: AsyncSession = Depends(get_async_db),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Account directory aggregated from Hostinger billing identities."""
    _require_admin_key(request)
    from sqlalchemy import select, func as sql_func, distinct, union, literal
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    normalized = search.strip().lower()

    # The operational customer directory is the union of billing identities and
    # authenticated customer accounts. A customer must remain discoverable even
    # before the first payment event or after a billing mirror has been reconciled.
    identity_sources = union(
        select(
            sql_func.lower(CustomerBillingEvent.recipient_email).label("email"),
            CustomerBillingEvent.license_key.label("license_key"),
            CustomerBillingEvent.updated_at.label("activity_at"),
        ).where(
            CustomerBillingEvent.recipient_email.is_not(None),
            CustomerBillingEvent.recipient_email != "",
        ),
        select(
            sql_func.lower(CustomerAccount.email).label("email"),
            CustomerAccount.license_key.label("license_key"),
            literal(None).label("activity_at"),
        ).where(
            CustomerAccount.email.is_not(None),
            CustomerAccount.email != "",
        ),
    ).subquery("customer_identity_sources")

    query = select(
        identity_sources.c.email.label("email"),
        sql_func.count(distinct(identity_sources.c.license_key)).label("license_count"),
        sql_func.max(identity_sources.c.activity_at).label("last_billing_activity"),
    ).group_by(identity_sources.c.email)
    count_query = select(sql_func.count(sql_func.distinct(identity_sources.c.email)))
    if normalized:
        search_term = normalized.replace("%", "").replace("_", "")
        email_filter = identity_sources.c.email.ilike(f"%{search_term}%")
        query = query.where(email_filter)
        count_query = count_query.where(email_filter)
    total = int((await operational_db.execute(count_query)).scalar_one() or 0)
    rows = (await operational_db.execute(
        query.order_by(sql_func.max(identity_sources.c.activity_at).desc(), identity_sources.c.email.asc())
        .offset(offset).limit(limit)
    )).all()

    legacy_directory = False
    if total == 0:
        # Compatibility fallback for deployments where the Hostinger data
        # migration has not yet been applied.
        legacy_directory = True
        legacy_query = select(
            sql_func.lower(PaymentWebhookEvent.recipient_email).label("email"),
            sql_func.count(distinct(PaymentWebhookEvent.license_id)).label("license_count"),
            sql_func.max(PaymentWebhookEvent.updated_at).label("last_billing_activity"),
        ).where(
            PaymentWebhookEvent.recipient_email.is_not(None),
            PaymentWebhookEvent.recipient_email != "",
            PaymentWebhookEvent.license_id.is_not(None),
        ).group_by(sql_func.lower(PaymentWebhookEvent.recipient_email))
        legacy_count = select(sql_func.count(sql_func.distinct(
            sql_func.lower(PaymentWebhookEvent.recipient_email)
        ))).where(
            PaymentWebhookEvent.recipient_email.is_not(None),
            PaymentWebhookEvent.recipient_email != "",
            PaymentWebhookEvent.license_id.is_not(None),
        )
        if normalized:
            legacy_filter = sql_func.lower(PaymentWebhookEvent.recipient_email).ilike(
                f"%{normalized.replace('%', '').replace('_', '')}%"
            )
            legacy_query = legacy_query.having(legacy_filter)
            legacy_count = legacy_count.where(legacy_filter)
        total = int((await db.execute(legacy_count)).scalar_one() or 0)
        rows = (await db.execute(
            legacy_query.order_by(sql_func.max(PaymentWebhookEvent.updated_at).desc())
            .offset(offset).limit(limit)
        )).all()

    items = []
    now = datetime.now(timezone.utc)
    for row in rows:
        if legacy_directory:
            license_rows = (await db.execute(select(SoftwareLicense).join(
                PaymentWebhookEvent, PaymentWebhookEvent.license_id == SoftwareLicense.id
            ).where(sql_func.lower(PaymentWebhookEvent.recipient_email) == row.email)
            .distinct())).scalars().all()
        else:
            operational_license_keys = union(
                select(CustomerBillingEvent.license_key).where(
                    sql_func.lower(CustomerBillingEvent.recipient_email) == row.email
                ),
                select(CustomerAccount.license_key).where(
                    sql_func.lower(CustomerAccount.email) == row.email
                ),
            ).subquery("customer_license_sources")
            license_keys = set((await operational_db.execute(
                select(operational_license_keys.c.license_key)
            )).scalars().all())
            license_rows = (await db.execute(
                select(SoftwareLicense).where(SoftwareLicense.license_key.in_(license_keys))
            )).scalars().all() if license_keys else []

        active = sum(
            1 for lic in license_rows
            if lic.is_active and (
                lic.expires_at is None
                or (lic.expires_at.replace(tzinfo=timezone.utc) if lic.expires_at.tzinfo is None else lic.expires_at) >= now
            )
        )
        items.append({
            "email": row.email,
            "license_count": len(license_rows),
            "active_license_count": active,
            "inactive_license_count": len(license_rows) - active,
            "last_billing_activity": row.last_billing_activity.isoformat() if row.last_billing_activity else None,
        })
    return {"items": items, "page": {
        "limit": limit, "offset": offset, "total": total,
        "has_more": offset + len(items) < total,
    }}

@app.get("/api/v1/admin/customers/detail")
async def admin_customer_account_detail(
    email: str = Query(..., min_length=3, max_length=254),
    request: Request = None,
    response: Response = None,
    db: AsyncSession = Depends(get_async_db),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Return an account-wide view across licenses, billing, sessions and support notes."""
    _require_admin_key(request)
    from sqlalchemy import select, func as sql_func
    normalized = email.strip().lower()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    customer_license_keys = set((await operational_db.execute(
        select(CustomerBillingEvent.license_key).where(
            sql_func.lower(CustomerBillingEvent.recipient_email) == normalized
        ).distinct()
    )).scalars().all())
    customer_license_keys.update((await operational_db.execute(
        select(CustomerAccount.license_key).where(
            sql_func.lower(CustomerAccount.email) == normalized
        ).distinct()
    )).scalars().all())
    rows = (await db.execute(
        select(SoftwareLicense).where(SoftwareLicense.license_key.in_(customer_license_keys))
        .order_by(SoftwareLicense.created_at.desc())
    )).scalars().all() if customer_license_keys else []
    if not rows:
        # Legacy fallback until Hostinger billing history migration is applied.
        rows = (await db.execute(select(SoftwareLicense).join(
            PaymentWebhookEvent, PaymentWebhookEvent.license_id == SoftwareLicense.id
        ).where(sql_func.lower(PaymentWebhookEvent.recipient_email) == normalized)
        .distinct().order_by(SoftwareLicense.created_at.desc()))).scalars().all()
    if not rows:
        raise HTTPException(status_code=404, detail="Customer account not found.")
    ids = [item.id for item in rows]
    license_keys = [item.license_key for item in rows]
    sessions = (await operational_db.execute(select(CustomerSession).where(CustomerSession.license_key.in_(license_keys)).order_by(CustomerSession.created_at.desc()).limit(200))).scalars().all()
    payments = (await operational_db.execute(
        select(CustomerBillingEvent).where(CustomerBillingEvent.license_key.in_(license_keys))
        .order_by(CustomerBillingEvent.updated_at.desc()).limit(200)
    )).scalars().all()
    # Keep the operational mirror and legacy PostgreSQL source visible together
    # during gradual migration; a partially migrated customer must not lose history.
    legacy_payments = (await db.execute(
        select(PaymentWebhookEvent).where(PaymentWebhookEvent.license_id.in_(ids))
        .order_by(PaymentWebhookEvent.updated_at.desc()).limit(200)
    )).scalars().all()
    known_event_ids = {item.event_id for item in payments}
    payments.extend(item for item in legacy_payments if item.event_id not in known_event_ids)
    payments.sort(key=lambda item: item.updated_at or item.created_at, reverse=True)
    payments = payments[:200]
    notes = (await operational_db.execute(select(AdminCustomerNote).where(
        sql_func.lower(AdminCustomerNote.customer_email) == normalized
    ).order_by(AdminCustomerNote.created_at.desc(), AdminCustomerNote.id.desc()).limit(100))).scalars().all()
    wordpress_sites = (await operational_db.execute(select(WordPressInstallation).where(
        WordPressInstallation.license_key.in_(license_keys)
    ).order_by(WordPressInstallation.created_at.desc()).limit(100))).scalars().all()
    now = datetime.now(timezone.utc)
    return {
        "email": normalized,
        "licenses": [{
            "id": item.id, "client_name": item.client_name, "tier": item.tier,
            "is_active": bool(item.is_active), "expired": bool(item.expires_at and (item.expires_at.replace(tzinfo=timezone.utc) if item.expires_at.tzinfo is None else item.expires_at) < now),
            "monthly_limit": item.max_monthly_audits,
            "expires_at": item.expires_at.isoformat() if item.expires_at else None,
            "billing_period_ends_at": item.billing_period_ends_at.isoformat() if item.billing_period_ends_at else None,
            "created_at": item.created_at.isoformat() if item.created_at else None,
        } for item in rows],
        "sessions": [{
            "email": item.email,
            "license_id": next((lic.id for lic in rows if lic.license_key == item.license_key), None),
            "status": "revoked" if item.revoked_at else ("expired" if (item.expires_at.replace(tzinfo=timezone.utc) if item.expires_at.tzinfo is None else item.expires_at) <= now else "active"),
            "created_at": item.created_at.isoformat() if item.created_at else None,
            "last_seen_at": item.last_seen_at.isoformat() if item.last_seen_at else None,
            "expires_at": item.expires_at.isoformat() if item.expires_at else None,
            "revoked_at": item.revoked_at.isoformat() if item.revoked_at else None,
        } for item in sessions],
        "billing_events": [{
            "event_id": item.event_id, "license_id": next((lic.id for lic in rows if lic.license_key == getattr(item, "license_key", None)), getattr(item, "license_id", None)), "status": item.status,
            "transaction_id": item.transaction_id, "subscription_id": item.subscription_id,
            "created_at": item.created_at.isoformat() if item.created_at else None,
            "updated_at": item.updated_at.isoformat() if item.updated_at else None,
        } for item in payments],
        "support_notes": [{
            "id": item.id, "note": item.note, "created_by": item.created_by,
            "created_at": item.created_at.isoformat() if item.created_at else None,
        } for item in notes],
        "wordpress_sites": [{
            "site_id": item.id, "license_key": item.license_key, "site_url": item.site_url,
            "site_host": item.site_host, "admin_email": item.admin_email,
            "wordpress_version": item.wordpress_version, "woocommerce_version": item.woocommerce_version,
            "plugin_version": item.plugin_version, "status": item.status,
            "created_at": item.created_at.isoformat() if item.created_at else None,
            "last_seen_at": item.last_seen_at.isoformat() if item.last_seen_at else None,
            "disconnected_at": item.disconnected_at.isoformat() if item.disconnected_at else None,
        } for item in wordpress_sites],
    }


@app.post("/api/v1/admin/customers/actions")
async def admin_customer_account_action(
    payload: AdminCustomerAccountAction,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Apply an explicit account-wide lifecycle action with email confirmation and audit logging."""
    _require_admin_key(request)
    from sqlalchemy import select, func as sql_func, update
    normalized = payload.confirm_email.strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", normalized):
        raise HTTPException(status_code=422, detail="Enter a valid customer email for confirmation.")
    account_license_keys = set((await operational_db.execute(
        select(CustomerBillingEvent.license_key).where(
            sql_func.lower(CustomerBillingEvent.recipient_email) == normalized
        ).distinct()
    )).scalars().all())
    account_license_keys.update((await operational_db.execute(
        select(CustomerAccount.license_key).where(
            sql_func.lower(CustomerAccount.email) == normalized
        ).distinct()
    )).scalars().all())
    ids = list((await db.execute(
        select(SoftwareLicense.id).where(SoftwareLicense.license_key.in_(account_license_keys))
    )).scalars().all()) if account_license_keys else []
    if not ids:
        ids = list((await db.execute(select(SoftwareLicense.id).join(
            PaymentWebhookEvent, PaymentWebhookEvent.license_id == SoftwareLicense.id
        ).where(sql_func.lower(PaymentWebhookEvent.recipient_email) == normalized).distinct()
        )).scalars().all())
    if not ids:
        raise HTTPException(status_code=404, detail="Customer account not found.")
    now = datetime.now(timezone.utc)
    if payload.action in {"suspend", "reactivate"}:
        active = payload.action == "reactivate"
        result = await db.execute(update(SoftwareLicense).where(SoftwareLicense.id.in_(ids)).values(is_active=active))
        changed = int(result.rowcount or 0)
    else:
        license_keys = list((await db.execute(select(SoftwareLicense.license_key).where(SoftwareLicense.id.in_(ids)))).scalars().all())
        result = await operational_db.execute(update(CustomerSession).where(
            CustomerSession.license_key.in_(license_keys), CustomerSession.revoked_at.is_(None)
        ).values(revoked_at=now))
        await operational_db.commit()
        changed = int(result.rowcount or 0)
    await _write_admin_log(db, "customer.account_" + payload.action, "customer", normalized, {
        "license_ids": ids, "changed_count": changed, "reason": payload.reason.strip(),
    })
    await db.commit()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    action_status = {"suspend": "suspended", "reactivate": "reactivated", "revoke_sessions": "sessions_revoked"}[payload.action]
    return {"status": action_status, "email": normalized, "license_count": len(ids), "changed_count": changed}


@app.post("/api/v1/admin/customers/notes")
async def admin_add_customer_note(
    payload: AdminCustomerNoteInput,
    email: str = Query(..., min_length=3, max_length=254),
    request: Request = None,
    response: Response = None,
    db: AsyncSession = Depends(get_async_db),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Append a bounded internal support note to a customer identity."""
    _require_admin_key(request)
    from sqlalchemy import select, func as sql_func
    normalized = email.strip().lower()
    note_license_keys = set((await operational_db.execute(
        select(CustomerBillingEvent.license_key).where(
            sql_func.lower(CustomerBillingEvent.recipient_email) == normalized
        ).distinct()
    )).scalars().all())
    note_license_keys.update((await operational_db.execute(
        select(CustomerAccount.license_key).where(
            sql_func.lower(CustomerAccount.email) == normalized
        ).distinct()
    )).scalars().all())
    if not note_license_keys:
        note_license_keys.update((await db.execute(select(SoftwareLicense.license_key).join(
            PaymentWebhookEvent, PaymentWebhookEvent.license_id == SoftwareLicense.id
        ).where(sql_func.lower(PaymentWebhookEvent.recipient_email) == normalized).distinct()
        )).scalars().all())
    if not note_license_keys:
        raise HTTPException(status_code=404, detail="Customer account not found.")
    created = AdminCustomerNote(
        license_key=sorted(note_license_keys)[0],
        customer_email=normalized,
        note=payload.note.strip(),
        created_by="admin",
        created_at=datetime.now(timezone.utc),
    )
    operational_db.add(created)
    await operational_db.commit()
    await _write_admin_log(db, "customer.support_note_added", "customer", normalized, {"note_id": created.id})
    await db.commit()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {"id": created.id, "email": normalized, "created_at": created.created_at.isoformat() if created.created_at else None}


@app.get("/api/v1/admin/clients/{license_id}/sessions")
async def admin_list_client_sessions(
    license_id: int,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """List customer session metadata without exposing bearer tokens or token digests."""
    _require_admin_key(request)
    from sqlalchemy import select
    client = (await db.execute(
        select(SoftwareLicense).where(SoftwareLicense.id == license_id)
    )).scalar_one_or_none()
    if client is None:
        raise HTTPException(status_code=404, detail="Client not found.")
    rows = (await operational_db.execute(
        select(CustomerSession).where(CustomerSession.license_key == client.license_key)
        .order_by(CustomerSession.created_at.desc()).limit(100)
    )).scalars().all()
    now = datetime.now(timezone.utc)
    items = []
    for item in rows:
        expiry = item.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        state = "revoked" if item.revoked_at is not None else ("expired" if expiry <= now else "active")
        items.append({
            "email": item.email,
            "status": state,
            "created_at": item.created_at.isoformat() if item.created_at else None,
            "last_seen_at": item.last_seen_at.isoformat() if item.last_seen_at else None,
            "expires_at": expiry.isoformat(),
            "revoked_at": item.revoked_at.isoformat() if item.revoked_at else None,
        })
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {"client_id": license_id, "items": items, "limit": 100}


@app.post("/api/v1/admin/clients/{license_id}/sessions/revoke-all")
async def admin_revoke_client_sessions(
    license_id: int,
    payload: AdminAPIKeyRevoke,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Revoke all browser sessions for a selected customer and record the operator action."""
    _require_admin_key(request)
    from sqlalchemy import select, update
    client = (await db.execute(
        select(SoftwareLicense).where(SoftwareLicense.id == license_id)
    )).scalar_one_or_none()
    if client is None:
        raise HTTPException(status_code=404, detail="Client not found.")
    now = datetime.now(timezone.utc)
    result = await operational_db.execute(update(CustomerSession).where(
        CustomerSession.license_key == client.license_key,
        CustomerSession.revoked_at.is_(None),
    ).values(revoked_at=now))
    count = int(result.rowcount or 0)
    await operational_db.commit()
    await _write_admin_log(db, "client.sessions_revoked", "client", license_id, {
        "revoked_count": count,
        "reason": payload.reason.strip(),
    })
    await db.commit()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {"status": "revoked", "client_id": license_id, "revoked_count": count}


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