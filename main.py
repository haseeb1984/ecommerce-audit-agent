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
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import delete, text
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_async_db
from ecommerce_agent import UniversalEcommerceAgent, LeadDossier
from models import SoftwareLicense, AuditLead, AuditQuotaReservation, AuditReport, PaymentWebhookEvent
from auth import verify_license_or_api_key
from quota import reserve_audit_slot, release_audit_reservation
from audit_checks import AuditFinding, normalize_target, run_phase_one_checks
from report_generator import render_audit_pdf
from crawl_checks import run_bounded_site_crawl
from conversion_checks import run_conversion_paid_traffic_checks
from coverage_manifest import build_coverage_manifest

logger = logging.getLogger("audit_service")

app = FastAPI(
    title="AI E-Commerce Audit Engine - Commercial Edition",
    description="Multi-model API serving SaaS, Managed Services, White-Label, and Enterprise integrations.",
    swagger_ui_parameters={"persistAuthorization": True}
)

agent = UniversalEcommerceAgent()


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
    reservation_id = None
    try:
        # Reserve quota in a short transaction. No row lock is held during external API calls.
        reservation_id, reserved_at = await reserve_audit_slot(db, license_obj.id)

        dossier = await agent.process_lead(domain=domain, user_email=email, source=source)

        db_lead = AuditLead(
            license_id=license_obj.id,
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
    except HTTPException:
        await db.rollback()
        if reservation_id is not None:
            try:
                await release_audit_reservation(db, reservation_id)
            except Exception as release_exc:
                logger.error("Failed to release quota reservation (error_type=%s)", type(release_exc).__name__)
        raise
    except Exception as exc:
        await db.rollback()
        if reservation_id is not None:
            try:
                await release_audit_reservation(db, reservation_id)
            except Exception as release_exc:
                logger.error("Failed to release quota reservation (error_type=%s)", type(release_exc).__name__)
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

    reservation_id = None
    try:
        reservation_id, reserved_at = await reserve_audit_slot(db, license_obj.id)

        # Existing PageSpeed metric fields are required by the current audit_leads schema.
        # Keep this call strict rather than writing fabricated placeholder metrics.
        metrics = await agent.run_audit(target_url)
        result = await run_phase_one_checks(target_url)
        crawl_findings, crawl_pages, crawl_limitations = await run_bounded_site_crawl(target_url)
        result.findings.extend(crawl_findings)
        result.pages_checked = list(dict.fromkeys([*result.pages_checked, *crawl_pages]))
        result.limitations.extend(crawl_limitations)
        conversion_findings, conversion_pages, conversion_limitations = await run_conversion_paid_traffic_checks(target_url)
        result.findings.extend(conversion_findings)
        result.pages_checked = list(dict.fromkeys([*result.pages_checked, *conversion_pages]))
        result.limitations.extend(conversion_limitations)
        result.findings.insert(0, AuditFinding(
            category="performance",
            title="Google PageSpeed mobile performance snapshot",
            status="verified",
            severity="medium" if metrics.mobile_score < 50 else "low" if metrics.mobile_score < 90 else "info",
            evidence=(
                f"Google PageSpeed Insights reported a mobile Lighthouse performance score "
                f"of {metrics.mobile_score}/100 and Speed Index of {metrics.speed_index_sec} seconds. "
                "These are lab results; field experience can differ."
            ),
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
        ))
        if not metrics.screenshot_data_uri:
            result.limitations.append(
                "No usable actual-page screenshot was supplied by the Google PageSpeed response for this run; "
                "the report uses explanatory vector illustrations only and does not fabricate website screenshots."
            )
        pdf_bytes = (
            render_audit_pdf(result, screenshot_data_uri=metrics.screenshot_data_uri)
            if metrics.screenshot_data_uri
            else render_audit_pdf(result)
        )

        # Coverage is category-level evidence, not a claim that every check passed.
        coverage_manifest = build_coverage_manifest(
            target_url=target_url,
            pages_checked=result.pages_checked,
            findings=result.findings,
            limitations=result.limitations,
        )
        report = AuditReport(
            license_id=license_obj.id,
            domain=urlsplit(target_url).hostname or metrics.domain,
            pdf_bytes=pdf_bytes,
            coverage_json=json.dumps(coverage_manifest, separators=(",", ":")),
            finding_count=len(result.findings),
            created_at=reserved_at,
        )
        db.add(report)
        await db.flush()
        report_id = report.id

        db.add(AuditLead(
            license_id=license_obj.id,
            domain=urlsplit(target_url).hostname or metrics.domain,
            mobile_score=metrics.mobile_score,
            speed_index_sec=metrics.speed_index_sec,
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
            },
        )
    except HTTPException:
        await db.rollback()
        if reservation_id is not None:
            try:
                await release_audit_reservation(db, reservation_id)
            except Exception as release_exc:
                logger.error("Failed to release quota reservation (error_type=%s)", type(release_exc).__name__)
        raise
    except Exception as exc:
        await db.rollback()
        if reservation_id is not None:
            try:
                await release_audit_reservation(db, reservation_id)
            except Exception as release_exc:
                logger.error("Failed to release quota reservation (error_type=%s)", type(release_exc).__name__)
        logger.error("Comprehensive audit report generation failed (error_type=%s)", type(exc).__name__)
        raise HTTPException(
            status_code=500,
            detail="Comprehensive audit report generation failed. Check server logs for diagnostics.",
        ) from exc

 
@app.get("/app", include_in_schema=False)
async def customer_portal():
    """Serve the lightweight, API-backed customer portal bundled with this repository."""
    return FileResponse(Path(__file__).resolve().parent / "customer_portal.html")


@app.get("/api/v1/reports")
async def list_audit_reports(
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
        headers={"Content-Disposition": f'attachment; filename="ecommerce-audit-{safe_hostname}-{row.id}.pdf"'},
    )


@app.get("/api/v1/reports/{report_id}/coverage")
async def get_audit_report_coverage(
    report_id: int,
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
    return json.loads(row.coverage_json)




def _send_license_email(recipient: str, license_key: str, tier: str, quota: int) -> None:
    """Deliver a newly provisioned license using SMTP secrets from the runtime environment."""
    host = os.getenv("SMTP_HOST", "").strip()
    sender = os.getenv("SMTP_FROM", "").strip()
    if not host or not sender:
        raise RuntimeError("Email delivery is not configured")
    port = int(os.getenv("SMTP_PORT", "587"))
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


def _configured_payment_plans() -> list[dict]:
    plans = []
    for tier, label, default_quota in (
        ("STARTER", "Starter", 100),
        ("PRO", "Pro", 500),
        ("BUSINESS", "Business", 2000),
    ):
        checkout_url = os.getenv(f"STRIPE_CHECKOUT_URL_{tier}", "").strip()
        payment_link_id = os.getenv(f"STRIPE_PAYMENT_LINK_ID_{tier}", "").strip()
        if not checkout_url or not payment_link_id:
            continue
        parsed = urlsplit(checkout_url)
        if parsed.scheme != "https" or not parsed.hostname:
            continue
        try:
            quota = int(os.getenv(f"LICENSE_MONTHLY_AUDITS_{tier}", str(default_quota)))
        except ValueError:
            continue
        if quota < 1:
            continue
        plans.append({
            "tier": tier.lower(),
            "label": label,
            "monthly_audit_allowance": quota,
            "checkout_url": checkout_url,
            "payment_link_id": payment_link_id,
        })
    return plans


@app.get("/api/v1/billing/plans")
async def public_billing_plans():
    """Expose checkout only when payment verification and license email delivery are ready."""
    checkout_ready = bool(
        os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()
        and os.getenv("SMTP_HOST", "").strip()
        and os.getenv("SMTP_FROM", "").strip()
    )
    plans = _configured_payment_plans() if checkout_ready else []
    return {
        "checkout_provider": "Stripe Payment Links",
        "configured": bool(plans),
        "plans": [
            {key: value for key, value in plan.items() if key != "payment_link_id"}
            for plan in plans
        ],
        "configuration_needed": [] if plans else [
            "Stripe webhook signing secret",
            "SMTP host and sender",
            "Checkout URL and Payment Link ID for each plan",
        ],
    }


@app.post("/api/v1/billing/stripe-webhook")
async def stripe_checkout_webhook(request: Request, db: AsyncSession = Depends(get_async_db)):
    """Verify Stripe signatures, provision paid licenses idempotently, and email the key."""
    secret = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()
    signature = request.headers.get("stripe-signature", "")
    if not secret or not signature:
        raise HTTPException(status_code=503 if not secret else 400,
                            detail="Payment webhook is not configured or signature is missing.")
    raw_body = await request.body()
    try:
        parts = {}
        for item in signature.split(","):
            key, value = item.split("=", 1)
            parts.setdefault(key, []).append(value)
        timestamp = int(parts["t"][0])
        signatures = parts.get("v1", [])
    except (KeyError, ValueError, IndexError):
        raise HTTPException(status_code=400, detail="Malformed payment signature.")
    if abs(int(time.time()) - timestamp) > 300:
        raise HTTPException(status_code=400, detail="Payment signature timestamp is outside the allowed window.")
    signed_payload = str(timestamp).encode() + b"." + raw_body
    expected = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, candidate) for candidate in signatures):
        raise HTTPException(status_code=400, detail="Invalid payment signature.")
    try:
        event = json.loads(raw_body)
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Invalid payment event JSON.")
    event_id = str(event.get("id", ""))
    event_type = str(event.get("type", ""))
    if not event_id:
        raise HTTPException(status_code=400, detail="Payment event ID is missing.")
    if event_type not in {"checkout.session.completed", "checkout.session.async_payment_succeeded"}:
        return {"status": "ignored", "event_id": event_id}
    session_data = event.get("data", {}).get("object", {})
    if session_data.get("payment_status") != "paid":
        return {"status": "payment_not_complete", "event_id": event_id}

    from sqlalchemy import select
    webhook_event = (await db.execute(
        select(PaymentWebhookEvent).where(PaymentWebhookEvent.event_id == event_id)
    )).scalar_one_or_none()
    if webhook_event is None:
        payment_link_id = session_data.get("payment_link")
        plan = next((p for p in _configured_payment_plans()
                     if p["payment_link_id"] == payment_link_id), None)
        if plan is None:
            raise HTTPException(status_code=400, detail="Paid checkout does not match a configured payment link.")
        customer = session_data.get("customer_details") or {}
        recipient = str(customer.get("email") or session_data.get("customer_email") or "").strip()
        if len(recipient) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", recipient):
            raise HTTPException(status_code=400, detail="Paid checkout did not include a valid customer email.")
        license_key = secrets.token_urlsafe(32)
        license_obj = SoftwareLicense(
            license_key=license_key,
            client_name=str(customer.get("name") or recipient)[:255],
            tier=plan["tier"],
            max_monthly_audits=plan["monthly_audit_allowance"],
            is_active=True,
        )
        db.add(license_obj)
        await db.flush()
        webhook_event = PaymentWebhookEvent(
            event_id=event_id,
            status="email_pending",
            license_id=license_obj.id,
            recipient_email=recipient,
        )
        db.add(webhook_event)
        await db.commit()
    elif webhook_event.status == "delivered":
        return {"status": "already_processed", "event_id": event_id}

    # For a prior email_pending event, retry the same stored license rather than minting a new key.
    license_obj = (await db.execute(
        select(SoftwareLicense).where(SoftwareLicense.id == webhook_event.license_id)
    )).scalar_one_or_none()
    if license_obj is None:
        raise HTTPException(status_code=500, detail="The provisioned license record is unavailable.")
    try:
        await asyncio.to_thread(
            _send_license_email, webhook_event.recipient_email, license_obj.license_key,
            license_obj.tier, license_obj.max_monthly_audits,
        )
    except Exception as exc:
        logger.error("License email delivery failed (error_type=%s)", type(exc).__name__)
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
    port = int(os.getenv("SMTP_PORT", "587"))
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
    return {"status": "sent", "report_id": row.id}
