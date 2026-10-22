import logging
import json
from pathlib import Path
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

from fastapi import FastAPI, Depends, HTTPException, Query, Response
from fastapi.openapi.utils import get_openapi
from fastapi.responses import FileResponse
from sqlalchemy import delete, text
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_async_db
from ecommerce_agent import UniversalEcommerceAgent, LeadDossier
from models import SoftwareLicense, AuditLead, AuditQuotaReservation, AuditReport
from auth import verify_license_or_api_key
from quota import reserve_audit_slot, release_audit_reservation
from audit_checks import AuditFinding, normalize_target, run_phase_one_checks
from report_generator import render_audit_pdf
from crawl_checks import run_bounded_site_crawl
from conversion_checks import run_conversion_paid_traffic_checks

logger = logging.getLogger("audit_service")

app = FastAPI(
    title="AI E-Commerce Audit Engine - Commercial Edition",
    description="Multi-model API serving SaaS, Managed Services, White-Label, and Enterprise integrations.",
    swagger_ui_parameters={"persistAuthorization": True}
)

agent = UniversalEcommerceAgent()


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

        # Persist the exact PDF and an evidence manifest under the owning license.
        # Finding counts are observations, not a denominator for all possible checks.
        status_counts = {}
        category_counts = {}
        for finding in result.findings:
            status_counts[finding.status] = status_counts.get(finding.status, 0) + 1
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
        coverage_manifest = {
            "schema_version": 1,
            "coverage_semantics": "observed_findings_not_all_possible_checks",
            "target_url": target_url,
            "pages_checked": result.pages_checked,
            "pages_checked_count": len(result.pages_checked),
            "findings_total": len(result.findings),
            "finding_status_counts": status_counts,
            "finding_category_counts": category_counts,
            "limitations": list(dict.fromkeys(result.limitations)),
            "not_a_claim_of_complete_wcag_security_indexing_or_conversion_coverage": True,
        }
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
