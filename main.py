import logging

from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.openapi.utils import get_openapi
from sqlalchemy import delete, text
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_async_db
from ecommerce_agent import UniversalEcommerceAgent, LeadDossier
from models import SoftwareLicense, AuditLead, AuditQuotaReservation
from auth import verify_license_or_api_key
from quota import reserve_audit_slot, release_audit_reservation

logging.basicConfig(level=logging.INFO)
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
    except Exception:
        logger.exception("Health check failed")
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
            except Exception:
                logger.exception("Failed to release quota reservation %s", reservation_id)
        raise
    except Exception:
        await db.rollback()
        if reservation_id is not None:
            try:
                await release_audit_reservation(db, reservation_id)
            except Exception:
                logger.exception("Failed to release quota reservation %s", reservation_id)
        logger.exception("Audit execution failed")
        raise HTTPException(
            status_code=500,
            detail="Audit execution failed. Check server logs for diagnostic details."
        )
