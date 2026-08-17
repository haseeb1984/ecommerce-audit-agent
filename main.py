import logging
from fastapi import FastAPI, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from database import get_async_db
from ecommerce_agent import UniversalEcommerceAgent, LeadDossier
from models import SoftwareLicense, AuditLead
from auth import verify_license_or_api_key

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("audit_service")

app = FastAPI(
    title="AI E-Commerce Audit Engine - Commercial Edition",
    description="Multi-model API serving SaaS, Managed Services, White-Label, and Enterprise integrations."
)
agent = UniversalEcommerceAgent()

@app.get("/")
def read_root():
    return {"status": "AI Agent Commercial Engine Operational"}

@app.get("/health-check")
async def health_check(db: AsyncSession = Depends(get_async_db)):
    try:
        result = await db.execute(text("SELECT 1"))
        return {"status": "success", "db_connected": True, "result": result.scalar()}
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database connection error: {str(e)}")

# Authorized Endpoint supporting SaaS / Managed Service / Enterprise
@app.post("/api/v1/audit-lead", response_model=LeadDossier)
async def audit_lead(
    domain: str = Query(..., description="E-commerce store URL/domain"),
    email: str = Query("", description="User email for audit copy"),
    source: str = Query("web_audit", description="Traffic source tag"),
    license_obj: SoftwareLicense = Depends(verify_license_or_api_key),
    db: AsyncSession = Depends(get_async_db)
):
    try:
        # Run Audit & Generate Pitch
        dossier = await agent.process_and_save_lead(domain=domain, user_email=email, db=db, source=source)
        
        # Attach License Context for Billing / Tracking
        db_lead = AuditLead(
            license_id=license_obj.id,
            domain=dossier.audit.domain,
            mobile_score=dossier.audit.mobile_score,
            speed_index_sec=dossier.audit.speed_index_sec,
            contact_email=dossier.contact.email,
            revenue_leak_hypothesis=dossier.pitch.revenue_leak_hypothesis,
            email_subject=dossier.pitch.email_subject,
            email_body=dossier.pitch.email_body,
            source_channel=source
        )
        db.add(db_lead)
        await db.commit()

        return dossier
    except Exception as e:
        logger.error(f"Audit execution error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
