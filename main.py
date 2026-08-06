from fastapi import FastAPI, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from contextlib import asynccontextmanager

from database import engine, Base, get_async_db
from ecommerce_agent import UniversalEcommerceAgent, LeadDossier

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Automatically create missing database tables on startup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield

app = FastAPI(title="AI E-Commerce Audit Engine", lifespan=lifespan)
agent = UniversalEcommerceAgent()

@app.get("/")
def read_root():
    return {"status": "Free Groq AI Agent is online and operational."}

@app.get("/health-check")
async def health_check(db: AsyncSession = Depends(get_async_db)):
    try:
        result = await db.execute(text("SELECT 1"))
        return {
            "status": "success",
            "db_connected": True,
            "result": result.scalar()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database connection error: {str(e)}")

@app.post("/audit-lead", response_model=LeadDossier)
async def audit_lead(
    domain: str = Query(..., description="E-commerce store URL/domain"),
    email: str = Query("", description="User email for audit copy"),
    source: str = Query("web_audit", description="Traffic source tag"),
    db: AsyncSession = Depends(get_async_db)
):
    try:
        dossier = await agent.process_and_save_lead(domain=domain, user_email=email, db=db, source=source)
        return dossier
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
