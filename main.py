import os
from fastapi import FastAPI, HTTPException
from ecommerce_agent import EcommerceLeadAgent, LeadDossier

app = FastAPI(title="Free E-Commerce Audit Agent API")

agent = EcommerceLeadAgent(
    agency_name="Apex Commerce Labs",
    agency_offering="Mobile Speed & Conversion Rate Optimization (CRO) for Shopify Stores"
)

@app.get("/")
def home():
    return {"status": "Free Groq AI Agent is online and operational."}

@app.post("/audit-lead", response_model=LeadDossier)
def audit_lead(domain: str):
    try:
        dossier = agent.process_lead(domain)
        return dossier
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))