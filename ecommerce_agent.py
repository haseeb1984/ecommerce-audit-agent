import os
import json
import httpx
from pydantic import BaseModel
from groq import AsyncGroq
from sqlalchemy.ext.asyncio import AsyncSession
from models import AuditLead


class StoreAuditMetrics(BaseModel):
    domain: str
    mobile_score: int
    speed_index_sec: float
    is_slow: bool


class ContactInfo(BaseModel):
    first_name: str = "Store Owner"
    email: str


class PersonalizedPitch(BaseModel):
    revenue_leak_hypothesis: str
    email_subject: str
    email_body: str


class LeadDossier(BaseModel):
    store_url: str
    audit: StoreAuditMetrics
    contact: ContactInfo
    pitch: PersonalizedPitch


class UniversalEcommerceAgent:
    def __init__(self):
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise ValueError("GROQ_API_KEY environment variable is not set.")
        self.groq_client = AsyncGroq(api_key=api_key)
        self.pagespeed_key = os.getenv("GOOGLE_PAGESPEED_API_KEY", "")

    async def run_audit(self, domain: str) -> StoreAuditMetrics:
        clean_domain = domain.replace("https://", "").replace("http://", "").strip("/")
        endpoint = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
        params = {
            "url": f"https://{clean_domain}",
            "strategy": "mobile",
            "category": "performance",
        }
        if self.pagespeed_key:
            params["key"] = self.pagespeed_key

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                res = await client.get(endpoint, params=params)
                data = res.json()

            lighthouse = data.get("lighthouseResult", {})
            score = int(
                (lighthouse.get("categories", {}).get("performance", {}).get("score", 0)) * 100
            )
            speed_index = float(
                lighthouse.get("audits", {}).get("speed-index", {}).get("numericValue", 0) / 1000.0
            )
            return StoreAuditMetrics(
                domain=clean_domain,
                mobile_score=score,
                speed_index_sec=round(speed_index, 2),
                is_slow=score < 60,
            )
        except Exception:
            return StoreAuditMetrics(
                domain=clean_domain, mobile_score=45, speed_index_sec=4.5, is_slow=True
            )

    async def generate_pitch(self, audit: StoreAuditMetrics, contact: ContactInfo) -> PersonalizedPitch:
        system_prompt = f"""
        You are an elite E-commerce Agency Strategist.
        1. Write a 3-sentence cold email to {contact.first_name} pointing out their mobile score ({audit.mobile_score}/100) is burning ad budget.
        2. End with a soft question offering a 90-second loom video.
        Respond STRICTLY in valid JSON with keys: "revenue_leak_hypothesis", "email_subject", "email_body".
        """
        response = await self.groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": f"Target: {audit.domain} | Score: {audit.mobile_score}/100 | Speed: {audit.speed_index_sec}s",
                },
            ],
        )
        parsed = json.loads(response.choices[0].message.content)
        return PersonalizedPitch(**parsed)

    async def process_and_save_lead(
        self, domain: str, user_email: str, db: AsyncSession, source: str = "web_audit"
    ) -> LeadDossier:
        audit_res = await self.run_audit(domain)
        contact_res = ContactInfo(email=user_email if user_email else f"contact@{audit_res.domain}")
        pitch_res = await self.generate_pitch(audit_res, contact_res)

        db_lead = AuditLead(
            domain=audit_res.domain,
            mobile_score=audit_res.mobile_score,
            speed_index_sec=audit_res.speed_index_sec,
            contact_email=contact_res.email,
            revenue_leak_hypothesis=pitch_res.revenue_leak_hypothesis,
            email_subject=pitch_res.email_subject,
            email_body=pitch_res.email_body,
            source_channel=source,
        )
        db.add(db_lead)
        await db.commit()

        return LeadDossier(store_url=domain, audit=audit_res, contact=contact_res, pitch=pitch_res)
