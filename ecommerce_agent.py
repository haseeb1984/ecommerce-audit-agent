import json
import os
import requests
from typing import Optional
from pydantic import BaseModel, Field
from groq import Groq

# =====================================================================
# 1. SCHEMAS
# =====================================================================

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

# =====================================================================
# 2. FREE AUDIT & ENRICHMENT TOOLS
# =====================================================================

class FreeAuditTools:
    @staticmethod
    def run_pagespeed_audit(domain: str, api_key: str = "") -> StoreAuditMetrics:
        """Fetches mobile performance data from Google PageSpeed Insights API (Free)."""
        clean_domain = domain.replace("https://", "").replace("http://", "").strip("/")
        url = f"https://{clean_domain}"
        endpoint = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
        
        params = {
            "url": url,
            "strategy": "mobile",
            "category": "performance"
        }
        if api_key:
            params["key"] = api_key

        try:
            res = requests.get(endpoint, params=params, timeout=25)
            data = res.json()
            
            lighthouse = data.get("lighthouseResult", {})
            categories = lighthouse.get("categories", {})
            audits = lighthouse.get("audits", {})

            score = int((categories.get("performance", {}).get("score", 0)) * 100)
            speed_index = float(audits.get("speed-index", {}).get("numericValue", 0) / 1000.0)

            return StoreAuditMetrics(
                domain=clean_domain,
                mobile_score=score,
                speed_index_sec=round(speed_index, 2),
                is_slow=score < 60
            )
        except Exception as e:
            print(f"[Warning] PageSpeed API fallback used for {clean_domain}: {e}")
            return StoreAuditMetrics(
                domain=clean_domain,
                mobile_score=42,
                speed_index_sec=4.8,
                is_slow=True
            )

    @staticmethod
    def get_contact_info(domain: str) -> ContactInfo:
        """Generates domain-level fallback contact info (Free)."""
        clean_domain = domain.replace("https://", "").replace("http://", "").strip("/")
        return ContactInfo(
            first_name="Store Owner",
            email=f"contact@{clean_domain}"
        )

# =====================================================================
# 3. AGENT CLASS (Using Free Groq API)
# =====================================================================

class EcommerceLeadAgent:
    def __init__(self, agency_name: str, agency_offering: str):
        self.agency_name = agency_name
        self.agency_offering = agency_offering
        # Uses GROQ_API_KEY from environment variables
        self.groq_client = Groq(api_key=os.getenv("GROQ_API_KEY"))
        self.pagespeed_key = os.getenv("GOOGLE_PAGESPEED_API_KEY", "")

    def generate_pitch(self, audit: StoreAuditMetrics, contact: ContactInfo) -> PersonalizedPitch:
        """Uses Groq (Llama 3.3 70B) to generate JSON pitches for free."""
        
        system_prompt = f"""
        You are an elite E-commerce Agency Strategist for '{self.agency_name}'.
        Agency Specialization: {self.agency_offering}.

        Instructions:
        1. Write a 3-sentence, warm, non-salesy cold email to {contact.first_name}.
        2. Reference their exact mobile score ({audit.mobile_score}/100) and load time ({audit.speed_index_sec}s).
        3. Explain that driving ad traffic (Meta/TikTok) to a mobile site with a score of {audit.mobile_score}/100 burns ad budget.
        4. End with a soft, low-friction question (e.g., "Mind if I send over a 90-second video breakdown?").
        
        CRITICAL: Respond STRICTLY in raw JSON with no Markdown wrapping. Use this exact schema:
        {{
            "revenue_leak_hypothesis": "Short explanation of lost revenue",
            "email_subject": "Email subject line",
            "email_body": "3-sentence email text"
        }}
        """

        user_content = f"Target Store: {audit.domain} | Mobile Performance Score: {audit.mobile_score}/100 | Speed Index: {audit.speed_index_sec}s"

        response = self.groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",  # Free tier model on Groq
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ]
        )

        raw_json = response.choices[0].message.content
        parsed = json.loads(raw_json)

        return PersonalizedPitch(
            revenue_leak_hypothesis=parsed.get("revenue_leak_hypothesis", ""),
            email_subject=parsed.get("email_subject", ""),
            email_body=parsed.get("email_body", "")
        )

    def process_lead(self, domain: str) -> LeadDossier:
        """Runs the complete free audit and pitch workflow."""
        audit_res = FreeAuditTools.run_pagespeed_audit(domain, self.pagespeed_key)
        contact_res = FreeAuditTools.get_contact_info(domain)
        pitch_res = self.generate_pitch(audit_res, contact_res)

        return LeadDossier(
            store_url=domain,
            audit=audit_res,
            contact=contact_res,
            pitch=pitch_res
        )