import os
import json
import logging

import httpx
from pydantic import BaseModel
from groq import AsyncGroq
from models import AuditLead


logger = logging.getLogger(__name__)


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
            async with httpx.AsyncClient(timeout=30.0) as client:
                res = await client.get(endpoint, params=params)

            if res.is_error:
                try:
                    error_data = res.json().get("error", {})
                    error_message = error_data.get("message", "No error message provided")
                except (ValueError, AttributeError):
                    error_message = "Google returned a non-JSON error response"

                logger.error(
                    "PageSpeed API returned HTTP %s for %s: %s",
                    res.status_code,
                    clean_domain,
                    error_message,
                )
                raise RuntimeError(
                    f"Google PageSpeed API returned HTTP {res.status_code}. "
                    "Check the API key, API restrictions, and Google Cloud configuration."
                )

            data = res.json()
            lighthouse = data.get("lighthouseResult")
            if not isinstance(lighthouse, dict):
                raise RuntimeError(
                    "Google PageSpeed API response did not contain a Lighthouse report."
                )

            performance_score = (
                lighthouse.get("categories", {})
                .get("performance", {})
                .get("score")
            )
            speed_index_ms = (
                lighthouse.get("audits", {})
                .get("speed-index", {})
                .get("numericValue")
            )

            if performance_score is None or speed_index_ms is None:
                raise RuntimeError(
                    "Google PageSpeed Lighthouse report is missing performance score "
                    "or Speed Index."
                )

            performance_score = float(performance_score)
            speed_index_ms = float(speed_index_ms)
            if not 0 <= performance_score <= 1 or speed_index_ms < 0:
                raise RuntimeError(
                    "Google PageSpeed returned out-of-range performance metrics."
                )

            score = round(performance_score * 100)
            speed_index = speed_index_ms / 1000.0
            return StoreAuditMetrics(
                domain=clean_domain,
                mobile_score=score,
                speed_index_sec=round(speed_index, 2),
                is_slow=score < 60,
            )
        except RuntimeError:
            raise
        except (httpx.HTTPError, ValueError, TypeError, AttributeError) as exc:
            logger.exception("PageSpeed audit failed for %s", clean_domain)
            raise RuntimeError(
                "Google PageSpeed audit failed. Check server logs for diagnostic details."
            ) from exc

    async def generate_pitch(self, audit: StoreAuditMetrics, contact: ContactInfo) -> PersonalizedPitch:
        system_prompt = f"""
        You are an elite E-commerce Agency Strategist.
        1. Write a 3-sentence cold email to {contact.first_name} pointing out their mobile score ({audit.mobile_score}/100) is burning ad budget.
        2. End with a soft question offering a 90-second loom video.
        Respond STRICTLY in valid JSON with keys: "revenue_leak_hypothesis", "email_subject", "email_body".
        """
        response = await self.groq_client.chat.completions.create(
            model="openai/gpt-oss-120b",
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

    async def process_lead(
        self, domain: str, user_email: str, source: str = "web_audit"
    ) -> LeadDossier:
        audit_res = await self.run_audit(domain)
        contact_res = ContactInfo(email=user_email if user_email else f"contact@{audit_res.domain}")
        pitch_res = await self.generate_pitch(audit_res, contact_res)

        return LeadDossier(store_url=domain, audit=audit_res, contact=contact_res, pitch=pitch_res)
