import os
import json
import logging

import httpx
from pydantic import BaseModel
from groq import AsyncGroq


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
        self.model = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
        self.pagespeed_key = os.getenv("GOOGLE_PAGESPEED_API_KEY", "")

    @staticmethod
    def _is_model_configuration_error(exc: Exception) -> bool:
        """Return True only for errors that plausibly mean this model cannot be used."""
        status = getattr(exc, "status_code", None)
        message = str(exc).lower()
        if status in (401, 403, 429) or status is None and isinstance(exc, (httpx.HTTPError,)):
            return False
        model_markers = (
            "model not found", "model_not_found", "model is not available",
            "model unavailable", "decommissioned", "retired model",
            "does not exist", "unsupported model", "invalid model",
        )
        json_compatibility_markers = (
            "response_format", "json_object", "json mode", "json mode is not supported",
        )
        return (
            status in (400, 404)
            and (
                any(marker in message for marker in model_markers)
                or any(marker in message for marker in json_compatibility_markers)
            )
        )

    @staticmethod
    def _is_non_chat_model(model_id: str) -> bool:
        model_id = model_id.lower()
        return any(
            marker in model_id
            for marker in (
                "whisper", "orpheus", "prompt-guard", "embedding", "embed",
                "rerank", "speech", "transcription", "tts", "safeguard",
            )
        )

    async def _compatible_model_candidates(self, current_model: str) -> list[str]:
        """Get active model IDs from Groq and order likely chat models first."""
        response = await self.groq_client.models.list()
        available = []
        for item in getattr(response, "data", []) or []:
            model_id = getattr(item, "id", None)
            active = getattr(item, "active", True)
            if (
                isinstance(model_id, str)
                and model_id != current_model
                and active is not False
                and not self._is_non_chat_model(model_id)
            ):
                available.append(model_id)

        preferred = [
            "openai/gpt-oss-120b",
            "openai/gpt-oss-20b",
            "qwen/qwen3.8-27b",
            "qwen/qwen3.6-27b",
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant",
        ]
        ordered = [model_id for model_id in preferred if model_id in available]
        ordered.extend(sorted(model_id for model_id in available if model_id not in ordered))
        return ordered

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

    async def _request_pitch(
        self,
        model: str,
        audit: StoreAuditMetrics,
        contact: ContactInfo,
    ) -> PersonalizedPitch:
        system_prompt = f"""
        You are an elite E-commerce Agency Strategist.
        1. Write a 3-sentence cold email to {contact.first_name} pointing out their mobile score ({audit.mobile_score}/100) is burning ad budget.
        2. End with a soft question offering a 90-second loom video.
        Respond STRICTLY in valid JSON with keys: "revenue_leak_hypothesis", "email_subject", "email_body".
        """
        response = await self.groq_client.chat.completions.create(
            model=model,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": f"Target: {audit.domain} | Score: {audit.mobile_score}/100 | Speed: {audit.speed_index_sec}s",
                },
            ],
        )
        content = response.choices[0].message.content
        parsed = json.loads(content)
        return PersonalizedPitch(**parsed)

    async def generate_pitch(self, audit: StoreAuditMetrics, contact: ContactInfo) -> PersonalizedPitch:
        current_model = getattr(self, "model", os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"))
        try:
            return await self._request_pitch(current_model, audit, contact)
        except Exception as exc:
            if not self._is_model_configuration_error(exc):
                raise
            logger.warning(
                "Groq model %s appears unavailable or incompatible; discovering alternatives",
                current_model,
            )

        try:
            candidates = await self._compatible_model_candidates(current_model)
        except Exception:
            logger.exception("Unable to retrieve the current Groq model list")
            raise

        last_error = None
        for candidate in candidates:
            try:
                # A real completion plus JSON/Pydantic validation verifies the model
                # supports the exact output format this backend needs.
                pitch = await self._request_pitch(candidate, audit, contact)
            except Exception as exc:
                status = getattr(exc, "status_code", None)
                if status in (401, 403, 429) or isinstance(exc, (httpx.HTTPError,)):
                    logger.warning(
                        "Stopping Groq model recovery after non-model error (HTTP %s)",
                        status,
                    )
                    raise
                last_error = exc
                logger.info("Groq candidate model %s failed compatibility check: %s", candidate, exc)
                continue

            self.model = candidate
            logger.warning(
                "Groq model recovery succeeded: switched from %s to %s",
                current_model,
                candidate,
            )
            return pitch

        if last_error:
            raise RuntimeError(
                "Groq's configured model is unavailable and no listed alternative passed "
                "the backend's JSON response validation."
            ) from last_error
        raise RuntimeError(
            "Groq's configured model is unavailable and the API returned no compatible chat models."
        )

    async def process_lead(
        self, domain: str, user_email: str, source: str = "web_audit"
    ) -> LeadDossier:
        audit_res = await self.run_audit(domain)
        contact_res = ContactInfo(email=user_email if user_email else f"contact@{audit_res.domain}")
        pitch_res = await self.generate_pitch(audit_res, contact_res)

        return LeadDossier(store_url=domain, audit=audit_res, contact=contact_res, pitch=pitch_res)
