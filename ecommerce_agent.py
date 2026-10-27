import os
import json
import logging
import math
import re
from urllib.parse import urlsplit, urlunsplit

import httpx
from pydantic import BaseModel, Field
from groq import AsyncGroq


logger = logging.getLogger(__name__)

FIELD_DATA_METRIC_CATEGORIES = {"GOOD", "NEEDS_IMPROVEMENT", "POOR"}
FIELD_DATA_OVERALL_CATEGORIES = {"FAST", "AVERAGE", "SLOW", "GOOD", "NEEDS_IMPROVEMENT", "POOR"}

def _safe_pagespeed_url(value: object) -> str | None:
    """Retain only public HTTP(S) URL identity, omitting userinfo, query and fragment."""
    try:
        parts = urlsplit(str(value or "").strip())
        scheme = parts.scheme.lower()
        host = parts.hostname
        port = parts.port
        if scheme not in {"http", "https"} or not host or parts.username is not None or parts.password is not None:
            return None
        host = host.lower()
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        default_port = 443 if scheme == "https" else 80
        netloc = f"{host}:{port}" if port and port != default_port else host
        return urlunsplit((scheme, netloc, parts.path or "/", "", ""))
    except (TypeError, ValueError, UnicodeError):
        return None


# HTTPX logs full request URLs at INFO; PageSpeed puts its API key in the query string.
# Keep HTTP request logs at WARNING+ so credentials cannot be emitted by request logging.
logging.getLogger("httpx").setLevel(logging.WARNING)


class StoreAuditMetrics(BaseModel):
    domain: str
    mobile_score: int
    speed_index_sec: float
    is_slow: bool
    # Transient PageSpeed screenshot data URI; never persisted in the lead database.
    screenshot_data_uri: str | None = None
    lcp_sec: float | None = None
    cls_score: float | None = None
    tbt_ms: float | None = None
    ttfb_ms: float | None = None
    field_metrics: dict[str, object] = Field(default_factory=dict)
    field_data_context: dict[str, object] = Field(default_factory=dict)
    lighthouse_version: str | None = None
    page_fetch_time: str | None = None
    final_url: str | None = None
    form_factor: str | None = None


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
        # Prefer the documented short name; retain the legacy name for existing deployments.
        self.pagespeed_key = os.getenv("PAGE_SPEED_API_KEY", "").strip() or os.getenv("GOOGLE_PAGESPEED_API_KEY", "").strip()

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
                # Do not log provider response bodies: they are external input and may
                # contain request details or other sensitive values.
                logger.error(
                    "PageSpeed API returned HTTP %s (target host omitted from logs)",
                    res.status_code,
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

            if (
                performance_score is None
                or speed_index_ms is None
                or isinstance(performance_score, bool)
                or isinstance(speed_index_ms, bool)
            ):
                raise RuntimeError(
                    "Google PageSpeed Lighthouse report is missing or malformed for performance score "
                    "or Speed Index."
                )

            performance_score = float(performance_score)
            speed_index_ms = float(speed_index_ms)
            if (
                not math.isfinite(performance_score)
                or not math.isfinite(speed_index_ms)
                or not 0 <= performance_score <= 1
                or speed_index_ms < 0
            ):
                raise RuntimeError(
                    "Google PageSpeed returned out-of-range performance metrics."
                )

            score = round(performance_score * 100)
            speed_index = speed_index_ms / 1000.0

            audits = lighthouse.get("audits", {}) if isinstance(lighthouse.get("audits"), dict) else {}
            def _metric_ms(audit_id: str) -> float | None:
                audit = audits.get(audit_id, {})
                value = audit.get("numericValue") if isinstance(audit, dict) else None
                try:
                    parsed = float(value)
                    return round(parsed, 2) if math.isfinite(parsed) and parsed >= 0 else None
                except (TypeError, ValueError):
                    return None

            lcp_ms = _metric_ms("largest-contentful-paint")
            cls_value = _metric_ms("cumulative-layout-shift")
            tbt_ms = _metric_ms("total-blocking-time")
            ttfb_ms = _metric_ms("server-response-time")
            field_metrics: dict[str, object] = {}
            field_data_context: dict[str, object] = {}
            metric_names = (
                "LARGEST_CONTENTFUL_PAINT_MS",
                "CUMULATIVE_LAYOUT_SHIFT_SCORE",
                "INTERACTION_TO_NEXT_PAINT",
                "FIRST_CONTENTFUL_PAINT_MS",
                "EXPERIMENTAL_TIME_TO_FIRST_BYTE",
            )
            for scope_key, scope_label in (
                ("loadingExperience", "url"),
                ("originLoadingExperience", "origin"),
            ):
                experience = data.get(scope_key, {})
                if not isinstance(experience, dict):
                    continue
                overall_category = experience.get("overall_category")
                if isinstance(overall_category, str) and overall_category.strip().upper() in FIELD_DATA_OVERALL_CATEGORIES:
                    field_data_context[f"{scope_label}_overall_category"] = overall_category.strip().upper()
                experience_id = experience.get("id")
                safe_experience_id = _safe_pagespeed_url(experience_id)
                if safe_experience_id:
                    field_data_context[f"{scope_label}_data_id"] = safe_experience_id[:300]
                metrics = experience.get("metrics", {})
                if not isinstance(metrics, dict):
                    continue
                for metric_name in metric_names:
                    metric = metrics.get(metric_name)
                    if not isinstance(metric, dict):
                        continue
                    percentile = metric.get("percentile")
                    category = metric.get("category")
                    if (
                        isinstance(percentile, (int, float))
                        and not isinstance(percentile, bool)
                        and math.isfinite(float(percentile))
                        and percentile >= 0
                    ):
                        normalized_value = percentile / 1000.0 if metric_name == "CUMULATIVE_LAYOUT_SHIFT_SCORE" else percentile
                        unit = (
                            "score" if metric_name == "CUMULATIVE_LAYOUT_SHIFT_SCORE"
                            else "ms" if metric_name.endswith("_MS") or metric_name in {
                                "INTERACTION_TO_NEXT_PAINT", "EXPERIMENTAL_TIME_TO_FIRST_BYTE"
                            }
                            else "provider unit"
                        )
                        field_metrics[f"{scope_label}:{metric_name}"] = {
                            "percentile": percentile,
                            "normalized_value": normalized_value,
                            "unit": unit,
                            "category": category.strip().upper() if isinstance(category, str) and category.strip().upper() in FIELD_DATA_METRIC_CATEGORIES else None,
                            "source": f"PageSpeed {scope_key} field data",
                        }
            lighthouse_version = lighthouse.get("lighthouseVersion")
            page_fetch_time = lighthouse.get("fetchTime")
            final_url = lighthouse.get("finalDisplayedUrl") or lighthouse.get("finalUrl")
            form_factor = lighthouse.get("configSettings", {}).get("formFactor") if isinstance(lighthouse.get("configSettings"), dict) else None

            # Lighthouse may provide a real rendered final screenshot as a data URI.
            # Treat it as optional, strictly bound its size/type, and never fail the audit
            # merely because the screenshot is absent or malformed.
            screenshot_data_uri = None
            try:
                import base64
                import re

                screenshot = (
                    lighthouse.get("audits", {})
                    .get("final-screenshot", {})
                    .get("details", {})
                    .get("data")
                )
                if isinstance(screenshot, str) and len(screenshot) <= 1_400_000:
                    match = re.fullmatch(
                        r"data:(image/png|image/jpeg);base64,([A-Za-z0-9+/]*={0,2})",
                        screenshot,
                    )
                    if match:
                        image_bytes = base64.b64decode(match.group(2), validate=True)
                        valid_png = match.group(1) == "image/png" and image_bytes.startswith(bytes.fromhex("89504e470d0a1a0a"))
                        valid_jpeg = match.group(1) == "image/jpeg" and image_bytes.startswith(bytes.fromhex("ffd8ff"))
                        if image_bytes and len(image_bytes) <= 1_000_000 and (valid_png or valid_jpeg):
                            screenshot_data_uri = screenshot
            except (ValueError, TypeError, AttributeError):
                logger.info("PageSpeed screenshot was absent or invalid")

            return StoreAuditMetrics(
                domain=clean_domain,
                mobile_score=score,
                speed_index_sec=round(speed_index, 2),
                is_slow=score < 60,
                screenshot_data_uri=screenshot_data_uri,
                lcp_sec=round(lcp_ms / 1000.0, 2) if lcp_ms is not None else None,
                cls_score=cls_value,
                tbt_ms=tbt_ms,
                ttfb_ms=ttfb_ms,
                field_metrics=field_metrics,
                field_data_context=field_data_context,
                lighthouse_version=lighthouse_version if isinstance(lighthouse_version, str) else None,
                page_fetch_time=page_fetch_time if isinstance(page_fetch_time, str) else None,
                final_url=_safe_pagespeed_url(final_url),
                form_factor=form_factor if isinstance(form_factor, str) else None,
            )
        except RuntimeError:
            raise
        except (httpx.HTTPError, ValueError, TypeError, AttributeError) as exc:
            logger.error("PageSpeed audit failed (error_type=%s)", type(exc).__name__)
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
        except Exception as exc:
            # SDK exception text/tracebacks can contain request metadata. Log only
            # the exception class; never provider bodies, headers, or full URLs.
            logger.error("Unable to retrieve current Groq model list (error_type=%s)", type(exc).__name__)
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
                logger.info(
                    "Groq candidate model failed compatibility check (model=%s, error_type=%s)",
                    candidate,
                    type(exc).__name__,
                )
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
