import os
import json
import logging
import math
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

import httpx
from pydantic import BaseModel, Field
from groq import AsyncGroq


logger = logging.getLogger(__name__)

FIELD_DATA_METRIC_CATEGORIES = {"GOOD", "NEEDS_IMPROVEMENT", "POOR"}
FIELD_DATA_OVERALL_CATEGORIES = {"FAST", "AVERAGE", "SLOW", "GOOD", "NEEDS_IMPROVEMENT", "POOR"}

def _normalize_audit_target(value: object) -> str:
    """Normalize a public HTTP(S) audit target and reject unsafe or ambiguous hosts."""
    raw = str(value or "").strip()
    if not raw or len(raw) > 2048 or any(ord(char) < 32 for char in raw):
        raise ValueError("Enter a valid public website URL or domain.")
    candidate = raw if "://" in raw else "https://" + raw
    try:
        parts = urlsplit(candidate)
        scheme = parts.scheme.lower()
        host = parts.hostname
        port = parts.port
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("Enter a valid public website URL or domain.") from exc
    if scheme not in {"http", "https"} or not host or parts.username is not None or parts.password is not None:
        raise ValueError("Only public HTTP(S) website URLs without embedded credentials are supported.")
    # Audit providers receive a canonical public page URL, never a query string
    # or fragment that could contain session tokens, search terms, or other user data.
    # Dropping these components is safer than logging or forwarding them to providers.
    if port is not None and port not in {80, 443}:
        raise ValueError("Custom ports are not supported for public website audits.")
    host = host.rstrip(".").lower()
    if not host or host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".lan")):
        raise ValueError("Private and local network targets cannot be audited.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise ValueError("Private, reserved, and local IP addresses cannot be audited.")
    if address is None:
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Enter a valid public website hostname.") from exc
        labels = ascii_host.split(".")
        if len(labels) < 2 or any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
            or not re.fullmatch(r"[a-z0-9-]+", label)
            for label in labels
        ):
            raise ValueError("Enter a valid public website hostname.")
        host = ascii_host
    path = parts.path or "/"
    if not path.startswith("/") or "\\" in path:
        raise ValueError("Enter a valid public website URL path.")
    # PageSpeed should receive a clean URL; credentials, query strings, and fragments never pass through.
    return urlunsplit(("https", host if address is None else f"[{host}]" if ":" in host else host, path, "", ""))


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


_UNSUPPORTED_PITCH_BUSINESS_TERMS = re.compile(
    r"\b(?:revenue|sales|conversion(?:s|\s+rate)?|ad\s+spend|ad\s+budget|profit|roi)\b",
    re.IGNORECASE,
)
_UNSUPPORTED_PITCH_QUANTIFICATION = re.compile(
    r"(?:[$£€]\s*\d|\b\d+(?:\.\d+)?\s*(?:%|percent|x|times)\b)",
    re.IGNORECASE,
)
_UNSUPPORTED_PITCH_CAUSALITY = re.compile(
    r"\b(?:burn(?:ing|s)?|wast(?:e|es|ing)|cost(?:s|ing)?|los(?:e|es|ing|t)|reduc(?:e|es|ing)|"
    r"lower(?:s|ing)?|hurt(?:s|ing)?|damage(?:s|d)?|increase(?:s|d|ing)?|boost(?:s|ed|ing)?|"
    r"improv(?:e|es|ed|ing)|rais(?:e|es|ed|ing)|drive(?:s|n|ing)?)\b"
    r"(?:\s+\w+){0,4}\s+\b(?:revenue|sales|conversion(?:s|\s+rate)?|ad\s+spend|ad\s+budget|profit)\b",
    re.IGNORECASE,
)


def _evidence_based_business_impact_hypothesis(audit: StoreAuditMetrics) -> str:
    return (
        f"PageSpeed recorded a mobile Lighthouse performance score of {audit.mobile_score}/100 "
        f"and a Speed Index of {audit.speed_index_sec:.2f} seconds. These are lab measurements only; "
        "ad spend, conversion rate, and revenue were not measured, so business impact is unknown."
    )


def _safe_pitch_fallback(audit: StoreAuditMetrics) -> tuple[str, str]:
    subject = f"Performance observations for {audit.domain}"
    body = (
        f"I reviewed the mobile PageSpeed run for {audit.domain}, which recorded a lab performance "
        f"score of {audit.mobile_score}/100 and a Speed Index of {audit.speed_index_sec:.2f} seconds. "
        "These measurements describe the tested page load and do not establish a business outcome. "
        "Would you be open to a 90-second Loom walking through the observed performance signals?"
    )
    return subject, body


def _pitch_copy_needs_grounded_fallback(value: str) -> bool:
    return bool(
        _UNSUPPORTED_PITCH_BUSINESS_TERMS.search(value)
        or _UNSUPPORTED_PITCH_QUANTIFICATION.search(value)
        or _UNSUPPORTED_PITCH_CAUSALITY.search(value)
    )


class UniversalEcommerceAgent:
    @staticmethod
    def _normalize_audit_target(value: object) -> str:
        """Expose the shared public-target validator for callers and regression tests."""
        return _normalize_audit_target(value)

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
        target_url = _normalize_audit_target(domain)
        endpoint = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
        params = {
            "url": target_url,
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

            clean_domain = urlsplit(target_url).hostname or target_url
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
        You are an evidence-first ecommerce performance communications assistant.
        Write a concise, three-sentence outreach email to {contact.first_name} about the supplied PageSpeed observations.
        You may state only the supplied mobile Lighthouse performance score ({audit.mobile_score}/100) and Speed Index ({audit.speed_index_sec:.2f} seconds).
        These are lab measurements for a tested page. They do not establish ad-spend waste, revenue loss, sales impact, or conversion impact.
        Do not mention revenue, sales, conversions, ad budgets, ROI, or financial outcomes. Do not invent percentages, currency amounts, uplift estimates, causes, or guarantees.
        The separate revenue_leak_hypothesis field must explicitly say business impact was not measured and must not claim a revenue leak.
        End the email with a soft question offering a 90-second Loom video.
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
        pitch = PersonalizedPitch(**parsed)
        # This statement is deterministic: PageSpeed does not measure financial
        # outcomes, so model output cannot turn lab metrics into a revenue claim.
        pitch.revenue_leak_hypothesis = _evidence_based_business_impact_hypothesis(audit)
        if (
            _pitch_copy_needs_grounded_fallback(pitch.email_subject)
            or _pitch_copy_needs_grounded_fallback(pitch.email_body)
        ):
            pitch.email_subject, pitch.email_body = _safe_pitch_fallback(audit)
        return pitch

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
