"""Authenticated client for the separately deployed Playwright audit service."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from urllib.parse import urlsplit, urlunsplit

import httpx


class BrowserAuditUnavailable(RuntimeError):
    pass


def _browser_service_base_url(value: str) -> str:
    """Accept only an HTTPS origin; endpoint paths and URL modifiers are not configuration."""
    candidate = value.strip()
    if not candidate:
        raise BrowserAuditUnavailable("Isolated browser service is not configured")
    try:
        parsed = urlsplit(candidate)
        valid = (
            parsed.scheme == "https"
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and parsed.path in ("", "/")
            and not parsed.query
            and not parsed.fragment
            and (parsed.port is None or 1 <= parsed.port <= 65535)
            and not any(character.isspace() for character in parsed.netloc)
            and "\\" not in parsed.netloc
        )
    except ValueError:
        valid = False
    if not valid:
        raise BrowserAuditUnavailable(
            "Browser service URL must be an HTTPS origin without credentials, path, query, or fragment"
        )
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


async def run_browser_audit(target_url: str, *, timeout_seconds: float = 70.0) -> dict:
    configured_url = os.getenv("BROWSER_AUDIT_SERVICE_URL", "")
    secret = os.getenv("BROWSER_AUDIT_SHARED_SECRET", "")
    if len(secret) < 32:
        raise BrowserAuditUnavailable("Isolated browser service is not configured")
    service_url = _browser_service_base_url(configured_url)
    payload = {"target_url": target_url, "request_id": uuid.uuid4().hex}
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    timestamp = str(int(time.time()))
    signature = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout_seconds, connect=5.0), follow_redirects=False) as client:
            response = await client.post(
                f"{service_url}/v1/audit", content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Audit-Timestamp": timestamp,
                    "X-Audit-Signature": f"sha256={signature}",
                },
            )
        if response.status_code in (401, 403, 422):
            raise BrowserAuditUnavailable(f"Browser service rejected the audit request (HTTP {response.status_code})")
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise BrowserAuditUnavailable("Browser service returned an invalid audit result")
        if data.get("request_id") != payload["request_id"]:
            raise BrowserAuditUnavailable("Browser service response did not match the request")
        if not isinstance(data.get("findings"), list) or not isinstance(data.get("check_outcomes"), list):
            raise BrowserAuditUnavailable("Browser service returned an invalid audit result")
        if "summary" in data and not isinstance(data["summary"], dict):
            raise BrowserAuditUnavailable("Browser service returned an invalid audit result")
        return data
    except BrowserAuditUnavailable:
        raise
    except (httpx.HTTPError, ValueError, TypeError):
        raise BrowserAuditUnavailable("Isolated browser audit service request failed") from None
