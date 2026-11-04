from __future__ import annotations

import hashlib
import hmac
import json
from types import SimpleNamespace

import pytest

import browser_audit_client


@pytest.mark.asyncio
async def test_browser_client_signs_request_and_accepts_matching_response(monkeypatch):
    monkeypatch.setenv("BROWSER_AUDIT_SERVICE_URL", "https://browser.internal.example")
    monkeypatch.setenv("BROWSER_AUDIT_SHARED_SECRET", "s" * 40)
    captured = {}

    class FakeResponse:
        status_code = 200
        def raise_for_status(self):
            return None
        def json(self):
            return {
                "request_id": captured["payload"]["request_id"],
                "findings": [],
                "check_outcomes": [],
                "summary": {},
            }

    class FakeClient:
        def __init__(self, *args, **kwargs):
            captured["timeout"] = kwargs["timeout"]
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None
        async def post(self, url, *, content, headers):
            captured["url"] = url
            captured["body"] = content
            captured["headers"] = headers
            captured["payload"] = json.loads(content)
            expected = hmac.new(
                ("s" * 40).encode(),
                headers["X-Audit-Timestamp"].encode() + b"." + content,
                hashlib.sha256,
            ).hexdigest()
            assert headers["X-Audit-Signature"] == f"sha256={expected}"
            return FakeResponse()

    monkeypatch.setattr(browser_audit_client.httpx, "AsyncClient", FakeClient)
    result = await browser_audit_client.run_browser_audit("https://shop.example/")
    assert result["check_outcomes"] == []
    assert captured["url"] == "https://browser.internal.example/v1/audit"
    assert captured["payload"]["target_url"] == "https://shop.example/"


@pytest.mark.asyncio
async def test_browser_client_fails_closed_when_not_configured(monkeypatch):
    monkeypatch.delenv("BROWSER_AUDIT_SERVICE_URL", raising=False)
    monkeypatch.delenv("BROWSER_AUDIT_SHARED_SECRET", raising=False)
    with pytest.raises(browser_audit_client.BrowserAuditUnavailable):
        await browser_audit_client.run_browser_audit("https://shop.example/")


@pytest.mark.asyncio
async def test_browser_client_rejects_non_https_service_url(monkeypatch):
    monkeypatch.setenv("BROWSER_AUDIT_SERVICE_URL", "http://browser.internal.example")
    monkeypatch.setenv("BROWSER_AUDIT_SHARED_SECRET", "s" * 40)
    with pytest.raises(browser_audit_client.BrowserAuditUnavailable):
        await browser_audit_client.run_browser_audit("https://shop.example/")


@pytest.mark.asyncio
async def test_browser_client_rejects_mismatched_response(monkeypatch):
    monkeypatch.setenv("BROWSER_AUDIT_SERVICE_URL", "https://browser.internal.example")
    monkeypatch.setenv("BROWSER_AUDIT_SHARED_SECRET", "s" * 40)

    class FakeResponse:
        status_code = 200
        def raise_for_status(self):
            return None
        def json(self):
            return {"request_id": "wrong", "findings": [], "check_outcomes": []}

    class FakeClient:
        def __init__(self, *args, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        async def post(self, *args, **kwargs): return FakeResponse()

    monkeypatch.setattr(browser_audit_client.httpx, "AsyncClient", FakeClient)
    with pytest.raises(browser_audit_client.BrowserAuditUnavailable):
        await browser_audit_client.run_browser_audit("https://shop.example/")
