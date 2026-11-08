from __future__ import annotations

import hashlib
import hmac
import json

import pytest

import browser_audit_client


@pytest.mark.asyncio
async def test_browser_client_signs_request_and_accepts_matching_response(monkeypatch):
    monkeypatch.setenv("BROWSER_AUDIT_SERVICE_URL", "https://browser.internal.example/")
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
            assert kwargs["follow_redirects"] is False
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
@pytest.mark.parametrize(
    "service_url",
    [
        "http://browser.internal.example",
        "https://user:password@browser.internal.example",
        "https://browser.internal.example/v1/audit",
        "https://browser.internal.example/?route=/v1/audit",
        "https://browser.internal.example/#fragment",
        "https://browser.internal.example?",
        "https://browser.internal.example#",
        "https://browser.internal.example:",
        "https://browser.internal.example:99999",
        "https://browser.internal.example:bad",
        "https://browser.internal.example\\\\path",
        "https://browser.internal.example with-space",
    ],
)
async def test_browser_client_rejects_non_origin_service_urls(monkeypatch, service_url):
    monkeypatch.setenv("BROWSER_AUDIT_SERVICE_URL", service_url)
    monkeypatch.setenv("BROWSER_AUDIT_SHARED_SECRET", "s" * 40)
    with pytest.raises(browser_audit_client.BrowserAuditUnavailable):
        await browser_audit_client.run_browser_audit("https://shop.example/")


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [[], "invalid", 7, None])
async def test_browser_client_rejects_non_object_json_response(monkeypatch, payload):
    monkeypatch.setenv("BROWSER_AUDIT_SERVICE_URL", "https://browser.internal.example")
    monkeypatch.setenv("BROWSER_AUDIT_SHARED_SECRET", "s" * 40)

    class FakeResponse:
        status_code = 200
        def raise_for_status(self):
            return None
        def json(self):
            return payload

    class FakeClient:
        def __init__(self, *args, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        async def post(self, *args, **kwargs): return FakeResponse()

    monkeypatch.setattr(browser_audit_client.httpx, "AsyncClient", FakeClient)
    with pytest.raises(browser_audit_client.BrowserAuditUnavailable):
        await browser_audit_client.run_browser_audit("https://shop.example/")


@pytest.mark.asyncio
async def test_browser_client_rejects_malformed_result_shape(monkeypatch):
    monkeypatch.setenv("BROWSER_AUDIT_SERVICE_URL", "https://browser.internal.example")
    monkeypatch.setenv("BROWSER_AUDIT_SHARED_SECRET", "s" * 40)

    class FakeResponse:
        status_code = 200
        def raise_for_status(self):
            return None
        def json(self):
            return {
                "request_id": captured["request_id"],
                "findings": {},
                "check_outcomes": [],
            }

    class FakeClient:
        def __init__(self, *args, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        async def post(self, url, *, content, headers):
            captured["request_id"] = json.loads(content)["request_id"]
            return FakeResponse()

    captured = {}
    monkeypatch.setattr(browser_audit_client.httpx, "AsyncClient", FakeClient)
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
