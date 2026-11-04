from __future__ import annotations

import asyncio
import hashlib
import hmac
import socket

import pytest
from fastapi import HTTPException

import browser_audit_service


@pytest.mark.asyncio
async def test_browser_service_rejects_local_and_private_addresses():
    assert not await browser_audit_service._public_http_url("http://127.0.0.1/")
    assert not await browser_audit_service._public_http_url("http://[::1]/")
    assert not await browser_audit_service._public_http_url("https://localhost/")
    assert not await browser_audit_service._public_http_url("file:///etc/passwd")


@pytest.mark.asyncio
async def test_browser_service_rejects_hostname_with_private_dns_answer(monkeypatch):
    class FakeLoop:
        async def getaddrinfo(self, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", 443))]

    monkeypatch.setattr(asyncio, "get_running_loop", lambda: FakeLoop())
    assert not await browser_audit_service._public_http_url("https://shop.example/")


@pytest.mark.asyncio
async def test_browser_service_accepts_hostname_with_only_public_dns_answers(monkeypatch):
    class FakeLoop:
        async def getaddrinfo(self, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr(asyncio, "get_running_loop", lambda: FakeLoop())
    assert await browser_audit_service._public_http_url("https://shop.example/")


def test_browser_service_authentication_is_time_limited_and_signed(monkeypatch):
    secret = "x" * 40
    monkeypatch.setenv("BROWSER_AUDIT_SHARED_SECRET", secret)
    timestamp = "1793832000"
    body = b'{"target_url":"https://shop.example/","request_id":"12345678"}'
    signature = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    # The timestamp must be within five minutes of the test clock.
    monkeypatch.setattr(browser_audit_service.time, "time", lambda: int(timestamp))
    browser_audit_service._verify_signature(timestamp, f"sha256={signature}", body)
    with pytest.raises(HTTPException) as error:
        browser_audit_service._verify_signature(timestamp, "sha256=bad", body)
    assert error.value.status_code == 401
