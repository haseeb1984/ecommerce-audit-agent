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
    monkeypatch.setattr(browser_audit_service.time, "time", lambda: int(timestamp) + 301)
    with pytest.raises(HTTPException) as expired:
        browser_audit_service._verify_signature(timestamp, f"sha256={signature}", body)
    assert expired.value.status_code == 401


@pytest.mark.asyncio
async def test_browser_service_rejects_mixed_public_and_private_dns_answers(monkeypatch):
    class FakeLoop:
        async def getaddrinfo(self, *args, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.20", 443)),
            ]

    monkeypatch.setattr(asyncio, "get_running_loop", lambda: FakeLoop())
    assert not await browser_audit_service._public_http_url("https://shop.example/")


def test_browser_service_restricts_top_level_navigation_to_requested_host():
    assert browser_audit_service._allowed_navigation_host("shop.example", "https://shop.example/products")
    assert browser_audit_service._allowed_navigation_host("shop.example", "https://www.shop.example/products")
    assert not browser_audit_service._allowed_navigation_host("shop.example", "https://attacker.example/")


@pytest.mark.asyncio
async def test_browser_service_rejects_non_web_ports():
    assert not await browser_audit_service._public_http_url("https://93.184.216.34:8443/")
    assert not await browser_audit_service._public_http_url("http://93.184.216.34:3306/")


def test_browser_service_redacts_query_and_fragment_from_evidence_urls():
    safe = browser_audit_service._safe_evidence_url(
        "https://user:pass@shop.example/products/item?token=secret&campaign=x#details"
    )
    assert safe == "https://shop.example/products/item"


def test_browser_service_redacts_secret_values_from_diagnostics():
    safe = browser_audit_service._safe_diagnostic_text(
        "Request failed https://shop.example/api?api_key=secret token=abc123"
    )
    assert "secret" not in safe
    assert "abc123" not in safe
    assert "api_key" not in safe


def test_browser_service_navigation_timing_outcome_is_not_assessed_without_entries():
    evidence = browser_audit_service._format_navigation_timing({}, {})
    assert "timing fields unavailable" in evidence


def test_browser_service_normalizes_only_same_site_internal_http_links():
    normalize = browser_audit_service._normalize_internal_crawl_url
    assert normalize(
        "https://shop.example/", "/products/item?token=secret#details", "shop.example"
    ) == "https://shop.example/products/item"
    assert normalize(
        "https://shop.example/", "https://www.shop.example/category/", "shop.example"
    ) == "https://www.shop.example/category/"
    assert normalize("https://shop.example/", "https://attacker.example/", "shop.example") is None
    assert normalize("https://shop.example/", "mailto:support@shop.example", "shop.example") is None
    assert normalize("https://shop.example/", "https://shop.example:8443/admin", "shop.example") is None
    assert normalize("https://shop.example/", "https://user:pass@shop.example/private", "shop.example") is None


def test_browser_internal_crawl_evidence_discloses_bounds_and_failures():
    evidence = browser_audit_service._format_internal_crawl_evidence({
        "rendered_pages": 6, "eligible_links": 12, "navigation_failures": 1,
        "page_cap_reached": True, "request_cap_reached": False,
    })
    assert "Rendered pages: 6 of a maximum 6" in evidence
    assert "eligible same-site links discovered: 12" in evidence
    assert "navigation failures: 1" in evidence
    assert "page-cap reached: True" in evidence
    assert "not a full-site crawl" in evidence


def test_rendered_metadata_evidence_discloses_presence_signals_without_claiming_validity():
    evidence = browser_audit_service._format_rendered_metadata_evidence({
        "title_length": 42, "description_count": 1, "description_length": 120,
        "canonical_count": 1, "canonical_same_origin": True, "robots_noindex": False,
        "visible_h1_count": 1, "product_schema_count": 1,
    })
    assert "Rendered title characters: 42" in evidence
    assert "canonical tags: 1" in evidence
    assert "Product/ProductGroup JSON-LD entities: 1" in evidence
    assert "not a complete SEO or structured-data validity verdict" in evidence


def test_rendered_metadata_review_is_conservative_and_detects_malformed_shapes():
    assert browser_audit_service._rendered_metadata_needs_review({
        "title_length": 20, "description_count": 1, "canonical_count": 1,
        "canonical_same_origin": True, "visible_h1_count": 1,
    }) is False
    assert browser_audit_service._rendered_metadata_needs_review({
        "title_length": 0, "description_count": 0, "canonical_count": 2,
        "canonical_same_origin": None, "visible_h1_count": 0,
    }) is True
    assert browser_audit_service._rendered_metadata_needs_review({
        "title_length": 20, "description_count": 1, "canonical_count": 1,
        "canonical_same_origin": False, "visible_h1_count": 1,
    }) is True
\n\ndef test_lab_vitals_summary_calculates_cls_session_window_and_long_tasks():
    summary = browser_audit_service._summarize_lab_vitals({
        "lcp_supported": True, "cls_supported": True, "longtask_supported": True,
        "lcp_ms": 2800,
        "_cls_entries": [
            {"start": 100, "value": 0.04},
            {"start": 500, "value": 0.03},
            {"start": 1800, "value": 0.08},
            {"start": 7000, "value": 0.02},
        ],
        "_long_tasks": [55, 80],
    })
    assert summary["cls"] == 0.15
    assert summary["long_task_count"] == 2
    assert summary["long_task_total_ms"] == 135
    assert summary["long_task_max_ms"] == 80
    assert browser_audit_service._lab_vitals_needs_review(summary) is True


def test_lab_vitals_are_not_assessed_when_browser_apis_are_unavailable():
    summary = browser_audit_service._summarize_lab_vitals({})
    assert summary["lcp_ms"] is None
    assert summary["cls"] is None
    assert summary["long_task_count"] is None
    assert browser_audit_service._format_lab_vitals_evidence(summary).startswith("Observed LCP: unavailable")
    assert browser_audit_service._lab_vitals_needs_review(summary) is False
