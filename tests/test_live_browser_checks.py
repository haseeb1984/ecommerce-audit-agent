from scripts.generate_live_audit_pdfs import _mobile_render_findings


def test_mobile_render_findings_detect_overflow_viewport_and_hidden_focusables():
    findings = _mobile_render_findings("https://shop.example/", {
        "viewport_width": 390,
        "document_width": 428,
        "viewport_meta": "width=device-width, initial-scale=1",
        "aria_hidden_focusables": 2,
    })
    titles = {finding.title for finding in findings}
    assert "Rendered page overflows the mobile viewport" in titles
    assert "Rendered focusable controls are hidden from assistive technology" in titles
    assert "Rendered page lacks a device-width viewport declaration" not in titles
    assert all(finding.status == "manual_review_required" for finding in findings)


def test_mobile_render_findings_report_missing_viewport_and_clean_layout():
    findings = _mobile_render_findings("https://shop.example/", {
        "viewport_width": 390,
        "document_width": 390,
        "viewport_meta": "",
        "aria_hidden_focusables": 0,
    })
    assert len(findings) == 1
    assert findings[0].title == "Rendered page lacks a device-width viewport declaration"


def test_mobile_render_findings_do_not_infer_results_from_missing_browser_metrics():
    findings = _mobile_render_findings("https://shop.example/", {})
    assert findings == []

import pytest

from scripts.generate_live_audit_pdfs import _allow_public_browser_request


class _FakeRequest:
    def __init__(self, url):
        self.url = url


class _FakeRoute:
    def __init__(self, url):
        self.request = _FakeRequest(url)
        self.action = None

    async def abort(self):
        self.action = "abort"

    async def continue_(self):
        self.action = "continue"


@pytest.mark.asyncio
@pytest.mark.parametrize("url", [
    "http://localhost/admin",
    "http://127.0.0.1/",
    "http://192.168.1.10/",
    "file:///etc/passwd",
    "ftp://example.com/file",
])
async def test_browser_request_guard_aborts_non_public_targets(url):
    route = _FakeRoute(url)
    await _allow_public_browser_request(route)
    assert route.action == "abort"


@pytest.mark.asyncio
async def test_browser_request_guard_fails_closed_when_dns_fails(monkeypatch):
    async def failed_getaddrinfo(*args, **kwargs):
        raise OSError("synthetic DNS failure")

    import asyncio
    monkeypatch.setattr(asyncio, "get_running_loop", lambda: _FakeLoop(failed_getaddrinfo))
    route = _FakeRoute("https://public-looking.example/")
    await _allow_public_browser_request(route)
    assert route.action == "abort"


class _FakeLoop:
    def __init__(self, resolver):
        self.resolver = resolver

    async def getaddrinfo(self, *args, **kwargs):
        return await self.resolver(*args, **kwargs)
