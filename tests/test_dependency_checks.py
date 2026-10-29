import json
from urllib.parse import urlsplit

import pytest

import dependency_checks


def test_extracts_only_supported_explicitly_versioned_cdn_scripts():
    html = """
    <script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script>
    <script src="https://unpkg.com/@example/widget@1.2.3/dist/widget.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.2/js/bootstrap.min.js"></script>
    <script src="https://assets.shop.example/js/app.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script>
    """
    dependencies = dependency_checks.extract_versioned_dependencies(html, "https://shop.example/")
    assert dependencies == [
        {"name": "jquery", "version": "3.7.1", "ecosystem": "npm"},
        {"name": "@example/widget", "version": "1.2.3", "ecosystem": "npm"},
        {"name": "bootstrap", "version": "5.3.2", "ecosystem": "npm"},
    ]


@pytest.mark.asyncio
async def test_no_detectable_version_is_not_reported_as_vulnerability_free():
    findings, limitations = await dependency_checks.inspect_client_dependency_versions(
        '<script src="/assets/bundle.js"></script>',
        "https://shop.example/",
    )
    assert len(findings) == 1
    assert findings[0].status == "not_tested"
    assert findings[0].title == "Frontend dependency vulnerabilities not assessed"
    assert any("bundled and self-hosted dependencies are not inventoried" in item for item in limitations)


class FakeContent:
    def __init__(self, body):
        self.body = body
        self.bytes_yielded = 0

    async def iter_chunked(self, size):
        for offset in range(0, len(self.body), size):
            chunk = self.body[offset:offset + size]
            self.bytes_yielded += len(chunk)
            yield chunk


class FakeResponse:
    def __init__(self, status, payload, raw_body=None):
        self.status = status
        body = raw_body if raw_body is not None else json.dumps(payload).encode("utf-8")
        self.content = FakeContent(body)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class FakeSession:
    def __init__(self, *, timeout=None, trust_env=None, status=200, payload=None, raw_body=None):
        self.status = status
        self.payload = payload if payload is not None else {"results": []}
        self.raw_body = raw_body
        self.request = None
        self.response = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def post(self, url, **kwargs):
        self.request = (url, kwargs)
        self.response = FakeResponse(self.status, self.payload, self.raw_body)
        return self.response


@pytest.mark.asyncio
async def test_osv_match_is_reported_as_manual_review_not_exploitability(monkeypatch):
    fake = FakeSession(payload={"results": [{"vulns": [{"id": "GHSA-test-1234"}]}]})
    monkeypatch.setattr(dependency_checks.aiohttp, "ClientSession", lambda **kwargs: fake)
    findings, limitations = await dependency_checks.inspect_client_dependency_versions(
        '<script src="https://cdn.jsdelivr.net/npm/jquery@1.2.3/dist/jquery.min.js"></script>',
        "https://shop.example/",
    )
    assert len(findings) == 1
    assert findings[0].title == "Versioned frontend dependency has matching OSV advisories"
    assert findings[0].status == "manual_review_required"
    assert "GHSA-test-1234" in findings[0].evidence
    assert "not downloaded or independently verified" in findings[0].evidence
    assert "does not inventory server-side packages" in limitations[0]
    assert fake.request[0] == dependency_checks.OSV_QUERY_URL
    assert fake.request[1]["json"]["queries"][0]["package"] == {"name": "jquery", "ecosystem": "npm"}


@pytest.mark.asyncio
async def test_osv_service_failure_stays_not_tested(monkeypatch):
    fake = FakeSession(status=503, payload={})
    monkeypatch.setattr(dependency_checks.aiohttp, "ClientSession", lambda **kwargs: fake)
    findings, limitations = await dependency_checks.inspect_client_dependency_versions(
        '<script src="https://cdn.jsdelivr.net/npm/jquery@1.2.3/dist/jquery.min.js"></script>',
        "https://shop.example/",
    )
    assert len(findings) == 1
    assert findings[0].status == "not_tested"
    assert findings[0].title == "Frontend dependency vulnerability lookup incomplete"
    assert "remain unverified" in limitations[0]



@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {"results": [None]},
        {"results": [{"vulns": "not-a-list"}]},
        {"results": [{"vulns": [{"title": "missing advisory ID"}]}]},
        {"unexpected": []},
    ],
)
async def test_malformed_osv_payload_never_looks_like_a_clean_scan(monkeypatch, payload):
    fake = FakeSession(payload=payload)
    monkeypatch.setattr(dependency_checks.aiohttp, "ClientSession", lambda **kwargs: fake)
    findings, limitations = await dependency_checks.inspect_client_dependency_versions(
        '<script src="https://cdn.jsdelivr.net/npm/jquery@1.2.3/dist/jquery.min.js"></script>',
        "https://shop.example/",
    )
    assert len(findings) == 1
    assert findings[0].status == "not_tested"
    assert findings[0].title == "Frontend dependency vulnerability lookup incomplete"
    assert "unverified" in limitations[0]
    assert "No matching OSV advisories returned" not in findings[0].title


@pytest.mark.asyncio
async def test_oversized_osv_response_is_not_treated_as_a_clean_scan(monkeypatch):
    fake = FakeSession(raw_body=b"{" + b" " * dependency_checks.MAX_OSV_RESPONSE_BYTES)
    monkeypatch.setattr(dependency_checks.aiohttp, "ClientSession", lambda **kwargs: fake)
    findings, limitations = await dependency_checks.inspect_client_dependency_versions(
        '<script src="https://cdn.jsdelivr.net/npm/jquery@1.2.3/dist/jquery.min.js"></script>',
        "https://shop.example/",
    )
    assert len(findings) == 1
    assert findings[0].status == "not_tested"
    assert findings[0].title == "Frontend dependency vulnerability lookup incomplete"
    assert "unverified" in limitations[0]
    assert fake.response.content.bytes_yielded <= dependency_checks.MAX_OSV_RESPONSE_BYTES + 65536
