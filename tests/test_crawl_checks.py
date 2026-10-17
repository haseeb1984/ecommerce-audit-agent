from __future__ import annotations

import pytest

import crawl_checks


class FakeClientSession:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


@pytest.mark.asyncio
async def test_bounded_crawl_stays_same_origin_and_detects_missing_titles(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)
    pages = {
        "https://shop.example/": (
            200,
            '<html><head><title>Store</title></head><body>'
            '<a href="/products/one">Product</a>'
            '<a href="https://other.example/phish">External</a>'
            '<a href="mailto:support@shop.example">Email</a>'
            '</body></html>',
            {"content-type": "text/html"},
            "https://shop.example/",
        ),
        "https://shop.example/products/one": (
            200,
            '<html><head></head><body><h1>Product One</h1></body></html>',
            {"content-type": "text/html"},
            "https://shop.example/products/one",
        ),
    }
    requested = []

    async def fake_safe_get(client, url):
        requested.append(url)
        return pages[url]

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, checked, limitations = await crawl_checks.run_bounded_site_crawl(
        "https://shop.example/"
    )

    assert "https://shop.example/products/one" in requested
    assert not any("other.example" in url for url in requested)
    assert any(f.title == "Internal page missing a title" for f in findings)
    assert any(f.title == "Internal page missing meta description" for f in findings)
    assert len(checked) == 2
    assert limitations


@pytest.mark.asyncio
async def test_bounded_crawl_reports_internal_http_errors(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)
    async def fake_safe_get(client, url):
        if url == "https://shop.example/":
            return 200, '<a href="/broken">Broken</a>', {"content-type": "text/html"}, url
        return 404, "", {"content-type": "text/html"}, url

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, checked, _ = await crawl_checks.run_bounded_site_crawl("shop.example")

    assert any(f.title == "Internal URL returned an error" for f in findings)
    assert "https://shop.example/broken" in checked
