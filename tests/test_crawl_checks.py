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
    assert any(f.title == "Internal page missing primary heading (H1)" for f in findings)
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



@pytest.mark.asyncio
async def test_crawl_flags_off_origin_canonical_and_noindex(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)

    async def fake_safe_get(client, url):
        if url == "https://shop.example/":
            return (
                200,
                '<html><head><title>Store</title>'
                '<meta name="robots" content="noindex, follow">'
                '<link rel="canonical" href="https://other.example/copy">'
                '</head><body><a href="/products/one">Product</a></body></html>',
                {"content-type": "text/html"},
                url,
            )
        return (
            200,
            '<html><head><title>Product</title><meta name="description" content="A product"></head></html>',
            {"content-type": "text/html"},
            url,
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    assert any(f.title == "Canonical URL points outside this page origin" for f in findings)
    assert any(f.title == "Page contains a noindex directive" for f in findings)



@pytest.mark.asyncio
async def test_product_page_detects_product_jsonld(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)

    async def fake_safe_get(client, url):
        if url == "https://shop.example/":
            return (
                200,
                '<html><head><title>Store</title></head><body>'
                '<a href="/products/one">Product</a></body></html>',
                {"content-type": "text/html"},
                url,
            )
        return (
            200,
            '<html><head><title>Product One</title>'
            '<script type="application/ld+json">'
            '{"@context":"https://schema.org","@type":"Product",'
            '"name":"Product One","offers":{"@type":"Offer","price":"10.00"}}'
            '</script></head><body><h1>Product One</h1></body></html>',
            {"content-type": "text/html"},
            url,
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    schema_finding = next(f for f in findings if f.category == "structured_data")
    assert schema_finding.title == "Product structured data detected"
    assert schema_finding.status == "verified"


@pytest.mark.asyncio
async def test_product_page_without_product_jsonld_requires_review(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)

    async def fake_safe_get(client, url):
        if url == "https://shop.example/":
            return (
                200,
                '<html><head><title>Store</title></head><body>'
                '<a href="/products/one">Product</a></body></html>',
                {"content-type": "text/html"},
                url,
            )
        return (
            200,
            '<html><head><title>Product One</title></head><body>'
            '<h1>Product One</h1></body></html>',
            {"content-type": "text/html"},
            url,
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    schema_finding = next(f for f in findings if f.category == "structured_data")
    assert schema_finding.title == "Product structured data not detected"
    assert schema_finding.status == "manual_review_required"
