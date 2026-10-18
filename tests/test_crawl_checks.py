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
            '<html><head></head><body><h1>Product One</h1><img src="/photo.jpg"></body></html>',
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
    assert any(f.title == "Internal page images missing alt attributes" for f in findings)
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



@pytest.mark.asyncio
async def test_bounded_crawl_uses_same_origin_sitemap_urls(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)
    homepage = "https://shop.example/"
    product = "https://shop.example/products/from-sitemap"
    requests = []

    async def fake_safe_get(client, url):
        requests.append(url)
        if url == homepage:
            return (
                200,
                '<html><head><title>Store</title></head><body>'
                '<a href="https://outside.example/products/skip">External</a>'
                '</body></html>',
                {"content-type": "text/html"},
                homepage,
            )
        if url == "https://shop.example/sitemap.xml":
            return (
                200,
                '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                f'<url><loc>{product}</loc></url>'
                '<url><loc>https://outside.example/products/skip</loc></url>'
                '</urlset>',
                {"content-type": "application/xml"},
                url,
            )
        if url == product:
            return (
                200,
                '<html><head><title>Product</title><meta name="description" content="Item">'
                '</head><body><h1>Product</h1></body></html>',
                {"content-type": "text/html"},
                product,
            )
        raise AssertionError(f"Unexpected request: {url}")

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, checked, limitations = await crawl_checks.run_bounded_site_crawl(homepage)

    assert product in requests
    assert product in checked
    assert not any("outside.example" in url for url in requests)
    assert any("sitemap.xml" in item for item in limitations)



@pytest.mark.asyncio
async def test_product_jsonld_reports_missing_common_properties_for_review(monkeypatch):
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
            '<html><head><title>Product</title>'
            '<script type="application/ld+json">'
            '{"@context":"https://schema.org","@type":"Product","name":"Product One"}'
            '</script></head><body><h1>Product One</h1></body></html>',
            {"content-type": "text/html"},
            url,
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    property_finding = next(
        f for f in findings if f.title == "Product JSON-LD needs property review"
    )
    assert property_finding.status == "manual_review_required"
    assert "image" in property_finding.evidence
    assert "offers (price and availability details)" in property_finding.evidence


@pytest.mark.asyncio
async def test_product_jsonld_with_common_properties_has_no_property_gap_finding(monkeypatch):
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
            '<html><head><title>Product</title>'
            '<script type="application/ld+json">'
            '{"@context":"https://schema.org","@type":"Product","name":"Product One",'
            '"image":["https://shop.example/one.jpg"],"offers":{"@type":"Offer",'
            '"price":"10.00","priceCurrency":"USD","availability":"https://schema.org/InStock"}}'
            '</script></head><body><h1>Product One</h1></body></html>',
            {"content-type": "text/html"},
            url,
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    assert not any(f.title == "Product JSON-LD needs property review" for f in findings)


@pytest.mark.asyncio
async def test_category_like_page_without_h1_is_flagged_for_review(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)

    async def fake_safe_get(client, url):
        if url == "https://shop.example/":
            return (
                200,
                '<html><head><title>Store</title></head><body>'
                '<a href="/collections/shoes">Shoes</a></body></html>',
                {"content-type": "text/html"},
                url,
            )
        return (
            200,
            '<html><head><title>Shoes</title></head><body><div>Products</div></body></html>',
            {"content-type": "text/html"},
            url,
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    assert any(
        f.title == "Category-like page has no H1 in returned HTML"
        and f.status == "manual_review_required"
        for f in findings
    )



@pytest.mark.asyncio
async def test_category_page_detects_itemlist_jsonld(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)

    async def fake_safe_get(client, url):
        if url == "https://shop.example/":
            return (
                200,
                '<html><head><title>Store</title></head><body>'
                '<a href="/collections/shoes">Shoes</a></body></html>',
                {"content-type": "text/html"},
                url,
            )
        return (
            200,
            '<html><head><title>Shoes</title>'
            '<script type="application/ld+json">'
            '{"@context":"https://schema.org","@type":"ItemList",'
            '"itemListElement":[{"@type":"ListItem","position":1,"url":"https://shop.example/products/one"}]}'
            '</script></head><body><h1>Shoes</h1></body></html>',
            {"content-type": "text/html"},
            url,
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    schema_finding = next(
        f for f in findings if f.title == "Category/list structured data detected"
    )
    assert schema_finding.status == "verified"


@pytest.mark.asyncio
async def test_internal_page_missing_viewport_is_flagged_for_manual_review(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)

    async def fake_safe_get(client, url):
        if url == "https://shop.example/":
            return (
                200,
                '<html><head><title>Store</title><meta name="viewport" content="width=device-width, initial-scale=1"></head>'
                '<body><a href="/collections/shoes">Shoes</a></body></html>',
                {"content-type": "text/html"},
                url,
            )
        return (
            200,
            '<html><head><title>Shoes</title></head><body><h1>Shoes</h1></body></html>',
            {"content-type": "text/html"},
            url,
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    finding = next(
        f for f in findings
        if f.title == "Viewport declaration not detected"
    )
    assert finding.status == "manual_review_required"
    assert "320 CSS px" in " ".join(finding.verification_steps)



def test_hreflang_valid_alternates_do_not_create_review_finding():
    html = """
    <html><head>
      <link rel="alternate" hreflang="en" href="https://shop.example/en/product">
      <link rel="alternate" hreflang="fr-CA" href="https://shop.example/fr-ca/product">
      <link rel="alternate" hreflang="x-default" href="https://shop.example/product">
    </head></html>
    """
    assert crawl_checks.inspect_hreflang(html, "https://shop.example/en/product") == []


def test_hreflang_malformed_language_target_and_duplicate_are_reviewed():
    html = """
    <html><head>
      <link rel="alternate" hreflang="english_US" href="javascript:alert(1)">
      <link rel="alternate" hreflang="fr" href="https://shop.example/fr/product">
      <link rel="alternate" hreflang="FR" href="https://shop.example/fr-ca/product">
      <link rel="alternate" hreflang="de">
    </head></html>
    """
    findings = crawl_checks.inspect_hreflang(html, "https://shop.example/en/product")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == "international_seo"
    assert finding.status == "manual_review_required"
    assert "english_US" in finding.evidence
    assert "javascript:alert(1)" in finding.evidence
    assert "FR" in finding.evidence or "fr" in finding.evidence
    assert "(missing href)" in finding.evidence


def test_hreflang_absence_is_not_assumed_to_be_a_problem():
    assert crawl_checks.inspect_hreflang(
        "<html><head><title>Single-language shop</title></head></html>",
        "https://shop.example/",
    ) == []
