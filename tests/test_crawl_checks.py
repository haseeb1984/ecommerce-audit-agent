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
async def test_multiple_canonical_declarations_require_review(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)

    async def fake_safe_get(client, url):
        if url == "https://shop.example/":
            return (
                200,
                '<html><head><title>Store</title>'
                '<link rel="canonical" href="/">'
                '<link rel="canonical" href="https://other.example/copy">'
                '<link rel="canonical">'
                '</head><body><a href="/products/one">Product</a></body></html>',
                {"content-type": "text/html"},
                url,
            )
        return (
            200,
            '<html><head><title>Product</title></head><body><h1>Product</h1></body></html>',
            {"content-type": "text/html"},
            url,
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    finding = next(f for f in findings if f.title == "Multiple canonical declarations detected")
    assert finding.status == "manual_review_required"
    assert "3 link elements" in finding.evidence
    missing_href = next(f for f in findings if f.title == "Canonical declaration is missing href")
    assert missing_href.status == "manual_review_required"
    assert "1 canonical link element" in missing_href.evidence


@pytest.mark.asyncio
async def test_malformed_canonical_is_reviewed_without_crashing(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)

    async def fake_safe_get(client, url):
        if url == "https://shop.example/":
            return (
                200,
                '<html><head><title>Store</title>'
                '<link rel="canonical" href="https://[broken-ipv6/copy">'
                '</head><body><a href="/products/one">Product</a></body></html>',
                {"content-type": "text/html"},
                url,
            )
        return (
            200,
            '<html><head><title>Product</title></head><body><h1>Product</h1></body></html>',
            {"content-type": "text/html"},
            url,
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, checked, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    finding = next(f for f in findings if f.title == "Canonical URL is malformed")
    assert finding.status == "manual_review_required"
    assert "broken-ipv6" in finding.evidence
    assert "https://shop.example/" in checked


@pytest.mark.asyncio
async def test_productgroup_nested_in_graph_is_detected(monkeypatch):
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
            '{"@context":"https://schema.org","@graph":[{"@type":"ProductGroup",'
            '"name":"Shirt","hasVariant":[{"@type":"Product","name":"Blue Shirt",'
            '"image":["https://shop.example/blue.jpg"],"offers":{"@type":"Offer",'
            '"price":"12.00","priceCurrency":"USD","availability":"https://schema.org/InStock"}}]}]}'
            '</script></head><body><h1>Shirt</h1></body></html>',
            {"content-type": "text/html"},
            url,
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    assert not any(f.title == "Product structured data not detected" for f in findings)
    assert not any(f.title == "Product JSON-LD needs property review" for f in findings)


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
async def test_product_jsonld_rejects_nonempty_but_wrong_shaped_properties(monkeypatch):
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
            '{"@context":"https://schema.org","@type":"Product",'
            '"name":{"@type":"Thing"},"image":{"@type":"ImageObject"},'
            '"offers":{"@type":"Offer","price":{"amount":"12"},'
            '"priceCurrency":[],"availability":{"@type":"Thing"}}}'
            '</script></head><body><h1>Product</h1></body></html>',
            {"content-type": "text/html"},
            url,
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    finding = next(f for f in findings if f.title == "Product JSON-LD needs property review")
    assert finding.status == "manual_review_required"
    for property_name in ("name", "image", "offers.price", "offers.priceCurrency", "offers.availability"):
        assert property_name in finding.evidence


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
      <link rel="alternate" hreflang="es" href="https://shop.example:not-a-port/es/product">
      <link rel="alternate" hreflang="it" href="https://[broken-ipv6/it/product">
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
    assert "https://shop.example:not-a-port/es/product" in finding.evidence
    assert "https://[broken-ipv6/it/product" in finding.evidence


def test_hreflang_absence_is_not_assumed_to_be_a_problem():
    assert crawl_checks.inspect_hreflang(
        "<html><head><title>Single-language shop</title></head></html>",
        "https://shop.example/",
    ) == []



@pytest.mark.asyncio
async def test_crawl_preserves_noindex_across_duplicate_meta_robots_tags(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)

    async def fake_safe_get(client, url):
        if url == "https://shop.example/":
            return (
                200,
                '<html><head><title>Store</title>'
                '<meta name="robots" content="noindex">'
                '<meta name="robots" content="index, follow">'
                '</head><body><a href="/products/one">Product</a></body></html>',
                {"content-type": "text/html"},
                url,
            )
        return (
            200,
            '<html><head><title>Product</title></head><body><h1>Product</h1></body></html>',
            {"content-type": "text/html"},
            url,
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    assert any(
        f.title == "Multiple meta robots declarations detected"
        and f.status == "manual_review_required"
        for f in findings
    )
    assert any(
        f.title == "Page contains a noindex directive"
        and f.status == "verified"
        and "noindex" in f.evidence
        for f in findings
    )


@pytest.mark.asyncio
async def test_crawl_detects_x_robots_tag_noindex_without_meta_robots(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)

    async def fake_safe_get(client, url):
        if url == "https://shop.example/":
            return (
                200,
                '<html><head><title>Store</title></head><body>Home</body></html>',
                {"content-type": "text/html", "x-robots-tag": "noindex"},
                url,
            )
        return (
            200,
            '<html><head><title>Product</title></head><body>Product</body></html>',
            {"content-type": "text/html"},
            url,
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    noindex = [f for f in findings if f.title == "Page contains a noindex directive"]
    assert len(noindex) == 1
    assert "X-Robots-Tag='noindex'" in noindex[0].evidence


@pytest.mark.asyncio
async def test_sitemap_entity_expansion_is_rejected_safely(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)
    homepage = "https://shop.example/"
    requested = []
    hostile_sitemap = (
        '<!DOCTYPE urlset [<!ENTITY expansion "https://shop.example/products/hidden">]>'
        '<urlset><url><loc>&expansion;</loc></url></urlset>'
    )

    async def fake_safe_get(client, url):
        requested.append(url)
        if url == homepage:
            return 200, '<html><head><title>Store</title></head><body></body></html>', {"content-type": "text/html"}, homepage
        if url == "https://shop.example/sitemap.xml":
            return 200, hostile_sitemap, {"content-type": "application/xml"}, url
        raise AssertionError(f"Unexpected request: {url}")

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, checked, limitations = await crawl_checks.run_bounded_site_crawl(homepage)

    assert homepage in checked
    assert "https://shop.example/products/hidden" not in requested
    assert any("sitemap.xml" in item for item in limitations)

@pytest.mark.asyncio
async def test_crawl_deduplicates_query_variants_and_fragments(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)
    monkeypatch.setattr(crawl_checks, "probe_common_exposure_paths", _empty_exposure)
    monkeypatch.setattr(crawl_checks, "inspect_transport_security", _empty_transport)
    homepage = "https://shop.example/"
    requested = []

    async def fake_safe_get(client, url):
        requested.append(url)
        if url == homepage:
            return 200, ('<html><head><title>Shop</title></head><body>'
                         '<a href="/products/one?utm_source=a">one</a>'
                         '<a href="/products/one?utm_source=b#details">one duplicate</a>'
                         '<a href="/collections/sale#top">sale</a></body></html>'), {"content-type": "text/html"}, homepage
        if url == "https://shop.example/sitemap.xml":
            return 404, "", {"content-type": "application/xml"}, url
        return 200, '<html><head><title>Page</title></head><body></body></html>', {"content-type": "text/html"}, url

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    _, checked, _ = await crawl_checks.run_bounded_site_crawl(homepage)
    assert "https://shop.example/products/one" in checked
    assert "https://shop.example/collections/sale" in checked
    assert requested.count("https://shop.example/products/one") == 1
    assert not any("utm_source" in url or "#" in url for url in requested)


async def _empty_exposure(*args, **kwargs):
    return [], []


async def _empty_transport(*args, **kwargs):
    return [], []


@pytest.mark.asyncio
async def test_crawl_respects_page_budget_and_homepage_link_discovery_cap(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)
    monkeypatch.setattr(crawl_checks, "probe_common_exposure_paths", _empty_exposure)
    monkeypatch.setattr(crawl_checks, "inspect_transport_security", _empty_transport)
    monkeypatch.setattr(crawl_checks, "MAX_CRAWL_PAGES", 12)
    monkeypatch.setattr(crawl_checks, "MAX_LINKS_FROM_HOME", 5)
    homepage = "https://shop.example/"
    requested = []
    links = "".join(f'<a href="/p{i}">P{i}</a>' for i in range(12))

    async def fake_safe_get(client, url):
        requested.append(url)
        if url == homepage:
            return 200, f'<html><head><title>Shop</title></head><body>{links}</body></html>', {"content-type": "text/html"}, homepage
        if url == "https://shop.example/sitemap.xml":
            return 404, "", {"content-type": "application/xml"}, url
        return 200, '<html><head><title>Page</title></head><body></body></html>', {"content-type": "text/html"}, url

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    _, checked, _ = await crawl_checks.run_bounded_site_crawl(homepage)
    assert len(checked) == 6
    assert len([url for url in checked if url != homepage]) == 5
    assert all(f"https://shop.example/p{i}" in checked for i in range(5))
    assert not any(f"https://shop.example/p{i}" in checked for i in range(5, 12))

@pytest.mark.asyncio
async def test_crawl_caps_sitemap_url_discovery(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)
    monkeypatch.setattr(crawl_checks, "probe_common_exposure_paths", _empty_exposure)
    monkeypatch.setattr(crawl_checks, "inspect_transport_security", _empty_transport)
    monkeypatch.setattr(crawl_checks, "MAX_CRAWL_PAGES", 12)
    monkeypatch.setattr(crawl_checks, "MAX_URLS_FROM_SITEMAP", 3)
    homepage = "https://shop.example/"
    sitemap = '<urlset>' + ''.join(
        f'<url><loc>https://shop.example/products/{i}</loc></url>' for i in range(10)
    ) + '</urlset>'
    requested = []

    async def fake_safe_get(client, url):
        requested.append(url)
        if url == homepage:
            return 200, '<html><head><title>Store</title></head><body></body></html>', {"content-type": "text/html"}, homepage
        if url == "https://shop.example/sitemap.xml":
            return 200, sitemap, {"content-type": "application/xml"}, url
        return 200, '<html><head><title>Product</title></head><body></body></html>', {"content-type": "text/html"}, url

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    _, checked, _ = await crawl_checks.run_bounded_site_crawl(homepage)
    assert all(f"https://shop.example/products/{i}" in checked for i in range(3))
    assert not any(f"https://shop.example/products/{i}" in checked for i in range(3, 10))
    assert len([url for url in checked if "/products/" in url]) == 3

@pytest.mark.asyncio
async def test_crawl_fetch_failure_is_not_reported_as_verified_broken_link(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)
    monkeypatch.setattr(crawl_checks, "probe_common_exposure_paths", _empty_exposure)
    monkeypatch.setattr(crawl_checks, "inspect_transport_security", _empty_transport)
    homepage = "https://shop.example/"

    async def fake_safe_get(client, url):
        if url == homepage:
            return 200, '<html><head><title>Store</title></head><body><a href="/products/one">One</a></body></html>', {"content-type": "text/html"}, homepage
        if url == "https://shop.example/sitemap.xml":
            return 404, "", {"content-type": "application/xml"}, url
        if url == "https://shop.example/products/one":
            raise TimeoutError("simulated timeout")
        raise AssertionError(f"Unexpected request: {url}")

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, checked, _ = await crawl_checks.run_bounded_site_crawl(homepage)
    fetch_findings = [f for f in findings if f.title == "Internal page could not be checked"]
    assert len(fetch_findings) == 1
    assert fetch_findings[0].status == "not_tested"
    assert not any(f.title == "Internal URL returned an error" for f in findings)
    assert homepage in checked
    assert "https://shop.example/products/one" not in checked



@pytest.mark.asyncio
async def test_product_jsonld_malformed_block_is_reviewed_without_crashing(monkeypatch):
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
            '<script type="application/ld+json">{"@type":"Product",</script>'
            '</head><body><h1>Product One</h1></body></html>',
            {"content-type": "text/html"},
            url,
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    schema_finding = next(
        f for f in findings
        if f.category == "structured_data" and "Product structured data" in f.title
    )
    assert schema_finding.title == "Product structured data not detected"
    assert schema_finding.status == "manual_review_required"


@pytest.mark.asyncio
async def test_same_origin_canonical_is_not_flagged_as_off_origin(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)

    async def fake_safe_get(client, url):
        if url == "https://shop.example/":
            return (
                200,
                '<html><head><title>Store</title>'
                '<link rel="canonical" href="https://shop.example:443/"></head><body>'
                '<a href="/products/one">Product</a></body></html>',
                {"content-type": "text/html"},
                url,
            )
        return (
            200,
            '<html><head><title>Product</title></head><body><h1>Product</h1></body></html>',
            {"content-type": "text/html"},
            url,
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    assert not any(
        f.title == "Canonical URL points outside this page origin"
        for f in findings
    )


@pytest.mark.asyncio
async def test_crawl_skips_malformed_link_urls_and_accepts_default_port_same_origin(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)
    monkeypatch.setattr(crawl_checks, "probe_common_exposure_paths", _empty_exposure)
    monkeypatch.setattr(crawl_checks, "inspect_transport_security", _empty_transport)
    homepage = "https://shop.example/"
    final_home = "https://shop.example:443/"
    valid = "https://shop.example/products/valid"
    requested = []

    async def fake_safe_get(client, url):
        requested.append(url)
        if url == homepage:
            return (
                200,
                '<html><head><title>Store</title></head><body>'
                '<a href="https://[broken-ipv6/products/bad">Malformed</a>'
                '<a href="https://shop.example/products/valid">Valid</a>'
                '</body></html>',
                {"content-type": "text/html"},
                final_home,
            )
        if url == "https://shop.example:443/sitemap.xml":
            return 404, "", {"content-type": "application/xml"}, url
        if url in {valid, "https://shop.example:443/products/valid"}:
            return (
                200,
                '<html><head><title>Valid product</title></head><body><h1>Valid</h1></body></html>',
                {"content-type": "text/html"},
                url,
            )
        raise AssertionError(f"Unexpected request: {url}")

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, checked, _ = await crawl_checks.run_bounded_site_crawl(homepage)

    assert valid in checked or "https://shop.example:443/products/valid" in checked
    assert not any("broken-ipv6" in url for url in requested)
    assert not any(f.title == "Internal page could not be checked" for f in findings)


@pytest.mark.asyncio
async def test_crawl_expands_limited_same_origin_sitemap_index(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)
    monkeypatch.setattr(crawl_checks, "probe_common_exposure_paths", _empty_exposure)
    monkeypatch.setattr(crawl_checks, "inspect_transport_security", _empty_transport)
    monkeypatch.setattr(crawl_checks, "MAX_CRAWL_PAGES", 12)
    monkeypatch.setattr(crawl_checks, "MAX_URLS_FROM_SITEMAP", 5)
    monkeypatch.setattr(crawl_checks, "MAX_CHILD_SITEMAPS", 2)
    homepage = "https://shop.example/"
    index = (
        "<sitemapindex>"
        "<sitemap><loc>https://shop.example/products-sitemap.xml</loc></sitemap>"
        "<sitemap><loc>https://outside.example/evil.xml</loc></sitemap>"
        "<sitemap><loc>https://shop.example/categories-sitemap.xml</loc></sitemap>"
        "<sitemap><loc>https://shop.example/ignored-sitemap.xml</loc></sitemap>"
        "</sitemapindex>"
    )
    product_sitemap = (
        "<urlset>" + "".join(
            f"<url><loc>https://shop.example/products/{i}</loc></url>" for i in range(4)
        ) + "</urlset>"
    )
    category_sitemap = (
        "<urlset>" + "".join(
            f"<url><loc>https://shop.example/categories/{i}</loc></url>" for i in range(4)
        ) + "</urlset>"
    )
    requested = []

    async def fake_safe_get(client, url):
        requested.append(url)
        if url == homepage:
            return 200, '<html><head><title>Store</title></head><body></body></html>', {"content-type": "text/html"}, homepage
        if url == "https://shop.example/sitemap.xml":
            return 200, index, {"content-type": "application/xml"}, url
        if url == "https://shop.example/products-sitemap.xml":
            return 200, product_sitemap, {"content-type": "application/xml"}, url
        if url == "https://shop.example/categories-sitemap.xml":
            return 200, category_sitemap, {"content-type": "application/xml"}, url
        if url == "https://shop.example/ignored-sitemap.xml":
            raise AssertionError("Child sitemap cap should prevent this request")
        if url.startswith("https://shop.example/products/") or url.startswith("https://shop.example/categories/"):
            return 200, '<html><head><title>Item</title></head><body><h1>Item</h1></body></html>', {"content-type": "text/html"}, url
        raise AssertionError(f"Unexpected request: {url}")

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    _, checked, limitations = await crawl_checks.run_bounded_site_crawl(homepage)

    assert any("at most 3 same-origin child sitemaps" in item and "deeper sitemap-index nesting" in item for item in limitations)
    assert "https://shop.example/products/0" in checked
    assert "https://shop.example/categories/0" in checked
    assert not any("outside.example" in url or "evil.xml" in url for url in requested)
    assert "https://shop.example/ignored-sitemap.xml" not in requested
    assert len([url for url in checked if "/products/" in url or "/categories/" in url]) <= 5


@pytest.mark.asyncio
async def test_crawl_page_budget_of_one_checks_only_homepage(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)
    monkeypatch.setattr(crawl_checks, "probe_common_exposure_paths", _empty_exposure)
    monkeypatch.setattr(crawl_checks, "inspect_transport_security", _empty_transport)
    monkeypatch.setattr(crawl_checks, "MAX_CRAWL_PAGES", 1)
    homepage = "https://shop.example/"

    async def fake_safe_get(client, url):
        if url == homepage:
            return 200, '<html><head><title>Store</title></head><body><a href="/product">Product</a></body></html>', {"content-type": "text/html"}, homepage
        if url == "https://shop.example/sitemap.xml":
            return 404, "", {"content-type": "application/xml"}, url
        raise AssertionError(f"Unexpected request: {url}")

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    _, checked, _ = await crawl_checks.run_bounded_site_crawl(homepage)

    assert checked == [homepage]


@pytest.mark.asyncio
async def test_crawl_flags_multiple_h1_as_review_not_automatic_error(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)

    async def fake_safe_get(client, url):
        if url == "https://shop.example/":
            return (
                200,
                '<html><head><title>Store</title><meta name="description" content="Store"></head>'
                '<body><a href="/products/one">Product</a></body></html>',
                {"content-type": "text/html"},
                url,
            )
        return (
            200,
            '<html><head><title>Product</title><meta name="description" content="Product"></head>'
            '<body><h1>Product</h1><section><h1>Related products</h1></section></body></html>',
            {"content-type": "text/html"},
            url,
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    finding = next(f for f in findings if f.title == "Internal page has multiple H1 headings")
    assert finding.status == "manual_review_required"
    assert finding.severity == "low"
    assert "2 H1 elements" in finding.evidence
    assert "not automatically an SEO error" in finding.explanation

@pytest.mark.asyncio
async def test_crawl_flags_empty_alt_on_internal_page_for_contextual_review(monkeypatch):
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
            '<html><head><title>Product</title></head><body>'
            '<img src="/decorative.svg" alt="">'
            '<img src="/product-detail.jpg" alt="">'
            '</body></html>',
            {"content-type": "text/html"},
            url,
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    finding = next(f for f in findings if f.title == "Internal page images have empty alt text")
    assert finding.status == "manual_review_required"
    assert finding.severity == "low"
    assert "2 of 2 image element(s)" in finding.evidence
    assert "appropriate for decorative images" in finding.explanation

@pytest.mark.asyncio
async def test_crawl_reports_empty_and_duplicate_meta_descriptions_separately(monkeypatch):
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
            '<meta name="description" content="">'
            '<meta name="description" content="Product details">'
            '</head><body><h1>Product</h1></body></html>',
            {"content-type": "text/html"},
            url,
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    empty = next(f for f in findings if f.title == "Internal page has an empty meta description")
    duplicate = next(f for f in findings if f.title == "Internal page has multiple meta descriptions")
    assert empty.status == "manual_review_required"
    assert "1 empty meta description" in empty.evidence
    assert duplicate.status == "manual_review_required"
    assert "2 meta description elements" in duplicate.evidence
    assert not any(f.title == "Internal page missing meta description" for f in findings)

@pytest.mark.asyncio
async def test_crawl_reports_title_and_description_length_as_review_signals(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)

    async def fake_safe_get(client, url):
        if url == "https://shop.example/":
            return (
                200,
                '<html><head><title>Store home</title></head><body>'
                '<a href="/products/one">Product</a></body></html>',
                {"content-type": "text/html"},
                url,
            )
        return (
            200,
            '<html><head><title>Product</title>'
            '<meta name="description" content="Short description">'
            '</head><body><h1>Product</h1></body></html>',
            {"content-type": "text/html"},
            url,
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    title = next(f for f in findings if f.title == "Internal page title length needs review")
    description = next(f for f in findings if f.title == "Internal page meta description length needs review")
    assert title.status == "manual_review_required"
    assert "7 characters" in title.evidence
    assert description.status == "manual_review_required"
    assert "17 characters" in description.evidence
    assert "not proof of an SEO error" in title.explanation

@pytest.mark.asyncio
async def test_crawl_distinguishes_empty_and_duplicate_title_elements(monkeypatch):
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
            '<html><head><title></title><title> </title></head>'
            '<body><h1>Product</h1></body></html>',
            {"content-type": "text/html"},
            url,
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    empty = next(f for f in findings if f.title == "Internal page has an empty title element")
    duplicate = next(f for f in findings if f.title == "Internal page has multiple title elements")
    assert empty.status == "verified"
    assert "2 title element(s)" in empty.evidence
    assert duplicate.status == "manual_review_required"
    assert "2 title elements" in duplicate.evidence
    assert not any(f.title == "Internal page missing a title" for f in findings)

@pytest.mark.asyncio
async def test_crawl_flags_empty_h1_heading_for_contextual_review(monkeypatch):
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
            '<html><head><title>Product</title></head><body>'
            '<h1></h1><h1> </h1></body></html>',
            {"content-type": "text/html"},
            url,
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    finding = next(f for f in findings if f.title == "Internal page has empty H1 headings")
    assert finding.status == "manual_review_required"
    assert finding.severity == "low"
    assert "2 empty H1 element(s) among 2 H1 element(s)" in finding.evidence
    assert "source-only crawler does not execute" in finding.explanation

def test_anchor_name_parser_flags_links_without_text_or_accessible_label():
    parser = crawl_checks._AnchorNameParser()
    parser.feed(
        '<a href="/empty"></a>'
        '<a href="/labelled" aria-label="Open cart"></a>'
        '<a href="/image"><img src="/icon.svg" alt="Account"></a>'
        '<a href="/text"><span>Contact</span></a>'
        '<a href="/title" title="Help"></a>'
    )
    assert parser.empty_name_hrefs == ["/empty"]


def test_hreflang_inspection_flags_duplicate_language_and_malformed_target():
    html = """
    <html><head>
      <link rel="alternate" hreflang="en" href="https://shop.example/en/">
      <link rel="alternate" hreflang="en" href="https://shop.example/en-us/">
      <link rel="alternate" hreflang="fr" href="http://[broken">
    </head></html>
    """
    findings = crawl_checks.inspect_hreflang(html, "https://shop.example/")
    finding = next(f for f in findings if f.title == "Hreflang declarations need review")
    assert finding.status == "manual_review_required"
    assert "duplicate language tag(s): en" in finding.evidence
    assert "target URL issue(s)" in finding.evidence


def test_hreflang_inspection_accepts_distinct_valid_language_targets():
    html = """
    <html><head>
      <link rel="alternate" hreflang="en-US" href="https://shop.example/us/">
      <link rel="alternate" hreflang="fr-FR" href="https://shop.example/fr/">
      <link rel="alternate" hreflang="x-default" href="https://shop.example/">
    </head></html>
    """
    assert crawl_checks.inspect_hreflang(html, "https://shop.example/") == []


def test_meta_refresh_parses_quoted_and_unquoted_urls():
    quoted = crawl_checks.inspect_meta_refresh(
        '<html><head><meta http-equiv="refresh" content="0; url=\'https://outside.example/next?token=secret\'"></head></html>',
        "https://shop.example/",
    )
    unquoted = crawl_checks.inspect_meta_refresh(
        '<html><head><meta http-equiv="refresh" content="5; URL=https://outside.example/next"></head></html>',
        "https://shop.example/",
    )
    assert len(quoted) == 1
    assert "outside.example" in quoted[0].evidence
    assert "secret" not in quoted[0].evidence
    assert len(unquoted) == 1
    assert "outside.example" in unquoted[0].evidence


def test_meta_refresh_same_origin_and_missing_url_do_not_claim_external_redirect():
    same_origin = crawl_checks.inspect_meta_refresh(
        '<meta http-equiv="refresh" content="0; url=/next">',
        "https://shop.example/",
    )
    missing = crawl_checks.inspect_meta_refresh(
        '<meta http-equiv="refresh" content="5">',
        "https://shop.example/",
    )
    assert len(same_origin) == 1
    assert same_origin[0].severity == "low"
    assert "External destination" not in same_origin[0].evidence
    assert missing == []


def test_meta_refresh_redacts_userinfo_query_and_fragment_from_external_destination():
    findings = crawl_checks.inspect_meta_refresh(
        '<meta http-equiv="refresh" content="0; url=\'https://alice:password@outside.example/next?token=secret#account\'">',
        "https://shop.example/",
    )
    assert len(findings) == 1
    evidence = findings[0].evidence
    assert "outside.example/next" in evidence
    assert "alice" not in evidence
    assert "password" not in evidence
    assert "secret" not in evidence
    assert "account" not in evidence


def test_meta_refresh_default_ports_are_same_origin():
    findings = crawl_checks.inspect_meta_refresh(
        '<meta http-equiv="refresh" content="0; url=https://shop.example:443/next">',
        "https://shop.example/",
    )
    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert "External destination" not in findings[0].evidence


def test_meta_refresh_directive_limit_is_disclosed():
    html = "".join(
        '<meta http-equiv="refresh" content="0; url=/page">'
        for _ in range(22)
    )
    findings = crawl_checks.inspect_meta_refresh(html, "https://shop.example/")
    assert len(findings) == 1
    assert "Detected 22 meta-refresh directive(s)" in findings[0].evidence
    assert "Only the first 20 directives were inspected" in findings[0].evidence


def test_hreflang_malformed_destination_redacts_credentials_query_and_fragment():
    findings = crawl_checks.inspect_hreflang(
        '<link rel="alternate" hreflang="en" href="https://user:password@outside.example/page?token=secret#section">'
        '<link rel="alternate" hreflang="en" href="javascript:alert(1)">',
        "https://shop.example/",
    )
    finding = next(item for item in findings if item.title == "Hreflang declarations need review")
    assert "outside.example/page" in finding.evidence
    assert "user" not in finding.evidence
    assert "password" not in finding.evidence
    assert "secret" not in finding.evidence
    assert "section" not in finding.evidence
    assert "javascript:alert" not in finding.evidence
    assert "malformed or unsupported target URL omitted" in finding.evidence



def test_canonical_page_url_normalizes_default_ports_and_tracking_queries():
    assert crawl_checks._canonical_page_url(
        "https://SHOP.example:443/products/one?utm_source=email#details"
    ) == "https://shop.example/products/one"
    assert crawl_checks._canonical_page_url(
        "http://shop.example:80/products/one?sort=price"
    ) == "http://shop.example/products/one"


def test_canonical_page_url_preserves_non_default_ports_and_ipv6_authorities():
    assert crawl_checks._canonical_page_url(
        "https://shop.example:8443/products/one"
    ) == "https://shop.example:8443/products/one"
    assert crawl_checks._canonical_page_url(
        "https://[2001:db8::1]:443/products/one"
    ) == "https://[2001:db8::1]/products/one"


def test_canonical_page_url_does_not_preserve_userinfo_in_normalized_authority():
    assert crawl_checks._canonical_page_url(
        "https://user:secret@shop.example/products/one?token=private"
    ) == "https://shop.example/products/one"


@pytest.mark.asyncio
async def test_bounded_crawl_runs_security_header_quality_on_sampled_html(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)

    async def fake_safe_get(client, url):
        return (
            200,
            '<html><head><title>Store</title></head><body><h1>Shop</h1></body></html>',
            {
                "content-type": "text/html",
                "content-security-policy": "default-src *; script-src 'unsafe-inline'",
                "strict-transport-security": "max-age=3600",
            },
            "https://shop.example/",
        )

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, checked, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    assert "https://shop.example/" in checked
    assert any(f.title == "Content Security Policy may be overly permissive" for f in findings)
    assert any(f.title == "HSTS policy may need review" for f in findings)
    assert any(f.title == "Baseline browser security headers need review" for f in findings)


def test_robots_txt_flags_sitewide_wildcard_disallow_for_manual_review():
    from crawl_checks import inspect_robots_txt

    findings, limitations = inspect_robots_txt(
        "User-agent: *\nDisallow: /\nSitemap: https://shop.example/sitemap.xml\n",
        "https://shop.example/robots.txt",
    )
    assert len(findings) == 1
    assert findings[0].category == "indexing"
    assert findings[0].severity == "high"
    assert findings[0].status == "manual_review_required"
    assert "Disallow: /" in findings[0].evidence
    assert not limitations


def test_robots_txt_does_not_treat_agent_specific_disallow_as_sitewide():
    from crawl_checks import inspect_robots_txt

    findings, limitations = inspect_robots_txt(
        "User-agent: Googlebot\nDisallow: /\n"
        "User-agent: *\nDisallow: /private/\n",
        "https://shop.example/robots.txt",
    )
    assert findings == []
    assert any("did not declare a Sitemap URL" in item for item in limitations)


def test_robots_txt_ignores_comments_and_empty_disallow():
    from crawl_checks import inspect_robots_txt

    findings, _ = inspect_robots_txt(
        "# Disallow: /\nUser-agent: *\nDisallow:\n",
        "https://shop.example/robots.txt",
    )
    assert findings == []


def test_robots_txt_does_not_carry_wildcard_group_into_later_agent_group():
    from crawl_checks import inspect_robots_txt

    findings, _ = inspect_robots_txt(
        "User-agent: *\nDisallow: /private/\n"
        "User-agent: Googlebot\nDisallow: /\n",
        "https://shop.example/robots.txt",
    )
    assert findings == []


def test_robots_txt_consecutive_user_agents_share_group_before_rules():
    from crawl_checks import inspect_robots_txt

    findings, _ = inspect_robots_txt(
        "User-agent: Googlebot\nUser-agent: *\nDisallow: /\n",
        "https://shop.example/robots.txt",
    )
    assert len(findings) == 1
    assert findings[0].status == "manual_review_required"


@pytest.mark.asyncio
async def test_crawl_discovers_nonstandard_sitemap_declared_in_robots(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)
    homepage = "https://shop.example/"
    sitemap = "https://shop.example/catalog-index.xml"
    product = "https://shop.example/products/from-declared-sitemap"
    requested = []

    async def fake_safe_get(client, url):
        requested.append(url)
        if url == homepage:
            return 200, '<html><head><title>Store</title></head><body></body></html>', {"content-type": "text/html"}, homepage
        if url == "https://shop.example/robots.txt":
            return 200, f"User-agent: *\nAllow: /\nSitemap: {sitemap}\n", {"content-type": "text/plain"}, url
        if url == sitemap:
            return 200, f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>{product}</loc></url></urlset>', {"content-type": "application/xml"}, sitemap
        if url == product:
            return 200, '<html><head><title>Product</title><meta name="description" content="Item"></head><body><h1>Product</h1></body></html>', {"content-type": "text/html"}, product
        raise AssertionError(f"Unexpected request: {url}")

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    _, checked, _ = await crawl_checks.run_bounded_site_crawl(homepage)

    assert sitemap in requested
    assert product in checked
    assert "https://shop.example/sitemap.xml" not in requested


@pytest.mark.asyncio
async def test_crawl_ignores_cross_origin_sitemap_directive(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)
    homepage = "https://shop.example/"
    requested = []

    async def fake_safe_get(client, url):
        requested.append(url)
        if url == homepage:
            return 200, '<html><head><title>Store</title></head><body></body></html>', {"content-type": "text/html"}, homepage
        if url == "https://shop.example/robots.txt":
            return 200, "Sitemap: https://outside.example/sitemap.xml\n", {"content-type": "text/plain"}, url
        if url == "https://shop.example/sitemap.xml":
            return 404, "", {"content-type": "application/xml"}, url
        return 404, "", {"content-type": "text/plain"}, url

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    await crawl_checks.run_bounded_site_crawl(homepage)

    assert "https://outside.example/sitemap.xml" not in requested
    assert "https://shop.example/sitemap.xml" in requested


def test_discovered_sitemap_reports_malformed_xml():
    findings = crawl_checks.inspect_crawl_sitemap(
        "<urlset><url>", "https://shop.example/catalog.xml"
    )
    assert len(findings) == 1
    assert findings[0].title == "Discovered sitemap XML is malformed"
    assert findings[0].status == "manual_review_required"


def test_discovered_sitemap_rejects_unexpected_xml_root():
    findings = crawl_checks.inspect_crawl_sitemap(
        "<feed><entry><id>https://shop.example/item</id></entry></feed>",
        "https://shop.example/catalog.xml",
    )
    assert len(findings) == 1
    assert findings[0].title == "Discovered sitemap has an unexpected root element"


def test_discovered_sitemap_reports_empty_and_invalid_locations():
    findings = crawl_checks.inspect_crawl_sitemap(
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        "<url><loc></loc></url><url><loc>javascript:alert(1)</loc></url></urlset>",
        "https://shop.example/catalog.xml",
    )
    assert len(findings) == 1
    assert findings[0].title == "Discovered sitemap contains invalid location entries"
    assert "empty locations: 1" in findings[0].evidence


def test_discovered_sitemap_accepts_valid_absolute_http_locations():
    findings = crawl_checks.inspect_crawl_sitemap(
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        "<url><loc>https://shop.example/products/one</loc></url></urlset>",
        "https://shop.example/catalog.xml",
    )
    assert findings == []


@pytest.mark.asyncio
async def test_crawl_reports_unavailable_robots_declared_sitemap(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)
    homepage = "https://shop.example/"
    sitemap = "https://shop.example/catalog-index.xml"

    async def fake_safe_get(client, url):
        if url == homepage:
            return 200, '<html><head><title>Store</title></head><body></body></html>', {"content-type": "text/html"}, homepage
        if url == "https://shop.example/robots.txt":
            return 200, f"User-agent: *\\nSitemap: {sitemap}\\n", {"content-type": "text/plain"}, url
        if url == sitemap:
            return 503, "temporarily unavailable", {"content-type": "text/plain"}, sitemap
        return 404, "", {"content-type": "text/plain"}, url

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl(homepage)

    finding = next(item for item in findings if item.title == "Robots-declared sitemap could not be retrieved")
    assert finding.status == "manual_review_required"
    assert finding.severity == "medium"
    assert "HTTP 503" in finding.evidence


@pytest.mark.asyncio
async def test_crawl_reports_unavailable_child_sitemap_from_index(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)
    homepage = "https://shop.example/"
    sitemap = "https://shop.example/sitemap.xml"
    child = "https://shop.example/products-sitemap.xml"

    async def fake_safe_get(client, url):
        if url == homepage:
            return 200, '<html><head><title>Store</title></head><body></body></html>', {"content-type": "text/html"}, homepage
        if url == "https://shop.example/robots.txt":
            return 200, "", {"content-type": "text/plain"}, url
        if url == sitemap:
            body = (
                '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                f"<sitemap><loc>{child}</loc></sitemap></sitemapindex>"
            )
            return 200, body, {"content-type": "application/xml"}, sitemap
        if url == child:
            return 404, "", {"content-type": "text/plain"}, child
        return 404, "", {"content-type": "text/plain"}, url

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl(homepage)

    finding = next(item for item in findings if item.title == "Child sitemap could not be retrieved")
    assert finding.status == "manual_review_required"
    assert "HTTP 404" in finding.evidence


@pytest.mark.asyncio
async def test_crawl_does_not_use_robots_sitemap_redirected_off_origin(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)
    homepage = "https://shop.example/"
    sitemap = "https://shop.example/catalog-index.xml"
    external = "https://outside.example/sitemap.xml"
    requested = []

    async def fake_safe_get(client, url):
        requested.append(url)
        if url == homepage:
            return 200, '<html><head><title>Store</title></head><body></body></html>', {"content-type": "text/html"}, homepage
        if url == "https://shop.example/robots.txt":
            return 200, f"User-agent: *\\nSitemap: {sitemap}\\n", {"content-type": "text/plain"}, url
        if url == sitemap:
            body = '<urlset><url><loc>https://shop.example/products/one</loc></url></urlset>'
            return 200, body, {"content-type": "application/xml"}, external
        return 404, "", {"content-type": "text/plain"}, url

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, checked, _ = await crawl_checks.run_bounded_site_crawl(homepage)

    assert any(f.title == "Sitemap redirect left the audited origin" for f in findings)
    assert external not in requested
    assert "https://shop.example/products/one" not in checked


def test_product_detail_route_without_jsonld_prompts_contextual_review():
    findings = crawl_checks.inspect_product_page_schema_presence(
        "<html><head><title>Blue Shirt</title></head><body><h1>Blue Shirt</h1></body></html>",
        "https://shop.example/products/blue-shirt",
    )
    assert len(findings) == 1
    assert findings[0].category == "structured_data"
    assert findings[0].status == "manual_review_required"
    assert findings[0].severity == "low"
    assert "does not inspect JavaScript-rendered markup" in findings[0].explanation


def test_product_detail_route_accepts_productgroup_inside_jsonld_graph():
    findings = crawl_checks.inspect_product_page_schema_presence(
        '<script type="application/ld+json">'
        '{"@context":"https://schema.org","@graph":[{"@type":"ProductGroup","name":"Shirt"}]}'
        '</script>',
        "https://shop.example/products/blue-shirt",
    )
    assert findings == []


def test_product_schema_heuristic_ignores_non_product_routes_and_malformed_jsonld():
    category = crawl_checks.inspect_product_page_schema_presence(
        "<html></html>", "https://shop.example/collections/shirts"
    )
    malformed = crawl_checks.inspect_product_page_schema_presence(
        '<script type="application/ld+json">{"@type":</script>',
        "https://shop.example/products/blue-shirt",
    )
    assert category == []
    assert malformed == []


@pytest.mark.asyncio
async def test_crawl_prioritizes_noindex_on_product_landing_page(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)
    homepage = "https://shop.example/"
    product = "https://shop.example/products/blue-shirt"

    async def fake_safe_get(client, url):
        if url == homepage:
            return 200, '<html><head><title>Store</title></head><body><a href="/products/blue-shirt">Blue shirt</a></body></html>', {"content-type": "text/html"}, homepage
        if url == "https://shop.example/robots.txt":
            return 404, "", {"content-type": "text/plain"}, url
        if url == "https://shop.example/sitemap.xml":
            return 404, "", {"content-type": "text/plain"}, url
        if url == product:
            return 200, '<html><head><title>Blue shirt</title><meta name="robots" content="noindex,follow"></head><body><h1>Blue shirt</h1></body></html>', {"content-type": "text/html"}, product
        return 404, "", {"content-type": "text/plain"}, url

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl(homepage)

    noindex = next(f for f in findings if f.title == "Page contains a noindex directive" and product in f.evidence)
    assert noindex.severity == "high"
    assert "commercially important organic landing pages" in noindex.explanation
    assert any(step == "Confirm the page's business purpose and intended indexability." for step in noindex.verification_steps)


@pytest.mark.asyncio
async def test_crawl_reports_sampled_internal_page_missing_title_element(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)
    homepage = "https://shop.example/"
    product = "https://shop.example/products/blue-shirt"

    async def fake_safe_get(client, url):
        if url == homepage:
            return 200, '<html><head><title>Store home</title></head><body><a href="/products/blue-shirt">Blue shirt</a></body></html>', {"content-type": "text/html"}, homepage
        if url in {"https://shop.example/robots.txt", "https://shop.example/sitemap.xml"}:
            return 404, "", {"content-type": "text/plain"}, url
        if url == product:
            return 200, '<html><head><meta name="description" content="Blue shirt"></head><body><h1>Blue shirt</h1></body></html>', {"content-type": "text/html"}, product
        return 404, "", {"content-type": "text/plain"}, url

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl(homepage)

    missing_title = [
        finding for finding in findings
        if finding.title == "Internal page missing title element" and product in finding.evidence
    ]
    assert len(missing_title) == 1
    assert missing_title[0].severity == "medium"
    assert "JavaScript runs" in missing_title[0].explanation


@pytest.mark.asyncio
async def test_product_jsonld_flags_negative_price_and_malformed_currency_code(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)

    async def fake_safe_get(client, url):
        if url == "https://shop.example/":
            return (
                200,
                '<html><head><title>Store</title></head><body><a href="/products/one">Product</a></body></html>',
                {"content-type": "text/html"},
                url,
            )
        if url in {"https://shop.example/robots.txt", "https://shop.example/sitemap.xml"}:
            return 404, "", {"content-type": "text/plain"}, url
        if url == "https://shop.example/products/one":
            body = (
                '<html><head><title>Product</title><script type="application/ld+json">'
                '{"@context":"https://schema.org","@type":"Product","name":"Product One",'
                '"image":["https://shop.example/one.jpg"],"offers":{"@type":"Offer",'
                '"price":"-10.00","priceCurrency":"US dollars",'
                '"availability":"https://schema.org/InStock"}}'
                '</script></head><body><h1>Product One</h1></body></html>'
            )
            return 200, body, {"content-type": "text/html"}, url
        return 404, "", {"content-type": "text/plain"}, url

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, _, _ = await crawl_checks.run_bounded_site_crawl("https://shop.example/")

    suspicious = [
        finding for finding in findings
        if finding.title == "Product offer values need validation"
    ]
    assert len(suspicious) == 1
    assert suspicious[0].status == "manual_review_required"
    assert "negative offer price" in suspicious[0].evidence
    assert "priceCurrency is not a three-letter currency code" in suspicious[0].evidence


def test_sensitive_get_form_detects_password_and_payment_fields():
    findings = crawl_checks.inspect_sensitive_get_forms(
        '<form action="/login" method="get"><input type="password" name="password">'
        '<input name="email"></form>'
        '<form action="/checkout" method="GET"><input name="cc-number" autocomplete="cc-number"></form>',
        "https://shop.example/checkout",
    )

    assert len(findings) == 1
    assert findings[0].title == "Sensitive-looking fields appear in a GET form"
    assert findings[0].status == "manual_review_required"
    assert findings[0].severity == "high"
    assert "password" in findings[0].evidence
    assert "cc-number" in findings[0].evidence
    assert "Do not submit real credentials" in findings[0].recommendation


def test_sensitive_get_form_ignores_safe_post_form_and_regular_get_search():
    findings = crawl_checks.inspect_sensitive_get_forms(
        '<form action="/login" method="post"><input type="password" name="password"></form>'
        '<form action="/search"><input type="text" name="q"></form>',
        "https://shop.example/",
    )

    assert findings == []


def test_product_schema_presence_accepts_absolute_schema_org_type_iri():
    findings = crawl_checks.inspect_product_page_schema_presence(
        '<script type="application/ld+json">'
        '{"@context":"https://schema.org","@type":"https://schema.org/Product","name":"Blue Shirt"}'
        '</script>',
        "https://shop.example/products/blue-shirt",
    )
    assert findings == []


def test_hreflang_reports_missing_self_reference():
    findings = crawl_checks.inspect_hreflang(
        '<link rel="alternate" hreflang="fr" href="https://shop.example/fr/produit">',
        "https://shop.example/en/product",
    )
    assert len(findings) == 1
    assert findings[0].category == "international_seo"
    assert "no hreflang target appears to reference this page itself" in findings[0].evidence


def test_hreflang_accepts_self_reference_with_fragment_or_query_difference():
    findings = crawl_checks.inspect_hreflang(
        '<link rel="alternate" hreflang="en" href="https://shop.example/en/product?source=lang#top">'
        '<link rel="alternate" hreflang="fr" href="https://shop.example/fr/produit">',
        "https://shop.example/en/product",
    )
    assert findings == []


def test_canonical_review_reports_multiple_and_missing_href_declarations():
    findings = crawl_checks.inspect_canonical_declaration(
        '<link rel="canonical" href="https://shop.example/products/a">'
        '<link rel="canonical" href="">',
        "https://shop.example/products/a",
    )
    titles = {finding.title for finding in findings}
    assert "Page declares multiple canonical links" in titles
    assert "Canonical link is missing its href" in titles


def test_canonical_review_reports_malformed_target_but_accepts_valid_relative_target():
    malformed = crawl_checks.inspect_canonical_declaration(
        '<link rel="canonical" href="https://[invalid">',
        "https://shop.example/products/a",
    )
    valid = crawl_checks.inspect_canonical_declaration(
        '<link rel="canonical" href="/products/a">',
        "https://shop.example/products/a",
    )
    assert any(f.title == "Canonical target URL needs review" for f in malformed)
    assert valid == []

@pytest.mark.asyncio
async def test_bounded_crawl_discovers_nested_same_origin_links_without_exceeding_budget(monkeypatch):
    monkeypatch.setattr(crawl_checks.aiohttp, "ClientSession", FakeClientSession)
    homepage = "https://shop.example/"
    category = "https://shop.example/collections/shoes"
    product = "https://shop.example/products/deep-product"
    requested = []

    async def fake_safe_get(client, url):
        requested.append(url)
        if url == homepage:
            return (
                200,
                '<html><head><title>Store</title></head><body>'
                '<a href="/collections/shoes">Shoes</a></body></html>',
                {"content-type": "text/html"},
                homepage,
            )
        if url == "https://shop.example/robots.txt":
            return 404, "", {"content-type": "text/plain"}, url
        if url == "https://shop.example/sitemap.xml":
            return 404, "", {"content-type": "text/plain"}, url
        if url == category:
            return (
                200,
                '<html><head><title>Shoes</title></head><body>'
                '<a href="/products/deep-product?utm_source=test#details">Product</a>'
                '<a href="https://outside.example/skip">External</a></body></html>',
                {"content-type": "text/html"},
                category,
            )
        if url == product:
            return (
                200,
                '<html><head><title>Deep Product</title></head><body><h1>Deep Product</h1></body></html>',
                {"content-type": "text/html"},
                product,
            )
        # Safe exposure-path probes and unrelated fixed probes may fail closed.
        return 404, "", {"content-type": "text/plain"}, url

    monkeypatch.setattr(crawl_checks, "_safe_get", fake_safe_get)
    findings, checked, limitations = await crawl_checks.run_bounded_site_crawl(homepage)

    assert homepage in checked
    assert category in checked
    assert product in checked
    assert requested.count(product) == 1
    assert not any("outside.example" in url for url in requested)
    assert len(checked) <= crawl_checks.MAX_CRAWL_PAGES
    assert limitations


def test_canonical_review_flags_cross_origin_target_for_manual_review():
    findings = crawl_checks.inspect_canonical_declaration(
        '<link rel="canonical" href="https://www.shop.example/products/a">',
        "https://shop.example/products/a",
    )
    assert len(findings) == 1
    assert findings[0].title == "Canonical target points to a different origin"
    assert findings[0].status == "manual_review_required"
    assert findings[0].severity == "medium"
    assert "does not fetch or validate the destination" in findings[0].evidence


def test_canonical_review_accepts_same_origin_scheme_and_default_port_normalization():
    findings = crawl_checks.inspect_canonical_declaration(
        '<link rel="canonical" href="https://shop.example:443/products/a">',
        "https://shop.example/products/a",
    )
    assert findings == []

