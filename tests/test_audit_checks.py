from urllib.parse import urlsplit

import pytest

import audit_checks


def test_normalize_target_adds_https_and_drops_fragment():
    assert audit_checks.normalize_target("Example.COM/path#section") == "https://example.com/path"


@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1",
        "http://10.0.0.1",
        "http://169.254.169.254/latest/meta-data",
        "http://localhost",
        "http://service.local",
        "file:///etc/passwd",
        "https://user:pass@example.com",
        "https://example.com:8443",
        "https://example.com\\\\@127.0.0.1",
    ],
)
def test_normalize_target_rejects_unsafe_or_unsupported_targets(target):
    with pytest.raises(ValueError):
        audit_checks.normalize_target(target)


def test_parser_detects_viewport_and_missing_alt():
    html = """
    <html><head><title>Shop home</title>
    <meta name="description" content="A shop">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    </head><body><h1>Shop</h1><img src="/hero.jpg"><img src="/decorative.png" alt=""></body></html>
    """
    parser = audit_checks._PageParser()
    parser.feed(html)
    assert parser.title_text == "Shop home"
    assert parser.meta_description == "A shop"
    assert parser.viewport == "width=device-width, initial-scale=1"
    assert parser.h1_count == 1
    assert parser.images == 2
    assert parser.images_missing_alt == 1



@pytest.mark.parametrize(
    ("head", "expected_title", "expected_evidence"),
    [
        (
            '<link rel="canonical" href="https://shop.example/one">'
            '<link rel="canonical" href="https://shop.example/two">',
            "Multiple canonical link elements",
            "Found 2 canonical link elements",
        ),
        (
            '<link rel="canonical">',
            "Canonical link missing href",
            "1 canonical link element(s) have no usable href",
        ),
    ],
)
def test_homepage_reports_malformed_canonical_declarations(head, expected_title, expected_evidence):
    html = f"<html><head>{head}</head><body><h1>Shop</h1></body></html>"
    findings = audit_checks.inspect_homepage(html, "https://shop.example/", {})
    finding = next(item for item in findings if item.title == expected_title)
    assert finding.status == "verified"
    assert finding.severity == "medium"
    assert expected_evidence in finding.evidence
    assert finding.recommendation
    assert finding.verification_steps


@pytest.mark.parametrize(
    "canonical_href",
    [
        "javascript:alert(1)",
        "https://user:pass@shop.example/product",
        "https://shop.example/product#details",
        "https://[invalid",
    ],
)
def test_homepage_reports_malformed_canonical_destination(canonical_href):
    html = f'<html><head><link rel="canonical" href="{canonical_href}"></head><body><h1>Shop</h1></body></html>'
    findings = audit_checks.inspect_homepage(html, "https://shop.example/", {})
    finding = next(item for item in findings if item.title == "Canonical URL is malformed")
    assert finding.status == "verified"
    assert finding.severity == "medium"
    assert finding.source_url == "https://shop.example/"
    assert finding.recommendation
    assert finding.verification_steps


def test_homepage_accepts_relative_canonical_destination():
    html = '<html><head><link rel="canonical" href="/products/widget"></head><body><h1>Widget</h1></body></html>'
    findings = audit_checks.inspect_homepage(html, "https://shop.example/products/widget", {})
    assert not any(item.title == "Canonical URL is malformed" for item in findings)


@pytest.mark.parametrize(
    ("page_url", "canonical_href", "should_flag"),
    [
        ("https://shop.example/product", "https://shop.example/product", False),
        ("https://shop.example/product", "/product", False),
        ("https://shop.example/product", "https://other.example/product", True),
        ("https://shop.example/product", "http://shop.example/product", True),
    ],
)
def test_homepage_reviews_cross_origin_canonical_targets(page_url, canonical_href, should_flag):
    html = f'<html><head><link rel="canonical" href="{canonical_href}"></head><body><h1>Product</h1></body></html>'
    findings = audit_checks.inspect_homepage(html, page_url, {})
    matches = [item for item in findings if item.title == "Canonical points to a different origin"]
    assert bool(matches) is should_flag
    if matches:
        assert matches[0].status == "manual_review_required"
        assert matches[0].severity == "medium"
        assert matches[0].source_url == page_url
        assert matches[0].verification_steps


@pytest.mark.parametrize(
    ("jsonld", "expected_title"),
    [
        ('{"@context":"https://schema.org","@type":"Product"}', "Product structured data missing name"),
        ('{"@context":"https://schema.org","@type":"Product","name":"Example item","image":"https://shop.example/item.jpg"}', None),
        ('{"@context":"https://schema.org","@type":"Product"', "Malformed JSON-LD structured data"),
    ],
)
def test_homepage_checks_jsonld_syntax_and_product_name(jsonld, expected_title):
    html = f'<html><head><script type="application/ld+json">{jsonld}</script></head><body><h1>Shop</h1></body></html>'
    findings = audit_checks.inspect_homepage(html, "https://shop.example/", {})
    structured_findings = [item for item in findings if item.category == "structured_data"]
    if expected_title is None:
        assert not any(item.title in {"Malformed JSON-LD structured data", "Product structured data missing name"} for item in structured_findings)
    else:
        finding = next(item for item in structured_findings if item.title == expected_title)
        assert finding.status == "verified"
        assert finding.evidence and finding.recommendation and finding.verification_steps


@pytest.mark.parametrize(
    ("description", "should_flag"),
    [
        (None, True),
        ("", True),
        ("A stainless steel water bottle.", False),
        (123, True),
    ],
)
def test_homepage_checks_product_description(description, should_flag):
    import json
    product = {
        "@context": "https://schema.org",
        "@type": "Product",
        "name": "Example",
        "image": "https://shop.example/item.jpg",
    }
    if description is not None:
        product["description"] = description
    html = f'<html><head><script type="application/ld+json">{json.dumps(product)}</script></head><body><h1>Shop</h1></body></html>'
    findings = audit_checks.inspect_homepage(html, "https://shop.example/", {})
    matches = [item for item in findings if item.title == "Product structured data missing description"]
    assert bool(matches) is should_flag
    if matches:
        assert matches[0].severity == "low"
        assert matches[0].source_url == "https://shop.example/"


@pytest.mark.parametrize(
    ("image", "should_flag"),
    [
        (None, True),
        ("", True),
        ("https://shop.example/item.jpg", False),
        (["", "https://shop.example/item-2.jpg"], False),
        ([{"@type": "ImageObject", "contentUrl": "https://shop.example/item.jpg"}], False),
    ],
)
def test_homepage_checks_product_image_property(image, should_flag):
    import json
    product = {"@context": "https://schema.org", "@type": "Product", "name": "Example"}
    if image is not None:
        product["image"] = image
    html = f'<html><head><script type="application/ld+json">{json.dumps(product)}</script></head><body><h1>Shop</h1></body></html>'
    findings = audit_checks.inspect_homepage(html, "https://shop.example/", {})
    image_findings = [item for item in findings if item.title == "Product structured data missing image"]
    assert bool(image_findings) is should_flag
    if image_findings:
        assert image_findings[0].status == "verified"
        assert image_findings[0].source_url == "https://shop.example/"


@pytest.mark.parametrize(
    ("offers", "should_flag"),
    [
        (None, True),
        ({}, True),
        ({"price": "19.99", "priceCurrency": "USD"}, False),
        ([{"price": "19.99", "priceCurrency": "USD"}], False),
        ({"@type": "AggregateOffer", "lowPrice": "10", "priceCurrency": "USD"}, False),
        ("not-an-offer", True),
    ],
)
def test_homepage_checks_product_offer_presence(offers, should_flag):
    import json
    product = {
        "@context": "https://schema.org",
        "@type": "Product",
        "name": "Example",
        "image": "https://shop.example/item.jpg",
    }
    if offers is not None:
        product["offers"] = offers
    html = f'<html><head><script type="application/ld+json">{json.dumps(product)}</script></head><body><h1>Shop</h1></body></html>'
    findings = audit_checks.inspect_homepage(html, "https://shop.example/", {})
    matches = [item for item in findings if item.title == "Product structured data has no offer information"]
    assert bool(matches) is should_flag
    if matches:
        assert matches[0].severity == "low"
        assert matches[0].source_url == "https://shop.example/"


@pytest.mark.parametrize(
    ("availability", "expected_title"),
    [
        (None, "Product offers missing availability"),
        ("", "Product offers missing availability"),
        ("https://schema.org/InStock", None),
        ("https://schema.org/UnknownState", "Product offers have invalid availability"),
    ],
)
def test_homepage_checks_offer_availability_presence_and_value(availability, expected_title):
    import json
    offer = {"price": "19.99", "priceCurrency": "USD"}
    if availability is not None:
        offer["availability"] = availability
    product = {
        "@context": "https://schema.org",
        "@type": "Product",
        "name": "Example",
        "image": "https://shop.example/item.jpg",
        "offers": offer,
    }
    html = f'<html><head><script type="application/ld+json">{json.dumps(product)}</script></head><body><h1>Shop</h1></body></html>'
    findings = audit_checks.inspect_homepage(html, "https://shop.example/", {})
    availability_findings = [
        item for item in findings
        if item.title in {
            "Product offers missing availability",
            "Product offers have invalid availability",
        }
    ]
    if expected_title is None:
        assert availability_findings == []
    else:
        assert len(availability_findings) == 1
        assert availability_findings[0].title == expected_title
        assert availability_findings[0].source_url == "https://shop.example/"


@pytest.mark.parametrize(
    ("availability", "should_flag"),
    [
        ("https://schema.org/InStock", False),
        ("https://schema.org/OutOfStock", False),
        ("https://schema.org/UnknownState", True),
        ({"value": "InStock"}, True),
        (None, False),
    ],
)
def test_homepage_checks_product_offer_availability(availability, should_flag):
    import json
    product = {
        "@context": "https://schema.org",
        "@type": "Product",
        "name": "Example",
        "image": "https://shop.example/item.jpg",
        "offers": {"price": "19.99", "priceCurrency": "USD"},
    }
    if availability is not None:
        product["offers"]["availability"] = availability
    html = f'<html><head><script type="application/ld+json">{json.dumps(product)}</script></head><body><h1>Shop</h1></body></html>'
    findings = audit_checks.inspect_homepage(html, "https://shop.example/", {})
    matches = [item for item in findings if item.title == "Product offers have invalid availability"]
    assert bool(matches) is should_flag
    if matches:
        assert matches[0].status == "verified"
        assert matches[0].source_url == "https://shop.example/"


@pytest.mark.parametrize(
    ("offer", "expected_title"),
    [
        ({"price": "19.99", "priceCurrency": "USD", "availability": "https://schema.org/InStock"}, None),
        ({"priceCurrency": "USD", "availability": "https://schema.org/InStock"}, "Product offers missing price"),
        ({"price": "19.99", "availability": "https://schema.org/InStock"}, "Product offers missing or invalid currency"),
        ({"price": "-1", "priceCurrency": "USD", "availability": "https://schema.org/InStock"}, "Product offers missing price"),
    ],
)
def test_homepage_checks_product_offer_price_and_currency(offer, expected_title):
    product = {"@context": "https://schema.org", "@type": "Product", "name": "Example", "image": "https://shop.example/item.jpg"}
    product["offers"] = offer
    import json
    jsonld = json.dumps(product)
    html = f'<html><head><script type="application/ld+json">{jsonld}</script></head><body><h1>Shop</h1></body></html>'
    findings = audit_checks.inspect_homepage(html, "https://shop.example/", {})
    offer_findings = [item for item in findings if item.category == "structured_data" and "Product offers" in item.title]
    if expected_title is None:
        assert offer_findings == []
    else:
        finding = next(item for item in offer_findings if item.title == expected_title)
        assert finding.status == "verified"
        assert finding.evidence and finding.recommendation and finding.verification_steps


def test_homepage_findings_include_evidence_and_verification_steps():
    findings = audit_checks.inspect_homepage(
        "<html><head></head><body><img src='x'></body></html>",
        "https://shop.example/",
        {},
    )
    assert findings
    assert all(item.evidence and item.explanation and item.recommendation for item in findings)
    assert all(item.verification_steps for item in findings)
    assert any(item.title == "Mobile viewport" for item in findings)
    assert any(item.title == "Images missing an alt attribute" for item in findings)


class FakeContent:
    def __init__(self, body):
        self.body = body.encode()

    async def iter_chunked(self, size):
        yield self.body


class FakeResponse:
    def __init__(self, status, headers=None, body=""):
        self.status = status
        self.headers = headers or {}
        self.charset = "utf-8"
        self.content = FakeContent(body)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class FakeSession:
    def __init__(self, handler):
        self.handler = handler
        self.urls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def get(self, url, allow_redirects=False):
        self.urls.append(url)
        return self.handler(url)


@pytest.mark.asyncio
async def test_discovery_file_server_errors_are_inconclusive_not_missing(monkeypatch):
    def handler(url):
        path = urlsplit(url).path
        if path == "/":
            return FakeResponse(200, {"Content-Type": "text/html"}, "<html><h1>Shop</h1></html>")
        if path == "/robots.txt":
            return FakeResponse(403, {}, "Forbidden")
        if path == "/sitemap.xml":
            return FakeResponse(503, {}, "Unavailable")
        if path == "/llms.txt":
            return FakeResponse(404, {}, "Not found")
        raise AssertionError(f"Unexpected request: {url}")

    session = FakeSession(handler)
    monkeypatch.setattr(audit_checks.aiohttp, "ClientSession", lambda **kwargs: session)
    monkeypatch.setattr(audit_checks.aiohttp, "TCPConnector", lambda **kwargs: object())
    monkeypatch.setattr(audit_checks.aiohttp, "ClientTimeout", lambda **kwargs: object())

    result = await audit_checks.run_phase_one_checks("https://shop.example/")
    by_title = {finding.title: finding for finding in result.findings}
    assert by_title["robots.txt availability"].status == "not_tested"
    assert "does not establish whether robots.txt exists" in by_title["robots.txt availability"].explanation
    assert by_title["sitemap.xml availability"].status == "not_tested"
    assert "does not establish whether sitemap.xml exists" in by_title["sitemap.xml availability"].explanation
    assert by_title["llms.txt availability"].status == "verified"
    assert "not found" in by_title["llms.txt availability"].explanation
    assert by_title["Google indexing status not verified"].status == "not_tested"
    assert "does not prove that Google has indexed" in by_title["Google indexing status not verified"].explanation
    assert any("Google index status is not queried" in item for item in result.limitations)


@pytest.mark.asyncio
async def test_homepage_audit_includes_bounded_dependency_findings(monkeypatch):
    import dependency_checks

    html = '<html><head><script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script></head></html>'

    def handler(url):
        path = urlsplit(url).path
        if path == "/":
            return FakeResponse(200, {"Content-Type": "text/html"}, html)
        if path in {"/robots.txt", "/sitemap.xml", "/llms.txt"}:
            return FakeResponse(404, {}, "Not found")
        raise AssertionError(f"Unexpected request: {url}")

    session = FakeSession(handler)
    monkeypatch.setattr(audit_checks.aiohttp, "ClientSession", lambda **kwargs: session)
    monkeypatch.setattr(audit_checks.aiohttp, "TCPConnector", lambda **kwargs: object())
    monkeypatch.setattr(audit_checks.aiohttp, "ClientTimeout", lambda **kwargs: object())

    async def fake_dependency_check(observed_html, page_url):
        assert observed_html == html
        assert page_url == "https://shop.example/"
        return ([audit_checks.AuditFinding(
            category="security_dependency",
            title="Dependency integration fixture",
            status="manual_review_required",
            severity="medium",
            evidence="Fixture advisory reference only.",
            explanation="This test verifies that dependency findings are included.",
            recommendation="Review the dependency in a package-aware scanner.",
            verification_steps=["Confirm the package and version."],
            source_url=page_url,
        )], ["Dependency integration limitation fixture."])

    monkeypatch.setattr(dependency_checks, "inspect_client_dependency_versions", fake_dependency_check)
    result = await audit_checks.run_phase_one_checks("https://shop.example/")

    assert any(item.title == "Dependency integration fixture" for item in result.findings)
    assert "Dependency integration limitation fixture." in result.limitations


@pytest.mark.asyncio
async def test_safe_get_rejects_redirect_to_localhost():
    client = FakeSession(lambda url: FakeResponse(302, {"Location": "http://127.0.0.1/admin"}))
    with pytest.raises(ValueError):
        await audit_checks._safe_get(client, "https://shop.example/")
    assert len(client.urls) == 1


@pytest.mark.asyncio
async def test_safe_get_follows_relative_redirect():
    def handler(url):
        if urlsplit(url).path == "/":
            return FakeResponse(301, {"Location": "/home"})
        return FakeResponse(200, {"Content-Type": "text/html"}, "<h1>Store</h1>")

    client = FakeSession(handler)
    status, body, headers, final_url = await audit_checks._safe_get(client, "https://shop.example/")
    assert status == 200
    assert "<h1>Store</h1>" in body
    assert urlsplit(final_url).path == "/home"
    assert len(client.urls) == 2


@pytest.mark.asyncio
async def test_public_resolver_rejects_private_dns_answer(monkeypatch):
    class FakeLoop:
        async def getaddrinfo(self, host, port, **kwargs):
            return [(audit_checks.socket.AF_INET, audit_checks.socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(audit_checks.asyncio, "get_running_loop", lambda: FakeLoop())
    with pytest.raises(OSError, match="private or non-public"):
        await audit_checks.PublicOnlyResolver().resolve("test.example", 443)


@pytest.mark.asyncio
async def test_public_resolver_pins_public_ip(monkeypatch):
    class FakeLoop:
        async def getaddrinfo(self, host, port, **kwargs):
            return [(audit_checks.socket.AF_INET, audit_checks.socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(audit_checks.asyncio, "get_running_loop", lambda: FakeLoop())
    result = await audit_checks.PublicOnlyResolver().resolve("public.example", 443)
    assert result[0]["host"] == "8.8.8.8"
    assert result[0]["hostname"] == "public.example"

@pytest.mark.parametrize(
    "viewport,expected_title",
    [
        ("", "Mobile viewport"),
        ("width=980", "Viewport may use a fixed layout width"),
        ("width=device-width, initial-scale=1, user-scalable=no", "Viewport may restrict zoom"),
        ("width=device-width, initial-scale=1, maximum-scale=1.0", "Viewport may restrict zoom"),
        ("width=device-width, initial-scale=1", "Mobile viewport declaration"),
    ],
)
def test_viewport_checks_identify_common_mobile_misconfigurations(viewport, expected_title):
    meta = f'<meta name="viewport" content="{viewport}">' if viewport else ""
    findings = audit_checks.inspect_homepage(
        f"<html><head>{meta}</head><body><h1>Shop</h1></body></html>",
        "https://shop.example/",
        {},
    )
    assert any(f.title == expected_title for f in findings)

def test_robots_directive_summary_counts_rules_without_claiming_full_validation():
    findings = audit_checks.inspect_discovery_contents(
        "robots_txt",
        """User-agent: *
Disallow: /admin/
Allow: /products/
Sitemap: https://shop.example/sitemap.xml
""",
        "https://shop.example/robots.txt",
    )
    assert len(findings) == 1
    assert findings[0].status == "verified"
    assert "1 User-agent" in findings[0].evidence
    assert "1 Allow" in findings[0].evidence
    assert "1 Disallow" in findings[0].evidence
def test_sitemap_parser_flags_malformed_xml_and_invalid_locations():
    malformed = audit_checks.inspect_discovery_contents(
        "sitemap_xml", "<urlset><url>", "https://shop.example/sitemap.xml"
    )[0]
    assert malformed.status == "verified"
    assert "not well-formed XML" in malformed.evidence

    invalid = audit_checks.inspect_discovery_contents(
        "sitemap_xml",
        "<urlset><url><loc>/relative-path</loc></url></urlset>",
        "https://shop.example/sitemap.xml",
    )[0]
    assert invalid.status == "manual_review_required"
    assert "without an absolute HTTP(S) URL: 1" in invalid.evidence


def test_sitemap_parser_handles_malformed_authorities_and_invalid_ports():
    finding = audit_checks.inspect_discovery_contents(
        "sitemap_xml",
        "<urlset>"
        "<url><loc>https://shop.example:99999/products/one</loc></url>"
        "<url><loc>https://[broken-ipv6/products/two</loc></url>"
        "</urlset>",
        "https://shop.example/sitemap.xml",
    )[0]
    assert finding.status == "manual_review_required"
    assert "entries without an absolute HTTP(S) URL: 2" in finding.evidence


def test_sitemap_parser_accepts_basic_urlset():
    finding = audit_checks.inspect_discovery_contents(
        "sitemap_xml",
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://shop.example/product/1</loc></url></urlset>',
        "https://shop.example/sitemap.xml",
    )[0]
    assert finding.status == "verified"
    assert "Root element: urlset" in finding.evidence
    assert "loc entries: 1" in finding.evidence


@pytest.mark.asyncio
async def test_safe_get_stops_after_redirect_limit():
    client = FakeSession(lambda url: FakeResponse(302, {"Location": "/again"}))
    with pytest.raises(ValueError, match="redirect limit"):
        await audit_checks._safe_get(client, "https://shop.example/")
    assert len(client.urls) == audit_checks.MAX_REDIRECTS + 1


@pytest.mark.asyncio
async def test_safe_get_rejects_oversized_content_length_before_reading_body():
    client = FakeSession(lambda url: FakeResponse(
        200, {"Content-Length": str(audit_checks.MAX_RESPONSE_BYTES + 1)}, ""
    ))
    with pytest.raises(ValueError, match="1 MB size limit"):
        await audit_checks._safe_get(client, "https://shop.example/")


@pytest.mark.asyncio
async def test_public_resolver_rejects_mixed_public_and_private_dns_answers(monkeypatch):
    class FakeLoop:
        async def getaddrinfo(self, host, port, **kwargs):
            return [
                (audit_checks.socket.AF_INET, audit_checks.socket.SOCK_STREAM, 6, "", ("8.8.8.8", port)),
                (audit_checks.socket.AF_INET, audit_checks.socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
            ]

    monkeypatch.setattr(audit_checks.asyncio, "get_running_loop", lambda: FakeLoop())
    with pytest.raises(OSError, match="private or non-public"):
        await audit_checks.PublicOnlyResolver().resolve("mixed.example", 443)


@pytest.mark.asyncio
async def test_public_resolver_rejects_empty_dns_answer(monkeypatch):
    class FakeLoop:
        async def getaddrinfo(self, host, port, **kwargs):
            return []

    monkeypatch.setattr(audit_checks.asyncio, "get_running_loop", lambda: FakeLoop())
    with pytest.raises(OSError, match="private or non-public"):
        await audit_checks.PublicOnlyResolver().resolve("empty.example", 443)


@pytest.mark.asyncio
@pytest.mark.parametrize("content_length", ["unknown", "-1", "1.5"])
async def test_safe_get_rejects_malformed_or_negative_content_length(content_length):
    client = FakeSession(lambda url: FakeResponse(
        200, {"Content-Length": content_length}, "small body"
    ))
    with pytest.raises(ValueError, match="invalid Content-Length"):
        await audit_checks._safe_get(client, "https://shop.example/")


@pytest.mark.asyncio
async def test_safe_get_rejects_streamed_body_over_limit_even_without_content_length():
    response = FakeResponse(200, {}, "x" * (audit_checks.MAX_RESPONSE_BYTES + 1))
    client = FakeSession(lambda url: response)
    with pytest.raises(ValueError, match="1 MB size limit"):
        await audit_checks._safe_get(client, "https://shop.example/")


@pytest.mark.parametrize(
    "target",
    [
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[fe80::1]/",
    ],
)
def test_normalize_target_rejects_non_public_ipv4_ipv6_and_obfuscated_loopback(target):
    with pytest.raises(ValueError):
        audit_checks.normalize_target(target)


@pytest.mark.asyncio
async def test_public_resolver_rejects_dns_resolution_failure(monkeypatch):
    class FakeLoop:
        async def getaddrinfo(self, host, port, **kwargs):
            raise audit_checks.socket.gaierror("temporary resolution failure")

    monkeypatch.setattr(audit_checks.asyncio, "get_running_loop", lambda: FakeLoop())
    with pytest.raises(OSError, match="Could not resolve target host"):
        await audit_checks.PublicOnlyResolver().resolve("dns-failure.example", 443)


@pytest.mark.asyncio
async def test_safe_get_rejects_redirect_with_embedded_credentials():
    client = FakeSession(lambda url: FakeResponse(
        302, {"Location": "https://user:pass@public.example/private"}
    ))
    with pytest.raises(ValueError, match="embedded credentials"):
        await audit_checks._safe_get(client, "https://shop.example/")
    assert len(client.urls) == 1


@pytest.mark.asyncio
async def test_safe_get_rejects_redirect_to_unsupported_port():
    client = FakeSession(lambda url: FakeResponse(
        302, {"Location": "https://public.example:8443/admin"}
    ))
    with pytest.raises(ValueError, match="Non-standard ports"):
        await audit_checks._safe_get(client, "https://shop.example/")
    assert len(client.urls) == 1


@pytest.mark.asyncio
async def test_safe_get_rejects_redirect_to_non_http_scheme():
    client = FakeSession(lambda url: FakeResponse(
        302, {"Location": "file:///etc/passwd"}
    ))
    with pytest.raises(ValueError, match="Only public HTTP and HTTPS"):
        await audit_checks._safe_get(client, "https://shop.example/")
    assert len(client.urls) == 1

@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["0x7f000001", "2130706433", "0177.0.0.1", "127.1"])
async def test_public_resolver_rejects_obfuscated_loopback_dns_result(host, monkeypatch):
    class FakeLoop:
        async def getaddrinfo(self, host, port, **kwargs):
            return [(audit_checks.socket.AF_INET, audit_checks.socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(audit_checks.asyncio, "get_running_loop", lambda: FakeLoop())
    with pytest.raises(OSError, match="private or non-public"):
        await audit_checks.PublicOnlyResolver().resolve(host, 443)




@pytest.mark.asyncio
async def test_safe_get_preserves_multiple_x_robots_tag_headers():
    class MultiValueHeaders(dict):
        def getall(self, name, default=None):
            if name.lower() == "x-robots-tag":
                return ["index, follow", "noindex"]
            return default or []

    client = FakeSession(lambda url: FakeResponse(
        200, MultiValueHeaders({"Content-Type": "text/html", "X-Robots-Tag": "index, follow"}),
        "<html></html>",
    ))
    status, _, headers, _ = await audit_checks._safe_get(client, "https://shop.example/")

    assert status == 200
    assert headers["x-robots-tag"] == "index, follow, noindex"


@pytest.mark.asyncio
async def test_safe_get_preserves_multiple_set_cookie_headers():
    class MultiValueHeaders(dict):
        def getall(self, name, default=None):
            if name.lower() == "set-cookie":
                return [
                    "session=redacted; Path=/; Secure; HttpOnly; SameSite=Lax",
                    "analytics=redacted; Path=/; SameSite=Lax",
                ]
            return default or []

    client = FakeSession(lambda url: FakeResponse(
        200, MultiValueHeaders({
            "Content-Type": "text/html",
            "Set-Cookie": "session=redacted; Path=/; Secure; HttpOnly; SameSite=Lax",
        }), "<html></html>",
    ))
    status, _, headers, _ = await audit_checks._safe_get(client, "https://shop.example/")

    assert status == 200
    assert "analytics=redacted" in headers["set-cookie"]
    assert "session=redacted" in headers["set-cookie"]


def test_present_homepage_elements_do_not_recommend_adding_them_again():
    html = (
        '<html><head><title>Example Store</title>'
        '<meta name="description" content="A useful store description">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '</head><body><h1>Example Store</h1></body></html>'
    )
    findings = audit_checks.inspect_homepage(
        html, "https://shop.example/", {"content-type": "text/html"}
    )
    by_title = {finding.title: finding for finding in findings}

    assert "Add a unique, descriptive title" not in by_title["Page title"].recommendation
    assert "Add a concise, page-specific meta description" not in by_title["Meta description"].recommendation
    assert "Keep the title accurate" in by_title["Page title"].recommendation
    assert "Keep the description accurate" in by_title["Meta description"].recommendation


def test_homepage_reports_duplicate_title_elements():
    findings = audit_checks.inspect_homepage(
        '<html><head><title>First title</title><title>Second title</title></head>'
        '<body><h1>Shop</h1></body></html>',
        "https://shop.example/",
        {},
    )
    finding = next(item for item in findings if item.title == "Multiple title elements")
    assert finding.status == "verified"
    assert finding.severity == "medium"
    assert "Found 2 title elements" in finding.evidence
    assert finding.verification_steps


@pytest.mark.parametrize(
    ("descriptions", "expected_empty"),
    [
        ('<meta name="description" content="First"><meta name="description" content="Second">', 0),
        ('<meta name="description" content="Useful"><meta name="description" content="">', 1),
    ],
)
def test_homepage_reports_duplicate_meta_descriptions(descriptions, expected_empty):
    findings = audit_checks.inspect_homepage(
        f"<html><head>{descriptions}</head><body><h1>Shop</h1></body></html>",
        "https://shop.example/",
        {},
    )
    finding = next(item for item in findings if item.title == "Multiple meta description elements")
    assert finding.status == "verified"
    assert f"{expected_empty} empty element(s)" in finding.evidence
    assert finding.recommendation
    assert finding.verification_steps


def test_single_meta_description_does_not_trigger_duplicate_finding():
    findings = audit_checks.inspect_homepage(
        '<html><head><meta name="description" content="Useful description"></head>'
        '<body><h1>Shop</h1></body></html>',
        "https://shop.example/",
        {},
    )
    assert not any(item.title == "Multiple meta description elements" for item in findings)


@pytest.mark.parametrize(
    ("html", "headers", "expected_source"),
    [
        (
            '<html><head><meta name="robots" content="index, noindex"></head><body><h1>Shop</h1></body></html>',
            {},
            "meta name=robots",
        ),
        (
            '<html><head></head><body><h1>Shop</h1></body></html>',
            {"x-robots-tag": "index, follow, noindex"},
            "X-Robots-Tag response header",
        ),
        (
            '<html><head><meta name="robots" content="index, follow"></head><body><h1>Shop</h1></body></html>',
            {"x-robots-tag": "index, follow"},
            None,
        ),
    ],
)
def test_homepage_noindex_detection_uses_explicit_directives(html, headers, expected_source):
    findings = audit_checks.inspect_homepage(html, "https://shop.example/", headers)
    noindex = [item for item in findings if item.title == "Homepage has a noindex directive"]
    if expected_source is None:
        assert noindex == []
    else:
        assert len(noindex) == 1
        assert noindex[0].status == "verified"
        assert expected_source in noindex[0].evidence
        assert "may be intentional" in noindex[0].explanation
        assert noindex[0].verification_steps



def test_homepage_reports_duplicate_meta_robots_elements():
    html = (
        '<html><head><meta name="robots" content="index, follow">'
        '<meta name="robots" content="noindex"></head><body><h1>Shop</h1></body></html>'
    )
    findings = audit_checks.inspect_homepage(html, "https://shop.example/", {})
    duplicate = next(item for item in findings if item.title == "Multiple meta robots elements")
    noindex = next(item for item in findings if item.title == "Homepage has a noindex directive")
    assert duplicate.status == "verified"
    assert duplicate.severity == "medium"
    assert "Found 2 meta name=robots elements" in duplicate.evidence
    assert duplicate.verification_steps
    assert "may be intentional" in noindex.explanation


def test_single_meta_robots_element_does_not_trigger_duplicate_finding():
    findings = audit_checks.inspect_homepage(
        '<html><head><meta name="robots" content="index, follow"></head><body><h1>Shop</h1></body></html>',
        "https://shop.example/",
        {},
    )
    assert not any(item.title == "Multiple meta robots elements" for item in findings)


@pytest.mark.parametrize(
    ("robots", "should_flag"),
    [
        ("User-agent: *\nDisallow: /\n", True),
        ("User-agent: *\nDisallow: /private/\n", False),
        ("User-agent: ExampleBot\nDisallow: /\n", False),
        ("User-agent: *\nAllow: /\nDisallow: /private/\n", False),
        ("User-agent: Googlebot\nDisallow: /tmp/\nUser-agent: *\nDisallow: /\n", True),
    ],
)
def test_robots_txt_detects_wildcard_full_site_block(robots, should_flag):
    findings = audit_checks.inspect_discovery_contents(
        "robots_txt", robots, "https://shop.example/robots.txt"
    )
    matches = [item for item in findings if item.title == "robots.txt may block the entire site"]
    assert bool(matches) is should_flag
    if should_flag:
        assert matches[0].severity == "high"
        assert matches[0].source_url == "https://shop.example/robots.txt"
        assert "may be intentional" in matches[0].explanation
        assert matches[0].verification_steps


def test_sitemap_reports_duplicate_exact_loc_entries():
    sitemap = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        '<url><loc>https://shop.example/products/widget</loc></url>'
        '<url><loc>https://shop.example/products/widget</loc></url>'
        '<url><loc>https://shop.example/products/other</loc></url>'
        '</urlset>'
    )
    findings = audit_checks.inspect_discovery_contents(
        "sitemap_xml", sitemap, "https://shop.example/sitemap.xml"
    )
    duplicate = next(item for item in findings if item.title == "Duplicate URLs in sitemap")
    assert duplicate.status == "verified"
    assert duplicate.severity == "low"
    assert "Found 1 duplicate" in duplicate.evidence
    assert duplicate.source_url == "https://shop.example/sitemap.xml"
    assert duplicate.verification_steps


def test_sitemap_does_not_report_unique_loc_entries_as_duplicates():
    sitemap = (
        '<urlset><url><loc>https://shop.example/a</loc></url>'
        '<url><loc>https://shop.example/b</loc></url></urlset>'
    )
    findings = audit_checks.inspect_discovery_contents(
        "sitemap_xml", sitemap, "https://shop.example/sitemap.xml"
    )
    assert not any(item.title == "Duplicate URLs in sitemap" for item in findings)


def test_aggregate_offer_price_range_is_accepted_without_scalar_price():
    html = '''<html><head><script type="application/ld+json">
    {"@type":"Product","name":"Widget","offers":{"@type":"AggregateOffer",
    "lowPrice":"10.00","highPrice":"25.00","priceCurrency":"USD",
    "availability":"https://schema.org/InStock"}}
    </script></head><body><h1>Widget</h1></body></html>'''
    findings = audit_checks.inspect_homepage(html, "https://shop.example/widget", {})
    assert not any(item.title == "Product offers missing price" for item in findings)
    assert not any(item.title == "Aggregate product offer has an invalid price range" for item in findings)


def test_aggregate_offer_flags_low_price_above_high_price():
    html = '''<html><head><script type="application/ld+json">
    {"@type":"Product","name":"Widget","offers":{"@type":"AggregateOffer",
    "lowPrice":"30","highPrice":"20","priceCurrency":"USD",
    "availability":"https://schema.org/InStock"}}
    </script></head><body><h1>Widget</h1></body></html>'''
    findings = audit_checks.inspect_homepage(html, "https://shop.example/widget", {})
    finding = next(item for item in findings if item.title == "Aggregate product offer has an invalid price range")
    assert finding.status == "verified"
    assert finding.severity == "medium"
    assert finding.verification_steps

@pytest.mark.parametrize(
    ("image_html", "expected_title"),
    [
        ('<img src="/product.jpg">', "Images missing alt attributes"),
        ('<img src="/product.jpg" alt="">', "Images have empty alt text"),
    ],
)
def test_homepage_reports_image_alt_issues_with_distinct_findings(image_html, expected_title):
    findings = audit_checks.inspect_homepage(
        f"<html><head><title>Shop</title></head><body>{image_html}</body></html>",
        "https://shop.example/",
        {},
    )
    matching = [item for item in findings if item.title == expected_title]
    assert len(matching) == 1
    assert matching[0].status == "verified"
    assert matching[0].verification_steps
    other_title = (
        "Images have empty alt text"
        if expected_title == "Images missing alt attributes"
        else "Images missing alt attributes"
    )
    assert not any(item.title == other_title for item in findings)


def test_homepage_does_not_flag_images_with_descriptive_alt_text():
    findings = audit_checks.inspect_homepage(
        '<html><head><title>Shop</title></head><body><img src="/product.jpg" alt="Blue cotton shirt"></body></html>',
        "https://shop.example/",
        {},
    )
    assert not any(item.title in {
        "Images missing alt attributes", "Images have empty alt text"
    } for item in findings)




@pytest.mark.parametrize(
    ("aggregate_rating", "should_flag"),
    [
        ({"@type": "AggregateRating", "ratingValue": "4.7", "reviewCount": 120}, False),
        ({"@type": "AggregateRating", "ratingValue": "6", "bestRating": "5", "worstRating": "1"}, True),
        ({"@type": "AggregateRating", "ratingValue": "not-a-number", "reviewCount": 12}, True),
        ({"@type": "AggregateRating", "ratingValue": "4.5", "reviewCount": -2}, True),
        ({"@type": "AggregateRating", "ratingValue": "2", "bestRating": "1", "worstRating": "5"}, True),
    ],
)
def test_product_aggregate_rating_checks_numeric_shape_and_bounds(aggregate_rating, should_flag):
    import json

    product = {
        "@context": "https://schema.org",
        "@type": "Product",
        "name": "Example item",
        "aggregateRating": aggregate_rating,
    }
    findings = audit_checks.inspect_homepage(
        f'<html><head><script type="application/ld+json">{json.dumps(product)}</script></head><body><h1>Example item</h1></body></html>',
        "https://shop.example/product",
        {},
    )
    matches = [
        finding for finding in findings
        if finding.title == "Product aggregate rating needs review"
    ]
    assert bool(matches) is should_flag
    if matches:
        assert matches[0].category == "structured_data"
        assert matches[0].status == "verified"
        assert matches[0].source_url == "https://shop.example/product"
        assert "cannot confirm that reviews are genuine" in matches[0].explanation
        assert matches[0].verification_steps
