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
