import ipaddress
from urllib.parse import urlsplit

import httpx
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


@pytest.mark.asyncio
async def test_safe_get_rejects_redirect_to_localhost(monkeypatch):
    async def public_host(host):
        if host == "shop.example":
            return None
        raise ValueError("private host blocked")

    monkeypatch.setattr(audit_checks, "_resolve_public_host", public_host)

    async def handler(request):
        return httpx.Response(302, headers={"Location": "http://127.0.0.1/admin"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False) as client:
        with pytest.raises(ValueError):
            await audit_checks._safe_get(client, "https://shop.example/")


@pytest.mark.asyncio
async def test_safe_get_follows_only_revalidated_public_redirects(monkeypatch):
    checked = []

    async def public_host(host):
        checked.append(host)
        if host != "shop.example":
            raise ValueError("private host blocked")

    monkeypatch.setattr(audit_checks, "_resolve_public_host", public_host)

    async def handler(request):
        if request.url.path == "/":
            return httpx.Response(301, headers={"Location": "/home"})
        return httpx.Response(200, headers={"Content-Type": "text/html"}, text="<h1>Store</h1>")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False) as client:
        status, body, headers, final_url = await audit_checks._safe_get(client, "https://shop.example/")

    assert status == 200
    assert "<h1>Store</h1>" in body
    assert urlsplit(final_url).path == "/home"
    assert checked == ["shop.example", "shop.example"]

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
