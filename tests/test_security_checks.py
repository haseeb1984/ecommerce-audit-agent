import pytest

from security_checks import inspect_exposure_response


def test_env_exposure_reports_key_names_but_never_secret_values():
    secret = "DB_PASSWORD=super-secret-value\nAPI_KEY=another-secret-value"
    findings = inspect_exposure_response(
        "/.env", 200, secret, {"content-type": "text/plain"}, "https://shop.example/.env"
    )
    assert len(findings) == 1
    assert findings[0].status == "verified"
    assert findings[0].severity == "high"
    assert "super-secret-value" not in findings[0].evidence
    assert "another-secret-value" not in findings[0].evidence


def test_git_head_exposure_requires_expected_signature():
    found = inspect_exposure_response(
        "/.git/HEAD", 200, "ref: refs/heads/main\n",
        {"content-type": "text/plain"}, "https://shop.example/.git/HEAD"
    )
    spa_fallback = inspect_exposure_response(
        "/.git/HEAD", 200, "<html><h1>Storefront</h1></html>",
        {"content-type": "text/html"}, "https://shop.example/.git/HEAD"
    )
    assert len(found) == 1
    assert spa_fallback == []


@pytest.mark.parametrize("status,body", [
    (403, "DB_PASSWORD=redacted\nAPI_KEY=redacted"),
    (404, "Not found"),
    (200, "<html><h1>Storefront</h1></html>"),
])
def test_env_probe_does_not_flag_blocked_or_generic_responses(status, body):
    assert inspect_exposure_response(
        "/.env", status, body, {}, "https://shop.example/.env"
    ) == []


def test_phpinfo_detection_uses_content_signature_not_status_only():
    findings = inspect_exposure_response(
        "/phpinfo.php", 200, "<html>PHP Version 8.3 phpinfo()</html>",
        {"content-type": "text/html"}, "https://shop.example/phpinfo.php"
    )
    assert len(findings) == 1
    assert findings[0].title == "A public PHP information page was detected"


@pytest.mark.asyncio
async def test_probe_ignores_redirects_to_other_paths_or_origins(monkeypatch):
    import security_checks

    async def fake_safe_get(client, url):
        if url.endswith("/.env"):
            return 200, "DB_PASSWORD=x\nAPI_KEY=y", {"content-type": "text/plain"}, "https://other.example/.env"
        return 200, "<html>store</html>", {"content-type": "text/html"}, url

    monkeypatch.setattr(security_checks, "_safe_get", fake_safe_get)
    findings, limitations = await security_checks.probe_common_exposure_paths(
        object(), "https://shop.example/"
    )
    assert findings == []
    assert any("not a penetration test" in item for item in limitations)


from security_checks import inspect_security_header_quality


def test_csp_wildcard_and_unsafe_inline_are_review_signals_without_echoing_policy():
    findings = inspect_security_header_quality(
        {"content-security-policy": "default-src *; script-src 'unsafe-inline'"},
        "https://shop.example/"
    )
    assert len(findings) == 1
    assert findings[0].status == "manual_review_required"
    assert "wildcard" in findings[0].evidence
    assert "unsafe-inline" in findings[0].evidence


def test_short_hsts_policy_is_flagged_for_review_not_as_confirmed_vulnerability():
    findings = inspect_security_header_quality(
        {"strict-transport-security": "max-age=3600"},
        "https://shop.example/"
    )
    assert len(findings) == 1
    assert findings[0].status == "manual_review_required"
    assert findings[0].severity == "low"


def test_cookie_review_names_cookie_but_never_reports_cookie_value():
    findings = inspect_security_header_quality(
        {"set-cookie": "session_token=top-secret; Path=/; SameSite=Lax"},
        "https://shop.example/"
    )
    assert len(findings) == 1
    assert "session_token" in findings[0].evidence
    assert "top-secret" not in findings[0].evidence
    assert "Secure" in findings[0].evidence
    assert "HttpOnly" in findings[0].evidence


def test_secure_cookie_attributes_do_not_trigger_review():
    findings = inspect_security_header_quality(
        {"set-cookie": "session=redacted; Path=/; Secure; HttpOnly; SameSite=Lax",
         "strict-transport-security": "max-age=31536000; includeSubDomains",
         "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'"},
        "https://shop.example/"
    )
    assert findings == []


def test_debug_log_detection_requires_error_signature_and_multiple_lines():
    found = inspect_exposure_response(
        "/debug.log", 200, "line one\nFatal error: example\nline three",
        {"content-type": "text/plain"}, "https://shop.example/debug.log"
    )
    generic = inspect_exposure_response(
        "/debug.log", 200, "ordinary storefront content",
        {"content-type": "text/plain"}, "https://shop.example/debug.log"
    )
    assert len(found) == 1
    assert generic == []


def test_database_dump_detection_does_not_copy_rows_into_evidence():
    body = "-- MySQL dump\nCREATE TABLE users (id int);\nINSERT INTO users VALUES ('sensitive');\n" + ("x" * 250)
    findings = inspect_exposure_response(
        "/backup.sql", 200, body, {"content-type": "text/plain"},
        "https://shop.example/backup.sql"
    )
    assert len(findings) == 1
    assert "sensitive" not in findings[0].evidence



@pytest.mark.asyncio
async def test_transport_checks_flag_http_resources_in_https_html(monkeypatch):
    import security_checks

    async def fake_safe_get(client, url):
        return 200, "<html></html>", {}, url

    monkeypatch.setattr(security_checks, "_safe_get", fake_safe_get)
    findings, limitations = await security_checks.inspect_transport_security(
        object(),
        '<html><script src="http://cdn.example/app.js"></script><img src="http://cdn.example/a.png"></html>',
        "http://shop.example/",
    )
    assert any("HTTP does not redirect to HTTPS" == item.title for item in findings)
    assert any("Mixed-content inspection was skipped" in item for item in limitations)
    assert not any("HTTP resources referenced by HTTPS page" == item.title for item in findings)


@pytest.mark.asyncio
async def test_transport_checks_detect_static_mixed_content_on_https_html(monkeypatch):
    import security_checks

    async def fake_safe_get(client, url):
        return 200, "<html></html>", {}, "https://shop.example/"

    monkeypatch.setattr(security_checks, "_safe_get", fake_safe_get)
    findings, limitations = await security_checks.inspect_transport_security(
        object(),
        '<html><script src="http://cdn.example/app.js"></script><img src="http://cdn.example/a.png"></html>',
        "https://shop.example/",
    )
    mixed = [item for item in findings if item.title == "HTTP resources referenced by HTTPS page"]
    assert len(mixed) == 1
    assert mixed[0].severity == "high"
    assert not any("Mixed-content inspection" in item for item in limitations)
