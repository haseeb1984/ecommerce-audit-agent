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


@pytest.mark.asyncio
async def test_probe_records_request_failures_as_unverified(monkeypatch):
    import security_checks

    async def fake_safe_get(client, url):
        if url.endswith("/.env"):
            raise TimeoutError("timeout")
        if url.endswith("/.git/HEAD"):
            return 200, "not a git head", {}, "https://elsewhere.example/.git/HEAD"
        return 404, "Not found", {}, url

    monkeypatch.setattr(security_checks, "_safe_get", fake_safe_get)
    findings, limitations = await security_checks.probe_common_exposure_paths(
        object(), "https://shop.example/"
    )
    assert findings == []
    assert any("2 of 14 exposure probes could not be verified" in item for item in limitations)


@pytest.mark.parametrize("path,body", [
    ("/server-status", "Server Version: Apache\\nServer Uptime: 10 minutes\\nScoreboard: _W"),
    ("/actuator/env", '{"activeProfiles":[],"propertySources":[]}'),
    ("/actuator/configprops", '{"contexts":{"application":{"beans":{}}}}'),
    ("/debug/vars", '{"cmdline":["app"],"memstats":{},"goroutines":2}'),
    ("/swagger-ui/index.html", '<html>swagger-ui swagger-ui-bundle</html>'),
    ("/openapi.json", '{"openapi":"3.1.0","paths":{"/internal":{}}}'),
])
def test_admin_and_diagnostic_exposure_signatures_are_detected(path, body):
    findings = inspect_exposure_response(
        path, 200, body, {"content-type": "application/json"},
        "https://shop.example" + path,
    )
    assert len(findings) == 1
    if path in {"/swagger-ui/index.html", "/openapi.json"}:
        assert findings[0].status == "manual_review_required"
        assert findings[0].severity == "low"
    else:
        assert findings[0].status == "verified"


@pytest.mark.parametrize("path", [
    "/server-status", "/actuator/env", "/actuator/configprops",
    "/debug/vars", "/swagger-ui/index.html", "/openapi.json",
])
def test_admin_and_diagnostic_probes_ignore_generic_spa_fallback(path):
    findings = inspect_exposure_response(
        path, 200, "<html><div id='app'>Storefront</div></html>",
        {"content-type": "text/html"}, "https://shop.example" + path,
    )
    assert findings == []


def test_actuator_environment_finding_never_copies_property_values():
    body = '{"activeProfiles":[],"propertySources":[{"name":"systemEnvironment","properties":{"DB_PASSWORD":"secret-value"}}]}'
    findings = inspect_exposure_response(
        "/actuator/env", 200, body, {}, "https://shop.example/actuator/env"
    )
    assert len(findings) == 1
    assert "secret-value" not in findings[0].evidence

@pytest.mark.asyncio
async def test_generic_success_responses_are_unverified_not_assumed_safe(monkeypatch):
    import security_checks

    async def fake_safe_get(client, url):
        return 200, "<html><h1>Storefront</h1></html>", {"content-type": "text/html"}, url

    monkeypatch.setattr(security_checks, "_safe_get", fake_safe_get)
    findings, limitations = await security_checks.probe_common_exposure_paths(
        object(), "https://shop.example/"
    )
    assert findings == []
    assert any(
        "14 of 14 exposure probes returned successful responses" in item
        and "treated as unverified" in item
        for item in limitations
    )



@pytest.mark.asyncio
async def test_probe_records_server_errors_as_unverified(monkeypatch):
    import security_checks

    async def fake_safe_get(client, url):
        if url.endswith("/.env"):
            return 503, "Service unavailable", {"content-type": "text/plain"}, url
        return 404, "Not found", {"content-type": "text/plain"}, url

    monkeypatch.setattr(security_checks, "_safe_get", fake_safe_get)
    findings, limitations = await security_checks.probe_common_exposure_paths(
        object(), "https://shop.example/"
    )

    assert findings == []
    assert any("1 of 14 exposure probes returned HTTP 5xx" in item for item in limitations)
    assert any("treated as unverified, not safe" in item for item in limitations)

@pytest.mark.asyncio
async def test_tls_certificate_validation_error_is_reported_as_untrusted_not_pass(monkeypatch):
    import asyncio
    import ssl
    import security_checks

    class FakeLoop:
        async def getaddrinfo(self, host, port, **kwargs):
            return [(security_checks.socket.AF_INET, security_checks.socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    async def invalid_certificate(*args, **kwargs):
        raise ssl.SSLCertVerificationError("certificate verify failed")

    async def fake_safe_get(client, url):
        return 200, "", {}, "https://shop.example/"

    monkeypatch.setattr(security_checks.asyncio, "get_running_loop", lambda: FakeLoop())
    monkeypatch.setattr(security_checks.asyncio, "open_connection", invalid_certificate)
    monkeypatch.setattr(security_checks, "_safe_get", fake_safe_get)

    findings, limitations = await security_checks.inspect_transport_security(
        object(), "<html></html>", "https://shop.example/"
    )
    cert = next(item for item in findings if item.title == "TLS certificate validation failed")
    assert cert.status == "verified"
    assert cert.severity == "high"
    assert "not trusted" in cert.evidence
    assert not any("TLS certificate chain and hostname validation succeeded" in item.evidence for item in findings)
    assert not any("could not be completed" in item for item in limitations)


@pytest.mark.asyncio
async def test_tls_dns_timeout_is_unverified_not_a_certificate_pass(monkeypatch):
    import security_checks

    class FakeLoop:
        async def getaddrinfo(self, host, port, **kwargs):
            raise TimeoutError("simulated DNS timeout")

    async def fake_safe_get(client, url):
        return 200, "", {}, "https://shop.example/"

    monkeypatch.setattr(security_checks.asyncio, "get_running_loop", lambda: FakeLoop())
    monkeypatch.setattr(security_checks, "_safe_get", fake_safe_get)

    findings, limitations = await security_checks.inspect_transport_security(
        object(), "<html></html>", "https://shop.example/"
    )
    assert not any(item.title == "TLS certificate validity and expiry" for item in findings)
    assert any("TLS certificate expiry inspection could not be completed" in item for item in limitations)

@pytest.mark.asyncio
async def test_expired_tls_certificate_is_reported_as_expired_not_currently_valid(monkeypatch):
    import security_checks

    class FakeLoop:
        async def getaddrinfo(self, host, port, **kwargs):
            return [(security_checks.socket.AF_INET, security_checks.socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    class FakeSSLObject:
        def getpeercert(self):
            return {"notAfter": "Jan 01 00:00:00 2020 GMT"}

    class FakeWriter:
        def get_extra_info(self, name):
            return FakeSSLObject() if name == "ssl_object" else None

        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def fake_open_connection(*args, **kwargs):
        return object(), FakeWriter()

    async def fake_safe_get(client, url):
        return 200, "", {}, "https://shop.example/"

    monkeypatch.setattr(security_checks.asyncio, "get_running_loop", lambda: FakeLoop())
    monkeypatch.setattr(security_checks.ssl, "create_default_context", lambda: object())
    monkeypatch.setattr(security_checks.asyncio, "open_connection", fake_open_connection)
    monkeypatch.setattr(security_checks, "_safe_get", fake_safe_get)

    findings, _ = await security_checks.inspect_transport_security(
        object(), "<html></html>", "https://shop.example/"
    )
    cert = next(item for item in findings if item.title == "TLS certificate validity and expiry")
    assert cert.status == "verified"
    assert cert.severity == "high"
    assert "expiry date has passed (2020-01-01)" in cert.evidence
    assert "valid at check time" not in cert.evidence


@pytest.mark.asyncio
async def test_http_server_error_does_not_confirm_missing_https_redirect(monkeypatch):
    import security_checks

    async def fake_safe_get(client, url):
        assert url == "http://shop.example/"
        return 503, "Service unavailable", {}, url

    monkeypatch.setattr(security_checks, "_safe_get", fake_safe_get)
    findings, limitations = await security_checks.inspect_transport_security(
        object(), "<html></html>", "http://shop.example/"
    )

    assert not any(item.title == "HTTP does not redirect to HTTPS" for item in findings)
    assert not any(item.title == "HTTP redirects to HTTPS" for item in findings)
    assert any(
        "returned status 503" in item and "not treated as a pass" in item
        for item in limitations
    )


@pytest.mark.asyncio
async def test_http_success_response_that_stays_http_is_a_redirect_finding(monkeypatch):
    import security_checks

    async def fake_safe_get(client, url):
        assert url == "http://shop.example/"
        return 200, "<html></html>", {}, url

    monkeypatch.setattr(security_checks, "_safe_get", fake_safe_get)
    findings, _ = await security_checks.inspect_transport_security(
        object(), "<html></html>", "http://shop.example/"
    )

    finding = next(item for item in findings if item.title == "HTTP does not redirect to HTTPS")
    assert finding.status == "verified"
    assert finding.severity == "high"


def test_cookie_review_checks_all_combined_set_cookie_values():
    findings = inspect_security_header_quality(
        {
            "set-cookie": (
                "session=redacted; Path=/; Secure; HttpOnly; SameSite=Lax, "
                "analytics=redacted; Path=/; SameSite=Lax"
            )
        },
        "https://shop.example/",
    )
    cookie_finding = next(item for item in findings if item.title == "Cookie security attributes need review")
    assert "analytics" in cookie_finding.evidence
    assert "Secure" in cookie_finding.evidence
    assert "redacted" not in cookie_finding.evidence


def test_csp_missing_base_uri_and_frame_ancestors_are_hardening_review_signals():
    findings = inspect_security_header_quality(
        {"content-security-policy": "default-src 'self'; script-src 'self'"},
        "https://shop.example/",
    )
    hardening = next(
        item for item in findings
        if item.title == "Content Security Policy has hardening opportunities"
    )
    assert hardening.status == "manual_review_required"
    assert hardening.severity == "low"
    assert "base-uri is not explicitly set" in hardening.evidence
    assert "frame-ancestors is not explicitly set" in hardening.evidence


def test_csp_with_explicit_embedding_and_base_restrictions_has_no_gap_finding():
    findings = inspect_security_header_quality(
        {"content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"},
        "https://shop.example/",
    )
    assert not any(
        item.title == "Content Security Policy has hardening opportunities"
        for item in findings
    )


def test_csp_without_default_or_object_source_flags_plugin_content_gap():
    findings = inspect_security_header_quality(
        {"content-security-policy": "script-src 'self'; base-uri 'self'; frame-ancestors 'none'"},
        "https://shop.example/",
    )
    hardening = next(
        item for item in findings
        if item.title == "Content Security Policy has hardening opportunities"
    )
    assert "neither object-src nor default-src limits plugin content" in hardening.evidence


@pytest.mark.parametrize("body", [
    '[{"id":7,"name":"Private Example Name","slug":"private-example"}]',
    '[{"id":12,"slug":"author-profile"}]',
])
def test_wordpress_user_endpoint_is_low_severity_review_and_redacts_profile_data(body):
    findings = inspect_exposure_response(
        "/wp-json/wp/v2/users", 200, body,
        {"content-type": "application/json"},
        "https://shop.example/wp-json/wp/v2/users",
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.title == "WordPress user-profile endpoint returns public records"
    assert finding.status == "manual_review_required"
    assert finding.severity == "low"
    assert "Private Example Name" not in finding.evidence
    assert "private-example" not in finding.evidence
    assert "id" not in finding.evidence.lower()


@pytest.mark.parametrize("status,body", [
    (404, '[{"id":1,"name":"Author"}]'),
    (200, '<html><div id="app">Storefront</div></html>'),
    (200, '{"message":"rest_no_route"}'),
    (200, '[{"error":"not a profile record"}]'),
])
def test_wordpress_user_endpoint_ignores_non_profile_or_unsuccessful_responses(status, body):
    assert inspect_exposure_response(
        "/wp-json/wp/v2/users", status, body, {},
        "https://shop.example/wp-json/wp/v2/users",
    ) == []


def test_duplicate_csp_directive_does_not_let_later_value_mask_first():
    findings = inspect_security_header_quality(
        {
            "content-security-policy": (
                "script-src 'unsafe-inline'; "
                "script-src 'self'; "
                "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
            )
        },
        "https://shop.example/",
    )

    permissive = next(
        finding for finding in findings
        if finding.title == "Content Security Policy may be overly permissive"
    )
    assert "script-src permits unsafe-inline/unsafe-eval" in permissive.evidence


def test_standard_security_headers_report_missing_baseline_controls_as_low_review():
    from security_checks import inspect_standard_security_headers

    findings = inspect_standard_security_headers(
        {"content-type": "text/html"},
        "https://shop.example/",
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == "security_headers"
    assert finding.status == "manual_review_required"
    assert finding.severity == "low"
    assert "X-Content-Type-Options" in finding.evidence
    assert "Referrer-Policy" in finding.evidence
    assert "Permissions-Policy" in finding.evidence
    assert "framing restriction" in finding.evidence


def test_standard_security_headers_accept_valid_baseline_and_csp_framing():
    from security_checks import inspect_standard_security_headers

    findings = inspect_standard_security_headers(
        {
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=(), microphone=()",
            "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
        },
        "https://shop.example/",
    )
    assert findings == []


def test_standard_security_headers_accept_x_frame_options_as_framing_fallback():
    from security_checks import inspect_standard_security_headers

    findings = inspect_standard_security_headers(
        {
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
            "x-frame-options": "DENY",
        },
        "https://shop.example/",
    )
    assert findings == []
