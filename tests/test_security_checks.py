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
