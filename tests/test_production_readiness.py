"""Production configuration readiness contract tests."""

import pytest

from scripts.check_production_readiness import (
    REQUIRED_ENV_GROUPS,
    _configuration_status,
    _valid_scan_worker_url,
)


@pytest.mark.parametrize(
    "value",
    [
        "https://app.example.com/internal/scan-worker/run",
        "https://worker.example.com/run?batch=5",
    ],
)
def test_scan_worker_url_accepts_secure_absolute_urls(value):
    assert _valid_scan_worker_url(value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "http://app.example.com/internal/scan-worker/run",
        "https:///internal/scan-worker/run",
        "https://user:password@app.example.com/run",
        "https://app.example.com/run#fragment",
        "not-a-url",
    ],
)
def test_scan_worker_url_rejects_insecure_or_malformed_values(value):
    assert not _valid_scan_worker_url(value)


def _set_complete_configuration(monkeypatch):
    values = {
        "ADMIN_API_KEY": "admin-test-key",
        "PADDLE_API_KEY": "paddle-test-key",
        "PADDLE_WEBHOOK_SECRET": "paddle-webhook-test",
        "PADDLE_CLIENT_TOKEN": "paddle-client-test",
        "PADDLE_PRICE_ID_STARTER": "pri_starter123",
        "PADDLE_PRICE_ID_PRO": "pri_pro123",
        "PADDLE_PRICE_ID_BUSINESS": "pri_business123",
        "SMTP_HOST": "smtp.example.com",
        "SMTP_FROM": "noreply@example.com",
        "GOOGLE_PAGESPEED_API_KEY": "pagespeed-test",
        "GROQ_API_KEY": "groq-test",
        "ACCOUNT_AUTH_SECRET": "a" * 40,
        "HOSTINGER_DATABASE_URL": "mysql+asyncmy://test:test@localhost/test",
        "PUBLIC_APP_URL": "https://app.example.com",
        "PADDLE_ENVIRONMENT": "sandbox",
        "SMTP_PORT": "587",
        "SMTP_TLS_MODE": "starttls",
        "DATABASE_SSL": "true",
        "HOSTINGER_DB_SSL": "true",
        "CRON_SECRET": "cron-test-secret",
        "SCAN_WORKER_URL": "https://app.example.com/internal/scan-worker/run",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_readiness_requires_worker_url_and_scheduler_secret(monkeypatch, capsys):
    _set_complete_configuration(monkeypatch)
    monkeypatch.delenv("SCAN_WORKER_URL")

    failed, details = _configuration_status()

    assert "scheduled_scan_worker" in failed
    assert any("SCAN_WORKER_URL" in detail for detail in details)
    assert "scheduled_scan_worker" in REQUIRED_ENV_GROUPS


@pytest.mark.parametrize("secret_name", ["CRON_SECRET", "SCAN_WORKER_TOKEN"])
def test_readiness_accepts_configured_worker_url_and_supported_secret(monkeypatch, secret_name):
    _set_complete_configuration(monkeypatch)
    monkeypatch.delenv("CRON_SECRET")
    monkeypatch.setenv(secret_name, "worker-test-secret")

    failed, details = _configuration_status()

    assert "scheduled_scan_worker" not in failed
    assert not any("SCAN_WORKER_URL" in detail for detail in details)
