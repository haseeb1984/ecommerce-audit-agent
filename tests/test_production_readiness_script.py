"""Regression tests for the read-only production readiness CLI."""
from __future__ import annotations

import os
import runpy
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_production_readiness.py"


def test_missing_database_url_fails_with_actionable_message() -> None:
    env = os.environ.copy()
    env.pop("DATABASE_URL", None)

    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    assert result.returncode == 2
    assert "FAIL database_url: DATABASE_URL is not configured." in result.stdout
    assert "readiness_check" not in result.stderr

def test_schema_gate_includes_application_runtime_columns() -> None:
    import models  # noqa: F401
    from database import Base

    contract = runpy.run_path(str(SCRIPT))["_postgres_schema_contract"]
    _, required_columns, _ = contract(Base)

    assert {"client_name", "expires_at", "created_at"} <= required_columns["software_licenses"]
    assert {"created_at", "key_prefix", "api_key_hash"} <= required_columns["api_keys"]
    assert {"contact_email", "email_subject", "email_body", "source_channel"} <= required_columns["audit_leads"]
    assert {
        "transaction_id", "subscription_id", "paddle_customer_id",
        "recipient_email", "updated_at",
    } <= required_columns["payment_webhook_events"]
    assert {
        "monthly_audit_allowance", "max_concurrent_audits", "is_active",
    } <= required_columns["saas_plan_packages"]

def test_core_schema_enforces_unique_paddle_price_mapping() -> None:
    migration = ROOT / "migrations" / "2026-10-28-core-saas-schema.sql"
    sql = migration.read_text(encoding="utf-8")

    assert "uq_saas_plan_packages_paddle_price_id" in sql
    assert "ON saas_plan_packages (paddle_price_id)" in sql
    assert "WHERE paddle_price_id IS NOT NULL" in sql

def test_schema_gate_requires_critical_operational_indexes() -> None:
    import models  # noqa: F401
    from database import Base

    contract = runpy.run_path(str(SCRIPT))["_postgres_schema_contract"]
    _, _, required_indexes = contract(Base)

    assert "uq_saas_plan_packages_paddle_price_id" in required_indexes
    assert "ix_audit_reports_license_created" in required_indexes
    assert "ix_audit_quota_reservations_license_created" in required_indexes
    assert "ix_payment_webhook_events_transaction_id" in required_indexes
    assert "ix_payment_webhook_events_subscription_id" in required_indexes



def test_public_app_url_readiness_requires_https_host_without_userinfo() -> None:
    namespace = runpy.run_path(str(SCRIPT))
    validate = namespace["_valid_public_app_url"]
    assert namespace["REQUIRED_ENV_GROUPS"]["public_app_url"] == ("PUBLIC_APP_URL",)

    assert validate("https://app.example.com") is True
    assert validate("https://app.example.com/") is True
    assert validate("http://app.example.com") is False
    assert validate("https:///missing-host") is False
    assert validate("https://user:password@app.example.com") is False
    assert validate("") is False



def test_configuration_gate_uses_public_app_url_validator() -> None:
    from unittest.mock import patch

    namespace = runpy.run_path(str(SCRIPT))
    configured = {
        "ADMIN_API_KEY": "admin-test",
        "PADDLE_API_KEY": "paddle-test",
        "PADDLE_WEBHOOK_SECRET": "webhook-test",
        "PADDLE_CLIENT_TOKEN": "client-test",
        "PADDLE_PRICE_ID_STARTER": "pri_starter",
        "PADDLE_PRICE_ID_PRO": "pri_pro",
        "PADDLE_PRICE_ID_BUSINESS": "pri_business",
        "SMTP_HOST": "smtp.example.com",
        "SMTP_FROM": "audit@example.com",
        "GOOGLE_PAGESPEED_API_KEY": "pagespeed-test",
        "GROQ_API_KEY": "groq-test",
        "ACCOUNT_AUTH_SECRET": "a" * 32,
        "HOSTINGER_DATABASE_URL": "mysql+asyncmy://test",
        "PUBLIC_APP_URL": "http://app.example.com",
        "SCAN_WORKER_TOKEN": "worker-test",
        "PADDLE_ENVIRONMENT": "sandbox",
        "SMTP_PORT": "587",
        "SMTP_TLS_MODE": "starttls",
    }
    with patch.dict(os.environ, configured, clear=True):
        failed, details = namespace["_configuration_status"]()

    assert "public_app_url" in failed
    assert any("PUBLIC_APP_URL must be an HTTPS URL" in detail for detail in details)



def test_hostinger_schema_contract_includes_tenant_and_workspace_foreign_keys():
    import hostinger_models  # noqa: F401 - register all operational models
    from hostinger_database import HostingerBase

    namespace = runpy.run_path(str(SCRIPT))
    required = namespace["_hostinger_foreign_key_contract"](HostingerBase)

    assert (
        "agency_client_workspaces",
        ("agency_id",),
        "agency_accounts",
        ("id",),
    ) in required
    assert (
        "agency_client_websites",
        ("workspace_id",),
        "agency_client_workspaces",
        ("id",),
    ) in required
    assert (
        "agency_workspace_access",
        ("team_member_id",),
        "agency_team_members",
        ("id",),
    ) in required


def test_hostinger_schema_readiness_reports_missing_foreign_key_signatures():
    namespace = runpy.run_path(str(SCRIPT))
    required = {
        ("agency_client_workspaces", ("agency_id",), "agency_accounts", ("id",)),
        ("agency_workspace_access", ("workspace_id",), "agency_client_workspaces", ("id",)),
    }
    observed = {
        ("agency_client_workspaces", ("agency_id",), "agency_accounts", ("id",)),
    }

    assert namespace["_missing_foreign_keys"](required, observed) == {
        ("agency_workspace_access", ("workspace_id",), "agency_client_workspaces", ("id",))
    }
