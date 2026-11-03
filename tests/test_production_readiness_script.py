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
    validate = runpy.run_path(str(SCRIPT))["_valid_public_app_url"]

    assert validate("https://app.example.com") is True
    assert validate("https://app.example.com/") is True
    assert validate("http://app.example.com") is False
    assert validate("https:///missing-host") is False
    assert validate("https://user:password@app.example.com") is False
    assert validate("") is False
