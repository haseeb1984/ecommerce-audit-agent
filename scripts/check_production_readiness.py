#!/usr/bin/env python3
"""Read-only production schema/configuration readiness check.

Run from the repository root in an environment with the same DATABASE_URL and
DATABASE_SSL settings as the deployment. The script never prints connection
strings, environment-variable values, customer data, or credential material.
It does not apply migrations or modify database state.
"""
import asyncio
import os
import sys

from sqlalchemy import text


REQUIRED_COLUMNS = {
    # Keep this list aligned with every mapped field used by application queries,
    # not just the minimum fields needed for a successful health-check response.
    "software_licenses": {
        "id", "license_key", "client_name", "tier", "max_monthly_audits",
        "is_active", "expires_at", "created_at",
    },
    "api_keys": {"id", "license_id", "api_key_hash", "key_prefix", "created_at"},
    "audit_leads": {
        "id", "license_id", "domain", "mobile_score", "speed_index_sec",
        "contact_email", "revenue_leak_hypothesis", "email_subject", "email_body",
        "source_channel", "created_at",
    },
    "audit_quota_reservations": {"id", "license_id", "created_at", "expires_at"},
    "audit_reports": {
        "id", "license_id", "domain", "pdf_bytes", "coverage_json",
        "finding_count", "created_at",
    },
    "payment_webhook_events": {
        "event_id", "status", "license_id", "transaction_id", "subscription_id",
        "paddle_customer_id", "recipient_email", "created_at", "updated_at",
    },
    "saas_plan_packages": {
        "tier", "label", "monthly_audit_allowance", "max_concurrent_audits",
        "paddle_price_id", "is_active", "created_at", "updated_at",
    },
    "saas_operation_events": {"id", "event_type", "license_id", "domain", "error_type", "created_at"},
    "saas_admin_action_logs": {"id", "action", "entity_type", "entity_id", "details_json", "created_at"},
}

# Indexes that protect uniqueness or keep high-volume account-scoped queries bounded.
# Compare names against pg_indexes; the check is read-only and never creates indexes.
REQUIRED_INDEXES = {
    "uq_saas_plan_packages_paddle_price_id",
    "ix_audit_reports_license_created",
    "ix_audit_quota_reservations_license_created",
    "ix_payment_webhook_events_transaction_id",
    "ix_payment_webhook_events_subscription_id",
}

REQUIRED_ENV_GROUPS = {
    "admin_access": ("ADMIN_API_KEY",),
    "paddle_checkout_and_provisioning": ("PADDLE_API_KEY", "PADDLE_WEBHOOK_SECRET", "PADDLE_CLIENT_TOKEN"),
    "smtp_delivery": ("SMTP_HOST", "SMTP_FROM"),
    "pagespeed_audits": ("GOOGLE_PAGESPEED_API_KEY", "PAGE_SPEED_API_KEY"),
    "ai_provider": ("GROQ_API_KEY",),
}


async def main() -> int:
    # Import database.py only after validating DATABASE_URL. That module builds
    # its SQLAlchemy engine at import time; importing it first masks this clear
    # configuration error with a lower-level URL parsing exception.
    if not os.getenv("DATABASE_URL", "").strip():
        print("FAIL database_url: DATABASE_URL is not configured.")
        return 2

    from database import AsyncSessionLocal

    missing: list[str] = []
    missing_indexes: list[str] = []
    missing_configuration: list[str] = []
    async with AsyncSessionLocal() as db:
        await db.execute(text("SELECT 1"))
        rows = (await db.execute(text("""
            SELECT table_name, column_name
            FROM information_schema.columns
            WHERE table_schema = current_schema()
        """))).all()
        index_rows = (await db.execute(text("""
            SELECT indexname
            FROM pg_indexes
            WHERE schemaname = current_schema()
        """))).all()

    observed: dict[str, set[str]] = {}
    for table_name, column_name in rows:
        observed.setdefault(table_name, set()).add(column_name)

    for table, required_columns in REQUIRED_COLUMNS.items():
        if table not in observed:
            missing.append(f"table:{table}")
            continue
        for column in sorted(required_columns - observed[table]):
            missing.append(f"column:{table}.{column}")

    observed_indexes = {row[0] for row in index_rows}
    missing_indexes = sorted(REQUIRED_INDEXES - observed_indexes)

    print(f"database_connectivity: PASS ({len(observed)} tables visible in current schema)")
    print("schema_readiness: " + ("PASS" if not missing and not missing_indexes else "FAIL"))
    for item in missing:
        print(f"missing_schema_item: {item}")
    for index_name in missing_indexes:
        print(f"missing_schema_index: {index_name}")

    for group, candidates in REQUIRED_ENV_GROUPS.items():
        configured = [name for name in candidates if os.getenv(name, "").strip()]
        ready = bool(configured)
        if group == "paddle_checkout_and_provisioning":
            ready = all(os.getenv(name, "").strip() for name in candidates)
        if group == "smtp_delivery":
            ready = all(os.getenv(name, "").strip() for name in candidates)
        print(f"configuration_{group}: {'PASS' if ready else 'FAIL'}")
        if not ready:
            missing_configuration.append(group)

    for group in missing_configuration:
        print(f"missing_configuration_group: {group}")
    return 1 if missing or missing_indexes or missing_configuration else 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except Exception as exc:
        # Deliberately suppress exception text; DB/driver errors can contain host details.
        print(f"FAIL readiness_check: database or schema query failed ({type(exc).__name__}).", file=sys.stderr)
        sys.exit(2)
