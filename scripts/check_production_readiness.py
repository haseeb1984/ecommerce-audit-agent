#!/usr/bin/env python3
"""Read-only production schema and integration readiness check.

Run from the repository root with the same DATABASE_URL and DATABASE_SSL
settings as the deployment. This script never prints secret values, connection
strings, customer data, or credential material. It never applies migrations.
"""
import asyncio
import os
import re
import sys


# This is an additional PostgreSQL partial index not represented by SQLAlchemy's
# portable metadata. All mapped columns and ordinary indexes are derived from
# the live ORM metadata to prevent this check drifting from application models.
EXTRA_REQUIRED_INDEXES = {
    "uq_saas_plan_packages_paddle_price_id",
}

EXTRA_REQUIRED_TABLES = {
    "saas_admin_customer_notes",
}

REQUIRED_ENV_GROUPS = {
    "admin_access": ("ADMIN_API_KEY",),
    "paddle_checkout_and_provisioning": (
        "PADDLE_API_KEY", "PADDLE_WEBHOOK_SECRET", "PADDLE_CLIENT_TOKEN",
    ),
    "paddle_price_catalog": (
        "PADDLE_PRICE_ID_STARTER", "PADDLE_PRICE_ID_PRO", "PADDLE_PRICE_ID_BUSINESS",
    ),
    "smtp_delivery": ("SMTP_HOST", "SMTP_FROM"),
    "pagespeed_audits": ("GOOGLE_PAGESPEED_API_KEY", "PAGE_SPEED_API_KEY"),
    "ai_provider": ("GROQ_API_KEY",),
    "customer_account_auth": ("ACCOUNT_AUTH_SECRET",),
    "hostinger_operational_database": ("HOSTINGER_DATABASE_URL",),
    "scheduled_scan_worker": ("SCAN_WORKER_TOKEN",),
}


def _configuration_status() -> tuple[list[str], list[str]]:
    """Return failed configuration group names and non-secret explanations."""
    failed: list[str] = []
    details: list[str] = []

    for group, names in REQUIRED_ENV_GROUPS.items():
        if group == "pagespeed_audits":
            ready = any(os.getenv(name, "").strip() for name in names)
        elif group == "paddle_price_catalog":
            ready = all(
                re.fullmatch(r"pri_[A-Za-z0-9]+", os.getenv(name, "").strip())
                for name in names
            )
        elif group == "customer_account_auth":
            ready = len(os.getenv("ACCOUNT_AUTH_SECRET", "")) >= 32
            if not ready:
                details.append("ACCOUNT_AUTH_SECRET must contain at least 32 characters")
        else:
            ready = all(os.getenv(name, "").strip() for name in names)
        print(f"configuration_{group}: {'PASS' if ready else 'FAIL'}")
        if not ready:
            failed.append(group)

    environment = os.getenv("PADDLE_ENVIRONMENT", "sandbox").strip().lower()
    paddle_environment_ready = environment in {"sandbox", "production"}
    print(f"configuration_paddle_environment: {'PASS' if paddle_environment_ready else 'FAIL'}")
    if not paddle_environment_ready:
        failed.append("paddle_environment")
        details.append("PADDLE_ENVIRONMENT must be sandbox or production")

    try:
        port = int(os.getenv("SMTP_PORT", "587").strip())
        smtp_port_ready = 1 <= port <= 65535
    except (TypeError, ValueError):
        smtp_port_ready = False
    if not smtp_port_ready:
        failed.append("smtp_port")
        details.append("SMTP_PORT must be an integer from 1 to 65535")

    tls_mode = os.getenv("SMTP_TLS_MODE", "starttls").strip().lower()
    if tls_mode not in {"starttls", "ssl"}:
        failed.append("smtp_tls_mode")
        details.append("SMTP_TLS_MODE must be starttls or ssl")

    username = os.getenv("SMTP_USERNAME", "").strip()
    password = os.getenv("SMTP_PASSWORD", "")
    if bool(username) != bool(password):
        failed.append("smtp_credentials")
        details.append("SMTP_USERNAME and SMTP_PASSWORD must both be set or both be empty")

    if os.getenv("DATABASE_SSL", "true").strip().lower() in {"0", "false", "no"}:
        details.append("DATABASE_SSL is disabled; production database TLS verification is expected")
        failed.append("database_tls")
    if os.getenv("HOSTINGER_DB_SSL", "true").strip().lower() in {"0", "false", "no"}:
        details.append("HOSTINGER_DB_SSL is disabled; production Hostinger MySQL TLS verification is expected")
        failed.append("hostinger_database_tls")

    return failed, details


async def main() -> int:
    # Validate before importing database.py, which constructs its engine at import time.
    if not os.getenv("DATABASE_URL", "").strip():
        print("FAIL database_url: DATABASE_URL is not configured.")
        return 2

    from sqlalchemy import text
    from database import AsyncSessionLocal, Base
    # Register every mapped table before deriving the schema contract.
    import models  # noqa: F401

    required_tables = set(Base.metadata.tables) | EXTRA_REQUIRED_TABLES
    required_columns = {
        table_name: {column.name for column in Base.metadata.tables[table_name].columns}
        for table_name in Base.metadata.tables
    }
    required_indexes = {
        index.name
        for table in Base.metadata.tables.values()
        for index in table.indexes
        if index.name
    } | EXTRA_REQUIRED_INDEXES

    missing: list[str] = []
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

    for table in sorted(required_tables):
        if table not in observed:
            missing.append(f"table:{table}")
            continue
        for column in sorted(required_columns.get(table, set()) - observed[table]):
            missing.append(f"column:{table}.{column}")

    observed_indexes = {row[0] for row in index_rows}
    missing_indexes = sorted(required_indexes - observed_indexes)

    print(f"postgres_connectivity: PASS ({len(observed)} tables visible in current schema)")
    print("postgres_schema_readiness: " + ("PASS" if not missing and not missing_indexes else "FAIL"))
    for item in missing:
        print(f"postgres_missing_schema_item: {item}")
    for index_name in missing_indexes:
        print(f"postgres_missing_schema_index: {index_name}")

    # The operational database is a separate schema owner and must be checked
    # independently; a healthy Supabase connection does not imply Hostinger is ready.
    hostinger_missing: list[str] = []
    hostinger_missing_indexes: list[str] = []
    try:
        from sqlalchemy import UniqueConstraint
        from hostinger_database import HostingerBase, hostinger_engine
        import hostinger_models  # noqa: F401

        if hostinger_engine is None:
            print("hostinger_connectivity: FAIL (HOSTINGER_DATABASE_URL is not configured)")
            hostinger_missing.append("connection:HOSTINGER_DATABASE_URL")
        else:
            hostinger_required_tables = set(HostingerBase.metadata.tables)
            hostinger_required_columns = {
                table_name: {column.name for column in table.columns}
                for table_name, table in HostingerBase.metadata.tables.items()
            }
            hostinger_required_indexes = {
                index.name
                for table in HostingerBase.metadata.tables.values()
                for index in table.indexes
                if index.name
            } | {
                constraint.name
                for table in HostingerBase.metadata.tables.values()
                for constraint in table.constraints
                if isinstance(constraint, UniqueConstraint) and constraint.name
            }
            async with hostinger_engine.connect() as operational_db:
                hostinger_rows = (await operational_db.execute(text("""
                    SELECT table_name, column_name
                    FROM information_schema.columns
                    WHERE table_schema = DATABASE()
                """))).all()
                hostinger_index_rows = (await operational_db.execute(text("""
                    SELECT DISTINCT index_name
                    FROM information_schema.statistics
                    WHERE table_schema = DATABASE()
                """))).all()
            hostinger_observed: dict[str, set[str]] = {}
            for table_name, column_name in hostinger_rows:
                hostinger_observed.setdefault(table_name, set()).add(column_name)
            for table_name in sorted(hostinger_required_tables):
                if table_name not in hostinger_observed:
                    hostinger_missing.append(f"table:{table_name}")
                    continue
                for column in sorted(hostinger_required_columns[table_name] - hostinger_observed[table_name]):
                    hostinger_missing.append(f"column:{table_name}.{column}")
            hostinger_observed_indexes = {row[0] for row in hostinger_index_rows}
            hostinger_missing_indexes = sorted(hostinger_required_indexes - hostinger_observed_indexes)
            print(f"hostinger_connectivity: PASS ({len(hostinger_observed)} tables visible in current database)")
            print("hostinger_schema_readiness: " + ("PASS" if not hostinger_missing and not hostinger_missing_indexes else "FAIL"))
            for item in hostinger_missing:
                print(f"hostinger_missing_schema_item: {item}")
            for index_name in hostinger_missing_indexes:
                print(f"hostinger_missing_schema_index: {index_name}")
            await hostinger_engine.dispose()
    except Exception as exc:
        hostinger_missing.append(f"inspection:{type(exc).__name__}")
        print(f"hostinger_connectivity: FAIL ({type(exc).__name__})", file=sys.stderr)

    failed_configuration, details = _configuration_status()
    for group in failed_configuration:
        print(f"missing_configuration_group: {group}")
    for detail in details:
        print(f"configuration_detail: {detail}")

    return 1 if missing or missing_indexes or hostinger_missing or hostinger_missing_indexes or failed_configuration else 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except Exception as exc:
        # Suppress exception text: DB/driver errors can include host and connection details.
        print(f"FAIL readiness_check: database or schema query failed ({type(exc).__name__}).", file=sys.stderr)
        sys.exit(2)
