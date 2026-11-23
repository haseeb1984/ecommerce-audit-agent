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
from urllib.parse import urlsplit


# This is an additional PostgreSQL partial index not represented by SQLAlchemy's
# portable metadata. All mapped columns and ordinary indexes are derived from
# the live ORM metadata to prevent this check drifting from application models.
EXTRA_REQUIRED_INDEXES = {
    "uq_saas_plan_packages_paddle_price_id",
}

EXTRA_REQUIRED_TABLES = {
    "saas_admin_customer_notes",
}

def _postgres_schema_contract(base):
    """Derive the PostgreSQL readiness contract from the registered ORM metadata."""
    required_tables = set(base.metadata.tables) | EXTRA_REQUIRED_TABLES
    required_columns = {
        table_name: {column.name for column in base.metadata.tables[table_name].columns}
        for table_name in base.metadata.tables
    }
    required_indexes = {
        index.name
        for table in base.metadata.tables.values()
        for index in table.indexes
        if index.name
    } | EXTRA_REQUIRED_INDEXES
    return required_tables, required_columns, required_indexes



def _hostinger_foreign_key_contract(base):
    """Represent operational ORM foreign keys without relying on generated names."""
    required = set()
    for table in base.metadata.tables.values():
        for constraint in table.foreign_key_constraints:
            elements = tuple(constraint.elements)
            if not elements:
                continue
            remote_tables = {element.column.table.name for element in elements}
            if len(remote_tables) != 1:
                continue
            required.add((
                table.name,
                tuple(element.parent.name for element in elements),
                next(iter(remote_tables)),
                tuple(element.column.name for element in elements),
            ))
    return required


def _missing_foreign_keys(required, observed):
    """Return required operational foreign-key signatures absent from MySQL."""
    return set(required) - set(observed)

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
    "hostinger_private_storage": ("HOSTINGER_STORAGE_BASE_URL", "HOSTINGER_STORAGE_HMAC_SECRET"),
    "public_app_url": ("PUBLIC_APP_URL",),
    "scheduled_scan_worker": ("SCAN_WORKER_URL", "CRON_SECRET"),
}


def _valid_public_app_url(value: str) -> bool:
    """Match the application requirement for secure agency invitation URLs."""
    candidate = value.strip().rstrip("/")
    if not candidate:
        return False
    try:
        parsed = urlsplit(candidate)
        return bool(
            parsed.scheme == "https"
            and parsed.hostname
            and not parsed.username
            and not parsed.password
        )
    except ValueError:
        return False


def _valid_hostinger_storage_url(value: str) -> bool:
    """Require the private storage bridge to use a credential-free HTTPS URL."""
    candidate = value.strip()
    if not candidate:
        return False
    try:
        parsed = urlsplit(candidate)
        return bool(
            parsed.scheme == "https"
            and parsed.netloc
            and not parsed.username
            and not parsed.password
            and not parsed.query
            and not parsed.fragment
            and not any(character.isspace() for character in parsed.netloc)
        )
    except ValueError:
        return False


def _valid_scan_worker_url(value: str) -> bool:
    """Require a public HTTPS endpoint for the scheduled worker invocation."""
    candidate = value.strip()
    if not candidate:
        return False
    try:
        parsed = urlsplit(candidate)
        return bool(
            parsed.scheme == "https"
            and parsed.hostname
            and not parsed.username
            and not parsed.password
            and not parsed.fragment
            and parsed.path.rstrip("/") == "/internal/scan-worker/run"
            and (parsed.port is None or 1 <= parsed.port <= 65535)
            and not any(character.isspace() for character in parsed.netloc)
        )
    except ValueError:
        return False


def _configuration_status() -> tuple[list[str], list[str]]:
    """Return failed configuration group names and non-secret explanations."""
    failed: list[str] = []
    details: list[str] = []

    for group, names in REQUIRED_ENV_GROUPS.items():
        if group == "scheduled_scan_worker":
            worker_url_ready = _valid_scan_worker_url(os.getenv("SCAN_WORKER_URL", ""))
            # The scheduled GitHub Actions workflow injects CRON_SECRET.
            # SCAN_WORKER_TOKEN is accepted by direct API invocations only.
            worker_secret_ready = bool(os.getenv("CRON_SECRET", "").strip())
            ready = worker_url_ready and worker_secret_ready
            if not worker_url_ready:
                details.append("SCAN_WORKER_URL must be a valid HTTPS URL without embedded credentials or a fragment")
            if not worker_secret_ready:
                details.append("CRON_SECRET must be configured for the scheduled GitHub Actions scan worker")
        elif group == "pagespeed_audits":
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
        elif group == "public_app_url":
            ready = _valid_public_app_url(os.getenv("PUBLIC_APP_URL", ""))
            if not ready:
                details.append("PUBLIC_APP_URL must be an HTTPS URL with a hostname and no embedded credentials")
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

    required_tables, required_columns, required_indexes = _postgres_schema_contract(Base)

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
    hostinger_missing_foreign_keys: list[tuple] = []
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
                hostinger_foreign_key_rows = (await operational_db.execute(text("""
                    SELECT table_name, constraint_name, column_name,
                           referenced_table_name, referenced_column_name, ordinal_position
                    FROM information_schema.key_column_usage
                    WHERE table_schema = DATABASE()
                      AND referenced_table_name IS NOT NULL
                    ORDER BY table_name, constraint_name, ordinal_position
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
            foreign_key_groups = {}
            for table_name, constraint_name, column_name, referenced_table, referenced_column, ordinal in hostinger_foreign_key_rows:
                group = foreign_key_groups.setdefault(
                    (table_name, constraint_name),
                    {"columns": [], "referenced_table": referenced_table, "referenced_columns": []},
                )
                group["columns"].append((ordinal, column_name))
                group["referenced_columns"].append((ordinal, referenced_column))
            hostinger_observed_foreign_keys = {
                (
                    table_name,
                    tuple(column for _, column in sorted(group["columns"])),
                    group["referenced_table"],
                    tuple(column for _, column in sorted(group["referenced_columns"])),
                )
                for (table_name, _), group in foreign_key_groups.items()
            }
            hostinger_required_foreign_keys = _hostinger_foreign_key_contract(HostingerBase)
            hostinger_missing_foreign_keys = sorted(
                _missing_foreign_keys(hostinger_required_foreign_keys, hostinger_observed_foreign_keys)
            )
            print(f"hostinger_connectivity: PASS ({len(hostinger_observed)} tables visible in current database)")
            print("hostinger_schema_readiness: " + ("PASS" if not hostinger_missing and not hostinger_missing_indexes and not hostinger_missing_foreign_keys else "FAIL"))
            for item in hostinger_missing:
                print(f"hostinger_missing_schema_item: {item}")
            for index_name in hostinger_missing_indexes:
                print(f"hostinger_missing_schema_index: {index_name}")
            for table_name, columns, referenced_table, referenced_columns in hostinger_missing_foreign_keys:
                print(
                    "hostinger_missing_foreign_key: "
                    f"{table_name}({','.join(columns)}) -> "
                    f"{referenced_table}({','.join(referenced_columns)})"
                )
            await hostinger_engine.dispose()
    except Exception as exc:
        hostinger_missing.append(f"inspection:{type(exc).__name__}")
        print(f"hostinger_connectivity: FAIL ({type(exc).__name__})", file=sys.stderr)

    failed_configuration, details = _configuration_status()
    for group in failed_configuration:
        print(f"missing_configuration_group: {group}")
    for detail in details:
        print(f"configuration_detail: {detail}")

    return 1 if missing or missing_indexes or hostinger_missing or hostinger_missing_indexes or hostinger_missing_foreign_keys or failed_configuration else 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except Exception as exc:
        # Suppress exception text: DB/driver errors can include host and connection details.
        print(f"FAIL readiness_check: database or schema query failed ({type(exc).__name__}).", file=sys.stderr)
        sys.exit(2)
