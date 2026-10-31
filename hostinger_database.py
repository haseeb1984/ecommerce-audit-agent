"""Hostinger MySQL connection for SaaS operational data.

Supabase/PostgreSQL remains isolated in database.py for licensing and audit-engine
records. This module deliberately owns a separate SQLAlchemy metadata registry.
"""
import os
import ssl
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base

HostingerBase = declarative_base()

HOSTINGER_DATABASE_URL = os.getenv("HOSTINGER_DATABASE_URL", "").strip()
if HOSTINGER_DATABASE_URL.startswith("mysql://"):
    HOSTINGER_DATABASE_URL = HOSTINGER_DATABASE_URL.replace(
        "mysql://", "mysql+asyncmy://", 1
    )
elif HOSTINGER_DATABASE_URL.startswith("mariadb://"):
    HOSTINGER_DATABASE_URL = HOSTINGER_DATABASE_URL.replace(
        "mariadb://", "mysql+asyncmy://", 1
    )
elif HOSTINGER_DATABASE_URL.startswith("mysql+aiomysql://"):
    # Allow an explicitly selected async driver without rewriting it.
    pass

hostinger_engine = None
HostingerAsyncSessionLocal = None

if HOSTINGER_DATABASE_URL:
    if not HOSTINGER_DATABASE_URL.startswith(
        ("mysql+asyncmy://", "mysql+aiomysql://")
    ):
        raise RuntimeError(
            "HOSTINGER_DATABASE_URL must use an async MySQL driver "
            "(mysql+asyncmy:// or mysql+aiomysql://)."
        )
    hostinger_ssl_enabled = os.getenv("HOSTINGER_DB_SSL", "true").strip().lower() not in {"0", "false", "no"}
    hostinger_connect_args = {"ssl": ssl.create_default_context()} if hostinger_ssl_enabled else {}
    hostinger_engine = create_async_engine(
        HOSTINGER_DATABASE_URL,
        connect_args=hostinger_connect_args,
        pool_pre_ping=True,
        pool_recycle=int(os.getenv("HOSTINGER_DB_POOL_RECYCLE", "1800")),
        pool_size=int(os.getenv("HOSTINGER_DB_POOL_SIZE", "5")),
        max_overflow=int(os.getenv("HOSTINGER_DB_MAX_OVERFLOW", "10")),
        pool_timeout=int(os.getenv("HOSTINGER_DB_POOL_TIMEOUT", "20")),
    )
    HostingerAsyncSessionLocal = async_sessionmaker(
        bind=hostinger_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )


async def get_hostinger_db():
    """Yield a Hostinger operational-data session; fail closed if not configured."""
    if HostingerAsyncSessionLocal is None:
        raise RuntimeError("Hostinger operational database is not configured.")
    async with HostingerAsyncSessionLocal() as session:
        yield session



async def ensure_hostinger_schema() -> None:
    """Create missing operational tables for deployments using this service's schema."""
    if hostinger_engine is None:
        raise RuntimeError("Hostinger operational database is not configured.")
    # Importing the models registers all operational tables on HostingerBase.
    import hostinger_models  # noqa: F401
    from sqlalchemy import inspect, text

    async with hostinger_engine.begin() as connection:
        await connection.run_sync(HostingerBase.metadata.create_all)

        def ensure_email_outbox_scope(sync_connection):
            inspector = inspect(sync_connection)
            table_name = "customer_email_identity_sync_outbox"
            columns = {column["name"] for column in inspector.get_columns(table_name)}
            if "license_key" not in columns:
                sync_connection.execute(text(
                    "ALTER TABLE customer_email_identity_sync_outbox "
                    "ADD COLUMN license_key VARCHAR(100) NULL"
                ))
            indexes = {index["name"] for index in inspect(sync_connection).get_indexes(table_name)}
            if "ix_customer_email_identity_outbox_license" not in indexes:
                sync_connection.execute(text(
                    "CREATE INDEX ix_customer_email_identity_outbox_license "
                    "ON customer_email_identity_sync_outbox (license_key)"
                ))

        await connection.run_sync(ensure_email_outbox_scope)
