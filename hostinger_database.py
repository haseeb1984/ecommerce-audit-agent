"""Connection to SaaS operational tables in the existing Hostinger WordPress MySQL database.

HOSTINGER_DATABASE_URL must point to the same physical database used by WordPress.
Supabase/PostgreSQL remains isolated in database.py for licensing and audit-engine
records. This module owns a separate SQLAlchemy metadata registry, not a separate DB.
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


async def get_optional_hostinger_db():
    """Yield an operational session when configured, or None for readiness reporting."""
    if HostingerAsyncSessionLocal is None:
        yield None
        return
    async with HostingerAsyncSessionLocal() as session:
        yield session
