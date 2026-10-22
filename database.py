import os
import ssl
from pathlib import Path

from sqlalchemy.orm import declarative_base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool

Base = declarative_base()

DATABASE_URL = os.getenv("DATABASE_URL", "")

# Standardize postgres connection string for asyncpg.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgresql://") and not DATABASE_URL.startswith("postgresql+asyncpg://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

# TLS verification is enabled by default. The Supabase root CA is added to
# the platform's default trust store so both standard public CAs and Supabase's
# database certificate chain can be validated.
connect_args = {
    "timeout": 10.0,
    "command_timeout": 10.0,
    # Supabase transaction-mode poolers may reuse backend connections across logical
    # clients. Disable asyncpg statement caching to avoid stale/duplicate prepared
    # statement names when NullPool opens a fresh client connection per invocation.
    "statement_cache_size": 0,
    "server_settings": {
        "tcp_user_timeout": "10000"
    },
}
if os.getenv("DATABASE_SSL", "true").lower() not in {"0", "false", "no"}:
    ssl_context = ssl.create_default_context()
    supabase_ca = Path(__file__).resolve().parent / "certs" / "prod-ca-2021.crt"
    if not supabase_ca.is_file():
        raise FileNotFoundError(f"Required Supabase CA certificate not found: {supabase_ca}")
    ssl_context.load_verify_locations(cafile=str(supabase_ca))
    connect_args["ssl"] = ssl_context

engine = create_async_engine(
    DATABASE_URL,
    poolclass=NullPool,
    connect_args=connect_args,
    # Also disable SQLAlchemy asyncpg dialect caching for transaction-pooler safety.
    prepared_statement_cache_size=0,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_async_db():
    async with AsyncSessionLocal() as session:
        yield session
