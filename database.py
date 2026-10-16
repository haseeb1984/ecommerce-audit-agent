import os
import ssl

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

# TLS verification is enabled by default. Only disable it explicitly for local test databases.
connect_args = {
    "timeout": 10.0,
    "command_timeout": 10.0,
    "server_settings": {
        "tcp_user_timeout": "10000"
    },
}
if os.getenv("DATABASE_SSL", "true").lower() not in {"0", "false", "no"}:
    connect_args["ssl"] = ssl.create_default_context()

engine = create_async_engine(
    DATABASE_URL,
    poolclass=NullPool,
    connect_args=connect_args,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_async_db():
    async with AsyncSessionLocal() as session:
        yield session
