import os
from urllib.parse import urlparse, urlunparse
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base

def get_async_db_url() -> str:
    raw_url = os.getenv("DATABASE_URL", "")
    if not raw_url:
        # Fallback or local dev string
        raw_url = "postgresql://postgres:password@db.pfzwlbpgcoosxiqoavhn.supabase.co:5432/postgres"

    # 1. Convert driver prefix for asyncpg
    if raw_url.startswith("postgresql://"):
        raw_url = raw_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif raw_url.startswith("postgres://"):
        raw_url = raw_url.replace("postgres://", "postgresql+asyncpg://", 1)

    # 2. Auto-switch port to 6543 if running on Vercel or if explicitly set
    is_vercel = os.getenv("VERCEL") == "1"
    parsed = urlparse(raw_url)
    
    if is_vercel and (parsed.port == 5432 or parsed.port is None):
        hostname = parsed.hostname
        user_pass = f"{parsed.username}:{parsed.password}" if parsed.username else ""
        new_netloc = f"{user_pass}@{hostname}:6543" if user_pass else f"{hostname}:6543"
        parsed = parsed._replace(netloc=new_netloc)

    return urlunparse(parsed)

DATABASE_URL = get_async_db_url()

# Disable statement caching to ensure compatibility with Supavisor transaction pooler
engine = create_async_engine(
    DATABASE_URL,
    connect_args={"statement_cache_size": 0, "prepared_statement_cache_size": 0},
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
    echo=False
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

Base = declarative_base()

async def get_async_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
