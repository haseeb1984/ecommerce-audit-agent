import os
import ssl
from sqlalchemy.orm import declarative_base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool

Base = declarative_base()

DATABASE_URL = os.getenv("DATABASE_URL", "")

# Standardize postgres connection string for asyncpg
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgresql://") and not DATABASE_URL.startswith("postgresql+asyncpg://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

# Configure SSL context explicitly
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# NullPool prevents reusing dead socket file descriptors across serverless executions
engine = create_async_engine(
    DATABASE_URL,
    poolclass=NullPool,
    connect_args={
        "ssl": ssl_context,
        "timeout": 10.0,
        "command_timeout": 10.0,
        "server_settings": {
            "tcp_user_timeout": "10000"
        }
    }
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

async def get_async_db():
    async with AsyncSessionLocal() as session:
        yield session
