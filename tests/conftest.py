import os

# Set environment before importing the application modules.
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://postgres:postgres@127.0.0.1:5432/ecommerce_audit_test",
)
os.environ.setdefault("DATABASE_SSL", "false")
os.environ.setdefault("GROQ_API_KEY", "test-only-key")

import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from database import Base, engine
from main import app


@pytest_asyncio.fixture(autouse=True)
async def clean_database():
    """Use a fresh schema for each test; intended for a dedicated test database only."""
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    yield


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as test_client:
        yield test_client
