import os

# Set environment before importing the application modules.
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://postgres:postgres@127.0.0.1:5432/ecommerce_audit_test",
)
os.environ.setdefault("DATABASE_SSL", "false")
os.environ.setdefault(
    "HOSTINGER_DATABASE_URL",
    "mysql+asyncmy://root:root@127.0.0.1:3306/ecommerce_audit_test",
)
os.environ.setdefault("HOSTINGER_DB_SSL", "false")
os.environ.setdefault("GROQ_API_KEY", "test-only-key")

# The autouse fixtures below drop and recreate both schemas. Refuse to run them
# against a database whose name is not clearly dedicated to tests.
from urllib.parse import urlsplit

for _database_env in ("DATABASE_URL", "HOSTINGER_DATABASE_URL"):
    _database_name = urlsplit(os.environ[_database_env]).path.strip("/").split("/")[-1].lower()
    if "test" not in _database_name and os.getenv("ALLOW_DESTRUCTIVE_TEST_DATABASE_RESET") != "1":
        raise RuntimeError(
            f"{_database_env} must target a dedicated database with 'test' in its name; "
            "set ALLOW_DESTRUCTIVE_TEST_DATABASE_RESET=1 only for an explicitly isolated test database."
        )

import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from sqlalchemy import delete

from database import Base, engine
from hostinger_database import HostingerBase, hostinger_engine
import hostinger_models  # noqa: F401 - register all operational models
from main import app


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def hostinger_schema():
    """Create the operational schema once; per-test cleanup truncates its rows."""
    if hostinger_engine is None:
        yield
        return
    async with hostinger_engine.begin() as connection:
        await connection.run_sync(HostingerBase.metadata.drop_all)
        await connection.run_sync(HostingerBase.metadata.create_all)
    yield
    await hostinger_engine.dispose()


@pytest_asyncio.fixture(autouse=True, loop_scope="session")
async def clean_database(hostinger_schema):
    """Reset isolated test data without repeatedly rebuilding the MySQL schema."""
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    if hostinger_engine is not None:
        async with hostinger_engine.begin() as connection:
            for table in reversed(HostingerBase.metadata.sorted_tables):
                await connection.execute(delete(table))
    yield
    await engine.dispose()


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as test_client:
        yield test_client
