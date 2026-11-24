"""Health endpoint reports each database's readiness without leaking secrets."""

import pytest

from database import get_async_db
from hostinger_database import get_optional_hostinger_db
from main import app


@pytest.mark.asyncio
async def test_health_check_identifies_unconfigured_hostinger_database(client):
    async def unavailable_operational_session():
        yield None

    app.dependency_overrides[get_optional_hostinger_db] = unavailable_operational_session
    try:
        response = await client.get("/health-check")
    finally:
        app.dependency_overrides.pop(get_optional_hostinger_db, None)

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["status"] == "not_ready"
    assert detail["message"] == (
        "The Hostinger MySQL operational database is unavailable or not configured."
    )
    assert detail["licensing_database"] == {
        "engine": "postgresql",
        "connected": True,
        "schema_ready": True,
    }
    assert detail["operational_database"] == {
        "engine": "mysql",
        "connected": False,
        "schema_ready": None,
    }


@pytest.mark.asyncio
async def test_health_check_identifies_postgres_connection_failure(client):
    class UnavailablePostgresSession:
        async def execute(self, statement):
            raise RuntimeError("sensitive connection details must not be returned")

    async def unavailable_licensing_session():
        yield UnavailablePostgresSession()

    app.dependency_overrides[get_async_db] = unavailable_licensing_session
    try:
        response = await client.get("/health-check")
    finally:
        app.dependency_overrides.pop(get_async_db, None)

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["status"] == "not_ready"
    assert detail["message"] == (
        "The Supabase PostgreSQL licensing/audit database is unavailable."
    )
    assert detail["licensing_database"] == {
        "engine": "postgresql",
        "connected": False,
        "schema_ready": None,
    }
    assert detail["operational_database"] == {
        "engine": "mysql",
        "connected": None,
        "schema_ready": None,
    }
    assert "sensitive connection details" not in response.text
