"""Health endpoint must report missing operational DB configuration as not-ready."""

import pytest

from database import get_async_db
from hostinger_database import get_optional_hostinger_db
from main import app


@pytest.mark.asyncio
async def test_health_check_returns_structured_503_when_hostinger_is_not_configured(client):
    async def unavailable_session():
        yield None

    app.dependency_overrides[get_async_db] = unavailable_session
    app.dependency_overrides[get_optional_hostinger_db] = unavailable_session
    try:
        response = await client.get("/health-check")
    finally:
        app.dependency_overrides.pop(get_async_db, None)
        app.dependency_overrides.pop(get_optional_hostinger_db, None)

    assert response.status_code == 503
    assert response.json()["detail"]["status"] == "not_ready"
    assert response.json()["detail"]["message"] == "One or more required databases are unavailable."
