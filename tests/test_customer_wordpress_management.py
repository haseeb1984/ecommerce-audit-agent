from types import SimpleNamespace

import pytest
from fastapi import Response

from main import list_account_wordpress_sites


class _ScalarRows:
    def all(self):
        return []


class _Result:
    def scalars(self):
        return _ScalarRows()


class _OperationalSession:
    def __init__(self):
        self.statement = None

    async def execute(self, statement):
        self.statement = statement
        return _Result()


@pytest.mark.asyncio
async def test_customer_wordpress_inventory_prioritizes_active_site_before_history():
    operational_db = _OperationalSession()
    response = Response()

    result = await list_account_wordpress_sites(
        response=response,
        license_obj=SimpleNamespace(license_key="license-test"),
        operational_db=operational_db,
    )

    sql = str(operational_db.statement.compile(compile_kwargs={"literal_binds": True}))
    active_order = "CASE WHEN wordpress_installations.status = 'active' THEN 0 ELSE 1 END ASC"

    assert active_order in sql
    assert sql.index(active_order) < sql.index("wordpress_installations.last_seen_at DESC")
    assert "LIMIT 100" in sql
    assert result == {"items": []}
    assert response.headers["Cache-Control"] == "no-store, private"
    assert response.headers["Pragma"] == "no-cache"
