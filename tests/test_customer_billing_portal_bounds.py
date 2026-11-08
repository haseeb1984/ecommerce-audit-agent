from types import SimpleNamespace

import pytest
from fastapi import Response

import main


class _ScalarRows:
    def __init__(self, values):
        self.values = values

    def scalars(self):
        return self

    def all(self):
        return self.values


class _BillingPortalDB:
    def __init__(self, customer_ids, subscription_ids):
        self.results = [_ScalarRows(customer_ids), _ScalarRows(subscription_ids)]
        self.queries = []

    async def execute(self, query):
        self.queries.append(query)
        return self.results[len(self.queries) - 1]


@pytest.mark.asyncio
async def test_customer_billing_portal_uses_bounded_distinct_recent_paddle_ids(monkeypatch):
    db = _BillingPortalDB(
        customer_ids=["ctm_customer123", "invalid-customer"],
        subscription_ids=["sub_recent123", "sub_older456", "invalid-subscription"],
    )
    paddle_call = {}

    async def fake_to_thread(function, *args, **kwargs):
        paddle_call["function"] = function
        paddle_call["args"] = args
        return {"data": {"urls": {"general": {"overview": "https://customer-portal.paddle.com/session"}}}}

    monkeypatch.setenv("PADDLE_API_KEY", "configured")
    monkeypatch.setattr(main.asyncio, "to_thread", fake_to_thread)
    monkeypatch.setattr(main, "_is_valid_paddle_hosted_url", lambda value: value.startswith("https://customer-portal.paddle.com/"))

    response = Response()
    result = await main.create_account_billing_portal(
        response,
        license_obj=SimpleNamespace(id=77),
        db=db,
    )

    assert result == {
        "portal_url": "https://customer-portal.paddle.com/session",
        "expires_in_seconds": 900,
    }
    assert len(db.queries) == 2
    assert all(query._limit_clause.value == 100 for query in db.queries)
    assert all(len(query._group_by_clauses) == 1 for query in db.queries)
    assert paddle_call["function"] is main._paddle_api_request
    assert paddle_call["args"] == (
        "/customers/ctm_customer123/portal-sessions",
        "POST",
        {"subscription_ids": ["sub_recent123", "sub_older456"]},
    )
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["pragma"] == "no-cache"


@pytest.mark.asyncio
async def test_customer_billing_portal_returns_conflict_without_customer_link(monkeypatch):
    db = _BillingPortalDB(customer_ids=["malformed"], subscription_ids=[])
    monkeypatch.setenv("PADDLE_API_KEY", "configured")

    with pytest.raises(main.HTTPException) as exc:
        await main.create_account_billing_portal(
            Response(),
            license_obj=SimpleNamespace(id=77),
            db=db,
        )

    assert exc.value.status_code == 409
    assert len(db.queries) == 1
