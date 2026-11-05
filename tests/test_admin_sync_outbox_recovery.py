from datetime import datetime, timezone
from types import SimpleNamespace
import pytest
from fastapi import HTTPException, Request

import main


class _Scalars:
    def __init__(self, values):
        self.values = values

    def scalars(self):
        return self

    def all(self):
        return self.values


class _RetryDB:
    def __init__(self, items):
        self.items = items
        self.statement = None
        self.committed = False

    async def execute(self, statement):
        self.statement = statement
        return _Scalars(self.items)

    async def commit(self):
        self.committed = True


def _admin_request(path="/api/v1/admin/sync-outboxes/retry"):
    return Request({
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": [(b"x-admin-key", b"test-admin-secret")],
        "query_string": b"",
        "server": ("testserver", 80),
        "scheme": "http",
        "client": ("testclient", 50000),
    })


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("queue", "model"),
    [
        ("customer_lifecycle", main.CustomerLifecycleSyncOutbox),
        ("customer_email_identity", main.CustomerEmailIdentitySyncOutbox),
    ],
)
async def test_admin_sync_outbox_retry_requeues_bounded_pending_rows(
    monkeypatch, queue, model
):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-secret")
    now_old = datetime(2026, 11, 1, tzinfo=timezone.utc)
    items = [
        SimpleNamespace(status="pending", next_attempt_at=now_old, created_at=now_old),
        SimpleNamespace(status="pending", next_attempt_at=now_old, created_at=now_old),
    ]
    db = _RetryDB(items)
    logs = []

    async def write_log(*args, **kwargs):
        logs.append((args, kwargs))

    monkeypatch.setattr(main, "_write_admin_log", write_log)
    result = await main.admin_retry_sync_outbox(
        request=_admin_request(), queue=queue, limit=2, db=db
    )

    assert result["queue"] == queue
    assert result["status"] == "queued"
    assert result["queued"] == 2
    assert result["next_worker_cycle"] is True
    checked_at = datetime.fromisoformat(result["checked_at"])
    assert all(item.next_attempt_at == checked_at for item in items)
    assert db.committed is True
    assert db.statement._for_update_arg.skip_locked is True
    assert f"FROM {model.__tablename__}" in str(db.statement)
    assert "status" in str(db.statement)
    assert len(logs) == 1
    assert logs[0][0][1] == "sync_outbox.retry_queued"
    assert logs[0][0][2] == queue
    assert logs[0][0][4] == {"requested_limit": 2, "queued": 2}


@pytest.mark.asyncio
async def test_admin_sync_outbox_retry_reports_empty_queue(monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-secret")
    db = _RetryDB([])
    async def write_log(*args, **kwargs):
        return None

    monkeypatch.setattr(main, "_write_admin_log", write_log)
    result = await main.admin_retry_sync_outbox(
        request=_admin_request(), queue="customer_lifecycle", limit=200, db=db
    )

    assert result["status"] == "empty"
    assert result["queued"] == 0
    assert result["next_worker_cycle"] is False
    assert db.committed is True


@pytest.mark.asyncio
async def test_admin_sync_outbox_retry_rejects_unknown_queue(monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-secret")
    db = _RetryDB([])

    with pytest.raises(HTTPException) as raised:
        await main.admin_retry_sync_outbox(
            request=_admin_request(), queue="billing_mirror", limit=10, db=db
        )

    assert raised.value.status_code == 422
    assert db.committed is False


@pytest.mark.asyncio
async def test_admin_sync_outbox_retry_requires_admin_authentication(monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-secret")
    db = _RetryDB([])

    request = Request({
        "type": "http",
        "method": "POST",
        "path": "/api/v1/admin/sync-outboxes/retry",
        "headers": [(b"x-admin-key", b"incorrect-secret")],
        "query_string": b"",
        "server": ("testserver", 80),
        "scheme": "http",
        "client": ("testclient", 50000),
    })

    with pytest.raises(HTTPException) as raised:
        await main.admin_retry_sync_outbox(
            request=request, queue="customer_lifecycle", limit=10, db=db
        )

    assert raised.value.status_code == 401
    assert db.statement is None
    assert db.committed is False
