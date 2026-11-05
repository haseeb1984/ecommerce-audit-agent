from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import Request

import main


class _ScalarResult:
    def __init__(self, value):
        self.value = value

    def scalar_one(self):
        return self.value


class _BillingDiagnosticsDB:
    def __init__(self, values, oldest_due):
        self.values = iter(values)
        self.oldest_due = oldest_due
        self.statements = []

    async def execute(self, statement):
        self.statements.append(statement)
        return _ScalarResult(next(self.values))

    async def scalar(self, statement):
        self.statements.append(statement)
        return self.oldest_due


@pytest.mark.asyncio
async def test_admin_billing_mirror_status_returns_safe_aggregate_diagnostics(monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-secret")
    request = Request({
        "type": "http",
        "method": "GET",
        "path": "/api/v1/admin/billing/mirror-status",
        "headers": [(b"x-admin-key", b"test-admin-secret")],
        "query_string": b"",
        "server": ("testserver", 80),
        "scheme": "http",
        "client": ("testclient", 50000),
    })
    oldest_due = datetime(2026, 11, 4, 4, 0, tzinfo=timezone.utc)
    db = _BillingDiagnosticsDB([4, 2, 12, 7], oldest_due)

    result = await main.admin_billing_mirror_status(request=request, db=db)

    assert result == {
        "pending": 4,
        "due": 2,
        "completed": 12,
        "max_attempts": 7,
        "oldest_due_at": oldest_due.isoformat(),
        "checked_at": result["checked_at"],
    }
    assert len(db.statements) == 5
    assert "event_id" not in str(result)
    assert "last_error" not in str(result)


class _ScalarsResult:
    def __init__(self, values):
        self.values = values

    def scalars(self):
        return self

    def all(self):
        return self.values


class _BillingRetryDB:
    def __init__(self, items):
        self.items = items
        self.statement = None
        self.committed = False

    async def execute(self, statement):
        self.statement = statement
        return _ScalarsResult(self.items)

    async def commit(self):
        self.committed = True


@pytest.mark.asyncio
async def test_admin_billing_mirror_retry_queues_only_selected_pending_rows(monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-secret")
    request = Request({
        "type": "http",
        "method": "POST",
        "path": "/api/v1/admin/billing/mirror-retry",
        "headers": [(b"x-admin-key", b"test-admin-secret")],
        "query_string": b"",
        "server": ("testserver", 80),
        "scheme": "http",
        "client": ("testclient", 50000),
    })
    items = [
        SimpleNamespace(status="pending", next_attempt_at=datetime(2026, 11, 1, tzinfo=timezone.utc)),
        SimpleNamespace(status="pending", next_attempt_at=datetime(2026, 11, 2, tzinfo=timezone.utc)),
    ]
    db = _BillingRetryDB(items)
    logs = []

    async def write_log(*args, **kwargs):
        logs.append((args, kwargs))

    monkeypatch.setattr(main, "_write_admin_log", write_log)

    result = await main.admin_retry_billing_mirror_deliveries(
        request=request, limit=2, db=db
    )

    assert result["status"] == "queued"
    assert result["queued"] == 2
    assert result["next_worker_cycle"] is True
    assert all(item.next_attempt_at == datetime.fromisoformat(result["checked_at"]) for item in items)
    assert db.committed is True
    assert len(logs) == 1
    assert logs[0][0][1] == "billing.mirror_retry_queued"
    assert logs[0][0][4] == {"requested_limit": 2, "queued": 2}


@pytest.mark.asyncio
async def test_admin_billing_mirror_retry_reports_empty_queue(monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-secret")
    request = Request({
        "type": "http",
        "method": "POST",
        "path": "/api/v1/admin/billing/mirror-retry",
        "headers": [(b"x-admin-key", b"test-admin-secret")],
        "query_string": b"",
        "server": ("testserver", 80),
        "scheme": "http",
        "client": ("testclient", 50000),
    })
    db = _BillingRetryDB([])
    async def write_log(*args, **kwargs):
        return None

    monkeypatch.setattr(main, "_write_admin_log", write_log)

    result = await main.admin_retry_billing_mirror_deliveries(
        request=request, limit=200, db=db
    )

    assert result["status"] == "empty"
    assert result["queued"] == 0
    assert result["next_worker_cycle"] is False
    assert db.committed is True


def test_admin_paddle_cancellation_serializes_subscription_lifecycle():
    import inspect

    source = inspect.getsource(main.admin_cancel_subscription)
    lock = source.index("await _lock_paddle_webhook_resource(db, subscription_id)")
    linked_lookup = source.index("await _get_paddle_subscription_license_event(db, subscription_id)")
    provider_request = source.index('f"/subscriptions/{subscription_id}/cancel"')
    assert lock < linked_lookup < provider_request

    
def test_admin_payment_reconciliation_serializes_transaction_webhook_work():
    import inspect

    source = inspect.getsource(main.admin_reconcile_payment)
    initial_lookup = source.index("PaymentWebhookEvent.event_id == event_id")
    subscription_lock = source.index(
        "await _lock_paddle_webhook_resource(db, subscription_id)"
    )
    transaction_lock = source.index(
        'await _lock_paddle_webhook_resource(db, transaction_id, "transaction_id")'
    )
    locked_reload = source.index(".with_for_update()", transaction_lock)
    provider_request = source.index('f"/transactions/{transaction_id}"')
    assert initial_lookup < subscription_lock < transaction_lock < locked_reload < provider_request



class _GenericOutboxRetryDB:
    def __init__(self, items):
        self.items = items
        self.statement = None
        self.committed = False

    async def execute(self, statement):
        self.statement = statement
        return _ScalarsResult(self.items)

    async def commit(self):
        self.committed = True


@pytest.mark.asyncio
async def test_admin_generic_sync_retry_supports_billing_mirror_queue(monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-secret")
    request = Request({
        "type": "http",
        "method": "POST",
        "path": "/api/v1/admin/sync-outboxes/retry",
        "headers": [(b"x-admin-key", b"test-admin-secret")],
        "query_string": b"queue=billing_mirror",
        "server": ("testserver", 80),
        "scheme": "http",
        "client": ("testclient", 50000),
    })
    now = datetime.now(timezone.utc)
    items = [
        SimpleNamespace(status="pending", next_attempt_at=datetime(2026, 11, 1, tzinfo=timezone.utc)),
        SimpleNamespace(status="pending", next_attempt_at=datetime(2026, 11, 2, tzinfo=timezone.utc)),
    ]
    db = _GenericOutboxRetryDB(items)
    logs = []

    async def write_log(*args, **kwargs):
        logs.append((args, kwargs))

    monkeypatch.setattr(main, "_write_admin_log", write_log)

    result = await main.admin_retry_sync_outbox(
        request=request, queue="billing_mirror", limit=2, db=db
    )

    assert result["queue"] == "billing_mirror"
    assert result["status"] == "queued"
    assert result["queued"] == 2
    assert result["next_worker_cycle"] is True
    assert all(item.next_attempt_at == datetime.fromisoformat(result["checked_at"]) for item in items)
    assert db.committed is True
    assert len(logs) == 1
    assert logs[0][0][1] == "sync_outbox.retry_queued"
    assert logs[0][0][2] == "billing_mirror"
