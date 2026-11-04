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
    transaction_lock = source.index(
        'await _lock_paddle_webhook_resource(db, transaction_id, "transaction_id")'
    )
    locked_reload = source.index(".with_for_update()", transaction_lock)
    provider_request = source.index('f"/transactions/{transaction_id}"')
    assert initial_lookup < transaction_lock < locked_reload < provider_request
