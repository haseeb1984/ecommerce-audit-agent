from datetime import datetime, timezone
from types import SimpleNamespace

from scan_worker import _billing_mirror_source_event_query, _mark_billing_mirror_outbox_completed
from models import PaymentWebhookEvent
from sqlalchemy.dialects import postgresql


def test_billing_mirror_outbox_delivery_is_marked_completed_and_retained():
    item = SimpleNamespace(
        status="pending",
        processed_at=None,
        last_error="PreviousTransientFailure",
    )
    processed_at = datetime(2026, 11, 1, 12, 30, tzinfo=timezone.utc)

    _mark_billing_mirror_outbox_completed(item, processed_at)

    assert item.status == "completed"
    assert item.processed_at == processed_at
    assert item.last_error is None


def test_billing_mirror_retry_locks_canonical_event_before_copying_state():
    statement = _billing_mirror_source_event_query("evt_mirror_lock")
    compiled = str(statement.compile(dialect=postgresql.dialect()))

    assert "FOR UPDATE" in compiled
    assert "payment_webhook_events.event_id" in compiled
