from datetime import datetime, timezone
from types import SimpleNamespace

from scan_worker import _billing_mirror_source_event_query, _mark_billing_mirror_outbox_completed
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



def test_cross_database_outboxes_share_capped_exponential_retry_backoff():
    from scan_worker import _outbox_retry_delay_seconds

    assert _outbox_retry_delay_seconds(0) == 30
    assert _outbox_retry_delay_seconds(1) == 60
    assert _outbox_retry_delay_seconds(2) == 120
    assert _outbox_retry_delay_seconds(6) == 1920
    assert _outbox_retry_delay_seconds(7) == 3600
    assert _outbox_retry_delay_seconds(12) == 3600
    assert _outbox_retry_delay_seconds(-3) == 30


def test_cross_database_outbox_retry_backoff_rejects_non_integer_attempts():
    import pytest

    from scan_worker import _outbox_retry_delay_seconds

    with pytest.raises(ValueError):
        _outbox_retry_delay_seconds("not-an-attempt-count")
