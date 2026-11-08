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
    from outbox_retry import outbox_retry_delay_seconds as _outbox_retry_delay_seconds

    assert _outbox_retry_delay_seconds(0) == 30
    assert _outbox_retry_delay_seconds(1) == 30
    assert _outbox_retry_delay_seconds(2) == 60
    assert _outbox_retry_delay_seconds(3) == 120
    assert _outbox_retry_delay_seconds(7) == 1920
    assert _outbox_retry_delay_seconds(8) == 3600
    assert _outbox_retry_delay_seconds(12) == 3600
    assert _outbox_retry_delay_seconds(-3) == 30


def test_cross_database_outbox_retry_backoff_rejects_non_integer_attempts():
    import pytest

    from scan_worker import _outbox_retry_delay_seconds

    with pytest.raises(ValueError):
        _outbox_retry_delay_seconds("not-an-attempt-count")
    with pytest.raises(ValueError):
        _outbox_retry_delay_seconds(1.5)
    with pytest.raises(ValueError):
        _outbox_retry_delay_seconds(True)


def test_cross_database_outboxes_treat_missing_attempt_count_as_first_retry():
    from scan_worker import _outbox_retry_delay_seconds

    assert _outbox_retry_delay_seconds(None) == 30



def test_outbox_attempt_counter_increments_valid_values_without_coercion():
    from outbox_retry import next_outbox_attempt_count as _next_outbox_attempt_count

    assert _next_outbox_attempt_count(None) == 1
    assert _next_outbox_attempt_count(0) == 1
    assert _next_outbox_attempt_count(1) == 2


def test_outbox_attempt_counter_rejects_malformed_persisted_values():
    import pytest

    from scan_worker import _next_outbox_attempt_count

    for malformed in (True, 1.5, "2", "invalid"):
        with pytest.raises(ValueError):
            _next_outbox_attempt_count(malformed)



def test_live_billing_mirror_failure_uses_persisted_exponential_retry_state():
    import inspect
    import main

    source = inspect.getsource(main._sync_billing_event_to_hostinger)

    assert "next_outbox_attempt_count(" in source
    assert "outbox_retry_delay_seconds(retry_attempts)" in source
    assert "pending.attempts = retry_attempts" in source



def test_missing_operational_license_mapping_releases_billing_mirror_row_locks():
    import inspect
    import main

    source = inspect.getsource(main._sync_billing_event_to_hostinger)
    missing_mapping = source[source.index("if not license_key:"):source.index("mirror_error = None")]
    assert "await db.rollback()" in missing_mapping
    assert missing_mapping.index("await db.rollback()") < missing_mapping.index("return False")
