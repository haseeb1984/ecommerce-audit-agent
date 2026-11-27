"""Ordering guarantees for PostgreSQL-to-Hostinger billing mirror retries."""

from datetime import datetime, timezone
import inspect

from sqlalchemy.dialects import postgresql

import scan_worker


def test_billing_mirror_claim_serializes_pending_events_per_license():
    statement = scan_worker._billing_mirror_outbox_claim_statement(
        datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
    )
    sql = str(statement.compile(dialect=postgresql.dialect())).lower().replace('"', "")

    assert "left outer join payment_webhook_events as payment_webhook_events_1" in sql
    assert "payment_webhook_events_2.license_id = payment_webhook_events_1.license_id" in sql
    assert "billing_mirror_sync_outbox_1.status = %(status_2)s" in sql
    assert "billing_mirror_sync_outbox_1.created_at < billing_mirror_sync_outbox.created_at" in sql
    assert "billing_mirror_sync_outbox_1.event_id < billing_mirror_sync_outbox.event_id" in sql
    assert "billing_mirror_sync_outbox.next_attempt_at <=" in sql
    assert "order by billing_mirror_sync_outbox.created_at asc, billing_mirror_sync_outbox.event_id asc" in sql
    assert "for update of billing_mirror_sync_outbox skip locked" in sql


def test_deferred_earlier_billing_event_remains_an_ordering_barrier():
    statement = scan_worker._billing_mirror_outbox_claim_statement(
        datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
    )
    sql = str(statement.compile(dialect=postgresql.dialect())).lower().replace('"', "")

    # The earlier-event predicate checks pending status but deliberately does
    # not require its next_attempt_at to be due. A retry delay must not let a
    # later event for the same license overtake it.
    earlier_clause = sql.split("billing_mirror_sync_outbox_1.status", 1)[1].split(")", 1)[0]
    assert "next_attempt_at" not in earlier_clause


def test_missing_or_unlinked_source_events_remain_claimable_for_discard():
    statement = scan_worker._billing_mirror_outbox_claim_statement(
        datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
    )
    sql = str(statement.compile(dialect=postgresql.dialect())).lower().replace('"', "")

    assert "payment_webhook_events_1.license_id is null" in sql


def test_billing_mirror_worker_uses_ordered_claim_before_source_event_lock():
    source = inspect.getsource(scan_worker.reconcile_billing_mirror_outbox)

    assert "_billing_mirror_outbox_claim_statement(now)" in source
    assert source.index("_billing_mirror_outbox_claim_statement(now)") < source.index(
        "_billing_mirror_source_event_query(event_id)"
    )
    assert "await operational_db.commit()" in source
    assert "_mark_billing_mirror_outbox_completed(" in source


def test_billing_worker_recovers_missing_outbox_rows_before_claiming_retries():
    source = inspect.getsource(scan_worker.reconcile_billing_mirror_outbox)
    backfill = inspect.getsource(scan_worker._backfill_missing_billing_mirror_outbox)

    assert '"recovered"' in source
    assert source.index("_backfill_missing_billing_mirror_outbox(") < source.index(
        "_billing_mirror_outbox_claim_statement(now)"
    )
    assert "PaymentWebhookEvent.billing_mirror_synced_at.is_(None)" in backfill
    assert "PaymentWebhookEvent.billing_mirror_synced_at < PaymentWebhookEvent.updated_at" in backfill
    assert "~has_outbox" in backfill
    assert "with_for_update(skip_locked=True)" in backfill
    assert "created_at=event.created_at" in backfill
