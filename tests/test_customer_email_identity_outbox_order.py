"""Regression tests for ordered customer email identity outbox delivery."""

from datetime import datetime, timezone

from sqlalchemy.dialects import mysql

from scan_worker import _customer_email_identity_outbox_claim_statement


def test_email_identity_outbox_claim_preserves_per_license_event_order():
    statement = _customer_email_identity_outbox_claim_statement(
        datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
    )
    sql = str(statement.compile(dialect=mysql.dialect())).lower().replace("`", "")

    # A newer event for the same license remains blocked while any older event
    # is pending, including one deferred until a future retry time.
    assert "not (exists (select" in sql
    assert "customer_email_identity_sync_outbox_1.license_key = customer_email_identity_sync_outbox.license_key" in sql
    assert "customer_email_identity_sync_outbox_1.status = %s" in sql
    assert "customer_email_identity_sync_outbox_1.created_at < customer_email_identity_sync_outbox.created_at" in sql
    assert "customer_email_identity_sync_outbox_1.id < customer_email_identity_sync_outbox.id" in sql

    # The selected event itself must be due, and ties must have a stable order.
    assert "customer_email_identity_sync_outbox.next_attempt_at <= %s" in sql
    assert "order by customer_email_identity_sync_outbox.created_at asc, customer_email_identity_sync_outbox.id asc" in sql
    assert "for update skip locked" in sql


def test_email_identity_outbox_ordering_is_per_license_not_global():
    statement = _customer_email_identity_outbox_claim_statement(
        datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
    )
    sql = str(statement.compile(dialect=mysql.dialect())).lower().replace("`", "")

    assert "customer_email_identity_sync_outbox_1.license_key = customer_email_identity_sync_outbox.license_key" in sql
    assert "customer_email_identity_sync_outbox_1.license_key !=" not in sql



def test_email_identity_worker_locks_canonical_license_before_billing_projection_update():
    import inspect
    import scan_worker
    from sqlalchemy.dialects import postgresql
    from scan_worker import _customer_email_identity_license_lock_query

    statement = _customer_email_identity_license_lock_query("license-key")
    sql = str(statement.compile(dialect=postgresql.dialect())).lower().replace('"', "")
    assert "from software_licenses" in sql
    assert "software_licenses.license_key =" in sql
    assert "for update" in sql

    source = inspect.getsource(scan_worker.reconcile_customer_email_identity_outbox)
    lock_read = source.index("_customer_email_identity_license_lock_query(event.license_key)")
    billing_update = source.index("_customer_email_identity_update_statement(", lock_read)
    canonical_commit = source.index("await licensing_db.commit()", billing_update)
    operational_complete = source.index('event.status = "completed"', canonical_commit)
    assert lock_read < billing_update < canonical_commit < operational_complete
