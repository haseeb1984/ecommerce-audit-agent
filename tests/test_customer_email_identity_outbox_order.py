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
    sql = str(statement.compile(dialect=mysql.dialect())).lower()

    assert "customer_email_identity_sync_outbox_1.license_key = customer_email_identity_sync_outbox.license_key" in sql
    assert "customer_email_identity_sync_outbox_1.license_key !=" not in sql
