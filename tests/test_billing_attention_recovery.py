from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import main


class _Rows:
    def __init__(self, rows):
        self.rows = rows

    def scalars(self):
        return self

    def all(self):
        return self.rows


class _RecoveryDB:
    def __init__(self, rows=()):
        self.rows = list(rows)

    async def execute(self, statement):
        return _Rows(self.rows)


@pytest.mark.asyncio
async def test_subscription_updated_past_due_attention_is_cleared_after_verified_recovery():
    now = datetime.now(timezone.utc)
    failure = SimpleNamespace(
        event_id="evt-past-due",
        status="subscription_updated_past_due",
        subscription_id="sub-recovered",
        created_at=now - timedelta(hours=2),
        updated_at=now - timedelta(hours=2),
    )
    recovery = SimpleNamespace(
        event_id="evt-recovered",
        status="subscription_updated_active",
        subscription_id="sub-recovered",
        created_at=now - timedelta(hours=1),
        updated_at=now - timedelta(hours=1),
    )

    visible = await main._filter_recovered_billing_attention_events(
        [failure],
        _RecoveryDB([recovery]),
        _RecoveryDB(),
    )

    assert visible == []


@pytest.mark.asyncio
async def test_subscription_updated_past_due_attention_remains_without_later_recovery():
    now = datetime.now(timezone.utc)
    failure = SimpleNamespace(
        event_id="evt-past-due-open",
        status="subscription_updated_past_due",
        subscription_id="sub-still-past-due",
        created_at=now,
        updated_at=now,
    )

    visible = await main._filter_recovered_billing_attention_events(
        [failure],
        _RecoveryDB(),
        _RecoveryDB(),
    )

    assert visible == [failure]


def test_admin_operations_includes_subscription_updated_past_due_in_attention_counts():
    import inspect

    source = inspect.getsource(main.admin_operations)

    assert '"subscription_updated_past_due"' in source
    assert '"subscription_updated_past_due_events": billing_attention_counts["subscription_updated_past_due"]' in source


@pytest.mark.parametrize(
    "status",
    ["active", "trialing", "paused", "past_due", "canceled", "cancelled"],
)
def test_paddle_subscription_status_recognizes_supported_provider_states(status):
    assert main._is_supported_paddle_subscription_status(status)


@pytest.mark.parametrize(
    "status",
    ["", "unknown", "incomplete_expired", None, 123, True],
)
def test_paddle_subscription_status_rejects_unknown_or_malformed_states(status):
    assert not main._is_supported_paddle_subscription_status(status)


def test_unknown_paddle_subscription_status_cannot_mutate_entitlements():
    import inspect

    source = inspect.getsource(main.paddle_webhook)
    assert "status_supported = _is_supported_paddle_subscription_status(provider_status)" in source
    assert "elif status_supported:" in source
    assert 'event_status = "subscription_update_unrecognized_status"' in source
    assert '"unrecognized_subscription_status_ignored"' in source


def test_admin_operations_surfaces_unknown_paddle_subscription_states():
    import inspect

    source = inspect.getsource(main.admin_operations)
    assert '"subscription_update_unrecognized_status"' in source
    assert '"subscription_unrecognized_status_events": billing_attention_counts["subscription_update_unrecognized_status"]' in source



@pytest.mark.asyncio
async def test_unrecognized_subscription_status_attention_clears_after_later_verified_recovery():
    now = datetime.now(timezone.utc)
    unknown = SimpleNamespace(
        event_id="evt-unknown-status",
        status="subscription_update_unrecognized_status",
        subscription_id="sub-status-recovered",
        created_at=now - timedelta(hours=2),
        updated_at=now - timedelta(hours=2),
    )
    recovery = SimpleNamespace(
        event_id="evt-known-status",
        status="subscription_updated_active",
        subscription_id="sub-status-recovered",
        created_at=now - timedelta(hours=1),
        updated_at=now - timedelta(hours=1),
    )

    visible = await main._filter_recovered_billing_attention_events(
        [unknown],
        _RecoveryDB([recovery]),
        _RecoveryDB(),
    )

    assert visible == []


@pytest.mark.asyncio
async def test_unrecognized_subscription_status_attention_remains_without_later_recovery():
    now = datetime.now(timezone.utc)
    unknown = SimpleNamespace(
        event_id="evt-unknown-status-open",
        status="subscription_update_unrecognized_status",
        subscription_id="sub-status-open",
        created_at=now,
        updated_at=now,
    )

    visible = await main._filter_recovered_billing_attention_events(
        [unknown],
        _RecoveryDB(),
        _RecoveryDB(),
    )

    assert visible == [unknown]



def test_admin_operations_exposes_bounded_billing_mirror_retry_queue():
    import inspect

    source = inspect.getsource(main.admin_operations)

    assert '"billing_mirror_pending_events": billing_mirror_pending_count' in source
    assert '"billing_mirror_due_events": billing_mirror_due_count' in source
    assert '"billing_mirror_sync_events"' in source
    assert ".limit(50)" in source
    assert 'BillingMirrorSyncOutbox.status == "pending"' in source



@pytest.mark.asyncio
async def test_unknown_subscription_status_is_included_in_stale_event_ordering_query():
    from sqlalchemy.dialects import postgresql

    class _ScalarResult:
        def scalar_one_or_none(self):
            return None

    class _CaptureDB:
        statement = None

        async def execute(self, statement):
            self.statement = statement
            return _ScalarResult()

    db = _CaptureDB()
    await main._latest_paddle_subscription_lifecycle_event(db, "sub-unknown-state")
    compiled = db.statement.compile(
        dialect=postgresql.dialect(),
        compile_kwargs={"render_postcompile": True},
    )

    assert "payment_webhook_events.status IN" in str(compiled)
    assert "subscription_update_unrecognized_status" in compiled.params.values()



def test_admin_payment_event_total_uses_streamed_sorted_union():
    import inspect
    import main

    source = inspect.getsource(main.admin_payment_events)
    assert "db.stream_scalars(" in source
    assert "operational_db.stream_scalars(" in source
    assert "_count_sorted_billing_event_id_union(" in source
    assert "pg_ids_statement.order_by(PaymentWebhookEvent.event_id.asc())" in source
    assert "host_ids_statement.order_by(CustomerBillingEvent.event_id.asc())" in source
    assert "await host_id_stream.close()" in source
    assert "await pg_id_stream.close()" in source
    assert "set((await db.execute(pg_ids_statement)).scalars().all())" not in source
    assert "set((await operational_db.execute(host_ids_statement)).scalars().all())" not in source


@pytest.mark.asyncio
async def test_paddle_subscription_license_conflict_lookup_is_limited_to_two_rows():
    from fastapi import HTTPException
    from sqlalchemy.dialects import postgresql

    class _Result:
        def scalars(self):
            return self

        def all(self):
            return ["license-a", "license-b"]

    class _CaptureDB:
        statement = None

        async def execute(self, statement):
            self.statement = statement
            return _Result()

    db = _CaptureDB()
    with pytest.raises(HTTPException) as error:
        await main._get_paddle_subscription_license_event(db, "sub-many-licenses")

    assert error.value.status_code == 409
    compiled = db.statement.compile(
        dialect=postgresql.dialect(),
        compile_kwargs={"render_postcompile": True},
    )
    assert "LIMIT" in str(compiled).upper()
    assert 2 in compiled.params.values()


def test_paddle_checkout_legacy_duplicate_detection_fetches_at_most_two_license_ids():
    import inspect

    source = inspect.getsource(main.create_paddle_checkout)
    start = source.index("legacy_ids =")
    end = source.index("if len(legacy_ids) > 1:", start)
    lookup = source[start:end]
    assert ".distinct().limit(2)" in lookup
    assert "legacy_ids = (await db.execute(" in lookup
