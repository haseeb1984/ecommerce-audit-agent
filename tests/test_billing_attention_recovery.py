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
