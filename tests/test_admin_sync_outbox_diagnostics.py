"""Tests for sanitized, bounded admin reconciliation queue diagnostics."""

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from admin_scan_api import pending_outbox_details


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return self._rows


class _Session:
    def __init__(self, rows):
        self.rows = rows
        self.statement = None

    async def execute(self, statement):
        self.statement = statement
        return _Rows(self.rows)


@pytest.mark.asyncio
async def test_pending_outbox_details_are_bounded_and_exclude_tenant_identity():
    from hostinger_models import CustomerEmailIdentitySyncOutbox

    created = datetime(2026, 11, 8, tzinfo=timezone.utc)
    row = SimpleNamespace(
        id="email-event-1",
        attempts=3,
        next_attempt_at=created,
        last_error="OperationalError",
        created_at=created,
        license_key="private-license-key",
        old_email="old@example.com",
        new_email="new@example.com",
    )
    session = _Session([row])

    result = await pending_outbox_details(
        session, CustomerEmailIdentitySyncOutbox, "id",
    )

    assert result == [{
        "event_id": "email-event-1",
        "attempts": 3,
        "next_attempt_at": created.isoformat(),
        "last_error": "OperationalError",
        "created_at": created.isoformat(),
    }]
    assert "LIMIT" in str(session.statement).upper()
    assert "old@example.com" not in repr(result)
    assert "new@example.com" not in repr(result)
    assert "private-license-key" not in repr(result)


@pytest.mark.asyncio
async def test_lifecycle_outbox_details_include_action_but_not_license_key():
    from models import CustomerLifecycleSyncOutbox

    created = datetime(2026, 11, 8, tzinfo=timezone.utc)
    row = SimpleNamespace(
        id="lifecycle-event-1",
        action="suspend",
        attempts=1,
        next_attempt_at=created,
        last_error=None,
        created_at=created,
        license_key="private-license-key",
    )
    result = await pending_outbox_details(
        _Session([row]), CustomerLifecycleSyncOutbox, "id", "action",
    )

    assert result[0]["event_type"] == "suspend"
    assert result[0]["event_id"] == "lifecycle-event-1"
    assert "private-license-key" not in repr(result)
