from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from main import _license_is_current


def test_current_business_license_is_accepted():
    license_obj = SimpleNamespace(is_active=True, expires_at=datetime.now(timezone.utc) + timedelta(days=1))
    assert _license_is_current(license_obj) is True


def test_expired_business_license_is_rejected():
    license_obj = SimpleNamespace(is_active=True, expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    assert _license_is_current(license_obj) is False


def test_inactive_business_license_is_rejected():
    license_obj = SimpleNamespace(is_active=False, expires_at=None)
    assert _license_is_current(license_obj) is False


def test_license_without_expiry_is_current_when_active():
    license_obj = SimpleNamespace(is_active=True, expires_at=None)
    assert _license_is_current(license_obj) is True


import pytest
from fastapi import Response
from types import SimpleNamespace


class AdminAgencySession:
    def __init__(self, agency, sessions=(), challenges=()):
        self.agency = agency
        self.rows = [list(sessions), list(challenges)]
        self.committed = False

    async def scalar(self, _statement):
        return self.agency

    async def execute(self, _statement):
        values = self.rows.pop(0)
        return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: values))

    async def commit(self):
        self.committed = True


def test_admin_agency_status_payload_only_allows_active_or_suspended():
    import pytest
    from pydantic import ValidationError
    from main import AdminAgencyStatusUpdate

    assert AdminAgencyStatusUpdate(status="suspended").status == "suspended"
    assert AdminAgencyStatusUpdate(status="active").status == "active"
    with pytest.raises(ValidationError):
        AdminAgencyStatusUpdate(status="deleted")


@pytest.mark.asyncio
async def test_admin_suspension_revokes_existing_team_sessions_and_pending_codes(monkeypatch):
    import main
    from main import AdminAgencyStatusUpdate, admin_update_business_agency

    now = datetime.now(timezone.utc)
    agency = SimpleNamespace(id="agency-1", status="active", updated_at=None)
    sessions = [
        SimpleNamespace(agency_id="agency-1", revoked_at=None),
        SimpleNamespace(agency_id="agency-1", revoked_at=None),
    ]
    challenges = [
        SimpleNamespace(agency_id="agency-1", consumed_at=None),
    ]
    db = AdminAgencySession(agency, sessions, challenges)
    monkeypatch.setattr(main, "_require_admin_key", lambda _request: None)

    result = await admin_update_business_agency(
        "agency-1", AdminAgencyStatusUpdate(status="suspended"),
        SimpleNamespace(), Response(), operational_db=db,
    )

    assert result["status"] == "suspended"
    assert result["team_sessions_revoked"] is True
    assert all(item.revoked_at is not None for item in sessions)
    assert all(item.consumed_at is not None for item in challenges)
    assert agency.updated_at is not None and db.committed
