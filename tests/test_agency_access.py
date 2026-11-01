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


class AgencyWorkspaceGrantSession:
    def __init__(self, agency, access):
        self.rows = [agency, access]
        self.deleted = []
        self.committed = False

    async def scalar(self, _statement):
        return self.rows.pop(0)

    async def delete(self, value):
        self.deleted.append(value)

    async def commit(self):
        self.committed = True


@pytest.mark.asyncio
async def test_owner_can_remove_one_team_workspace_grant_without_revoking_member(monkeypatch):
    import main
    from main import remove_business_agency_team_workspace_access

    agency = SimpleNamespace(id="agency-1", owner_license_key="business-license", status="active")
    grant = SimpleNamespace(
        id="grant-1", agency_id="agency-1",
        team_member_id="member-1", workspace_id="workspace-1",
    )
    db = AgencyWorkspaceGrantSession(agency, grant)
    license_obj = SimpleNamespace(license_key="business-license", tier="business")
    monkeypatch.setattr(main, "plan_features", lambda _tier: {"agency_management": True})

    result = await remove_business_agency_team_workspace_access(
        "member-1", "workspace-1", Response(),
        license_obj=license_obj, operational_db=db,
    )

    assert result == {
        "status": "removed",
        "member_id": "member-1",
        "workspace_id": "workspace-1",
    }
    assert db.deleted == [grant]
    assert db.committed


@pytest.mark.asyncio
async def test_suspended_agency_cannot_list_client_workspaces(monkeypatch):
    import main
    from fastapi import HTTPException, Response
    from main import list_business_agency_clients

    agency = SimpleNamespace(
        id="agency-suspended", owner_license_key="business-license",
        status="suspended",
    )
    class SuspendedAgencySession:
        async def scalar(self, _statement):
            return agency

    monkeypatch.setattr(main, "plan_features", lambda _tier: {"agency_management": True})
    with pytest.raises(HTTPException) as error:
        await list_business_agency_clients(
            Response(),
            license_obj=SimpleNamespace(license_key="business-license", tier="business"),
            operational_db=SuspendedAgencySession(),
        )
    assert error.value.status_code == 404


class AgencyInvitationSession:
    def __init__(self, *rows):
        self.rows = list(rows)
        self.committed = False

    async def scalar(self, _statement):
        return self.rows.pop(0)

    async def commit(self):
        self.committed = True


@pytest.mark.asyncio
async def test_invitation_acceptance_rejects_suspended_agency():
    from fastapi import HTTPException, Response
    from main import AgencyInvitationAccept, accept_business_agency_invitation

    member = SimpleNamespace(
        id="member-1", agency_id="agency-1", status="invited",
        invitation_expires_at=datetime.utcnow() + timedelta(hours=1),
        accepted_at=None, invitation_token_hash="hash",
        invitation_expires_at_original=None, role="analyst", email="teammate@example.com",
    )
    operational = AgencyInvitationSession(member, None)
    with pytest.raises(HTTPException) as error:
        await accept_business_agency_invitation(
            AgencyInvitationAccept(token="t" * 40), Response(),
            db=AgencyInvitationSession(),
            operational_db=operational,
        )
    assert error.value.status_code == 403
    assert member.status == "invited"
    assert not operational.committed


@pytest.mark.asyncio
async def test_invitation_acceptance_handles_naive_mysql_expiry_timestamp():
    from fastapi import Response
    from main import AgencyInvitationAccept, accept_business_agency_invitation

    member = SimpleNamespace(
        id="member-2", agency_id="agency-2", status="invited",
        invitation_expires_at=datetime.utcnow() + timedelta(hours=1),
        accepted_at=None, invitation_token_hash="hash",
        role="viewer", email="viewer@example.com",
    )
    agency = SimpleNamespace(id="agency-2", owner_license_key="business-license", status="active")
    license_obj = SimpleNamespace(is_active=True, expires_at=None, tier="business")
    operational = AgencyInvitationSession(member, agency)
    result = await accept_business_agency_invitation(
        AgencyInvitationAccept(token="t" * 40), Response(),
        db=AgencyInvitationSession(license_obj),
        operational_db=operational,
    )
    assert result["status"] == "accepted"
    assert member.status == "active"
    assert member.invitation_token_hash is None
    assert operational.committed


@pytest.mark.parametrize(
    "email",
    [
        "owner@example.com",
        "first.last+agency@example.co.uk",
        "name@sub.example.org",
    ],
)
def test_agency_invitation_email_validation_accepts_normal_addresses(email):
    import re

    assert re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email)


@pytest.mark.parametrize(
    "email",
    [
        "owner@example.com",
        "first.last+agency@example.co.uk",
        "name@sub.example.org",
    ],
)
def test_agency_invitation_email_validation_accepts_normal_addresses(email):
    from main import _is_valid_agency_team_email

    assert _is_valid_agency_team_email(email)


@pytest.mark.parametrize(
    "email",
    [
        "has space@example.com",
        "missing-at.example.com",
        "missing-domain@",
        "name@domain",
        r"bad\sname@example.com",
    ],
)
def test_agency_invitation_email_validation_rejects_malformed_addresses(email):
    from main import _is_valid_agency_team_email

    assert not _is_valid_agency_team_email(email)
