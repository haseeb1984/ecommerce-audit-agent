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
    def __init__(self, agency, sessions=(), challenges=(), invitations=()):
        self.agency = agency
        self.rows = [list(sessions), list(challenges), list(invitations)]
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
    invitations = [
        SimpleNamespace(
            agency_id="agency-1", status="invited",
            invitation_token_hash="one-time-hash",
            invitation_expires_at=now + timedelta(hours=1),
        ),
    ]
    db = AdminAgencySession(agency, sessions, challenges, invitations)
    monkeypatch.setattr(main, "_require_admin_key", lambda _request: None)

    result = await admin_update_business_agency(
        "agency-1", AdminAgencyStatusUpdate(status="suspended"),
        SimpleNamespace(), Response(), operational_db=db,
    )

    assert result["status"] == "suspended"
    assert result["team_sessions_revoked"] is True
    assert all(item.revoked_at is not None for item in sessions)
    assert all(item.consumed_at is not None for item in challenges)
    assert all(item.status == "revoked" for item in invitations)
    assert all(item.invitation_token_hash is None for item in invitations)
    assert all(item.invitation_expires_at is None for item in invitations)
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
    operational = AgencyInvitationSession(member, agency, member)
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


class AgencyTeamScanSession:
    def __init__(self, *rows):
        self.rows = list(rows)

    async def scalar(self, _statement):
        return self.rows.pop(0)


@pytest.mark.asyncio
async def test_agency_analyst_can_queue_connected_client_audits_under_shared_license(monkeypatch):
    import scan_queue
    from fastapi import Response
    from main import AgencyTeamScanSubmission, submit_agency_team_workspace_scans

    grant = SimpleNamespace(role="analyst")
    workspace = SimpleNamespace(id="workspace-1", display_name="Client One")
    site = SimpleNamespace(site_host="client.example")
    db = AgencyTeamScanSession(grant, workspace, site)
    owner_license = SimpleNamespace(license_key="business-owner-license", tier="business")
    identity = {
        "agency": SimpleNamespace(id="agency-1"),
        "member": SimpleNamespace(id="member-1", email="analyst@example.com"),
        "owner_license": owner_license,
    }
    captured = {}

    async def enqueue(_db, **kwargs):
        captured.update(kwargs)
        return {
            "request_id": kwargs["request_id"],
            "submitted_urls": len(kwargs["urls"]),
            "batch_count": 1,
            "new_jobs": len(kwargs["urls"]),
        }

    monkeypatch.setattr(scan_queue, "enqueue_scan_request", enqueue)
    response = Response()
    result = await submit_agency_team_workspace_scans(
        "workspace-1",
        AgencyTeamScanSubmission(
            urls=["https://client.example/", "https://client.example/products/item"],
            request_id="team-scan-request-001",
        ),
        SimpleNamespace(),
        response,
        identity=identity,
        operational_db=db,
    )

    assert result["status"] == "accepted"
    assert result["workspace_id"] == "workspace-1"
    assert captured["license_key"] == "business-owner-license"
    assert captured["package_tier"] == "business"
    assert captured["workspace_id"] == "workspace-1"
    assert captured["requested_by"] == "analyst@example.com"
    assert captured["batch_size"] == 10
    assert len(captured["urls"]) == 2
    assert response.headers["cache-control"] == "no-store, private"


@pytest.mark.asyncio
async def test_agency_viewer_cannot_queue_client_audits():
    from fastapi import HTTPException, Response
    from main import AgencyTeamScanSubmission, submit_agency_team_workspace_scans

    identity = {
        "agency": SimpleNamespace(id="agency-1"),
        "member": SimpleNamespace(id="member-1", email="viewer@example.com"),
        "owner_license": SimpleNamespace(license_key="business-owner-license", tier="business"),
    }
    with pytest.raises(HTTPException) as error:
        await submit_agency_team_workspace_scans(
            "workspace-1",
            AgencyTeamScanSubmission(
                urls=["https://client.example/"],
                request_id="team-scan-request-002",
            ),
            SimpleNamespace(),
            Response(),
            identity=identity,
            operational_db=AgencyTeamScanSession(SimpleNamespace(role="viewer")),
        )
    assert error.value.status_code == 403
    assert "read-only" in error.value.detail


@pytest.mark.asyncio
async def test_agency_team_audit_submission_rejects_urls_outside_connected_site():
    from fastapi import HTTPException, Response
    from main import AgencyTeamScanSubmission, submit_agency_team_workspace_scans

    identity = {
        "agency": SimpleNamespace(id="agency-1"),
        "member": SimpleNamespace(id="member-1", email="analyst@example.com"),
        "owner_license": SimpleNamespace(license_key="business-owner-license", tier="business"),
    }
    with pytest.raises(HTTPException) as error:
        await submit_agency_team_workspace_scans(
            "workspace-1",
            AgencyTeamScanSubmission(
                urls=["https://other.example/"],
                request_id="team-scan-request-003",
            ),
            SimpleNamespace(),
            Response(),
            identity=identity,
            operational_db=AgencyTeamScanSession(
                SimpleNamespace(role="analyst"),
                SimpleNamespace(id="workspace-1", display_name="Client One"),
                SimpleNamespace(site_host="client.example"),
            ),
        )
    assert error.value.status_code == 422
    assert "connected to this workspace" in error.value.detail


def test_agency_team_scan_submission_route_is_registered():
    import main

    assert "/api/v1/agency/team/workspaces/{workspace_id}/scan-batches" in main.app.openapi()["paths"]



@pytest.mark.asyncio
async def test_agency_team_login_request_locks_membership_before_cooldown_check(monkeypatch):
    import os
    import main
    from fastapi import Response
    from main import AgencyTeamLoginRequest, request_agency_team_login

    now = datetime.now(timezone.utc)
    member = SimpleNamespace(id="member-1", agency_id="agency-1")
    agency = SimpleNamespace(id="agency-1", owner_license_key="business-license")
    recent = SimpleNamespace(created_at=now - timedelta(seconds=10))

    class OperationalSession:
        def __init__(self):
            self.calls = []
        async def scalar(self, statement):
            self.calls.append(statement)
            return [member, agency, recent][len(self.calls) - 1]
        async def execute(self, _statement):
            raise AssertionError("A recent challenge must stop OTP issuance.")
        async def commit(self):
            raise AssertionError("A cooldown response must not issue a new challenge.")

    class LicenseSession:
        async def scalar(self, _statement):
            return SimpleNamespace(license_key="business-license", is_active=True, tier="business")

    operational = OperationalSession()
    monkeypatch.setenv("ACCOUNT_AUTH_SECRET", "x" * 40)
    monkeypatch.setattr(main, "_license_is_current", lambda _license: True)
    monkeypatch.setattr(main, "plan_features", lambda _tier: {"agency_management": True})

    result = await request_agency_team_login(
        AgencyTeamLoginRequest(email="teammate@example.com"),
        Response(),
        db=LicenseSession(),
        operational_db=operational,
    )

    assert result["status"] == "accepted"
    assert len(operational.calls) == 3
    assert operational.calls[0]._for_update_arg is not None



def test_agency_invitation_mutations_follow_agency_first_lock_order():
    import inspect
    import main

    invite_source = inspect.getsource(main.invite_business_agency_team_member)
    accept_source = inspect.getsource(main.accept_business_agency_invitation)
    suspend_source = inspect.getsource(main.admin_update_business_agency)

    invite_agency_lock = invite_source.index("AgencyAccount.owner_license_key")
    invite_member_lock = invite_source.index("AgencyTeamMember.normalized_email")
    assert ".with_for_update()" in invite_source[invite_agency_lock:invite_member_lock]

    accept_candidate = accept_source.index("candidate = await operational_db.scalar")
    accept_agency_lock = accept_source.index("AgencyAccount.id == candidate.agency_id")
    accept_member_lock = accept_source.index("AgencyTeamMember.id == candidate.id")
    assert accept_candidate < accept_agency_lock < accept_member_lock
    assert ".with_for_update()" in accept_source[accept_agency_lock:accept_member_lock]

    suspend_agency_lock = suspend_source.index("AgencyAccount.id == agency_id")
    suspend_invite_revoke = suspend_source.index("AgencyTeamMember.status == \"invited\"")
    assert suspend_agency_lock < suspend_invite_revoke
    assert "member.invitation_token_hash = None" in suspend_source[suspend_invite_revoke:]



def test_agency_invitation_mutations_follow_agency_first_lock_order():
    import inspect
    import main

    invite_source = inspect.getsource(main.invite_business_agency_team_member)
    accept_source = inspect.getsource(main.accept_business_agency_invitation)
    suspend_source = inspect.getsource(main.admin_update_business_agency)

    invite_agency_lock = invite_source.index("AgencyAccount.owner_license_key")
    invite_member_lock = invite_source.index("AgencyTeamMember.normalized_email")
    assert ".with_for_update()" in invite_source[invite_agency_lock:invite_member_lock]

    accept_candidate = accept_source.index("candidate = await operational_db.scalar")
    accept_agency_lock = accept_source.index("AgencyAccount.id == candidate.agency_id")
    accept_member_lock = accept_source.index("AgencyTeamMember.id == candidate.id")
    assert accept_candidate < accept_agency_lock < accept_member_lock
    assert ".with_for_update()" in accept_source[accept_agency_lock:accept_member_lock]

    suspend_agency_lock = suspend_source.index("AgencyAccount.id == agency_id")
    suspend_invite_revoke = suspend_source.index('AgencyTeamMember.status == "invited"')
    assert suspend_agency_lock < suspend_invite_revoke
    assert "member.invitation_token_hash = None" in suspend_source[suspend_invite_revoke:]


def test_agency_wordpress_connection_mutations_share_tenant_lock_order():
    import inspect
    import main

    issue_token = inspect.getsource(main.create_agency_website_connection_token)
    register_site = inspect.getsource(main.register_agency_wordpress_site)

    issue_agency_lock = issue_token.index("AgencyAccount.owner_license_key")
    issue_workspace_lock = issue_token.index("AgencyClientWorkspace.id")
    assert ".with_for_update()" in issue_token[issue_agency_lock:issue_workspace_lock]
    assert ".with_for_update()" in issue_token[issue_workspace_lock:]

    candidate_lookup = register_site.index("candidate = await operational_db.scalar")
    register_agency_lock = register_site.index("AgencyAccount.id == candidate.agency_id")
    register_workspace_lock = register_site.index("AgencyClientWorkspace.id == candidate.workspace_id")
    challenge_lock = register_site.index("AgencyWebsiteConnectChallenge.id == candidate.id")
    assert candidate_lookup < register_agency_lock < register_workspace_lock < challenge_lock
    assert ".with_for_update()" in register_site[register_agency_lock:register_workspace_lock]
    assert ".with_for_update()" in register_site[register_workspace_lock:challenge_lock]
    assert ".with_for_update()" in register_site[challenge_lock:]


def test_agency_wordpress_site_registration_rechecks_single_active_workspace_after_lock():
    import inspect
    import main

    source = inspect.getsource(main.register_agency_wordpress_site)
    workspace_lock = source.index("AgencyClientWorkspace.id == candidate.workspace_id")
    active_site_check = source.index("active_site = await operational_db.scalar")
    assert workspace_lock < active_site_check
    assert "AgencyClientWebsite.status == \"active\"" in source[active_site_check:]


class BusinessAgencyTeamListSession:
    def __init__(self, agency, members, access_rows=()):
        self.agency = agency
        self.results = [list(members), list(access_rows)]

    async def scalar(self, _statement):
        return self.agency

    async def execute(self, _statement):
        values = self.results.pop(0)
        return SimpleNamespace(
            scalars=lambda: SimpleNamespace(all=lambda: values),
            all=lambda: values,
        )


@pytest.mark.asyncio
async def test_agency_team_list_exposes_invitation_expiry_without_token_material(monkeypatch):
    import main
    from fastapi import Response
    from main import list_business_agency_team

    expires = datetime.now(timezone.utc) + timedelta(hours=12)
    member = SimpleNamespace(
        id="member-invited", email="invitee@example.com", role="analyst",
        status="invited", created_at=datetime.now(timezone.utc),
        accepted_at=None, invitation_expires_at=expires,
    )
    agency = SimpleNamespace(id="agency-1", status="active")
    db = BusinessAgencyTeamListSession(agency, [member])
    monkeypatch.setattr(main, "plan_features", lambda _tier: {"agency_management": True})

    result = await list_business_agency_team(
        Response(),
        license_obj=SimpleNamespace(license_key="business-license", tier="business"),
        operational_db=db,
    )

    assert result["items"][0]["invitation_expires_at"] == expires.isoformat()
    assert "invitation_token_hash" not in result["items"][0]
    assert "token" not in result["items"][0]


class AgencyWebsiteStatusSession:
    def __init__(self, agency, workspace, site):
        self.rows = [agency, workspace, site]

    async def scalar(self, _statement):
        return self.rows.pop(0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("last_seen", "expected_health"),
    [
        (datetime.now(timezone.utc) - timedelta(days=1), "healthy"),
        (datetime.now(timezone.utc) - timedelta(days=8), "stale"),
        (None, "stale"),
        (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=2), "healthy"),
    ],
)
async def test_agency_client_website_status_reports_heartbeat_health(
    monkeypatch, last_seen, expected_health
):
    import main
    from fastapi import Response
    from main import get_agency_client_website

    agency = SimpleNamespace(id="agency-1", owner_license_key="business-license", status="active")
    workspace = SimpleNamespace(id="workspace-1")
    site = SimpleNamespace(
        id="site-1", site_url="https://client.example", site_host="client.example",
        admin_email="admin@client.example", plugin_version="1.2.3",
        connected_at=datetime.now(timezone.utc), last_seen_at=last_seen,
    )
    monkeypatch.setattr(main, "plan_features", lambda _tier: {"agency_management": True})
    response = Response()
    result = await get_agency_client_website(
        "workspace-1", response,
        license_obj=SimpleNamespace(license_key="business-license", tier="business"),
        operational_db=AgencyWebsiteStatusSession(agency, workspace, site),
    )

    assert result["connected"] is True
    assert result["connection_health"] == expected_health
    assert result["health_checked_at"]
    assert result["last_seen_at"] == last_seen.isoformat() if last_seen else result["last_seen_at"] is None
    assert response.headers["cache-control"] == "no-store, private"


@pytest.mark.asyncio
async def test_agency_client_website_status_distinguishes_unconnected_workspace(monkeypatch):
    import main
    from fastapi import Response
    from main import get_agency_client_website

    agency = SimpleNamespace(id="agency-1", owner_license_key="business-license", status="active")
    workspace = SimpleNamespace(id="workspace-1")
    monkeypatch.setattr(main, "plan_features", lambda _tier: {"agency_management": True})
    result = await get_agency_client_website(
        "workspace-1", Response(),
        license_obj=SimpleNamespace(license_key="business-license", tier="business"),
        operational_db=AgencyWebsiteStatusSession(agency, workspace, None),
    )

    assert result["connected"] is False
    assert result["connection_health"] == "not_connected"
    assert result["health_checked_at"]


class AgencyArchiveSession:
    def __init__(self, agency, workspace, site, challenges):
        self.rows = [agency, workspace, site]
        self.challenges = challenges
        self.committed = False

    async def scalar(self, _statement):
        return self.rows.pop(0)

    async def execute(self, _statement):
        return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: self.challenges))

    async def commit(self):
        self.committed = True


@pytest.mark.asyncio
async def test_archiving_agency_workspace_revokes_plugin_credential_and_pending_tokens(monkeypatch):
    import main
    from main import AgencyClientWorkspaceUpdate, update_business_agency_client

    agency = SimpleNamespace(id="agency-archive", status="active", owner_license_key="business-license")
    workspace = SimpleNamespace(
        id="workspace-archive", agency_id=agency.id, display_name="Client",
        external_reference=None, status="active", updated_at=None,
    )
    site = SimpleNamespace(
        agency_id=agency.id, workspace_id=workspace.id, status="active",
        site_token_hash="hashed-live-site-token", disconnected_at=None,
    )
    challenges = [
        SimpleNamespace(agency_id=agency.id, workspace_id=workspace.id, consumed_at=None),
        SimpleNamespace(agency_id=agency.id, workspace_id=workspace.id, consumed_at=None),
    ]
    db = AgencyArchiveSession(agency, workspace, site, challenges)
    monkeypatch.setattr(main, "plan_features", lambda _tier: {"agency_management": True})

    result = await update_business_agency_client(
        workspace.id, AgencyClientWorkspaceUpdate(status="archived"), Response(),
        license_obj=SimpleNamespace(license_key="business-license", tier="business"),
        operational_db=db,
    )

    assert result["status"] == "archived"
    assert result["connection_revoked"] is True
    assert site.status == "disconnected"
    assert site.site_token_hash is None
    assert site.disconnected_at is not None
    assert all(challenge.consumed_at is not None for challenge in challenges)
    assert db.committed


@pytest.mark.asyncio
async def test_archiving_workspace_without_connections_is_safe(monkeypatch):
    import main
    from main import AgencyClientWorkspaceUpdate, update_business_agency_client

    agency = SimpleNamespace(id="agency-empty", status="active", owner_license_key="business-license")
    workspace = SimpleNamespace(
        id="workspace-empty", agency_id=agency.id, display_name="Empty",
        external_reference=None, status="active", updated_at=None,
    )
    db = AgencyArchiveSession(agency, workspace, None, [])
    monkeypatch.setattr(main, "plan_features", lambda _tier: {"agency_management": True})

    result = await update_business_agency_client(
        workspace.id, AgencyClientWorkspaceUpdate(status="archived"), Response(),
        license_obj=SimpleNamespace(license_key="business-license", tier="business"),
        operational_db=db,
    )

    assert result["status"] == "archived"
    assert result["connection_revoked"] is False
    assert db.committed
