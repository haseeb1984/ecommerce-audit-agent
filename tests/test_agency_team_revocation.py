from pathlib import Path


def test_agency_team_revocation_uses_agency_first_lock_order():
    source = Path("main.py").read_text(encoding="utf-8")
    start = source.index('@app.delete("/api/v1/account/agency/team/{member_id}")')
    end = source.index('@app.get("/api/v1/account/agency/clients")', start)
    route = source[start:end]

    assert "AgencyAccount.owner_license_key == license_obj.license_key" in route
    assert ").with_for_update())" in route
    assert "AgencyTeamMember.id == member_id" in route
    assert "AgencyTeamSession.team_member_id == member.id" in route
    assert 'member.status = "revoked"' in route
    assert "delete(AgencyWorkspaceAccess)" in route


def test_customer_portal_confirms_and_reports_team_member_revocation():
    portal = Path("customer_portal.html").read_text(encoding="utf-8")
    start = portal.index("async function loadAgencyTeam()")
    end = portal.index("async function inviteAgencyTeam()", start)
    section = portal[start:end]

    assert 'window.confirm("Revoke access for " + item.email' in section
    assert 'method:"DELETE"' in section
    assert 'setStatus("agencyStatus", "Access revoked for " + item.email, "success")' in section
    assert "revoke.disabled = true" in section


def test_workspace_grant_mutations_follow_agency_member_workspace_grant_lock_order():
    source = Path("main.py").read_text(encoding="utf-8")
    start = source.index('@app.put("/api/v1/account/agency/team/{member_id}/workspaces/{workspace_id}")')
    middle = source.index('@app.delete("/api/v1/account/agency/team/{member_id}/workspaces/{workspace_id}")', start)
    end = source.index('@app.delete("/api/v1/account/agency/team/{member_id}")', middle)
    grant_routes = source[start:end]

    for marker in (
        "AgencyAccount.owner_license_key == license_obj.license_key",
        "AgencyTeamMember.id == member_id",
        "AgencyClientWorkspace.id == workspace_id",
        "AgencyWorkspaceAccess.agency_id == agency.id",
    ):
        assert marker in grant_routes

    agency_lock = grant_routes.index("AgencyAccount.owner_license_key == license_obj.license_key")
    member_lock = grant_routes.index("AgencyTeamMember.id == member_id")
    workspace_lock = grant_routes.index("AgencyClientWorkspace.id == workspace_id")
    grant_lock = grant_routes.index("AgencyWorkspaceAccess.agency_id == agency.id")
    assert agency_lock < member_lock < workspace_lock < grant_lock
    assert grant_routes.count(".with_for_update()") >= 8
    assert "agency.status != \"active\"" in grant_routes
    assert "workspace.status == \"active\"" in grant_routes


def test_agency_workspace_creation_locks_active_agency_before_insert():
    source = Path("main.py").read_text(encoding="utf-8")
    start = source.index('@app.post("/api/v1/account/agency/clients")')
    end = source.index('@app.patch("/api/v1/account/agency/clients/{workspace_id}")', start)
    route = source[start:end]

    agency_lookup = route.index("AgencyAccount.owner_license_key == license_obj.license_key")
    workspace_insert = route.index("operational_db.add(item)")
    assert ".with_for_update()" in route[agency_lookup:workspace_insert]
    assert 'agency.status != "active"' in route[agency_lookup:workspace_insert]
    assert agency_lookup < workspace_insert
