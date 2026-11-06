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


def test_agency_team_login_code_uses_agency_before_member_lock_order():
    source = Path("main.py").read_text(encoding="utf-8")
    start = source.index("async def request_agency_team_login")
    end = source.index('@app.post("/api/v1/agency/team/auth/verify-code")', start)
    route = source[start:end]

    candidate_lookup = route.index("AgencyTeamMember.normalized_email == email")
    agency_lock = route.index("AgencyAccount.id == candidate.agency_id")
    member_lock = route.index("AgencyTeamMember.id == candidate.id")
    challenge_insert = route.index("operational_db.add(challenge)")
    assert candidate_lookup < agency_lock < member_lock < challenge_insert
    assert ".with_for_update()" in route[agency_lock:member_lock]
    assert ".with_for_update()" in route[member_lock:challenge_insert]
    assert 'agency.status != "active"' in route[agency_lock:member_lock]


def test_agency_team_session_authorization_serializes_with_revocation():
    source = Path("main.py").read_text(encoding="utf-8")
    start = source.index("async def require_agency_team_session")
    end = source.index('@app.get("/api/v1/account/agency/usage")', start)
    guard = source[start:end]

    candidate_lookup = guard.index("AgencyTeamSession.token_hash == token_hash")
    agency_lock = guard.index("AgencyAccount.id == candidate.agency_id")
    member_lock = guard.index("AgencyTeamMember.id == candidate.team_member_id")
    session_recheck = guard.index("AgencyTeamSession.id == candidate.id")
    assert candidate_lookup < agency_lock < member_lock < session_recheck
    assert guard[agency_lock:member_lock].count(".with_for_update()") == 1
    assert guard[member_lock:session_recheck].count(".with_for_update()") == 1
    assert guard[session_recheck:].count(".with_for_update()") == 1
    assert 'agency.status != "active"' in guard
    assert 'AgencyTeamSession.revoked_at.is_(None)' in guard[session_recheck:]
    assert 'AgencyTeamSession.expires_at > datetime.now(timezone.utc)' in guard[session_recheck:]


def test_owner_wordpress_disconnect_uses_agency_workspace_site_challenge_lock_order():
    import inspect
    import main

    source = inspect.getsource(main.disconnect_agency_client_website)
    agency_lock = source.index("AgencyAccount.owner_license_key")
    workspace_lock = source.index("AgencyClientWorkspace.id == workspace_id")
    site_lock = source.index("AgencyClientWebsite.agency_id == agency.id")
    challenge_lock = source.index("AgencyWebsiteConnectChallenge.agency_id == agency.id")
    commit = source.index("await operational_db.commit()")

    assert agency_lock < workspace_lock < site_lock < challenge_lock < commit
    assert ".with_for_update()" in source[agency_lock:workspace_lock]
    assert ".with_for_update()" in source[workspace_lock:site_lock]
    assert ".with_for_update()" in source[site_lock:challenge_lock]
    assert ".with_for_update()" in source[challenge_lock:commit]
    assert 'agency.status != "active"' in source[agency_lock:workspace_lock]
    assert 'workspace.status != "active"' in source[workspace_lock:site_lock]
    assert "site.site_token_hash = None" in source[site_lock:challenge_lock]


def test_agency_wordpress_heartbeat_revalidates_credential_under_lifecycle_locks():
    import inspect
    import main

    source = inspect.getsource(main.get_agency_wordpress_site_status)
    candidate = source.index("AgencyClientWebsite.site_token_hash == token_hash")
    agency_lock = source.index("AgencyAccount.id == candidate.agency_id")
    workspace_lock = source.index("AgencyClientWorkspace.id == candidate.workspace_id")
    site_recheck = source.index("AgencyClientWebsite.id == candidate.id")
    heartbeat = source.index("site.last_seen_at = datetime.now(timezone.utc)")
    commit = source.index("await operational_db.commit()")

    assert candidate < agency_lock < workspace_lock < site_recheck < heartbeat < commit
    assert ".with_for_update()" in source[agency_lock:workspace_lock]
    assert ".with_for_update()" in source[workspace_lock:site_recheck]
    assert ".with_for_update()" in source[site_recheck:heartbeat]
    assert 'agency.status != "active"' in source[agency_lock:workspace_lock]
    assert 'workspace.status != "active"' in source[workspace_lock:site_recheck]
    assert 'AgencyClientWebsite.site_token_hash == token_hash' in source[site_recheck:heartbeat]
    assert 'AgencyClientWebsite.status == "active"' in source[site_recheck:heartbeat]
