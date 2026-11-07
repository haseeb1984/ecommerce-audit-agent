from pathlib import Path


def test_agency_portal_invalidates_in_flight_requests_when_session_changes():
    portal = Path("agency_portal.html").read_text(encoding="utf-8")
    start = portal.index("(() => {")
    script = portal[start:portal.index("</script>", start)]

    assert "let sessionVersion = 0;" in script
    assert "function assertCurrentSession(version)" in script
    assert "assertCurrentSession(expectedVersion);" in script
    assert "assertCurrentSession(expectedVersion);\n    const data = await response.json()" in script
    assert "sessionVersion += 1;" in script
    assert '$("workspaces").replaceChildren();' in script
    assert 'const logoutToken=token;showSignedOut();' in script
    assert 'if(actionVersion===sessionVersion)' in script


def test_agency_portal_protects_workspace_and_saved_audit_requests():
    portal = Path("agency_portal.html").read_text(encoding="utf-8")
    start = portal.index("(() => {")
    script = portal[start:portal.index("</script>", start)]

    assert '"/api/v1/agency/team/workspaces", {}, expectedVersion' in script
    assert '"/api/v1/agency/team/auth/me",{},expectedVersion' in script
    assert '"/audits?limit="+historyPageSize+"&offset="+offset,{},actionVersion' in script
    assert '"/audit-results?batch_id="+encodeURIComponent(batch.id)+"&limit=25",{},evidenceVersion' in script
    assert '},actionVersion);' in script


def test_agency_portal_paginates_audit_history_without_losing_session_guards():
    portal = Path("agency_portal.html").read_text(encoding="utf-8")
    start = portal.index("(() => {")
    script = portal[start:portal.index("</script>", start)]

    assert "const historyPageSize=50;" in script
    assert '"/audits?limit="+historyPageSize+"&offset="+offset' in script
    assert 'historyLoadMore.textContent="Load older audit batches"' in script
    assert "historyOffset=offset+result.items.length;" in script
    assert "loadHistoryPage(historyOffset,true)" in script
    assert "assertCurrentSession(actionVersion);" in script
    assert "history.replaceChildren(); historyOffset=0;" in script


def test_customer_portal_agency_workspace_rename_and_archive_confirmation():
    from pathlib import Path

    portal = Path("customer_portal.html").read_text()
    assert 'rename.textContent = "Rename client"' in portal
    assert "body: JSON.stringify({display_name: displayName})" in portal
    assert "Client workspace name cannot be blank." in portal
    assert "if (!window.confirm(confirmation)) return;" in portal
    assert "Existing audit history is retained." in portal


def test_agency_portal_exposes_agency_role_editor_and_preserves_workspace_overrides():
    portal = Path("customer_portal.html").read_text(encoding="utf-8")

    assert 'agencyRoleLabel.textContent = "Agency default role"' in portal
    assert 'method:"PUT"' in portal
    assert '"/api/v1/account/agency/team/" + encodeURIComponent(item.id)' in portal
    assert "Custom workspace roles were preserved." in portal


def test_agency_member_role_api_updates_default_role_without_overwriting_custom_grants():
    import inspect
    import main

    assert "/api/v1/account/agency/team/{member_id}" in main.app.openapi()["paths"]
    source = inspect.getsource(main.update_business_agency_team_member_role)
    assert "AgencyAccount.owner_license_key == license_obj.license_key" in source
    assert "AgencyTeamMember.agency_id == agency.id" in source
    assert 'AgencyTeamMember.status == "active"' in source
    assert "AgencyWorkspaceAccess.role == previous_role" in source
    assert ".values(role=payload.role)" in source


def test_customer_portal_confirms_and_reports_team_member_revocation():
    portal = Path("customer_portal.html").read_text(encoding="utf-8")
    start = portal.index("async function loadAgencyTeam()")
    end = portal.index("async function inviteAgencyTeam()", start)
    section = portal[start:end]

    assert 'window.confirm("Revoke access for " + item.email' in section
    assert 'method:"DELETE"' in section
    assert 'setStatus("agencyStatus", "Access revoked for " + item.email, "success")' in section
    assert "revoke.disabled = true" in section


def test_agency_portal_otp_attempts_ignore_stale_responses():
    portal = Path("agency_portal.html").read_text(encoding="utf-8")
    start = portal.index("(() => {")
    script = portal[start:portal.index("</script>", start)]

    assert "let authAttemptVersion = 0;" in script
    assert "const attemptVersion=++authAttemptVersion;" in script
    assert "if(attemptVersion!==authAttemptVersion)return;" in script
    assert 'if(actionVersion===sessionVersion&&attemptVersion===authAttemptVersion)$("loginStatus").textContent=error.message;' in script
    assert 'if(actionVersion===sessionVersion&&attemptVersion===authAttemptVersion)button.disabled=false;' in script
    assert "authAttemptVersion += 1;" in script
    assert 'if(!result.access_token)throw new Error("The server did not return an agency session.");' in script
