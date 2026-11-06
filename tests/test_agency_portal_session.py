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
