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
