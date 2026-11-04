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
    assert '"/audits?limit=100",{},actionVersion' in script
    assert '"/audit-results?batch_id="+encodeURIComponent(batch.id)+"&limit=25",{},actionVersion' in script
    assert '},actionVersion);' in script
