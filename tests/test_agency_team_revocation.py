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
