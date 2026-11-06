from pathlib import Path
import inspect

import main


def test_admin_agency_detail_is_tenant_scoped_bounded_and_secret_free():
    source = inspect.getsource(main.admin_get_business_agency_detail)
    assert 'AgencyAccount.id == agency_id' in source
    assert 'AgencyClientWorkspace.agency_id == agency.id' in source
    assert 'AgencyTeamMember.agency_id == agency.id' in source
    assert '.limit(100)' in source
    assert 'AgencyClientWebsite.agency_id == agency.id' in source
    assert 'AgencyWorkspaceAccess.agency_id == agency.id' in source
    assert '"workspaces_total": workspace_total' in source
    assert '"team_members_total": member_total' in source
    assert '"truncated": len(workspaces) < workspace_total or len(members) < member_total' in source
    for secret_field in (
        'site_token_hash', 'invitation_token_hash', 'owner_license_key',
        'invitation_expires_at',
    ):
        assert secret_field not in source
    assert 'Cache-Control' in source and 'no-store, private' in source


def test_admin_agency_detail_ui_guards_session_switch_and_renders_workspace_team_data():
    portal = (Path(__file__).resolve().parents[1] / "admin_portal.html").read_text()
    assert 'id="agencyDetail"' in portal
    assert 'View details' in portal
    assert 'showAgencyDetail' in portal
    assert 'agencyDetailRequestVersion' in portal
    assert 'requestVersion!==agencyDetailRequestVersion' in portal
    assert 'sessionVersion!==adminSessionVersion' in portal
    assert 'website_connections' in portal
    assert 'team_members' in portal
    assert 'agencyDetailRequestVersion+=1' in portal



def test_admin_agency_status_transition_is_audited_after_commit():
    source = inspect.getsource(main.admin_update_business_agency)
    assert 'previous_status = agency.status' in source
    assert 'await operational_db.commit()' in source
    assert 'await _write_admin_log(' in source
    assert source.index('await operational_db.commit()') < source.index('await _write_admin_log(')
    assert '"agency_status_changed"' in source
    assert '"previous_status": previous_status' in source
    assert '"new_status": agency.status' in source
    assert 'if previous_status != agency.status:' in source
