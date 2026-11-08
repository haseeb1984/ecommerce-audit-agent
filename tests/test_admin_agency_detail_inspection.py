from pathlib import Path
import inspect

import main


def test_admin_agency_detail_is_tenant_scoped_bounded_and_secret_free():
    source = inspect.getsource(main.admin_get_business_agency_detail)
    assert 'AgencyAccount.id == agency_id' in source
    assert 'AgencyClientWorkspace.agency_id == agency.id' in source
    assert 'AgencyTeamMember.agency_id == agency.id' in source
    assert 'workspace_limit: int = Query(default=50, ge=1, le=100)' in source
    assert 'workspace_offset: int = Query(default=0, ge=0, le=1000000)' in source
    assert 'member_limit: int = Query(default=50, ge=1, le=100)' in source
    assert 'member_offset: int = Query(default=0, ge=0, le=1000000)' in source
    assert '.offset(workspace_offset).limit(workspace_limit)' in source
    assert '.offset(member_offset).limit(member_limit)' in source
    assert 'AgencyClientWebsite.agency_id == agency.id' in source
    assert 'AgencyWorkspaceAccess.agency_id == agency.id' in source
    assert '"workspaces_total": workspace_total' in source
    assert '"team_members_total": member_total' in source
    assert '"workspaces_has_more": workspace_offset + len(workspaces) < workspace_total' in source
    assert '"members_has_more": member_offset + len(members) < member_total' in source
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



def test_admin_agency_detail_ui_loads_workspace_and_member_pages_independently():
    portal = (Path(__file__).resolve().parents[1] / "admin_portal.html").read_text()
    assert '"Load more workspaces"' in portal
    assert '"Load more team members"' in portal
    assert 'workspace_offset="+(p.workspace_offset+p.workspace_limit)' in portal
    assert 'member_offset="+(p.member_offset+p.member_limit)' in portal
    assert 'requestVersion!==agencyDetailRequestVersion||sessionVersion!==adminSessionVersion' in portal
