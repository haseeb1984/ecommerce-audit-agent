from hostinger_models import (
    AgencyAccount,
    AgencyClientWorkspace,
    AgencyClientWebsite,
    AgencyTeamMember,
    AgencyWorkspaceAccess,
    AgencyUsageEvent,
    ScanBatch,
)


def _unique_column_sets(model):
    return {
        tuple(column.name for column in constraint.columns)
        for constraint in model.__table__.constraints
        if constraint.__class__.__name__ == "UniqueConstraint"
    }


def _foreign_key_targets(model):
    return {
        (column.name, next(iter(column.foreign_keys)).target_fullname)
        for column in model.__table__.columns
        if column.foreign_keys
    }


def test_business_agency_tables_are_registered():
    expected = {
        "agency_accounts", "agency_client_workspaces", "agency_client_websites",
        "agency_team_members", "agency_workspace_access", "agency_usage_events",
    }
    actual = {
        AgencyAccount.__tablename__, AgencyClientWorkspace.__tablename__,
        AgencyClientWebsite.__tablename__, AgencyTeamMember.__tablename__,
        AgencyWorkspaceAccess.__tablename__, AgencyUsageEvent.__tablename__,
    }
    assert actual == expected


def test_agency_is_unique_per_business_license():
    assert ("owner_license_key",) in _unique_column_sets(AgencyAccount)


def test_agency_client_workspaces_are_tenant_owned():
    assert ("agency_id", "agency_accounts.id") in _foreign_key_targets(AgencyClientWorkspace)
    assert ("agency_id", "external_reference") in _unique_column_sets(AgencyClientWorkspace)


def test_agency_website_is_bound_to_its_agency_and_workspace():
    targets = _foreign_key_targets(AgencyClientWebsite)
    assert ("agency_id", "agency_accounts.id") in targets
    assert ("workspace_id", "agency_client_workspaces.id") in targets
    assert ("workspace_id", "site_host") in _unique_column_sets(AgencyClientWebsite)


def test_agency_team_invitation_and_workspace_grants_are_tenant_scoped():
    assert ("agency_id", "normalized_email") in _unique_column_sets(AgencyTeamMember)
    assert ("agency_id", "agency_accounts.id") in _foreign_key_targets(AgencyTeamMember)
    targets = _foreign_key_targets(AgencyWorkspaceAccess)
    assert ("agency_id", "agency_accounts.id") in targets
    assert ("workspace_id", "agency_client_workspaces.id") in targets
    assert ("team_member_id", "agency_team_members.id") in targets
    assert ("workspace_id", "team_member_id") in _unique_column_sets(AgencyWorkspaceAccess)


def test_agency_usage_ledger_has_idempotency_and_workspace_ownership():
    assert ("agency_id", "source_reference") in _unique_column_sets(AgencyUsageEvent)
    targets = _foreign_key_targets(AgencyUsageEvent)
    assert ("agency_id", "agency_accounts.id") in targets
    assert ("workspace_id", "agency_client_workspaces.id") in targets


def test_scan_batches_can_be_attributed_to_a_client_workspace():
    assert "workspace_id" in ScanBatch.__table__.columns
    assert ("workspace_id", "agency_client_workspaces.id") in _foreign_key_targets(ScanBatch)
