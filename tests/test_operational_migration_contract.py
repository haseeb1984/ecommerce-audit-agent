"""Keep the Hostinger scan-batch migration aligned with its ORM contract."""

from pathlib import Path

from hostinger_models import ScanBatch


ROOT = Path(__file__).resolve().parents[1]


def test_scan_batch_sequence_constraint_is_declared_in_the_orm():
    constraint_names = {
        constraint.name for constraint in ScanBatch.__table__.constraints
    }
    assert "uq_scan_batches_sequence" in constraint_names


def test_fresh_hostinger_schema_includes_scan_batch_sequence_constraint():
    schema = (ROOT / "migrations" / "hostinger_operational_schema.sql").read_text()
    assert (
        "UNIQUE KEY uq_scan_batches_sequence "
        "(license_key, batch_number, created_at)"
    ) in schema


def test_existing_hostinger_databases_have_forward_sequence_constraint_migration():
    migration = (
        ROOT / "migrations" / "20261107_scan_batch_sequence_constraint.sql"
    ).read_text()
    assert "information_schema.statistics" in migration
    assert "uq_scan_batches_sequence" in migration
    assert "CREATE UNIQUE INDEX uq_scan_batches_sequence" in migration
    assert "HAVING COUNT(*) > 1" in migration

def test_agency_operational_tables_exist_in_fresh_schema_and_forward_migration():
    from hostinger_models import (
        AgencyAccount,
        AgencyClientWebsite,
        AgencyClientWorkspace,
        AgencyTeamLoginChallenge,
        AgencyTeamMember,
        AgencyTeamSession,
        AgencyUsageEvent,
        AgencyWebsiteConnectChallenge,
        AgencyWorkspaceAccess,
    )

    expected = {
        "agency_accounts": AgencyAccount,
        "agency_client_workspaces": AgencyClientWorkspace,
        "agency_client_websites": AgencyClientWebsite,
        "agency_website_connect_challenges": AgencyWebsiteConnectChallenge,
        "agency_team_members": AgencyTeamMember,
        "agency_team_login_challenges": AgencyTeamLoginChallenge,
        "agency_team_sessions": AgencyTeamSession,
        "agency_workspace_access": AgencyWorkspaceAccess,
        "agency_usage_events": AgencyUsageEvent,
    }
    baseline = (ROOT / "migrations" / "hostinger_operational_schema.sql").read_text()
    migration = (
        ROOT / "migrations" / "20261108_agency_operational_tables.sql"
    ).read_text()

    for table_name, model in expected.items():
        assert f"CREATE TABLE IF NOT EXISTS {table_name}" in baseline
        assert f"CREATE TABLE IF NOT EXISTS {table_name}" in migration
        assert table_name in model.__table__.metadata.tables
        assert model.__tablename__ == table_name

    assert "FOREIGN KEY (workspace_id) REFERENCES agency_client_workspaces(id)" in baseline
    assert "FOREIGN KEY (team_member_id) REFERENCES agency_team_members(id)" in baseline
    assert "uq_agency_team_normalized_email" in baseline
    assert "uq_agency_usage_source_reference" in baseline
    assert "uq_agency_workspace_site_host" in baseline
