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
        ROOT / "migrations" / "20261101_agency_operational_tables.sql"
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

def test_fresh_hostinger_schema_covers_every_registered_operational_model():
    from hostinger_database import HostingerBase
    import hostinger_models  # noqa: F401 - register all operational model tables

    schema = (ROOT / "migrations" / "hostinger_operational_schema.sql").read_text()
    missing = [
        table_name
        for table_name in HostingerBase.metadata.tables
        if f"CREATE TABLE IF NOT EXISTS {table_name}" not in schema
    ]
    assert missing == []


def test_customer_report_storage_key_uses_mysql_safe_fixed_width_uniqueness():
    from hostinger_models import CustomerReportFile

    columns = CustomerReportFile.__table__.columns
    assert columns["storage_key"].type.length == 1024
    assert columns["storage_key"].unique is not True
    assert columns["storage_key_hash"].type.length == 64
    assert columns["storage_key_hash"].unique is True


def test_fresh_hostinger_schema_and_forward_migration_cover_storage_key_hash():
    schema = (ROOT / "migrations" / "hostinger_operational_schema.sql").read_text()
    migration = (
        ROOT / "migrations" / "hostinger"
        / "20261103_customer_report_storage_key_hash.sql"
    ).read_text()
    assert "storage_key VARCHAR(1024) NOT NULL," in schema
    assert "storage_key_hash CHAR(64) NOT NULL UNIQUE" in schema
    assert "SHA2(storage_key, 256)" in migration
    assert "information_schema.columns" in migration
    assert "information_schema.statistics" in migration
    assert "DROP INDEX storage_key" in migration
    assert "uq_customer_report_files_storage_key_hash" in migration
    assert "SELECT 1" in migration



def test_fresh_hostinger_schema_preserves_operational_index_and_unique_constraint_coverage():
    import re

    from sqlalchemy import UniqueConstraint
    from hostinger_database import HostingerBase
    import hostinger_models  # noqa: F401 - register all operational model tables

    schema = (ROOT / "migrations" / "hostinger_operational_schema.sql").read_text()
    table_blocks = {
        name: body
        for name, body in re.findall(
            r"CREATE TABLE IF NOT EXISTS\s+(\w+)\s*\((.*?)\)\s*ENGINE=",
            schema,
            flags=re.IGNORECASE | re.DOTALL,
        )
    }

    def declared_indexes(table_name):
        body = table_blocks[table_name]
        found = []
        for unique, columns in re.findall(
            r"\b(UNIQUE\s+)?(?:KEY|INDEX)\s+\w+\s*\(([^)]*)\)",
            body,
            flags=re.IGNORECASE,
        ):
            names = tuple(
                part.strip().strip("`").split()[0].split("(")[0]
                for part in columns.split(",")
            )
            found.append((bool(unique), names))
        # Column-level UNIQUE also creates a unique MySQL index.
        for column_name, definition in re.findall(
            r"^\s*(\w+)\s+([^,\n]+)",
            body,
            flags=re.MULTILINE,
        ):
            if re.search(r"\bUNIQUE\b", definition, flags=re.IGNORECASE):
                found.append((True, (column_name,)))
        return found

    missing = []
    for table in HostingerBase.metadata.tables.values():
        if table.name not in table_blocks:
            continue
        sql_indexes = declared_indexes(table.name)
        for index in table.indexes:
            expected = tuple(column.name for column in index.columns)
            covered = any(
                sql_columns[: len(expected)] == expected
                and (not index.unique or sql_unique)
                for sql_unique, sql_columns in sql_indexes
            )
            if not covered:
                missing.append(f"{table.name}.{index.name}{expected}")
        for constraint in table.constraints:
            if not isinstance(constraint, UniqueConstraint) or not constraint.name:
                continue
            expected = tuple(column.name for column in constraint.columns)
            covered = any(
                sql_unique and sql_columns == expected
                for sql_unique, sql_columns in sql_indexes
            )
            if not covered:
                missing.append(f"{table.name}.{constraint.name}{expected}")

    assert missing == [], (
        "Fresh Hostinger schema is missing ORM index/unique coverage: "
        f"{missing}"
    )


def test_support_note_migration_refuses_ambiguous_email_to_license_mapping():
    from types import SimpleNamespace

    from scripts.migrate_operational_data_to_hostinger import _billing_license_map

    billing_rows = [
        SimpleNamespace(recipient_email=" Shared@Example.com ", license_id=1),
        SimpleNamespace(recipient_email="shared@example.com", license_id=2),
        SimpleNamespace(recipient_email="single@example.com", license_id=3),
        SimpleNamespace(recipient_email="orphan@example.com", license_id=None),
    ]

    resolved, ambiguous = _billing_license_map(
        billing_rows,
        {1: "license-one", 2: "license-two", 3: "license-three"},
    )

    assert resolved == {"single@example.com": "license-three"}
    assert ambiguous == {"shared@example.com"}
