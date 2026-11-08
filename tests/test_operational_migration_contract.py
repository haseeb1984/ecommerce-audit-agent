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



def test_legacy_customer_account_id_is_stable_and_tenant_scoped():
    from scripts.migrate_operational_data_to_hostinger import _legacy_account_id

    first = _legacy_account_id("LICENSE-A", "Customer@Example.com")
    repeated = _legacy_account_id("license-a", "customer@example.com")
    another_license = _legacy_account_id("license-b", "customer@example.com")

    assert first == repeated
    assert first.startswith("legacy-")
    assert len(first) == len("legacy-") + 48
    assert first != another_license


def test_operational_migration_defaults_to_rollback_and_only_commits_on_apply():
    import ast

    source = (
        ROOT / "scripts" / "migrate_operational_data_to_hostinger.py"
    ).read_text()
    tree = ast.parse(source)
    migrate_function = next(
        node for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "migrate"
    )
    commit_calls = [
        node for node in ast.walk(migrate_function)
        if isinstance(node, ast.Await)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Attribute)
        and node.value.func.attr == "commit"
    ]
    rollback_calls = [
        node for node in ast.walk(migrate_function)
        if isinstance(node, ast.Await)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Attribute)
        and node.value.func.attr == "rollback"
    ]

    assert len(commit_calls) == 3  # account batches, note batches, and final flush
    assert len(rollback_calls) == 1
    apply_guards = [
        node for node in ast.walk(migrate_function)
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Name)
        and node.test.id == "apply_changes"
    ]
    assert all(
        any(call in ast.walk(guard) for guard in apply_guards)
        for call in commit_calls
    )
    assert all(
        rollback_calls[0] not in ast.walk(guard)
        for guard in apply_guards
    )



def test_operational_migration_verification_counts_only_missing_mapped_rows():
    from scripts.migrate_operational_data_to_hostinger import _verification_gaps

    reports = {
        "customer_accounts": {"source_candidates": 4, "to_copy": 2, "already_present": 2},
        "customer_sessions": {"source": 5, "to_copy": 0, "already_present_or_unmapped": 5},
        "admin_customer_notes": {
            "source": 3,
            "to_copy": 0,
            "already_present": 1,
            "ambiguous_license_mapping": 1,
            "unmapped_email": 1,
        },
    }

    assert _verification_gaps(reports) == {
        "customer_accounts": {"missing": 2, "field_mismatches": 0}
    }


def test_operational_migration_verification_fails_on_existing_field_divergence():
    from scripts.migrate_operational_data_to_hostinger import (
        _mismatched_fields,
        _verification_gaps,
    )
    from types import SimpleNamespace
    from datetime import datetime, timezone

    existing = SimpleNamespace(
        license_key="license-a",
        email="customer@example.com",
        display_name="Old name",
        created_at=datetime(2026, 1, 1),
    )
    expected = {
        "license_key": "license-a",
        "email": "customer@example.com",
        "display_name": "New name",
        "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
    }

    assert _mismatched_fields(existing, expected) == ["display_name"]
    assert _verification_gaps({
        "customer_accounts": {
            "to_copy": 0,
            "field_mismatches": 1,
            "mismatched_fields": ["display_name"],
        }
    }) == {
        "customer_accounts": {"missing": 0, "field_mismatches": 1}
    }


def test_operational_migration_verification_normalizes_timezone_equivalent_datetimes():
    from scripts.migrate_operational_data_to_hostinger import _mismatched_fields
    from types import SimpleNamespace
    from datetime import datetime, timezone, timedelta

    expected = datetime(2026, 1, 1, 12, tzinfo=timezone(timedelta(hours=5)))
    existing = SimpleNamespace(created_at=datetime(2026, 1, 1, 7, tzinfo=timezone.utc))

    assert _mismatched_fields(existing, {"created_at": expected}) == []


def test_operational_migration_cli_offers_mutually_exclusive_apply_and_verify_modes():
    import ast

    source = (
        ROOT / "scripts" / "migrate_operational_data_to_hostinger.py"
    ).read_text()
    tree = ast.parse(source)
    main_function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    source_segment = ast.get_source_segment(source, main_function)

    assert "add_mutually_exclusive_group()" in source_segment
    assert '"--apply"' in source_segment
    assert '"--verify"' in source_segment
    assert "verify_only=args.verify" in source_segment
    assert "raise SystemExit(1)" in source_segment



def test_dry_run_and_verify_never_stage_target_inserts():
    source = (
        ROOT / "scripts" / "migrate_operational_data_to_hostinger.py"
    ).read_text()

    assert "if stage_missing:\n                    target.add(target_model(**values))" in source
    assert "if apply_changes:\n                    target.add(CustomerAccount(**expected_account))" in source
    assert "if apply_changes:\n                    target.add(AdminCustomerNote(**expected_note))" in source
    assert source.count("stage_missing=apply_changes") == 8


def test_operational_row_migration_streams_and_reconciles_in_bounded_batches():
    import ast

    source = (
        ROOT / "scripts" / "migrate_operational_data_to_hostinger.py"
    ).read_text()
    tree = ast.parse(source)
    copy_rows = next(
        node for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_copy_rows"
    )
    source_segment = ast.get_source_segment(source, copy_rows)

    assert "MIGRATION_BATCH_SIZE = 500" in source
    assert "source.stream_scalars(statement)" in source_segment
    assert "async for row in result" in source_segment
    assert "key_column.in_(list(expected_by_key))" in source_segment
    assert "target.scalar(" not in source_segment
    assert "await result.close()" in source_segment


def test_account_and_support_note_migration_streams_source_and_batches_target_lookups():
    import ast

    source = (
        ROOT / "scripts" / "migrate_operational_data_to_hostinger.py"
    ).read_text()
    tree = ast.parse(source)
    migrate_function = next(
        node for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "migrate"
    )
    migrate_segment = ast.get_source_segment(source, migrate_function)

    assert "_stream_rows(source, AccountSession)" in migrate_segment
    assert "_stream_rows(source, WordPressSite)" in migrate_segment
    assert "source.stream_scalars(billing_statement)" in migrate_segment
    assert "_stream_rows(source, SaaSAdminCustomerNote)" in migrate_segment
    assert "tuple_(CustomerAccount.license_key, CustomerAccount.email).in_(identity_keys)" in migrate_segment
    assert "AdminCustomerNote.id.in_(list(expected_by_id))" in migrate_segment
    assert "account_candidate_iterator = iter(account_candidates.items())" in migrate_segment
    assert "list(account_candidates.items())" not in migrate_segment
    assert '"source": note_source_count' in migrate_segment


def test_operational_license_identity_map_uses_streaming_projection():
    import ast

    source = (
        ROOT / "scripts" / "migrate_operational_data_to_hostinger.py"
    ).read_text()
    tree = ast.parse(source)
    license_map = next(
        node for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_license_map"
    )
    segment = ast.get_source_segment(source, license_map)

    assert "source.stream(" in segment
    assert "SoftwareLicense.id, SoftwareLicense.license_key, SoftwareLicense.client_name" in segment
    assert ".scalars().all()" not in segment
    assert "await result.close()" in segment


def test_generic_operational_copy_commits_each_apply_batch_but_not_dry_run():
    import ast

    source = (
        ROOT / "scripts" / "migrate_operational_data_to_hostinger.py"
    ).read_text()
    tree = ast.parse(source)
    copy_rows = next(
        node for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_copy_rows"
    )
    reconcile = next(
        node for node in copy_rows.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "reconcile_batch"
    )
    apply_guard = next(
        node for node in reconcile.body
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Name)
        and node.test.id == "stage_missing"
    )
    commits = [
        node for node in ast.walk(reconcile)
        if isinstance(node, ast.Await)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Attribute)
        and node.value.func.attr == "commit"
    ]

    assert len(commits) == 1
    assert commits[0] in ast.walk(apply_guard)


def test_billing_email_license_ownership_is_grouped_and_streamed_by_postgres():
    import ast

    source = (
        ROOT / "scripts" / "migrate_operational_data_to_hostinger.py"
    ).read_text()
    tree = ast.parse(source)
    resolver = next(
        node for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef)
        and node.name == "_stream_billing_license_ownership"
    )
    segment = ast.get_source_segment(source, resolver)

    assert "func.count(func.distinct(SoftwareLicense.license_key))" in segment
    assert ".group_by(normalized_email)" in segment
    assert "source.stream(statement)" in segment
    assert "await result.close()" in segment
    assert "candidates.setdefault(email, set())" not in segment

    migrate = next(
        node for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "migrate"
    )
    migrate_segment = ast.get_source_segment(source, migrate)
    assert "await _stream_billing_license_ownership(source)" in migrate_segment
    assert "billing_license_candidates" not in migrate_segment
