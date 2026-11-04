from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_scan_batch_workspace_foreign_key_matches_orm_and_is_idempotent():
    from hostinger_models import ScanBatch

    column = ScanBatch.__table__.columns["workspace_id"]
    foreign_keys = list(column.foreign_keys)

    assert column.nullable is True
    assert len(foreign_keys) == 1
    foreign_key = foreign_keys[0]
    assert foreign_key.target_fullname == "agency_client_workspaces.id"
    assert foreign_key.ondelete == "SET NULL"

    migration = (
        ROOT / "migrations" / "20261109_scan_batch_workspace_foreign_key.sql"
    ).read_text()
    assert "information_schema.referential_constraints" in migration
    assert "fk_scan_batches_workspace" in migration
    assert (
        "FOREIGN KEY (workspace_id) "
        "REFERENCES agency_client_workspaces(id) ON DELETE SET NULL"
    ) in migration
    assert "PREPARE scan_batch_workspace_fk_stmt" in migration
    assert "DEALLOCATE PREPARE scan_batch_workspace_fk_stmt" in migration
