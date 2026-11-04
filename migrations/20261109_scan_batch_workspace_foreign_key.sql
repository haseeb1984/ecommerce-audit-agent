-- Enforce the same optional workspace relationship declared by ScanBatch.workspace_id.
-- Apply after 20261101_agency_operational_tables.sql and
-- 20261108_hostinger_operational_index_alignment.sql.
-- Existing orphan workspace IDs intentionally cause ALTER TABLE to fail so an
-- operator can reconcile the data rather than silently leaving referential drift.

SET @scan_batch_workspace_fk_exists = (
    SELECT COUNT(*)
    FROM information_schema.referential_constraints
    WHERE constraint_schema = DATABASE()
      AND table_name = 'scan_batches'
      AND constraint_name = 'fk_scan_batches_workspace'
);

SET @scan_batch_workspace_fk_sql = IF(
    @scan_batch_workspace_fk_exists = 0,
    'ALTER TABLE scan_batches ADD CONSTRAINT fk_scan_batches_workspace FOREIGN KEY (workspace_id) REFERENCES agency_client_workspaces(id) ON DELETE SET NULL',
    'SELECT 1'
);

PREPARE scan_batch_workspace_fk_stmt FROM @scan_batch_workspace_fk_sql;
EXECUTE scan_batch_workspace_fk_stmt;
DEALLOCATE PREPARE scan_batch_workspace_fk_stmt;
