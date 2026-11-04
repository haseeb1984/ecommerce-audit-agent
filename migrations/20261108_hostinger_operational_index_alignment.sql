-- Hostinger MySQL: align operational tables with the current SQLAlchemy model indexes.
-- Safe to run after the agency operational tables migration. No live database is
-- modified by CI; operators must review and apply this migration deliberately.

SET @scan_batches_workspace_column_exists = (
    SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'scan_batches'
      AND column_name = 'workspace_id'
);
SET @scan_batches_workspace_column_sql = IF(
    @scan_batches_workspace_column_exists = 0,
    'ALTER TABLE scan_batches ADD COLUMN workspace_id VARCHAR(64) NULL AFTER request_id',
    'SELECT 1'
);
PREPARE scan_batches_workspace_column_stmt FROM @scan_batches_workspace_column_sql;
EXECUTE scan_batches_workspace_column_stmt;
DEALLOCATE PREPARE scan_batches_workspace_column_stmt;

-- Create each index only when it is absent. Existing composite indexes are
-- retained; these named indexes mirror the ORM's declared access paths.
SET @ddl = IF((SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='scan_batches' AND index_name='ix_scan_batches_workspace_id')=0,
    'CREATE INDEX ix_scan_batches_workspace_id ON scan_batches (workspace_id)', 'SELECT 1');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;

SET @ddl = IF((SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='scan_batches' AND index_name='ix_scan_batches_available_at')=0,
    'CREATE INDEX ix_scan_batches_available_at ON scan_batches (available_at)', 'SELECT 1');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;

SET @ddl = IF((SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='website_scan_jobs' AND index_name='ix_website_scan_jobs_next_attempt_at')=0,
    'CREATE INDEX ix_website_scan_jobs_next_attempt_at ON website_scan_jobs (next_attempt_at)', 'SELECT 1');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;

SET @ddl = IF((SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='wordpress_site_link_challenges' AND index_name='ix_wp_site_link_challenges_license_created')=0,
    'CREATE INDEX ix_wp_site_link_challenges_license_created ON wordpress_site_link_challenges (license_key, created_at)', 'SELECT 1');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;

SET @ddl = IF((SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='website_scan_results' AND index_name='ix_website_scan_results_job_id')=0,
    'CREATE INDEX ix_website_scan_results_job_id ON website_scan_results (job_id)', 'SELECT 1');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;

SET @ddl = IF((SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='customer_email_identity_sync_outbox' AND index_name='ix_customer_email_identity_sync_outbox_next_attempt_at')=0,
    'CREATE INDEX ix_customer_email_identity_sync_outbox_next_attempt_at ON customer_email_identity_sync_outbox (next_attempt_at)', 'SELECT 1');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;
