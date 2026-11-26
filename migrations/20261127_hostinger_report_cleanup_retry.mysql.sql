-- Add durable retry ordering for Hostinger private report cleanup.
-- Fresh installs already receive these fields from hostinger_operational_schema.sql.
-- Existing installations: back up the operational DB, then apply once.

SET @ddl = IF(
    (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='customer_report_files' AND column_name='cleanup_attempts')=0,
    'ALTER TABLE customer_report_files ADD COLUMN cleanup_attempts INT NOT NULL DEFAULT 0',
    'SELECT 1'
);
PREPARE eaa_report_cleanup_attempts FROM @ddl; EXECUTE eaa_report_cleanup_attempts; DEALLOCATE PREPARE eaa_report_cleanup_attempts;

SET @ddl = IF(
    (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='customer_report_files' AND column_name='cleanup_last_attempt_at')=0,
    'ALTER TABLE customer_report_files ADD COLUMN cleanup_last_attempt_at DATETIME(6) NULL',
    'SELECT 1'
);
PREPARE eaa_report_cleanup_last_attempt FROM @ddl; EXECUTE eaa_report_cleanup_last_attempt; DEALLOCATE PREPARE eaa_report_cleanup_last_attempt;

SET @ddl = IF(
    (SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='customer_report_files' AND index_name='ix_customer_report_files_cleanup')=0,
    'CREATE INDEX ix_customer_report_files_cleanup ON customer_report_files (expires_at, deleted_at, cleanup_last_attempt_at)',
    'SELECT 1'
);
PREPARE eaa_report_cleanup_index FROM @ddl; EXECUTE eaa_report_cleanup_index; DEALLOCATE PREPARE eaa_report_cleanup_index;
