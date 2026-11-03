-- Hostinger MySQL: enforce the ORM's per-license batch sequence uniqueness.
-- The enqueue path serializes allocations through scan_batch_sequences; this
-- constraint is the final database-level guard against duplicate sequence rows.
-- Review any duplicate rows returned by the preflight query before applying:
-- SELECT license_key, batch_number, created_at, COUNT(*) AS duplicate_count
-- FROM scan_batches GROUP BY license_key, batch_number, created_at
-- HAVING COUNT(*) > 1;
--
-- Conditional DDL keeps this migration safe after the updated baseline has
-- already created the index on a fresh installation.
SET @scan_batch_sequence_index_exists = (
    SELECT COUNT(*)
    FROM information_schema.statistics
    WHERE table_schema = DATABASE()
      AND table_name = 'scan_batches'
      AND index_name = 'uq_scan_batches_sequence'
);
SET @scan_batch_sequence_index_sql = IF(
    @scan_batch_sequence_index_exists = 0,
    'CREATE UNIQUE INDEX uq_scan_batches_sequence ON scan_batches (license_key, batch_number, created_at)',
    'SELECT 1'
);
PREPARE scan_batch_sequence_index_stmt FROM @scan_batch_sequence_index_sql;
EXECUTE scan_batch_sequence_index_stmt;
DEALLOCATE PREPARE scan_batch_sequence_index_stmt;
