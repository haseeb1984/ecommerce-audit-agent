-- Preserve full private report storage keys without exceeding MySQL's
-- 3072-byte utf8mb4 unique-index limit.
-- Safe for both fresh schemas (which already include storage_key_hash) and
-- existing schemas (which require a backfill and unique-index replacement).
SET @has_storage_key_hash := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'customer_report_files'
    AND column_name = 'storage_key_hash'
);
SET @add_storage_key_hash := IF(
  @has_storage_key_hash = 0,
  'ALTER TABLE customer_report_files ADD COLUMN storage_key_hash CHAR(64) NULL AFTER storage_key',
  'SELECT 1'
);
PREPARE stmt_add_storage_key_hash FROM @add_storage_key_hash;
EXECUTE stmt_add_storage_key_hash;
DEALLOCATE PREPARE stmt_add_storage_key_hash;

UPDATE customer_report_files
SET storage_key_hash = SHA2(storage_key, 256)
WHERE storage_key_hash IS NULL;

ALTER TABLE customer_report_files
  MODIFY storage_key_hash CHAR(64) NOT NULL;

SET @has_legacy_storage_key_index := (
  SELECT COUNT(*) FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'customer_report_files'
    AND index_name = 'storage_key'
);
SET @drop_legacy_storage_key_index := IF(
  @has_legacy_storage_key_index > 0,
  'ALTER TABLE customer_report_files DROP INDEX storage_key',
  'SELECT 1'
);
PREPARE stmt_drop_legacy_storage_key_index FROM @drop_legacy_storage_key_index;
EXECUTE stmt_drop_legacy_storage_key_index;
DEALLOCATE PREPARE stmt_drop_legacy_storage_key_index;

SET @has_storage_key_hash_index := (
  SELECT COUNT(*) FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'customer_report_files'
    AND index_name = 'uq_customer_report_files_storage_key_hash'
);
SET @add_storage_key_hash_index := IF(
  @has_storage_key_hash_index = 0,
  'ALTER TABLE customer_report_files ADD UNIQUE KEY uq_customer_report_files_storage_key_hash (storage_key_hash)',
  'SELECT 1'
);
PREPARE stmt_add_storage_key_hash_index FROM @add_storage_key_hash_index;
EXECUTE stmt_add_storage_key_hash_index;
DEALLOCATE PREPARE stmt_add_storage_key_hash_index;
