-- Preserve full private report storage keys without exceeding MySQL's
-- 3072-byte utf8mb4 unique-index limit.
-- Apply to Hostinger MySQL after taking a backup.
ALTER TABLE customer_report_files
  ADD COLUMN storage_key_hash CHAR(64) NULL AFTER storage_key;

UPDATE customer_report_files
SET storage_key_hash = SHA2(storage_key, 256)
WHERE storage_key_hash IS NULL;

ALTER TABLE customer_report_files
  MODIFY storage_key_hash CHAR(64) NOT NULL,
  DROP INDEX storage_key,
  ADD UNIQUE KEY uq_customer_report_files_storage_key_hash (storage_key_hash);
