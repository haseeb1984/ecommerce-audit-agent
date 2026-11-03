-- Adds cancellation accounting to existing Hostinger scan batches.
-- MySQL 8.0.29+ supports ADD COLUMN IF NOT EXISTS.
ALTER TABLE scan_batches
  ADD COLUMN IF NOT EXISTS cancelled_count INT NOT NULL DEFAULT 0
  AFTER failed_count;
