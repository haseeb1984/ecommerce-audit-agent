-- Durable cross-database reconciliation for verified customer email changes.
-- Apply to Hostinger MySQL after taking a backup. No Supabase schema changes.
CREATE TABLE IF NOT EXISTS customer_email_identity_sync_outbox (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  license_key VARCHAR(100) NOT NULL,
  old_email VARCHAR(254) NOT NULL,
  new_email VARCHAR(254) NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  attempts INT NOT NULL DEFAULT 0,
  next_attempt_at DATETIME(6) NOT NULL,
  last_error VARCHAR(120) NULL,
  created_at DATETIME(6) NOT NULL,
  processed_at DATETIME(6) NULL,
  KEY ix_customer_email_identity_outbox_license (license_key),
  KEY ix_email_identity_outbox_old_email (old_email),
  KEY ix_email_identity_outbox_new_email (new_email),
  KEY ix_email_identity_outbox_due (status, next_attempt_at, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
