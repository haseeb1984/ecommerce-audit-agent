-- Hostinger MySQL operational schema.
-- Apply only to the Hostinger operational database after its credentials and
-- backup/restore procedure are configured. This file does not alter Supabase.
-- All license_key columns are external references; no cross-database FKs exist.

CREATE TABLE IF NOT EXISTS customer_accounts (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  license_key VARCHAR(100) NOT NULL,
  email VARCHAR(254) NOT NULL,
  display_name VARCHAR(255) NULL,
  status VARCHAR(24) NOT NULL DEFAULT 'active',
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  UNIQUE KEY uq_customer_accounts_license_email (license_key, email),
  KEY ix_customer_accounts_status_created (status, created_at),
  KEY ix_customer_accounts_license_key (license_key),
  KEY ix_customer_accounts_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS customer_login_challenges (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  license_key VARCHAR(100) NOT NULL,
  email VARCHAR(254) NOT NULL,
  code_hash VARCHAR(64) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  consumed_at DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL,
  KEY ix_customer_login_challenges_license_key (license_key),
  KEY ix_customer_login_challenges_email (email),
  KEY ix_customer_login_challenges_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS customer_sessions (
  token_hash VARCHAR(64) NOT NULL PRIMARY KEY,
  license_key VARCHAR(100) NOT NULL,
  email VARCHAR(254) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  revoked_at DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL,
  last_seen_at DATETIME(6) NULL,
  public_id VARCHAR(64) NULL UNIQUE,
  user_agent VARCHAR(500) NULL,
  KEY ix_customer_sessions_license_key (license_key),
  KEY ix_customer_sessions_email (email),
  KEY ix_customer_sessions_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS customer_email_change_challenges (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  license_key VARCHAR(100) NOT NULL,
  old_email VARCHAR(254) NOT NULL,
  new_email VARCHAR(254) NOT NULL,
  code_hash VARCHAR(64) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  consumed_at DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL,
  KEY ix_customer_email_change_license_key (license_key),
  KEY ix_customer_email_change_old_email (old_email),
  KEY ix_customer_email_change_new_email (new_email),
  KEY ix_customer_email_change_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS customer_websites (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  license_key VARCHAR(100) NOT NULL,
  submitted_by VARCHAR(254) NULL,
  url VARCHAR(2048) NOT NULL,
  normalized_url VARCHAR(2048) NOT NULL,
  host VARCHAR(253) NOT NULL,
  label VARCHAR(160) NULL,
  status VARCHAR(24) NOT NULL DEFAULT 'active',
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  UNIQUE KEY uq_customer_websites_license_url (license_key, normalized_url(512)),
  KEY ix_customer_websites_license_status (license_key, status),
  KEY ix_customer_websites_host (host)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS scan_batches (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  license_key VARCHAR(100) NOT NULL,
  requested_by VARCHAR(254) NULL,
  package_tier VARCHAR(50) NOT NULL,
  batch_number INT NOT NULL,
  batch_size INT NOT NULL DEFAULT 10,
  total_urls INT NOT NULL DEFAULT 0,
  queued_count INT NOT NULL DEFAULT 0,
  processing_count INT NOT NULL DEFAULT 0,
  completed_count INT NOT NULL DEFAULT 0,
  failed_count INT NOT NULL DEFAULT 0,
  status VARCHAR(24) NOT NULL DEFAULT 'queued',
  available_at DATETIME(6) NOT NULL,
  started_at DATETIME(6) NULL,
  completed_at DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL,
  KEY ix_scan_batches_claim (status, available_at, created_at),
  KEY ix_scan_batches_license_key (license_key),
  KEY ix_scan_batches_license_sequence (license_key, batch_number)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS website_scan_jobs (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  batch_id VARCHAR(64) NOT NULL,
  license_key VARCHAR(100) NOT NULL,
  website_id VARCHAR(64) NOT NULL,
  target_url VARCHAR(2048) NOT NULL,
  status VARCHAR(24) NOT NULL DEFAULT 'queued',
  idempotency_key VARCHAR(128) NOT NULL UNIQUE,
  attempt_count INT NOT NULL DEFAULT 0,
  max_attempts INT NOT NULL DEFAULT 3,
  next_attempt_at DATETIME(6) NOT NULL,
  locked_at DATETIME(6) NULL,
  locked_by VARCHAR(128) NULL,
  last_error_code VARCHAR(80) NULL,
  result_reference VARCHAR(255) NULL,
  quota_reserved TINYINT(1) NOT NULL DEFAULT 0,
  quota_consumed TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME(6) NOT NULL,
  started_at DATETIME(6) NULL,
  completed_at DATETIME(6) NULL,
  KEY ix_scan_jobs_batch_status (batch_id, status),
  KEY ix_scan_jobs_claim (status, next_attempt_at, created_at),
  KEY ix_scan_jobs_license_created (license_key, created_at),
  KEY ix_scan_jobs_website_id (website_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS customer_usage_events (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  license_key VARCHAR(100) NOT NULL,
  job_id VARCHAR(64) NULL,
  event_key VARCHAR(128) NOT NULL UNIQUE,
  event_type VARCHAR(40) NOT NULL,
  quantity INT NOT NULL DEFAULT 1,
  package_tier VARCHAR(50) NOT NULL,
  details_json LONGTEXT NOT NULL,
  created_at DATETIME(6) NOT NULL,
  KEY ix_customer_usage_license_created (license_key, created_at),
  KEY ix_customer_usage_job_id (job_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS customer_activity_events (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  license_key VARCHAR(100) NOT NULL,
  actor_email VARCHAR(254) NULL,
  event_type VARCHAR(80) NOT NULL,
  entity_type VARCHAR(50) NULL,
  entity_id VARCHAR(64) NULL,
  details_json LONGTEXT NOT NULL,
  created_at DATETIME(6) NOT NULL,
  KEY ix_customer_activity_license_created (license_key, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS wordpress_installations (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  license_key VARCHAR(100) NOT NULL,
  site_url VARCHAR(2048) NOT NULL,
  site_host VARCHAR(253) NOT NULL,
  admin_email VARCHAR(254) NOT NULL,
  customer_email VARCHAR(254) NULL,
  wordpress_version VARCHAR(30) NULL,
  woocommerce_version VARCHAR(30) NULL,
  plugin_version VARCHAR(30) NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'active',
  created_at DATETIME(6) NOT NULL,
  last_seen_at DATETIME(6) NOT NULL,
  disconnected_at DATETIME(6) NULL,
  UNIQUE KEY uq_wp_installations_license_host (license_key, site_host),
  KEY ix_wp_installations_license_created (license_key, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS customer_branding (
  license_key VARCHAR(100) NOT NULL PRIMARY KEY,
  brand_name VARCHAR(100) NOT NULL,
  logo_url VARCHAR(2048) NULL,
  primary_color VARCHAR(7) NOT NULL DEFAULT '#155a8a',
  updated_at DATETIME(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS admin_customer_notes (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  license_key VARCHAR(100) NOT NULL,
  customer_email VARCHAR(254) NOT NULL,
  note TEXT NOT NULL,
  created_by VARCHAR(100) NOT NULL DEFAULT 'admin',
  created_at DATETIME(6) NOT NULL,
  KEY ix_admin_customer_notes_license (license_key),
  KEY ix_admin_customer_notes_email_created (customer_email, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS customer_report_files (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  license_key VARCHAR(100) NOT NULL,
  job_id VARCHAR(64) NULL,
  report_name VARCHAR(255) NOT NULL,
  storage_key VARCHAR(1024) NOT NULL UNIQUE,
  mime_type VARCHAR(100) NOT NULL DEFAULT 'application/pdf',
  byte_size BIGINT NOT NULL,
  created_at DATETIME(6) NOT NULL,
  KEY ix_customer_report_files_license (license_key),
  KEY ix_customer_report_files_job (job_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
