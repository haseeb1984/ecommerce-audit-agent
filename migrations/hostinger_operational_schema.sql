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

CREATE TABLE IF NOT EXISTS customer_login_throttles (
  email VARCHAR(254) NOT NULL PRIMARY KEY
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS customer_email_change_throttles (
  license_key VARCHAR(100) NOT NULL PRIMARY KEY
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
  normalized_url_hash CHAR(64) NOT NULL,
  host VARCHAR(253) NOT NULL,
  label VARCHAR(160) NULL,
  status VARCHAR(24) NOT NULL DEFAULT 'active',
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  UNIQUE KEY uq_customer_websites_license_url_hash (license_key, normalized_url_hash),
  KEY ix_customer_websites_license_status (license_key, status),
  KEY ix_customer_websites_host (host)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS scan_batch_sequences (
  license_key VARCHAR(100) NOT NULL PRIMARY KEY,
  next_batch_number INT NOT NULL DEFAULT 1,
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS scan_batches (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  license_key VARCHAR(100) NOT NULL,
  requested_by VARCHAR(254) NULL,
  package_tier VARCHAR(50) NOT NULL,
  request_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(64) NULL,
  request_hash CHAR(64) NOT NULL,
  batch_number INT NOT NULL,
  batch_size INT NOT NULL DEFAULT 10,
  total_urls INT NOT NULL DEFAULT 0,
  queued_count INT NOT NULL DEFAULT 0,
  processing_count INT NOT NULL DEFAULT 0,
  completed_count INT NOT NULL DEFAULT 0,
  failed_count INT NOT NULL DEFAULT 0,
  cancelled_count INT NOT NULL DEFAULT 0,
  status VARCHAR(24) NOT NULL DEFAULT 'queued',
  available_at DATETIME(6) NOT NULL,
  started_at DATETIME(6) NULL,
  completed_at DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL,
  KEY ix_scan_batches_claim (status, available_at, created_at),
  KEY ix_scan_batches_workspace_id (workspace_id),
  KEY ix_scan_batches_available_at (available_at),
  KEY ix_scan_batches_license_key (license_key),
  KEY ix_scan_batches_license_sequence (license_key, batch_number),
  UNIQUE KEY uq_scan_batches_request_sequence (license_key, request_id, batch_number),
  UNIQUE KEY uq_scan_batches_sequence (license_key, batch_number, created_at)
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
  KEY ix_website_scan_jobs_next_attempt_at (next_attempt_at),
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
  wordpress_user_id INT NULL,
  wordpress_user_login VARCHAR(60) NULL,
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


CREATE TABLE IF NOT EXISTS wordpress_site_link_challenges (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  license_key VARCHAR(100) NOT NULL,
  token_hash VARCHAR(64) NOT NULL UNIQUE,
  expires_at DATETIME(6) NOT NULL,
  consumed_at DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL,
  KEY ix_wp_site_link_challenges_license (license_key),
  KEY ix_wp_site_link_challenges_expiry (expires_at),
  KEY ix_wp_site_link_challenges_created (created_at),
  KEY ix_wp_site_link_challenges_license_created (license_key, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS customer_branding (
  license_key VARCHAR(100) NOT NULL PRIMARY KEY,
  brand_name VARCHAR(100) NOT NULL,
  logo_url VARCHAR(2048) NULL,
  logo_storage_key VARCHAR(1024) NULL,
  logo_sha256 VARCHAR(64) NULL,
  logo_mime_type VARCHAR(100) NULL,
  logo_byte_size BIGINT NULL,
  primary_color VARCHAR(7) NOT NULL DEFAULT '#155a8a',
  updated_at DATETIME(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS customer_branding_logo_cleanup (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  license_key VARCHAR(100) NOT NULL,
  storage_key VARCHAR(512) NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  last_error VARCHAR(120) NULL,
  created_at DATETIME(6) NOT NULL,
  last_attempt_at DATETIME(6) NULL,
  UNIQUE KEY uq_brand_logo_cleanup_storage_key (storage_key),
  KEY ix_brand_logo_cleanup_license_created (license_key, created_at)
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
  report_id BIGINT NULL UNIQUE,
  license_key VARCHAR(100) NOT NULL,
  job_id VARCHAR(64) NULL,
  report_name VARCHAR(255) NOT NULL,
  domain VARCHAR(253) NULL,
  finding_count INT NOT NULL DEFAULT 0,
  storage_key VARCHAR(1024) NOT NULL,
  storage_key_hash CHAR(64) NOT NULL UNIQUE,
  pdf_sha256 CHAR(64) NULL,
  mime_type VARCHAR(100) NOT NULL DEFAULT 'application/pdf',
  byte_size BIGINT NOT NULL,
  created_at DATETIME(6) NOT NULL,
  expires_at DATETIME(6) NULL,
  deleted_at DATETIME(6) NULL,
  cleanup_attempts INT NOT NULL DEFAULT 0,
  cleanup_last_attempt_at DATETIME(6) NULL,
  KEY ix_customer_report_files_license (license_key),
  KEY ix_customer_report_files_job (job_id),
  KEY ix_customer_report_files_domain (domain),
  KEY ix_customer_report_files_expiry (expires_at, deleted_at),
  KEY ix_customer_report_files_cleanup (deleted_at, cleanup_last_attempt_at, expires_at, id),
  KEY ix_customer_report_files_cleanup_last_attempt_at (cleanup_last_attempt_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS website_scan_results (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  job_id VARCHAR(64) NOT NULL UNIQUE,
  license_key VARCHAR(100) NOT NULL,
  website_id VARCHAR(64) NOT NULL,
  target_url VARCHAR(2048) NOT NULL,
  status VARCHAR(24) NOT NULL DEFAULT 'completed',
  overall_score INT NULL,
  finding_count INT NOT NULL DEFAULT 0,
  findings_json LONGTEXT NOT NULL,
  check_outcomes_json LONGTEXT NOT NULL,
  coverage_json LONGTEXT NOT NULL,
  summary_json LONGTEXT NOT NULL,
  created_at DATETIME(6) NOT NULL,
  KEY ix_website_scan_results_license_created (license_key, created_at),
  KEY ix_website_scan_results_website_created (website_id, created_at),
  KEY ix_website_scan_results_job_id (job_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS admin_action_logs (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  action VARCHAR(80) NOT NULL,
  entity_type VARCHAR(50) NOT NULL,
  entity_id VARCHAR(255) NULL,
  details_json LONGTEXT NOT NULL,
  created_at DATETIME(6) NOT NULL,
  KEY ix_admin_action_logs_created (created_at, id),
  KEY ix_admin_action_logs_entity (entity_type, entity_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS customer_billing_events (
  event_id VARCHAR(255) NOT NULL PRIMARY KEY,
  license_key VARCHAR(100) NOT NULL,
  recipient_email VARCHAR(254) NOT NULL,
  status VARCHAR(40) NOT NULL,
  transaction_id VARCHAR(100) NULL,
  subscription_id VARCHAR(100) NULL,
  paddle_customer_id VARCHAR(100) NULL,
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  KEY ix_customer_billing_license_created (license_key, created_at),
  KEY ix_customer_billing_email_created (recipient_email, created_at),
  KEY ix_customer_billing_transaction_id (transaction_id),
  KEY ix_customer_billing_subscription_id (subscription_id),
  KEY ix_customer_billing_paddle_customer_id (paddle_customer_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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
  KEY ix_email_identity_outbox_due (status, next_attempt_at, created_at),
  KEY ix_customer_email_identity_sync_outbox_next_attempt_at (next_attempt_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS operational_diagnostic_events (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  event_type VARCHAR(80) NOT NULL,
  license_key VARCHAR(100) NULL,
  domain VARCHAR(255) NULL,
  error_type VARCHAR(120) NULL,
  legacy_source_id BIGINT NULL UNIQUE,
  created_at DATETIME(6) NOT NULL,
  KEY ix_operational_diagnostic_events_license_key (license_key),
  KEY ix_operational_diagnostic_created (created_at, id),
  KEY ix_operational_diagnostic_type_created (event_type, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- Agency workspaces, WordPress site credentials, team access and usage ledger.
CREATE TABLE IF NOT EXISTS agency_accounts (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  owner_license_key VARCHAR(100) NOT NULL,
  owner_email VARCHAR(254) NOT NULL,
  status VARCHAR(24) NOT NULL DEFAULT 'active',
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  UNIQUE KEY ix_agency_accounts_owner_license_key (owner_license_key),
  KEY ix_agency_accounts_owner_email (owner_email),
  KEY ix_agency_accounts_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS agency_client_workspaces (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  agency_id VARCHAR(64) NOT NULL,
  display_name VARCHAR(160) NOT NULL,
  external_reference VARCHAR(120) NULL,
  status VARCHAR(24) NOT NULL DEFAULT 'active',
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  CONSTRAINT fk_agency_workspace_agency FOREIGN KEY (agency_id) REFERENCES agency_accounts(id) ON DELETE CASCADE,
  UNIQUE KEY uq_agency_workspace_external_ref (agency_id, external_reference),
  KEY ix_agency_client_workspaces_agency_id (agency_id),
  KEY ix_agency_client_workspaces_status (status),
  KEY ix_agency_workspace_tenant_status (agency_id, status, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS agency_client_websites (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  agency_id VARCHAR(64) NOT NULL,
  workspace_id VARCHAR(64) NOT NULL,
  site_url VARCHAR(2048) NOT NULL,
  site_host VARCHAR(253) NOT NULL,
  admin_email VARCHAR(254) NULL,
  connection_type VARCHAR(24) NOT NULL DEFAULT 'wordpress_plugin',
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  site_token_hash VARCHAR(64) NULL,
  plugin_version VARCHAR(30) NULL,
  wordpress_version VARCHAR(30) NULL,
  woocommerce_version VARCHAR(30) NULL,
  connected_at DATETIME(6) NOT NULL,
  last_seen_at DATETIME(6) NULL,
  disconnected_at DATETIME(6) NULL,
  CONSTRAINT fk_agency_site_agency FOREIGN KEY (agency_id) REFERENCES agency_accounts(id) ON DELETE CASCADE,
  CONSTRAINT fk_agency_site_workspace FOREIGN KEY (workspace_id) REFERENCES agency_client_workspaces(id) ON DELETE CASCADE,
  UNIQUE KEY site_token_hash (site_token_hash),
  UNIQUE KEY uq_agency_workspace_site_host (workspace_id, site_host),
  UNIQUE KEY uq_agency_site_host (agency_id, site_host),
  KEY ix_agency_client_websites_agency_id (agency_id),
  KEY ix_agency_client_websites_workspace_id (workspace_id),
  KEY ix_agency_client_websites_status (status),
  KEY ix_agency_client_site_tenant_workspace (agency_id, workspace_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS agency_website_connect_challenges (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  agency_id VARCHAR(64) NOT NULL,
  workspace_id VARCHAR(64) NOT NULL,
  token_hash VARCHAR(64) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  consumed_at DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL,
  CONSTRAINT fk_agency_connect_challenge_agency FOREIGN KEY (agency_id) REFERENCES agency_accounts(id) ON DELETE CASCADE,
  CONSTRAINT fk_agency_connect_challenge_workspace FOREIGN KEY (workspace_id) REFERENCES agency_client_workspaces(id) ON DELETE CASCADE,
  UNIQUE KEY token_hash (token_hash),
  KEY ix_agency_website_connect_challenges_agency_id (agency_id),
  KEY ix_agency_website_connect_challenges_workspace_id (workspace_id),
  KEY ix_agency_website_connect_challenges_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS agency_team_members (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  agency_id VARCHAR(64) NOT NULL,
  email VARCHAR(254) NOT NULL,
  normalized_email VARCHAR(254) NOT NULL,
  role VARCHAR(24) NOT NULL DEFAULT 'analyst',
  status VARCHAR(24) NOT NULL DEFAULT 'invited',
  invited_by VARCHAR(254) NOT NULL,
  invitation_token_hash VARCHAR(64) NULL,
  invitation_expires_at DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL,
  accepted_at DATETIME(6) NULL,
  CONSTRAINT fk_agency_team_member_agency FOREIGN KEY (agency_id) REFERENCES agency_accounts(id) ON DELETE CASCADE,
  UNIQUE KEY invitation_token_hash (invitation_token_hash),
  UNIQUE KEY uq_agency_team_normalized_email (agency_id, normalized_email),
  KEY ix_agency_team_members_agency_id (agency_id),
  KEY ix_agency_team_members_status (status),
  KEY ix_agency_team_tenant_status (agency_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS agency_team_login_challenges (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  agency_id VARCHAR(64) NOT NULL,
  team_member_id VARCHAR(64) NOT NULL,
  email VARCHAR(254) NOT NULL,
  code_hash VARCHAR(64) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  consumed_at DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL,
  CONSTRAINT fk_agency_team_login_agency FOREIGN KEY (agency_id) REFERENCES agency_accounts(id) ON DELETE CASCADE,
  CONSTRAINT fk_agency_team_login_member FOREIGN KEY (team_member_id) REFERENCES agency_team_members(id) ON DELETE CASCADE,
  KEY ix_agency_team_login_challenges_agency_id (agency_id),
  KEY ix_agency_team_login_challenges_team_member_id (team_member_id),
  KEY ix_agency_team_login_challenges_email (email),
  KEY ix_agency_team_login_challenges_expires_at (expires_at),
  KEY ix_agency_team_login_email_active (email, consumed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS agency_team_sessions (
  token_hash VARCHAR(64) NOT NULL PRIMARY KEY,
  agency_id VARCHAR(64) NOT NULL,
  team_member_id VARCHAR(64) NOT NULL,
  email VARCHAR(254) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  revoked_at DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL,
  last_seen_at DATETIME(6) NULL,
  user_agent VARCHAR(500) NULL,
  CONSTRAINT fk_agency_team_session_agency FOREIGN KEY (agency_id) REFERENCES agency_accounts(id) ON DELETE CASCADE,
  CONSTRAINT fk_agency_team_session_member FOREIGN KEY (team_member_id) REFERENCES agency_team_members(id) ON DELETE CASCADE,
  KEY ix_agency_team_sessions_agency_id (agency_id),
  KEY ix_agency_team_sessions_team_member_id (team_member_id),
  KEY ix_agency_team_sessions_email (email),
  KEY ix_agency_team_sessions_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS agency_workspace_access (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  agency_id VARCHAR(64) NOT NULL,
  workspace_id VARCHAR(64) NOT NULL,
  team_member_id VARCHAR(64) NOT NULL,
  role VARCHAR(24) NOT NULL DEFAULT 'viewer',
  created_at DATETIME(6) NOT NULL,
  CONSTRAINT fk_agency_workspace_access_agency FOREIGN KEY (agency_id) REFERENCES agency_accounts(id) ON DELETE CASCADE,
  CONSTRAINT fk_agency_workspace_access_workspace FOREIGN KEY (workspace_id) REFERENCES agency_client_workspaces(id) ON DELETE CASCADE,
  CONSTRAINT fk_agency_workspace_access_member FOREIGN KEY (team_member_id) REFERENCES agency_team_members(id) ON DELETE CASCADE,
  UNIQUE KEY uq_agency_workspace_member (workspace_id, team_member_id),
  KEY ix_agency_workspace_access_agency_id (agency_id),
  KEY ix_agency_workspace_access_workspace_id (workspace_id),
  KEY ix_agency_workspace_access_team_member_id (team_member_id),
  KEY ix_agency_workspace_access_tenant (agency_id, workspace_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS agency_usage_events (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  agency_id VARCHAR(64) NOT NULL,
  workspace_id VARCHAR(64) NULL,
  event_type VARCHAR(40) NOT NULL,
  quantity INT NOT NULL DEFAULT 1,
  period_start DATETIME(6) NOT NULL,
  period_end DATETIME(6) NOT NULL,
  source_reference VARCHAR(100) NULL,
  created_at DATETIME(6) NOT NULL,
  CONSTRAINT fk_agency_usage_agency FOREIGN KEY (agency_id) REFERENCES agency_accounts(id) ON DELETE CASCADE,
  CONSTRAINT fk_agency_usage_workspace FOREIGN KEY (workspace_id) REFERENCES agency_client_workspaces(id) ON DELETE CASCADE,
  UNIQUE KEY uq_agency_usage_source_reference (agency_id, source_reference),
  KEY ix_agency_usage_events_agency_id (agency_id),
  KEY ix_agency_usage_events_workspace_id (workspace_id),
  KEY ix_agency_usage_events_period_start (period_start),
  KEY ix_agency_usage_tenant_period (agency_id, period_start, event_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- Add the scan-batch workspace relationship after agency tables exist.
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


CREATE TABLE IF NOT EXISTS platform_settings (
  setting_key VARCHAR(100) NOT NULL PRIMARY KEY,
  setting_value VARCHAR(255) NOT NULL,
  updated_at DATETIME(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
