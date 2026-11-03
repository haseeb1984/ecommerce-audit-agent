-- Provision all agency operational tables used by hostinger_models.py.
-- Safe for fresh and existing installations; tables are created in FK dependency order.
-- Apply to the Hostinger operational MySQL database, not the licensing database.

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
