-- Phase 5: additive, repeatable schema alignment for the SaaS database integrations.
-- Prerequisite: the original software_licenses, api_keys, and audit_leads tables exist.
-- Apply this file to PostgreSQL before deploying the matching application revision.
-- No customer rows are dropped or rewritten.

ALTER TABLE software_licenses
    ADD COLUMN IF NOT EXISTS billing_period_ends_at TIMESTAMPTZ NULL;

CREATE TABLE IF NOT EXISTS audit_quota_reservations (
    id SERIAL PRIMARY KEY,
    license_id INTEGER NOT NULL REFERENCES software_licenses(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_audit_quota_reservations_license_id
    ON audit_quota_reservations (license_id);
CREATE INDEX IF NOT EXISTS ix_audit_quota_reservations_license_created
    ON audit_quota_reservations (license_id, created_at);
CREATE INDEX IF NOT EXISTS ix_audit_quota_reservations_expires_at
    ON audit_quota_reservations (expires_at);

CREATE TABLE IF NOT EXISTS audit_reports (
    id SERIAL PRIMARY KEY,
    license_id INTEGER NOT NULL REFERENCES software_licenses(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    pdf_bytes BYTEA NOT NULL,
    coverage_json TEXT NOT NULL DEFAULT '{}',
    finding_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_audit_reports_license_id ON audit_reports (license_id);
CREATE INDEX IF NOT EXISTS ix_audit_reports_domain ON audit_reports (domain);
CREATE INDEX IF NOT EXISTS ix_audit_reports_license_created
    ON audit_reports (license_id, created_at);

CREATE TABLE IF NOT EXISTS payment_webhook_events (
    event_id VARCHAR(255) PRIMARY KEY,
    status VARCHAR(40) NOT NULL DEFAULT 'email_pending',
    license_id INTEGER NULL REFERENCES software_licenses(id) ON DELETE SET NULL,
    transaction_id VARCHAR(100) NULL,
    subscription_id VARCHAR(100) NULL,
    paddle_customer_id VARCHAR(100) NULL,
    recipient_email VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE payment_webhook_events
    ADD COLUMN IF NOT EXISTS transaction_id VARCHAR(100) NULL,
    ADD COLUMN IF NOT EXISTS subscription_id VARCHAR(100) NULL,
    ADD COLUMN IF NOT EXISTS paddle_customer_id VARCHAR(100) NULL,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
CREATE INDEX IF NOT EXISTS ix_payment_webhook_events_license_id ON payment_webhook_events (license_id);
CREATE INDEX IF NOT EXISTS ix_payment_webhook_events_transaction_id ON payment_webhook_events (transaction_id);
CREATE INDEX IF NOT EXISTS ix_payment_webhook_events_subscription_id ON payment_webhook_events (subscription_id);
CREATE INDEX IF NOT EXISTS ix_payment_webhook_events_paddle_customer_id ON payment_webhook_events (paddle_customer_id);

CREATE TABLE IF NOT EXISTS saas_plan_packages (
    tier VARCHAR(50) PRIMARY KEY,
    label VARCHAR(100) NOT NULL,
    monthly_audit_allowance INTEGER NOT NULL CHECK (monthly_audit_allowance BETWEEN 1 AND 10000000),
    max_concurrent_audits INTEGER NOT NULL CHECK (max_concurrent_audits BETWEEN 1 AND 10000),
    paddle_price_id VARCHAR(100) NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_saas_plan_packages_paddle_price_id
    ON saas_plan_packages (paddle_price_id) WHERE paddle_price_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS saas_admin_action_logs (
    id BIGSERIAL PRIMARY KEY,
    action VARCHAR(80) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    entity_id VARCHAR(255) NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_saas_admin_action_logs_created
    ON saas_admin_action_logs (created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS saas_operation_events (
    id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(80) NOT NULL,
    license_id INTEGER NULL REFERENCES software_licenses(id) ON DELETE SET NULL,
    domain VARCHAR(255) NULL,
    error_type VARCHAR(120) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_saas_operation_events_created
    ON saas_operation_events (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS ix_saas_operation_events_type_created
    ON saas_operation_events (event_type, created_at DESC);

CREATE TABLE IF NOT EXISTS account_login_challenges (
    id VARCHAR(64) PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    license_id INTEGER NOT NULL REFERENCES software_licenses(id) ON DELETE CASCADE,
    code_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    consumed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_account_login_challenges_email ON account_login_challenges (email);
CREATE INDEX IF NOT EXISTS ix_account_login_challenges_license_id ON account_login_challenges (license_id);
CREATE INDEX IF NOT EXISTS ix_account_login_challenges_email_created
    ON account_login_challenges (email, created_at);
CREATE INDEX IF NOT EXISTS ix_account_login_challenges_expires_at
    ON account_login_challenges (expires_at);

CREATE TABLE IF NOT EXISTS account_sessions (
    token_hash VARCHAR(64) PRIMARY KEY,
    license_id INTEGER NOT NULL REFERENCES software_licenses(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NULL,
    public_id VARCHAR(64) UNIQUE NULL,
    user_agent VARCHAR(500) NULL
);
CREATE INDEX IF NOT EXISTS ix_account_sessions_license_id ON account_sessions (license_id);
CREATE INDEX IF NOT EXISTS ix_account_sessions_public_id ON account_sessions (public_id);
CREATE INDEX IF NOT EXISTS ix_account_sessions_license_created
    ON account_sessions (license_id, created_at);
CREATE INDEX IF NOT EXISTS ix_account_sessions_expires_at ON account_sessions (expires_at);

CREATE TABLE IF NOT EXISTS account_email_change_challenges (
    id VARCHAR(64) PRIMARY KEY,
    old_email VARCHAR(255) NOT NULL,
    new_email VARCHAR(255) NOT NULL,
    license_id INTEGER NOT NULL REFERENCES software_licenses(id) ON DELETE CASCADE,
    code_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    consumed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_account_email_change_challenges_old_email
    ON account_email_change_challenges (old_email);
CREATE INDEX IF NOT EXISTS ix_account_email_change_challenges_new_email
    ON account_email_change_challenges (new_email);
CREATE INDEX IF NOT EXISTS ix_account_email_change_challenges_license_id
    ON account_email_change_challenges (license_id);
CREATE INDEX IF NOT EXISTS ix_account_email_change_challenges_old_created
    ON account_email_change_challenges (old_email, created_at);
CREATE INDEX IF NOT EXISTS ix_account_email_change_challenges_new_created
    ON account_email_change_challenges (new_email, created_at);
CREATE INDEX IF NOT EXISTS ix_account_email_change_challenges_expires_at
    ON account_email_change_challenges (expires_at);

CREATE TABLE IF NOT EXISTS wordpress_sites (
    id VARCHAR(64) PRIMARY KEY,
    license_id INTEGER NOT NULL REFERENCES software_licenses(id) ON DELETE CASCADE,
    site_url VARCHAR(2048) NOT NULL,
    site_host VARCHAR(253) NOT NULL,
    admin_email VARCHAR(254) NOT NULL,
    customer_email VARCHAR(254) NULL,
    wordpress_version VARCHAR(30) NULL,
    woocommerce_version VARCHAR(30) NULL,
    plugin_version VARCHAR(30) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    disconnected_at TIMESTAMPTZ NULL
);
CREATE INDEX IF NOT EXISTS ix_wordpress_sites_license_id ON wordpress_sites (license_id);
CREATE INDEX IF NOT EXISTS ix_wordpress_sites_license_created
    ON wordpress_sites (license_id, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS ix_wordpress_sites_license_host
    ON wordpress_sites (license_id, site_host);

CREATE TABLE IF NOT EXISTS saas_admin_customer_notes (
    id BIGSERIAL PRIMARY KEY,
    customer_email VARCHAR(254) NOT NULL,
    note TEXT NOT NULL,
    created_by VARCHAR(100) NOT NULL DEFAULT 'admin',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_saas_admin_customer_notes_email_created
    ON saas_admin_customer_notes (LOWER(customer_email), created_at DESC);
