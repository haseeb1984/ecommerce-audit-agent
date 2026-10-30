-- Ecommerce Audit Agent: core SaaS schema baseline
-- Apply manually in the target PostgreSQL database after reviewing the deployment plan.
-- This file is idempotent for tables and indexes. It does NOT backfill business data,
-- rotate secrets, or run automatically at application startup.
--
-- The application health check requires every table below. Keep this migration aligned
-- with models.py whenever the persistence model changes.

CREATE TABLE IF NOT EXISTS software_licenses (
    id SERIAL PRIMARY KEY,
    license_key VARCHAR(100) NOT NULL UNIQUE,
    client_name VARCHAR(255) NOT NULL,
    tier VARCHAR(50) DEFAULT 'starter',
    max_monthly_audits INTEGER DEFAULT 100,
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMPTZ NULL,
    billing_period_ends_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    license_id INTEGER NOT NULL REFERENCES software_licenses(id) ON DELETE CASCADE,
    api_key_hash VARCHAR(255) NOT NULL UNIQUE,
    key_prefix VARCHAR(10) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_leads (
    id SERIAL PRIMARY KEY,
    license_id INTEGER NULL REFERENCES software_licenses(id) ON DELETE SET NULL,
    domain VARCHAR(255) NOT NULL,
    mobile_score INTEGER NULL,
    speed_index_sec DOUBLE PRECISION NULL,
    contact_email VARCHAR(255) NULL,
    revenue_leak_hypothesis TEXT NULL,
    email_subject VARCHAR(255) NULL,
    email_body TEXT NULL,
    source_channel VARCHAR(50) DEFAULT 'wordpress_hub',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_quota_reservations (
    id SERIAL PRIMARY KEY,
    license_id INTEGER NOT NULL REFERENCES software_licenses(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_reports (
    id SERIAL PRIMARY KEY,
    license_id INTEGER NOT NULL REFERENCES software_licenses(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    pdf_bytes BYTEA NOT NULL,
    coverage_json TEXT NOT NULL DEFAULT '{}',
    finding_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS saas_plan_packages (
    tier VARCHAR(50) PRIMARY KEY,
    label VARCHAR(100) NOT NULL,
    monthly_audit_allowance INTEGER NOT NULL,
    max_concurrent_audits INTEGER NOT NULL,
    paddle_price_id VARCHAR(100) NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Keep Paddle price-to-plan assignment unique even when two admin requests race.
-- Existing duplicate non-NULL price IDs must be reconciled before this index can be created.
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

CREATE TABLE IF NOT EXISTS saas_operation_events (
    id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(80) NOT NULL,
    license_id INTEGER NULL REFERENCES software_licenses(id) ON DELETE SET NULL,
    domain VARCHAR(255) NULL,
    error_type VARCHAR(120) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

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

-- Forward-compatible additions for databases created by earlier versions of the app.
ALTER TABLE payment_webhook_events
    ADD COLUMN IF NOT EXISTS transaction_id VARCHAR(100) NULL,
    ADD COLUMN IF NOT EXISTS subscription_id VARCHAR(100) NULL,
    ADD COLUMN IF NOT EXISTS paddle_customer_id VARCHAR(100) NULL,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Indexes declared by models.py and relied on by account-scoped queries.
CREATE INDEX IF NOT EXISTS ix_software_licenses_id ON software_licenses (id);
CREATE INDEX IF NOT EXISTS ix_software_licenses_license_key ON software_licenses (license_key);
CREATE INDEX IF NOT EXISTS ix_api_keys_id ON api_keys (id);
CREATE INDEX IF NOT EXISTS ix_api_keys_license_id ON api_keys (license_id);
CREATE INDEX IF NOT EXISTS ix_audit_leads_id ON audit_leads (id);
CREATE INDEX IF NOT EXISTS ix_audit_leads_domain ON audit_leads (domain);
CREATE INDEX IF NOT EXISTS ix_audit_leads_license_id ON audit_leads (license_id);
CREATE INDEX IF NOT EXISTS ix_audit_quota_reservations_id ON audit_quota_reservations (id);
CREATE INDEX IF NOT EXISTS ix_audit_quota_reservations_license_id ON audit_quota_reservations (license_id);
CREATE INDEX IF NOT EXISTS ix_audit_quota_reservations_license_created ON audit_quota_reservations (license_id, created_at);
CREATE INDEX IF NOT EXISTS ix_audit_quota_reservations_expires_at ON audit_quota_reservations (expires_at);
CREATE INDEX IF NOT EXISTS ix_audit_reports_id ON audit_reports (id);
CREATE INDEX IF NOT EXISTS ix_audit_reports_license_id ON audit_reports (license_id);
CREATE INDEX IF NOT EXISTS ix_audit_reports_domain ON audit_reports (domain);
CREATE INDEX IF NOT EXISTS ix_audit_reports_license_created ON audit_reports (license_id, created_at);
CREATE INDEX IF NOT EXISTS ix_saas_admin_action_logs_created ON saas_admin_action_logs (created_at, id);
CREATE INDEX IF NOT EXISTS ix_saas_operation_events_created ON saas_operation_events (created_at, id);
CREATE INDEX IF NOT EXISTS ix_saas_operation_events_type_created ON saas_operation_events (event_type, created_at);
CREATE INDEX IF NOT EXISTS ix_payment_webhook_events_license_id ON payment_webhook_events (license_id);
CREATE INDEX IF NOT EXISTS ix_payment_webhook_events_transaction_id ON payment_webhook_events (transaction_id);
CREATE INDEX IF NOT EXISTS ix_payment_webhook_events_subscription_id ON payment_webhook_events (subscription_id);
CREATE INDEX IF NOT EXISTS ix_payment_webhook_events_paddle_customer_id ON payment_webhook_events (paddle_customer_id);

-- Forward-compatible billing-period metadata for existing customer licenses.
ALTER TABLE software_licenses ADD COLUMN IF NOT EXISTS billing_period_ends_at TIMESTAMPTZ NULL;
