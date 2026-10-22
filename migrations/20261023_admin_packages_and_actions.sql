-- Ecommerce Audit Agent SaaS admin tables (PostgreSQL).
-- Idempotent migration; safe to apply more than once.
CREATE TABLE IF NOT EXISTS saas_plan_packages (
    tier VARCHAR(50) PRIMARY KEY,
    label VARCHAR(100) NOT NULL,
    monthly_audit_allowance INTEGER NOT NULL CHECK (monthly_audit_allowance BETWEEN 1 AND 10000000),
    max_concurrent_audits INTEGER NOT NULL CHECK (max_concurrent_audits BETWEEN 1 AND 10000),
    paddle_price_id VARCHAR(100),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_saas_plan_packages_paddle_price_id
    ON saas_plan_packages (paddle_price_id) WHERE paddle_price_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS saas_operation_events (
    id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(80) NOT NULL,
    license_id INTEGER REFERENCES software_licenses(id) ON DELETE SET NULL,
    domain VARCHAR(255),
    error_type VARCHAR(120),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_saas_operation_events_created
    ON saas_operation_events (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS ix_saas_operation_events_type_created
    ON saas_operation_events (event_type, created_at DESC);

CREATE TABLE IF NOT EXISTS saas_admin_action_logs (
    id BIGSERIAL PRIMARY KEY,
    action VARCHAR(80) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    entity_id VARCHAR(255),
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_saas_admin_action_logs_created
    ON saas_admin_action_logs (created_at DESC, id DESC);
