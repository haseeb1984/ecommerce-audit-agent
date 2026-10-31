-- Ecommerce Audit Agent: durable worker and cross-database outbox support.
-- Apply to the canonical PostgreSQL database before deploying the matching app revision.
-- Hostinger operational tables are created separately by ensure_hostinger_schema().

ALTER TABLE audit_leads
    ADD COLUMN IF NOT EXISTS source_job_id VARCHAR(64);

CREATE UNIQUE INDEX IF NOT EXISTS ix_audit_leads_source_job_id
    ON audit_leads (source_job_id)
    WHERE source_job_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS customer_lifecycle_sync_outbox (
    id BIGSERIAL PRIMARY KEY,
    license_key VARCHAR(100) NOT NULL,
    action VARCHAR(40) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error VARCHAR(120) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS ix_customer_lifecycle_outbox_due
    ON customer_lifecycle_sync_outbox (status, next_attempt_at, created_at);
CREATE INDEX IF NOT EXISTS ix_customer_lifecycle_sync_outbox_license_key
    ON customer_lifecycle_sync_outbox (license_key);

CREATE TABLE IF NOT EXISTS billing_mirror_sync_outbox (
    event_id VARCHAR(255) PRIMARY KEY,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error VARCHAR(120) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS ix_billing_mirror_outbox_due
    ON billing_mirror_sync_outbox (status, next_attempt_at, created_at);
