-- Durable PostgreSQL-to-Hostinger synchronization for admin customer lifecycle actions.
-- Apply to Supabase PostgreSQL after backup; no Hostinger schema changes.
CREATE TABLE IF NOT EXISTS customer_lifecycle_sync_outbox (
    id VARCHAR(64) PRIMARY KEY,
    license_key VARCHAR(100) NOT NULL,
    action VARCHAR(24) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error VARCHAR(120),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_customer_lifecycle_sync_license
    ON customer_lifecycle_sync_outbox (license_key);
CREATE INDEX IF NOT EXISTS ix_customer_lifecycle_sync_due
    ON customer_lifecycle_sync_outbox (status, next_attempt_at, created_at);
