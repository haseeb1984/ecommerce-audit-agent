-- Durable retry queue for Paddle billing events whose Hostinger mirror write failed.
-- Apply to Supabase PostgreSQL after backup. Does not change license or entitlement state.
CREATE TABLE IF NOT EXISTS billing_mirror_sync_outbox (
    event_id VARCHAR(255) PRIMARY KEY,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error VARCHAR(120),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_billing_mirror_sync_due
    ON billing_mirror_sync_outbox (status, next_attempt_at, created_at);

-- Supports the correlated per-license ordering check for pending retries.
CREATE INDEX IF NOT EXISTS ix_billing_mirror_sync_pending_order
    ON billing_mirror_sync_outbox (status, created_at, event_id);
