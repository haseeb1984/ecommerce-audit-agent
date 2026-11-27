-- Recover billing mirrors when a canonical event commit succeeds but its outbox write fails.
-- Apply to Supabase PostgreSQL after backup. Existing rows remain NULL and are backfilled
-- by the normal worker in bounded batches; no billing or entitlement state is changed.
ALTER TABLE payment_webhook_events
    ADD COLUMN IF NOT EXISTS billing_mirror_synced_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS ix_payment_webhook_events_mirror_recovery
    ON payment_webhook_events (billing_mirror_synced_at, updated_at, created_at, event_id)
    WHERE license_id IS NOT NULL;
