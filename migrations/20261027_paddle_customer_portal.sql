-- Store the Paddle customer reference needed to create authenticated self-service portal sessions.
-- Idempotent; apply through the reviewed deployment migration process, never from a request handler.
ALTER TABLE payment_webhook_events
    ADD COLUMN IF NOT EXISTS paddle_customer_id VARCHAR(100);

CREATE INDEX IF NOT EXISTS ix_payment_webhook_events_paddle_customer_id
    ON payment_webhook_events (paddle_customer_id);
