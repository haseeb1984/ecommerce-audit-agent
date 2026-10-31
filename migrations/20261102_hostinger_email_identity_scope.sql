-- Hostinger MySQL operational database migration.
-- Runtime schema initialization also applies this additive change automatically.
ALTER TABLE customer_email_identity_sync_outbox
    ADD COLUMN license_key VARCHAR(100) NULL;

CREATE INDEX ix_customer_email_identity_outbox_license
    ON customer_email_identity_sync_outbox (license_key);
