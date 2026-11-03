-- Durable internal customer-support notes for account-level operator workflows.
CREATE TABLE IF NOT EXISTS saas_admin_customer_notes (
    id BIGSERIAL PRIMARY KEY,
    customer_email VARCHAR(254) NOT NULL,
    note TEXT NOT NULL,
    created_by VARCHAR(100) NOT NULL DEFAULT 'admin',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_saas_admin_customer_notes_email_created
    ON saas_admin_customer_notes (LOWER(customer_email), created_at DESC);
