-- Hostinger operational database migration: customer billing event history.
-- Only sanitized provider identifiers and lifecycle state are mirrored here.
-- Supabase remains authoritative for license entitlement and webhook idempotency.
CREATE TABLE IF NOT EXISTS customer_billing_events (
    event_id VARCHAR(255) NOT NULL,
    license_key VARCHAR(100) NOT NULL,
    recipient_email VARCHAR(254) NOT NULL,
    status VARCHAR(40) NOT NULL,
    transaction_id VARCHAR(100) NULL,
    subscription_id VARCHAR(100) NULL,
    paddle_customer_id VARCHAR(100) NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (event_id),
    INDEX ix_customer_billing_events_license_key (license_key),
    INDEX ix_customer_billing_events_recipient_email (recipient_email),
    INDEX ix_customer_billing_events_transaction_id (transaction_id),
    INDEX ix_customer_billing_events_subscription_id (subscription_id),
    INDEX ix_customer_billing_events_paddle_customer_id (paddle_customer_id),
    INDEX ix_customer_billing_license_created (license_key, created_at),
    INDEX ix_customer_billing_email_created (recipient_email, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
