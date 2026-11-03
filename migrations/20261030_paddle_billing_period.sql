-- Paddle billing-period end metadata. Safe to apply more than once.
ALTER TABLE software_licenses
    ADD COLUMN IF NOT EXISTS billing_period_ends_at TIMESTAMPTZ NULL;
