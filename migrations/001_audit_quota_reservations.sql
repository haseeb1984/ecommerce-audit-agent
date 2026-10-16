-- Required before deploying the quota-reservation application code.
-- Safe to re-run: creates the table and indexes only when absent.

CREATE TABLE IF NOT EXISTS audit_quota_reservations (
    id SERIAL PRIMARY KEY,
    license_id INTEGER NOT NULL
        REFERENCES software_licenses(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_audit_quota_reservations_license_created
    ON audit_quota_reservations (license_id, created_at);

CREATE INDEX IF NOT EXISTS ix_audit_quota_reservations_expires_at
    ON audit_quota_reservations (expires_at);

CREATE INDEX IF NOT EXISTS ix_audit_quota_reservations_license_id
    ON audit_quota_reservations (license_id);
