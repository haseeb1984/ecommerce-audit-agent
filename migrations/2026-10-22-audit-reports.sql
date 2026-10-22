-- Apply once to the production PostgreSQL database before enabling report-history routes.
-- Keep the SQL in source control; do not run against production without the normal migration approval.
CREATE TABLE IF NOT EXISTS audit_reports (
    id BIGSERIAL PRIMARY KEY,
    license_id INTEGER NOT NULL REFERENCES software_licenses(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    pdf_bytes BYTEA NOT NULL,
    coverage_json TEXT NOT NULL DEFAULT '{}',
    finding_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_audit_reports_license_id ON audit_reports (license_id);
CREATE INDEX IF NOT EXISTS ix_audit_reports_domain ON audit_reports (domain);
CREATE INDEX IF NOT EXISTS ix_audit_reports_license_created ON audit_reports (license_id, created_at);
