-- PostgreSQL migration for Hostinger private report storage.
-- Apply manually after taking a database backup. This only adds metadata and
-- makes the legacy payload nullable; it does NOT delete or rewrite any PDF.
BEGIN;

ALTER TABLE audit_reports
    ALTER COLUMN pdf_bytes DROP NOT NULL;

ALTER TABLE audit_reports
    ADD COLUMN IF NOT EXISTS storage_key VARCHAR(1024),
    ADD COLUMN IF NOT EXISTS pdf_sha256 VARCHAR(64),
    ADD COLUMN IF NOT EXISTS pdf_byte_size BIGINT,
    ADD COLUMN IF NOT EXISTS pdf_deleted_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS ix_audit_reports_pdf_retention
    ON audit_reports (created_at, pdf_deleted_at);

COMMIT;
