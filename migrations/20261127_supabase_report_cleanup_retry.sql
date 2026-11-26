-- Supabase PostgreSQL: fair retry ordering for legacy audit report PDF cleanup.
-- Safe to apply repeatedly; this migration does not delete report metadata or bytes.
ALTER TABLE audit_reports
    ADD COLUMN IF NOT EXISTS pdf_cleanup_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS pdf_cleanup_last_attempt_at TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS ix_audit_reports_pdf_cleanup_retry
    ON audit_reports (pdf_deleted_at, pdf_cleanup_last_attempt_at, created_at, id);
