-- Supabase PostgreSQL: make one successful quota/audit record unique per bulk scan job.
-- Safe to apply to an existing audit_leads table; does not alter Hostinger data.
ALTER TABLE audit_leads
    ADD COLUMN IF NOT EXISTS source_job_id VARCHAR(64);

CREATE UNIQUE INDEX IF NOT EXISTS ix_audit_leads_source_job_id
    ON audit_leads (source_job_id)
    WHERE source_job_id IS NOT NULL;
