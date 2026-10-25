-- Allow evidence-first audit reports to be saved when the external PageSpeed API is unavailable.
-- NULL means no measurement was obtained; it must not be replaced with a fabricated zero.
ALTER TABLE audit_leads
    ALTER COLUMN mobile_score DROP NOT NULL,
    ALTER COLUMN speed_index_sec DROP NOT NULL;
