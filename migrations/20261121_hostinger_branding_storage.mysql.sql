-- Hostinger MySQL migration for private customer logo references.
-- Apply after backing up the operational database. Existing logo_url values
-- remain intact for backwards compatibility.
ALTER TABLE customer_branding
    ADD COLUMN logo_storage_key VARCHAR(1024) NULL,
    ADD COLUMN logo_sha256 VARCHAR(64) NULL,
    ADD COLUMN logo_mime_type VARCHAR(100) NULL,
    ADD COLUMN logo_byte_size BIGINT NULL;
