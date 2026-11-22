-- Hostinger MySQL migration for customer-facing private PDF metadata.
-- Back up the operational database before applying. Existing rows remain valid;
-- report_id stays nullable for older scan-generated report files.
ALTER TABLE customer_report_files
    ADD COLUMN report_id BIGINT NULL,
    ADD COLUMN domain VARCHAR(253) NULL,
    ADD COLUMN finding_count INT NOT NULL DEFAULT 0,
    ADD COLUMN expires_at DATETIME(6) NULL,
    ADD COLUMN deleted_at DATETIME(6) NULL;

CREATE UNIQUE INDEX uq_customer_report_files_report_id
    ON customer_report_files (report_id);

CREATE INDEX ix_customer_report_files_domain
    ON customer_report_files (domain);

CREATE INDEX ix_customer_report_files_expiry
    ON customer_report_files (expires_at, deleted_at);
