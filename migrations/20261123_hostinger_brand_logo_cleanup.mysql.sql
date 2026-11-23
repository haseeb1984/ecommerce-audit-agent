-- Durable retry queue for logo objects detached from customer branding.
-- Apply once after backing up the Hostinger operational database.
CREATE TABLE customer_branding_logo_cleanup (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    license_key VARCHAR(100) NOT NULL,
    storage_key VARCHAR(512) NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    last_error VARCHAR(120) NULL,
    created_at DATETIME(6) NOT NULL,
    last_attempt_at DATETIME(6) NULL,
    UNIQUE KEY uq_brand_logo_cleanup_storage_key (storage_key),
    KEY ix_brand_logo_cleanup_license_created (license_key, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
