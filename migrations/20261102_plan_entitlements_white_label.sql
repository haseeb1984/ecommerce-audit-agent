-- Additive plan entitlement and white-label configuration support.
CREATE TABLE IF NOT EXISTS white_label_branding (
    license_id INTEGER PRIMARY KEY REFERENCES software_licenses(id) ON DELETE CASCADE,
    brand_name VARCHAR(100) NOT NULL,
    logo_url VARCHAR(2048) NULL,
    primary_color VARCHAR(7) NOT NULL DEFAULT '#155a8a',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
