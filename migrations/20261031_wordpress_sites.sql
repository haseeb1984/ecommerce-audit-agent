-- WordPress installations linked to authenticated SaaS licenses.
CREATE TABLE IF NOT EXISTS wordpress_sites (
    id VARCHAR(64) PRIMARY KEY,
    license_id INTEGER NOT NULL REFERENCES software_licenses(id) ON DELETE CASCADE,
    site_url VARCHAR(2048) NOT NULL,
    site_host VARCHAR(253) NOT NULL,
    admin_email VARCHAR(254) NOT NULL,
    customer_email VARCHAR(254) NULL,
    wordpress_version VARCHAR(30) NULL,
    woocommerce_version VARCHAR(30) NULL,
    plugin_version VARCHAR(30) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    disconnected_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS ix_wordpress_sites_license_id ON wordpress_sites (license_id);
CREATE INDEX IF NOT EXISTS ix_wordpress_sites_license_created ON wordpress_sites (license_id, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS ix_wordpress_sites_license_host ON wordpress_sites (license_id, site_host);
