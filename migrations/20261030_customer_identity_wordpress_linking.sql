-- Customer identity / WordPress site linking.
-- Store only SHA-256 challenge hashes; raw one-time codes are returned once to the authenticated owner.
CREATE TABLE IF NOT EXISTS wordpress_link_challenges (
    id SERIAL PRIMARY KEY,
    license_id INTEGER NOT NULL REFERENCES software_licenses(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_wordpress_link_challenges_license_id ON wordpress_link_challenges(license_id);
CREATE INDEX IF NOT EXISTS ix_wordpress_link_challenges_license_expires ON wordpress_link_challenges(license_id, expires_at);

CREATE TABLE IF NOT EXISTS wordpress_site_links (
    id SERIAL PRIMARY KEY,
    license_id INTEGER NOT NULL REFERENCES software_licenses(id) ON DELETE CASCADE,
    site_url VARCHAR(255) NOT NULL,
    wp_user_id INTEGER NOT NULL,
    wp_user_login VARCHAR(60) NOT NULL,
    wp_user_email VARCHAR(254) NOT NULL,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_wordpress_site_links_license_site UNIQUE (license_id, site_url)
);
CREATE INDEX IF NOT EXISTS ix_wordpress_site_links_license_id ON wordpress_site_links(license_id);
CREATE INDEX IF NOT EXISTS ix_wordpress_site_links_license_linked ON wordpress_site_links(license_id, linked_at);
