-- Additive Hostinger MySQL migration for one-time WordPress customer identity linking.
-- Safe to re-run: column additions are guarded through information_schema checks.
SET @has_wp_user_id := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'wordpress_installations' AND column_name = 'wordpress_user_id'
);
SET @ddl_wp_user_id := IF(@has_wp_user_id = 0,
  'ALTER TABLE wordpress_installations ADD COLUMN wordpress_user_id INT NULL',
  'SELECT 1');
PREPARE stmt_wp_user_id FROM @ddl_wp_user_id;
EXECUTE stmt_wp_user_id;
DEALLOCATE PREPARE stmt_wp_user_id;

SET @has_wp_user_login := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'wordpress_installations' AND column_name = 'wordpress_user_login'
);
SET @ddl_wp_user_login := IF(@has_wp_user_login = 0,
  'ALTER TABLE wordpress_installations ADD COLUMN wordpress_user_login VARCHAR(60) NULL',
  'SELECT 1');
PREPARE stmt_wp_user_login FROM @ddl_wp_user_login;
EXECUTE stmt_wp_user_login;
DEALLOCATE PREPARE stmt_wp_user_login;

CREATE TABLE IF NOT EXISTS wordpress_site_link_challenges (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  license_key VARCHAR(100) NOT NULL,
  token_hash VARCHAR(64) NOT NULL UNIQUE,
  expires_at DATETIME(6) NOT NULL,
  consumed_at DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL,
  KEY ix_wp_site_link_challenges_license (license_key),
  KEY ix_wp_site_link_challenges_expiry (expires_at),
  KEY ix_wp_site_link_challenges_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
