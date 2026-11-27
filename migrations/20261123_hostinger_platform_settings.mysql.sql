-- Owner-managed platform policy settings in Hostinger operational MySQL.
-- Apply once after backup and schema inspection; this does not modify WordPress core tables.
CREATE TABLE IF NOT EXISTS platform_settings (
  setting_key VARCHAR(100) NOT NULL PRIMARY KEY,
  setting_value VARCHAR(255) NOT NULL,
  updated_at DATETIME(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
