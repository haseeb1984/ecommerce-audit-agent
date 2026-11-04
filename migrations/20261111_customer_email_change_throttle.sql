-- Serialize customer email-change throttling across all active sessions for a license.
-- Apply to the Hostinger operational MySQL database before deploying the
-- application version that uses CustomerEmailChangeThrottle.
CREATE TABLE IF NOT EXISTS customer_email_change_throttles (
  license_key VARCHAR(100) NOT NULL PRIMARY KEY
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
