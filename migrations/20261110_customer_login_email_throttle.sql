-- Serialize passwordless customer login throttling by normalized email.
-- Apply to the Hostinger operational MySQL database before deploying the
-- application version that uses CustomerLoginThrottle.
CREATE TABLE IF NOT EXISTS customer_login_throttles (
  email VARCHAR(254) NOT NULL PRIMARY KEY
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
