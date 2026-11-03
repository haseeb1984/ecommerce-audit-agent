-- Canonical customer identity: a normalized verified email may own only one license.
-- Existing duplicate email -> license mappings abort this migration for explicit reconciliation;
-- no license, payment, report, API key, or usage history is silently merged or discarded.
-- Run scripts/report_duplicate_customer_emails.sql before applying this migration.

ALTER TABLE software_licenses
    ADD COLUMN IF NOT EXISTS account_email VARCHAR(255);

DO $$
BEGIN
    IF EXISTS (
        SELECT lower(trim(recipient_email))
        FROM payment_webhook_events
        WHERE license_id IS NOT NULL
        GROUP BY lower(trim(recipient_email))
        HAVING count(DISTINCT license_id) > 1
    ) THEN
        RAISE EXCEPTION 'Customer identity migration blocked: one or more verified emails map to multiple licenses. Reconcile those accounts before applying the unique identity index.';
    END IF;
END $$;

UPDATE software_licenses AS license
SET account_email = source.email
FROM (
    SELECT license_id, min(lower(trim(recipient_email))) AS email
    FROM payment_webhook_events
    WHERE license_id IS NOT NULL
    GROUP BY license_id
    HAVING count(DISTINCT lower(trim(recipient_email))) = 1
) AS source
WHERE license.id = source.license_id
  AND license.account_email IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_software_licenses_account_email_lower
    ON software_licenses (lower(account_email))
    WHERE account_email IS NOT NULL;
