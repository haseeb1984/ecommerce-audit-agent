-- Read-only preflight for migrations/20261031_single_customer_license_identity.sql.
-- Review each collision with an operator before deciding which license remains canonical.
-- Do not delete or merge rows automatically: payment events, reports, API keys,
-- quota history, WordPress links, and subscriptions may belong to different records.

SELECT
    lower(trim(recipient_email)) AS normalized_email,
    array_agg(DISTINCT license_id ORDER BY license_id) AS conflicting_license_ids,
    count(*) AS payment_event_count,
    array_agg(DISTINCT status ORDER BY status) AS observed_payment_statuses,
    min(created_at) AS first_payment_event_at,
    max(updated_at) AS last_payment_event_at
FROM payment_webhook_events
WHERE license_id IS NOT NULL
GROUP BY lower(trim(recipient_email))
HAVING count(DISTINCT license_id) > 1
ORDER BY normalized_email;
