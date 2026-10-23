# Production readiness and release verification

This runbook is intentionally read-only by default. Do not run SQL migrations against the production database until the operator has reviewed and approved them.

## Verify the deployed service

1. Open `https://ecommerce-audit-agent.vercel.app/health-check`. Expect HTTP 200 and `db_connected: true`.
2. Open `https://ecommerce-audit-agent.vercel.app/app`. The customer portal should load.
3. Open `https://ecommerce-audit-agent.vercel.app/api/v1/billing/plans`. Confirm that the intended active plans are listed.
4. Open `https://ecommerce-audit-agent.vercel.app/admin`. The console is only useful after an operator-only `ADMIN_API_KEY` is configured in Vercel Production Environment Variables. Do not disable authentication to make the console work.
5. In the operator console, verify database health, package configuration, pending payment emails, stale quota reservations, and recent operation failures.

For the exact operator steps to configure the missing admin secret without exposing it, follow [`docs/admin-access-setup.md`](admin-access-setup.md). The secret must be generated and entered directly by an authorized operator in Vercel; never commit it or send it through chat.

## Verify database schema without changing it

Run from the repository root in a controlled environment configured with the same `DATABASE_URL` and `DATABASE_SSL` as production:

```bash
python scripts/check_production_readiness.py
```

The script checks required tables/columns and reports only configuration-presence booleans. It does not print secret values or apply changes. A non-zero exit code means the schema or one or more required configuration groups need attention.

The key report-history and billing migration is `migrations/2026-10-22-audit-reports.sql`; the admin package/operations migration is `migrations/20261023_admin_packages_and_actions.sql`. Review each SQL file and confirm its prerequisites before applying it. Keep a backup and record the migration result. The admin migration expects `payment_webhook_events` to exist, so apply the audit-reports migration first on a database where it is not already present.

## Acceptance checks before calling the SaaS ready

- [ ] Production schema check passes; report-history and webhook columns are present.
- [ ] `ADMIN_API_KEY` exists in Vercel Production Environment Variables; admin console authenticates and displays health.
- [ ] A valid licensed audit returns a PDF and `X-Audit-Report-ID`.
- [ ] The same license can list and download that report; another license cannot access it.
- [ ] Quota usage increments once and the reservation is released after success or failure.
- [ ] Report email is sent only after explicit recipient confirmation.
- [ ] Paddle sandbox/production environment, server API key, webhook signing secret, price IDs, client token, and SMTP delivery are tested together using a controlled transaction.
- [ ] Duplicate webhook delivery does not issue a second license; failed license-email delivery is visible and safely retryable.
- [ ] No customer website is modified by Product A. Remediation belongs to Product B.

A passing unit suite and a successful deployment are necessary but do not replace these production acceptance checks.
