# Deployment and Operations Runbook

This runbook describes the current deployment topology and the safe order for preparing an environment. It does not authorize a production deployment, database migration, or branch merge.

## Service boundaries

- **Vercel / FastAPI**: HTTP API, customer and administrator interfaces, scheduled scan-worker invocation, and application orchestration.
- **Supabase PostgreSQL**: canonical software licenses, API keys, quota reservations, audit leads/reports, Paddle webhook events, and plan packages.
- **Hostinger MySQL**: customer accounts and sessions, email challenges, website inventory, WordPress installations, scan batches/jobs/results, customer usage/activity, billing mirrors, administrator notes/actions, operational diagnostics, and the durable email-identity synchronization outbox.
- **Private object storage**: intended location for generated report files and customer uploads. Configure and verify this independently before enabling any workflow that relies on private object storage.

Do not move customer operational tables back into Supabase. The stable cross-database reference is the license key; there are intentionally no cross-database foreign keys.

## Required deployment secrets

Configure secrets in the Vercel project environment settings (and in the local secret manager for development). Never commit real values.

### Databases
- `DATABASE_URL`: Supabase PostgreSQL connection URL using the async SQLAlchemy driver.
- `DATABASE_SSL=true`: require TLS for PostgreSQL.
- `HOSTINGER_DATABASE_URL`: Hostinger MySQL connection URL using `mysql+asyncmy` and TLS.
- `HOSTINGER_DB_SSL=true`: enables certificate-verified TLS for Hostinger MySQL (disable only for isolated local development).
- `HOSTINGER_DB_POOL_SIZE`, `HOSTINGER_DB_MAX_OVERFLOW`, `HOSTINGER_DB_POOL_RECYCLE`, `HOSTINGER_DB_POOL_TIMEOUT`: optional pool tuning.

### Audit providers
- `GROQ_API_KEY` and optional `GROQ_MODEL`.
- `PAGE_SPEED_API_KEY` for PageSpeed integration.

### Customer email
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, and `SMTP_TLS_MODE`.
- `ACCOUNT_AUTH_SECRET`: unique random secret of at least 32 characters. Rotating it invalidates outstanding account authentication challenges/tokens that depend on the secret.

### Billing and administrator access
- `PADDLE_ENVIRONMENT`, `PADDLE_API_KEY`, `PADDLE_WEBHOOK_SECRET`, and `PADDLE_CLIENT_TOKEN`.
- Optional `PADDLE_CHECKOUT_URL`.
- `PADDLE_PRICE_ID_STARTER`, `PADDLE_PRICE_ID_PRO`, `PADDLE_PRICE_ID_BUSINESS` and the corresponding `LICENSE_MONTHLY_AUDITS_*` / `LICENSE_MAX_CONCURRENT_AUDITS_*` values used to bootstrap package records.
- `ADMIN_API_KEY`: long random administrator secret.
- `CRON_SECRET`: long random Vercel Cron secret. Vercel sends it automatically as `Authorization: Bearer <CRON_SECRET>` on scheduled requests. `SCAN_WORKER_TOKEN` is also accepted for controlled non-Vercel worker invocations.

## Safe environment preparation order

1. Create separate Supabase PostgreSQL and Hostinger MySQL databases. Enable TLS and restrict credentials to the application.
2. Take restorable backups and verify that restore access is available before schema changes.
3. Apply the PostgreSQL licensing/audit schema migrations from the repository to Supabase.
4. Apply `migrations/hostinger_operational_schema.sql` to the Hostinger operational database. Apply any later Hostinger-specific migration scripts in chronological order, including `migrations/20261105_customer_email_identity_outbox.sql` for durable cross-database verified-email synchronization.
5. Configure the environment variables above in Vercel. Use Paddle sandbox credentials until billing has been deliberately validated.
6. Deploy only to a non-production preview environment after explicit release approval.
7. Call `/health-check`. A successful response must report both PostgreSQL and MySQL as connected and schema-ready. Resolve every missing table, column, or required index before routing customer traffic.
8. Verify the scheduled worker configuration in `vercel.json` and set `CRON_SECRET` in Vercel project environment variables. Vercel adds its bearer authorization header automatically. The cron schedule is once per minute and requests at most ten jobs per invocation; package concurrency remains governed by the license entitlement. Each invocation also reconciles up to 50 pending verified-email changes from the Hostinger outbox into canonical PostgreSQL billing events. Updates are idempotent, failures are retained with capped exponential retry scheduling, and the worker response reports processed/deferred counts. Completed outbox records older than 90 days are removed by bounded cleanup. The worker also removes expired login/email challenges older than seven days and expired/revoked sessions older than 30 days in batches of up to 500 per record type. Housekeeping failures are logged and reported but do not stop scan processing.
9. Configure outbound SMTP and verify deliverability using controlled test accounts.
10. Configure Paddle webhook delivery to the deployed `/api/v1/billing/paddle-webhook` endpoint and verify the webhook secret and sandbox event flow before enabling live billing.
11. Confirm the WordPress plugin ZIP endpoint serves the expected package and that a staging WordPress/WooCommerce site can register, report status, and disconnect.
12. Confirm database backups, application logs, secret rotation, and incident ownership before production release.

## Legacy operational data migration

The script `scripts/migrate_operational_data_to_hostinger.py` is a compatibility migration utility. It defaults to a dry run and preserves the PostgreSQL source records.

- Review the dry-run output and reconcile row counts before any write.
- Do not pass `--apply` until the operator has approved a maintenance window, verified backups, and confirmed that the Hostinger schema is current.
- Re-run the dry run after migration and verify the migrated customer accounts, sessions/challenges, WordPress installations, branding, admin notes, billing mirrors, admin actions, and diagnostics.
- Do not assume old browser sessions are valid until legacy session migration has been completed and verified.

## Operational endpoints and ownership

- `/health-check`: independent readiness of PostgreSQL licensing/audit schema and Hostinger operational schema.
- `/internal/scan-worker/run`: internal scheduled worker; Vercel Cron uses `CRON_SECRET` bearer authentication, with `SCAN_WORKER_TOKEN` retained for controlled manual invocations.
- `/api/v1/admin/operations`: administrator-only operational and billing diagnostics.
- Admin customer suspension/reactivation updates canonical PostgreSQL license state first, then synchronizes Hostinger customer-account status; suspension also revokes all browser sessions. Customer portal authentication and passwordless sign-in reject inactive licenses, so a Hostinger synchronization failure cannot restore access while PostgreSQL remains suspended.
- `/api/v1/admin/billing/reconcile`: bounded mirror reconciliation from canonical PostgreSQL payment events into Hostinger.
- Verified customer email changes are committed to Hostinger with a durable outbox entry; the scheduled worker then updates matching canonical PostgreSQL billing-event email addresses. A pending outbox item is retried automatically with backoff until acknowledged.
- `/api/v1/billing/paddle-webhook`: canonical billing lifecycle event intake.

## Release safety

- Do not merge the feature branch or deploy production without explicit release approval.
- Do not run production migrations without a verified backup and explicit approval.
- Keep live Paddle credentials disabled until sandbox lifecycle verification is complete.
- Do not put database URLs, provider credentials, license keys, customer tokens, or administrator keys in logs or source control.
- Treat the final PDF/report storage and presentation refinement as a separate final product phase; this runbook does not claim that phase is complete.
