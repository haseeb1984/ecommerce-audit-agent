# Deployment and Operations Runbook

This runbook describes the current deployment topology and the safe order for preparing an environment. It does not authorize a production deployment, database migration, or branch merge.

## Service boundaries

- **Vercel / FastAPI**: HTTP API, customer and administrator interfaces, and application orchestration.
- **Hostinger / managed Python worker runtime**: persistent `worker_service.py` process that drains scan jobs and cross-database synchronization outboxes.
- **Supabase PostgreSQL**: canonical software licenses, API keys, quota reservations, audit leads/reports, Paddle webhook events, and plan packages.
- **Hostinger MySQL**: customer accounts and sessions, email challenges, customer website inventory, durable scan jobs/results, and operational billing/email projections.
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
- `CRON_SECRET` or `SCAN_WORKER_SECRET`: long random value used to protect `GET /api/v1/internal/scan-worker`. The endpoint accepts `Authorization: Bearer <configured-value>`.
- `SCAN_WORKER_MAX_JOBS` (1–10, default 1) and `SCAN_WORKER_POLL_SECONDS` (1–300, default 5) tune the long-running `worker_service.py` process.

## Safe environment preparation order

1. Create separate Supabase PostgreSQL and Hostinger MySQL databases. Enable TLS and restrict credentials to the application.
2. Take restorable backups and verify that restore access is available before schema changes.
3. Apply the PostgreSQL licensing/audit schema migrations from the repository to Supabase.
4. The Hostinger operational tables registered in `hostinger_models.py` are created by the schema initializer on the first website API or worker invocation. Confirm `HOSTINGER_DATABASE_URL` and TLS settings before triggering it; take a backup before any first-time schema creation.
5. Configure the environment variables above in Vercel. Use Paddle sandbox credentials until billing has been deliberately validated.
6. Deploy only to a non-production preview environment after explicit release approval.
7. Call `/health-check` to verify the PostgreSQL application schema. The current endpoint does not yet report Hostinger readiness; invoke the protected worker endpoint once in staging and inspect its response/logs to confirm Hostinger schema initialization.
8. Prefer running `python worker_service.py` as a persistent process in a managed Python runtime with the same environment variables and database access as the API. It polls durable jobs, reconciles outboxes, and shuts down on SIGTERM/SIGINT. If a persistent worker is not available, configure an approved external scheduler to call `GET /api/v1/internal/scan-worker` with `Authorization: Bearer <CRON_SECRET>` (or `SCAN_WORKER_SECRET`). No cron schedule is currently configured in `vercel.json`; each HTTP invocation claims at most one scan job.
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

- `/health-check`: PostgreSQL licensing/audit schema readiness. Hostinger readiness is initialized by the protected worker and is not yet included in this health response.
- `worker_service.py`: persistent worker process for Hostinger/managed Python runtimes.
- `/api/v1/internal/scan-worker`: authenticated one-job scheduler fallback; protect with `CRON_SECRET` or `SCAN_WORKER_SECRET`.
- `/api/v1/admin/operations`: administrator-only operational and billing diagnostics.
- `/api/v1/admin/billing/reconcile`: bounded mirror reconciliation from canonical PostgreSQL payment events into Hostinger.
- `/api/v1/billing/paddle-webhook`: canonical billing lifecycle event intake.

## Release safety

- Do not merge the feature branch or deploy production without explicit release approval.
- Do not run production migrations without a verified backup and explicit approval.
- Keep live Paddle credentials disabled until sandbox lifecycle verification is complete.
- Do not put database URLs, provider credentials, license keys, customer tokens, or administrator keys in logs or source control.
- Treat the final PDF/report storage and presentation refinement as a separate final product phase; this runbook does not claim that phase is complete.
