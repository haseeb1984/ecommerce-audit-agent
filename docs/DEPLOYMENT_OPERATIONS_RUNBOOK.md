# Deployment and Operations Runbook

This runbook describes the current deployment topology and the safe order for preparing an environment. It does not authorize a production deployment, database migration, or branch merge.

## Service boundaries

- **Vercel / FastAPI**: HTTP API, customer and administrator interfaces, scheduled scan-worker invocation, and application orchestration.
- **Supabase PostgreSQL**: canonical software licenses, API keys, quota reservations, audit leads/reports, Paddle webhook events, and plan packages.
- **Hostinger MySQL**: customer accounts and sessions, email challenges, website inventory, WordPress installations, scan batches/jobs/results, customer usage/activity, billing mirrors, administrator notes/actions, operational diagnostics, and the durable email-identity and billing-mirror synchronization outboxes.
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
3. Apply the PostgreSQL licensing/audit schema migrations from the repository to Supabase, including `migrations/20261105_customer_lifecycle_sync_outbox.sql` for durable admin customer lifecycle synchronization and `migrations/20261106_billing_mirror_sync_outbox.sql` for failed Paddle-to-Hostinger billing mirror retries.
4. Apply `migrations/hostinger_operational_schema.sql` to the Hostinger operational database. Apply any later Hostinger-specific migration scripts in chronological order, including `migrations/20261105_customer_email_identity_outbox.sql` for durable cross-database verified-email synchronization.
5. Configure the environment variables above in Vercel. Use Paddle sandbox credentials until billing has been deliberately validated.
6. Deploy only to a non-production preview environment after explicit release approval.
7. Call `/health-check`. A successful response must report both PostgreSQL and MySQL as connected and schema-ready. Resolve every missing table, column, or required index before routing customer traffic.
8. Verify the scheduled worker configuration in `vercel.json` and set `CRON_SECRET` in Vercel project environment variables. Vercel adds its bearer authorization header automatically. The cron schedule is once per minute and requests at most ten jobs per invocation; package concurrency remains governed by the license entitlement. Each invocation also reconciles up to 50 pending admin customer lifecycle actions from the PostgreSQL outbox into Hostinger customer-account/session records, up to 50 verified-email changes from the Hostinger outbox into canonical PostgreSQL billing events, and up to 50 failed billing-history mirror writes from the PostgreSQL outbox into Hostinger. Billing entitlements remain canonical in PostgreSQL; mirror failures are retained with capped exponential retry scheduling and are visible in the worker response. Updates are idempotent, failures are retained with capped exponential retry scheduling, and the worker response reports processed/deferred counts. Completed outbox records older than 90 days are removed by bounded cleanup. The worker also removes expired login/email challenges older than seven days and expired/revoked sessions older than 30 days in batches of up to 500 per record type. Housekeeping failures are logged and reported but do not stop scan processing.
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
- `POST /api/v1/scan-jobs/{job_id}/retry`: customer-authenticated retry for one terminally failed scan job. It reopens only a failed, non-cancelled batch, resets the job's bounded attempt counter, preserves the original job/idempotency identity, and relies on the worker's existing source-job quota idempotency. Cancelled or in-flight jobs cannot be reopened.
- `/api/v1/admin/operations`: administrator-only operational and billing diagnostics.
- Admin customer suspension/reactivation updates canonical PostgreSQL license state and records a durable lifecycle outbox event in the same transaction, then synchronizes Hostinger customer-account status; suspension also revokes all browser sessions. The linked-license switch API also rejects inactive or expired licenses and returns an explicit `selectable` eligibility flag for customer portal controls. The scheduled worker retries Hostinger synchronization with capped exponential backoff. Customer portal authentication and passwordless sign-in reject inactive licenses, so a Hostinger synchronization failure cannot restore access while PostgreSQL remains suspended.
- `/api/v1/admin/billing/reconcile`: bounded mirror reconciliation from canonical PostgreSQL payment events into Hostinger.
- `/api/v1/admin/subscriptions/{subscription_id}/reconcile`: fetches the current Paddle subscription snapshot, validates the returned subscription ID/status, then reconciles the canonical PostgreSQL license status, mapped plan allowance, and billing-period end. Webhook and admin billing paths also verify that all recorded events for a subscription resolve to one license; conflicting legacy links fail closed with HTTP 409 and require manual administrator reconciliation rather than changing an arbitrary customer's entitlement. `paused` and `canceled` disable access; `active`/`trialing` restore access only when the license has not expired; `past_due` preserves the current access state while Paddle's dunning policy runs. For finite-expiry subscription licenses, a verified active/trialing billing period extends `expires_at` to the later provider period end (never shortens an existing later expiry); perpetual licenses with `expires_at = NULL` remain non-expiring. The same expiry synchronization is applied to successful recurring transaction renewals and active/trialing subscription updates. The action records a billing lifecycle event and admin audit entry. If Paddle cannot be verified, local entitlement state is left unchanged. Customer billing attention and admin operations feeds suppress older `payment_failed`/`subscription_past_due` alerts once a later verified successful renewal, active subscription update, resume, or activation is recorded; the original failure remains in immutable billing history.
- Verified customer email changes are committed to Hostinger with a durable outbox entry; the scheduled worker then updates matching canonical PostgreSQL billing-event email addresses. A pending outbox item is retried automatically with backoff until acknowledged.
- `/api/v1/billing/paddle-webhook`: canonical billing lifecycle event intake.

## Release safety

- Do not merge the feature branch or deploy production without explicit release approval.
- Do not run production migrations without a verified backup and explicit approval.
- Keep live Paddle credentials disabled until sandbox lifecycle verification is complete.
- Do not put database URLs, provider credentials, license keys, customer tokens, or administrator keys in logs or source control.
- Treat the final PDF/report storage and presentation refinement as a separate final product phase; this runbook does not claim that phase is complete.

## WordPress connection lifecycle

- A WordPress registration is scoped to the saved license credential and configured HTTPS API base. When either identity changes in plugin settings, the plugin first requests disconnection using the previous saved credential and endpoint; it does not overwrite the old identity if that retirement request fails.
- A disconnect response of HTTP 404 is treated as already disconnected, allowing stale local site identifiers to be cleared safely. Other API failures retain the saved registration and block credential replacement until connectivity is restored.
- Disconnecting an installation from the SaaS customer portal is reflected in the plugin on its next scheduled status sync. A 404 status response clears the stale local site identifier and asks the administrator to save settings to register again.
- Plugin deactivation only removes its scheduled status-sync event; it does not revoke the SaaS registration. This avoids treating temporary plugin deactivation as an explicit account disconnect. Use the plugin's Disconnect action or the SaaS customer portal when the installation should be retired.
- The SaaS customer portal disconnect is scoped to the currently selected license. It retains audit history, license records, and billing history. Reconnection is an explicit plugin settings save.


### Paddle failed-transaction webhook recovery

- Both `transaction.payment_failed` and `transaction.past_due` are recorded as payment-failure attention events. Paddle can emit both for one failed renewal; transaction-ID idempotency prevents duplicate failure rows. A `transaction.payment_failed` or `transaction.past_due` event with no `subscription_id` is linked only when the same Paddle transaction already has a canonical PostgreSQL billing event tied to a license. The handler does not infer license ownership from an email address or Paddle customer ID.
- If the transaction has not yet been linked to a license, the webhook returns a retryable `503`; allow Paddle delivery retries or reconcile the originating transaction before treating the failure as resolved.
- A delayed failure notification is ignored when the same transaction already has a verified completion/provisioning record (`delivered`, `email_pending`, `email_sending`, or `subscription_renewed`). This prevents stale failure notifications from reopening a recovered billing issue.
- Failure events remain billing-history/operations events and do not independently deactivate a license. Subscription cancellation and pause remain separate lifecycle transitions; Paddle subscription state and verified renewal events govern recovery.
- When a transaction is linked to a subscription, preserve the subscription identifier on the failure event so customer/admin attention feeds can clear the old failure after a newer verified recovery event.


### Customer bulk-scan retry from the portal

- In Bulk website scanning, open a batch with **View URLs** to inspect each job's state, attempt count, and safe error code. Completed jobs expose their saved scan results.
- A failed job shows **Retry failed scan** only as an enabled action after its parent batch reaches `failed`. While the request is in flight the control is disabled to prevent duplicate clicks.
- The portal calls `POST /api/v1/scan-jobs/{job_id}/retry` using the currently connected license/session. The API scopes the job and batch to that license, accepts only failed jobs in a failed non-cancelled batch, and returns HTTP 409 for a state conflict or 404 for a job outside the account.
- A retry reuses the original job and idempotency identity; it does not create another URL submission. After acceptance, the portal reloads the batch list and job detail so queued/processing/completed state is refreshed. If the request fails, the portal displays the API error and leaves the retry available only when the previously loaded batch state still permits it.
- Progress is refreshed on demand through **Refresh progress** or after queue/cancel/retry actions. This portal view does not claim continuous live updates.


### Admin bulk-scan queue monitoring

- The admin portal's **Bulk scan queue monitoring** panel calls `GET /api/v1/admin/scan-operations` with the configured admin key. The endpoint is read-only and sets private no-store response headers.
- Queue counts are aggregated from Hostinger operational tables. Failed-job details use `failed_limit` (default 25, maximum 100) and `failed_offset` query parameters; the response includes total count and `failed_jobs_has_more` so administrators can page through the entire failed-job set without an unbounded result. The display includes only job/batch IDs, mapped license ID, hostname, attempt counts, safe error code, and timestamps—not full target URLs, credentials, or customer secrets.
- The endpoint reads scan batches/jobs from Hostinger and maps license keys to license IDs using the licensing database. Both database dependencies must be healthy for complete customer mapping; an unmapped license is shown as such rather than exposing its license key.
- This is an operator snapshot, not a live stream. Use **Refresh diagnostics** to request a new snapshot. The panel does not retry, cancel, or otherwise mutate jobs.
