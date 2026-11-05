# Deployment and Operations Runbook

This runbook describes the current deployment topology and the safe order for preparing an environment. It does not authorize a production deployment, database migration, or branch merge.

## Service boundaries

- **Vercel / FastAPI**: HTTP API, customer and administrator interfaces, and application orchestration. The worker is invoked by a separate GitHub Actions scheduler.
- **Supabase PostgreSQL**: canonical software licenses, API keys, quota reservations, audit leads/reports, Paddle webhook events, and plan packages.
- **Hostinger MySQL**: customer accounts and sessions, email challenges, website inventory, WordPress installations, scan batches/jobs/results, customer usage/activity, billing mirrors, administrator notes/actions, operational diagnostics, and the durable email-identity and billing-mirror synchronization outboxes. WordPress administrator identity links use hashed, ten-minute single-use challenges.
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
- `PADDLE_ENVIRONMENT`, `PADDLE_API_KEY`, `PADDLE_WEBHOOK_SECRET`, and `PADDLE_CLIENT_TOKEN`. The Paddle API key must include permission to read configured prices so the public pricing page can display the verified active catalogue amount; checkout still uses the server-managed Paddle price ID.
- Optional `PADDLE_CHECKOUT_URL`.
- `PADDLE_PRICE_ID_STARTER`, `PADDLE_PRICE_ID_PRO`, `PADDLE_PRICE_ID_BUSINESS` and the corresponding `LICENSE_MONTHLY_AUDITS_*` / `LICENSE_MAX_CONCURRENT_AUDITS_*` values used to bootstrap package records.
- `ADMIN_API_KEY`: long random administrator secret.
- `CRON_SECRET`: long random bearer secret. The GitHub Actions scheduler sends it as `Authorization: Bearer <CRON_SECRET>`; configure the same value in Vercel and as a GitHub Actions repository secret. `SCAN_WORKER_TOKEN` is also accepted for controlled manual invocations.

## Safe environment preparation order

1. Create separate Supabase PostgreSQL and Hostinger MySQL databases. Enable TLS and restrict credentials to the application.
2. Take restorable backups and verify that restore access is available before schema changes.
3. Apply the PostgreSQL licensing/audit schema migrations from the repository to Supabase, including `migrations/20261105_customer_lifecycle_sync_outbox.sql` for durable admin customer lifecycle synchronization and `migrations/20261106_billing_mirror_sync_outbox.sql` for failed Paddle-to-Hostinger billing mirror retries.
4. Apply `migrations/hostinger_operational_schema.sql` to the Hostinger operational database. Apply any later Hostinger-specific migration scripts in chronological order, including `migrations/hostinger/20261103_customer_report_storage_key_hash.sql` to replace the oversized utf8mb4 report-storage unique index with a fixed-width SHA-256 index, `migrations/20261103_wordpress_identity_linking.sql` for hashed WordPress identity claims, and `migrations/20261105_customer_email_identity_outbox.sql` for durable cross-database verified-email synchronization.
5. Configure the environment variables above in Vercel. Use Paddle sandbox credentials until billing has been deliberately validated.
6. Deploy only to a non-production preview environment after explicit release approval.
7. Call `/health-check`. A successful response must report both PostgreSQL and MySQL as connected and schema-ready. Resolve every missing table, column, or required index before routing customer traffic.
8. Configure the external scan-worker scheduler. The repository workflow `.github/workflows/scan-worker.yml` invokes `/internal/scan-worker/run?max_jobs=10` every five minutes using GitHub Actions (the minimum supported scheduled interval). Set the repository variable `SCAN_WORKER_URL` to the full HTTPS endpoint URL and add `CRON_SECRET` as a GitHub Actions repository secret; set the identical `CRON_SECRET` in Vercel environment variables. The workflow uses a bearer header, makes no credential available to repository code, and can also be run manually with `workflow_dispatch`. GitHub scheduled workflows run from the default branch, so enable this scheduler after the workflow is merged into `main`. Do not restore a Vercel cron on Hobby: it rejects schedules more frequent than daily. Do not downgrade the queue worker to daily because that would leave customer scans waiting for up to a day. Each invocation requests at most ten jobs and also reconciles up to 50 pending admin customer lifecycle actions from the PostgreSQL outbox into Hostinger customer-account/session records, up to 50 verified-email changes from the Hostinger outbox into canonical PostgreSQL billing events, and up to 50 failed billing-history mirror writes from the PostgreSQL outbox into Hostinger. Billing entitlements remain canonical in PostgreSQL; mirror failures are retained with capped exponential retry scheduling and are visible in the worker response. Updates are idempotent, failures are retained with capped exponential retry scheduling, and the worker response reports processed/deferred counts. Completed outbox records older than 90 days are removed by bounded cleanup. The worker also removes expired login/email challenges older than seven days and expired/revoked sessions older than 30 days in batches of up to 500 per record type. Housekeeping failures are logged and reported but do not stop scan processing.
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
- `/internal/scan-worker/run`: internal scheduled worker; GitHub Actions uses `CRON_SECRET` bearer authentication, with `SCAN_WORKER_TOKEN` retained for controlled manual invocations.
- `POST /api/v1/scan-jobs/{job_id}/retry`: customer-authenticated retry for one terminally failed scan job. It reopens only a failed, non-cancelled batch, resets the job's bounded attempt counter, preserves the original job/idempotency identity, and relies on the worker's existing source-job quota idempotency. Cancelled or in-flight jobs cannot be reopened.
- `/api/v1/admin/operations`: administrator-only operational and billing diagnostics.
- Admin customer suspension/reactivation updates canonical PostgreSQL license state and records a durable lifecycle outbox event in the same transaction, then synchronizes Hostinger customer-account status; suspension also revokes all browser sessions. The scheduled worker retries Hostinger synchronization with capped exponential backoff. Customer portal authentication and passwordless sign-in reject inactive licenses, so a Hostinger synchronization failure cannot restore access while PostgreSQL remains suspended.
- `/api/v1/admin/billing/reconcile`: bounded mirror reconciliation from canonical PostgreSQL payment events into Hostinger.
- `POST /api/v1/admin/sync-outboxes/retry?queue=customer_lifecycle|customer_email_identity&limit=200`: administrator-only, bounded re-queuing of pending customer lifecycle or email-identity synchronization events for the next scheduled worker cycle; this does not alter canonical license/billing state or run a worker inline.
- `POST /api/v1/admin/billing/mirror-retry?limit=200`: administrator-only, bounded re-queuing of pending billing mirror outbox records. Rows are locked with `SKIP LOCKED`, made eligible at the next scheduled worker cycle, and recorded in the admin activity log; this does not alter canonical billing events or customer entitlements.
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
- The SaaS customer portal disconnect is scoped to the currently authenticated customer license. It retains audit history, license records, and billing history. Reconnection is an explicit plugin settings save.


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


### Individual admin client suspension/reactivation

- `PATCH /api/v1/admin/clients/{license_id}` supports explicit `is_active` changes as part of client entitlement management. A real active-state transition is serialized by locking the canonical license row and writes a `CustomerLifecycleSyncOutbox` record in the same PostgreSQL transaction.
- The outbox action is `suspend` or `reactivate`; the lifecycle worker mirrors the customer account status to Hostinger and revokes active browser sessions on suspension. This keeps individual client edits consistent with account-wide customer lifecycle actions.
- Updating unrelated client fields, or submitting the already-current active state, does not enqueue redundant lifecycle work. The admin action log records the changed field names and account ID, not the license key.


### Admin bulk-scan queue monitoring

- The admin portal's **Bulk scan queue monitoring** panel calls `GET /api/v1/admin/scan-operations` with the configured admin key. The endpoint is read-only and sets private no-store response headers.
- Queue counts are aggregated from Hostinger operational tables. The admin portal exposes `GET /api/v1/admin/scan-jobs` for a paginated all-status queue view (queued, processing, retry-wait, completed, failed, and cancelled), with optional status and license filters; its response maps operational license keys to PostgreSQL license IDs and does not return license keys. The separate `GET /api/v1/admin/scan-operations` diagnostics endpoint retains bounded failed-job details via `failed_limit` (default 25, maximum 100) and `failed_offset`; its response includes total count and `failed_jobs_has_more` so administrators can page through failed jobs without an unbounded result. Both views display only job/batch IDs, mapped license ID, website/hostname context, attempt counts, safe error codes, and timestamps—not credentials or customer secrets.
- The endpoint reads scan batches/jobs from Hostinger and maps license keys to license IDs using the licensing database. Both database dependencies must be healthy for complete customer mapping; an unmapped license is shown as such rather than exposing its license key.
- This is an operator snapshot, not a live stream. Use **Refresh diagnostics** to request a new snapshot. The panel does not retry, cancel, or otherwise mutate jobs.


### WordPress connection health and customer recovery

- The customer portal lists WordPress installations for the currently authenticated customer license only. Active installations report connection_health=healthy while their last plugin heartbeat is within seven days; an active installation with no heartbeat or a heartbeat older than seven days reports connection_health=stale.
- Staleness is an operational signal, not proof that the site is offline or disconnected. It is calculated from the persisted last_seen_at value and does not mutate the installation status or revoke access.
- For a stale connection, ask the customer to confirm that the Ecommerce Audit Agent plugin remains active in WordPress Admin, that the site can make outbound HTTPS requests, and that the plugin connection settings still contain the intended license. Reconnect from the plugin settings; registration for the same license and hostname refreshes the existing installation record rather than creating a duplicate.
- Disconnected installations remain visible in account history but are not marked stale. Reconnection is subject to the one-active-WordPress-site-per-license rule and license authentication.
- WordPress registration acquires a PostgreSQL row lock on the canonical license before reading or changing Hostinger account/installation rows. Requests for the same license therefore serialize even when the customer account is being created for the first time, preventing concurrent registrations from exceeding the one-active-WordPress-site-per-license rule. The lock is held through the Hostinger commit; registrations for different licenses remain independent.


### Customer lifecycle outbox ordering and retry safety

- Lifecycle outbox events are durable PostgreSQL records mirrored into Hostinger by the scan worker. Before applying a suspend/reactivate retry, the worker re-reads the canonical SoftwareLicense state in PostgreSQL. A delayed suspend is ignored if the license is currently active; a delayed reactivate is ignored if the license is currently inactive.
- This protects Hostinger customer-account state and session revocation from an older retry arriving after a newer admin transition. Explicit revoke_sessions actions remain independent of current entitlement and continue to revoke active sessions.
- A skipped stale transition is acknowledged as processed; operators should diagnose current entitlement from the canonical licensing database rather than replaying old lifecycle actions manually.

### Managed long-running scan worker option

- A managed Python process can drain the same durable queue without relying on HTTP scheduler invocations. Start it with `python worker_service.py` in a separate worker service/container; do not run it inside the Vercel request process.
- Configure `HOSTINGER_DATABASE_URL`, `DATABASE_URL`, and the same provider/authentication environment required by the API. The worker refuses to start when Hostinger MySQL is not configured.
- Optional bounded controls: `SCAN_WORKER_MAX_JOBS` (1–10, default 1), `SCAN_WORKER_POLL_SECONDS` (1–300, default 5), and `WORKER_LOG_LEVEL` (default INFO).
- The process drains queued jobs promptly, backs off after a failed cycle, and handles SIGINT/SIGTERM for clean shutdown. It logs counts and exception classes only; it must not log credentials, full target URLs, or customer tokens.
- Use either this persistent worker or the protected GitHub Actions scheduler as the active queue-draining mechanism unless duplicate processing capacity is deliberately configured. The database lease/claim contract remains the concurrency boundary.

- Before entering its polling loop, the worker now validates that the live `website_scan_jobs` table contains every column required by the batch/idempotency queue model. Missing tables or columns stop startup with a migration-directed error; the worker does not execute schema-changing DDL.
- The authoritative table definition is in `migrations/hostinger_operational_schema.sql`. Apply and verify that migration through the approved non-production database rollout before enabling the managed worker.

## WordPress identity-link schema

Before enabling the customer portal's one-time WordPress identity-link flow, apply `migrations/20261103_wordpress_identity_linking.sql` to Hostinger MySQL. It adds the linked WordPress user ID/login fields and creates the hashed, expiring challenge table. Fresh installations receive the same objects from `migrations/hostinger_operational_schema.sql`. Do not apply the migration to PostgreSQL.


Customer account device security:
- The customer portal lists active devices with last-seen and session-expiry timestamps; opaque session tokens and token digests are never displayed.
- Customers can revoke one other device, revoke all other devices while retaining the current browser session, or sign out every device. Device-wide actions require an active passwordless customer session, not a license/API credential.
- The "sign out other devices" action calls `POST /api/v1/account/sessions/revoke-others`; the current browser session remains active.


Agency team invitation lifecycle:
- The owner team list exposes each pending invitation's expiry timestamp, but never the one-time token or its hash.
- Invitations expire after 48 hours. Expired, revoked, or email-delivery-failed invitations can be resent from the customer portal after explicit confirmation; resending issues a new single-use link and invalidates the previous link.
- Active team members cannot be re-invited through the resend action. Existing workspace assignments and role are prefilled for a resend.


Customer bulk scan operations:
- Batch cancellation is an explicit confirmation action. It requests cancellation of queued/not-yet-started work; already completed jobs remain completed and in-progress work may finish before the batch settles.
- The portal reports cancellation and batch-detail request failures inline and restores the action when a cancellation request fails, allowing the customer to retry safely.
