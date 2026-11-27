# Database and external integration rollout

This document follows the product's agreed database boundary. It does not connect to or mutate a production database.

## Authoritative database responsibilities

- **Supabase PostgreSQL (Vercel licensing/audit engine):** license records and entitlements, API keys, quota reservations/consumption, canonical audit leads/results, plan entitlement catalogue, and the minimum Paddle webhook idempotency/lifecycle state needed to provision or update licenses.
- **Existing Hostinger WordPress MySQL database (shared physical database):** WordPress core tables plus SaaS operational tables for customer accounts and sessions, login/email challenges, WordPress installations, white-label branding, customer website inventory, scan batches/jobs/results, usage and activity history, customer billing-event history, admin support notes, and administrator action history. Do not create a separate Hostinger database; `HOSTINGER_DATABASE_URL` must point to this existing WordPress database.
- **Hostinger private file storage:** new customer PDF reports and uploaded customer logos. Report-file metadata belongs in Hostinger MySQL; file bytes are stored in Hostinger private storage. Existing historical PDFs may remain in legacy PostgreSQL storage until a separately approved backfill and verification is complete.
- **Vercel:** application hosting, API execution, and secure communication between the customer-facing SaaS, Hostinger operations, and the licensing/audit engine. GitHub Actions is the configured scheduler for durable scan-worker invocation.

No foreign keys cross the Supabase/PostgreSQL and Hostinger/MySQL database boundary. WordPress core and SaaS operational tables share the same Hostinger MySQL database. `license_key` is the stable operational reference validated against the PostgreSQL licensing service.

## Migration sequence

Back up the existing WordPress/Hostinger MySQL database and Supabase PostgreSQL before applying migrations. Hostinger operational migrations target the existing WordPress database; no new Hostinger database is provisioned. All migration execution is an explicit operator-controlled release step; application startup and HTTP requests must never mutate schemas.

1. Apply the PostgreSQL licensing/audit schema migrations required for software_licenses, api_keys, audit_leads, audit_quota_reservations, saas_plan_packages, and payment_webhook_events. Keep only the minimal webhook and license lifecycle facts needed by entitlement processing in PostgreSQL.
2. Apply the Hostinger MySQL operational schema to the existing WordPress database from `migrations/hostinger_operational_schema.sql` and the applicable Hostinger-specific incremental migrations (including the `migrations/hostinger/` files and root-level MySQL migrations). Review each file's database target and prerequisites; the incremental set includes agency operational tables, WordPress identity linking, customer email identity outbox, scan/workspace alignment, billing/admin mirrors, report storage metadata, branding/logo cleanup, and platform settings. Do not apply PostgreSQL migrations to Hostinger MySQL or assume every one-time migration is needed on a fresh schema.
3. Review the source-to-target mapping in scripts/migrate_operational_data_to_hostinger.py. Its default mode is a strictly read-only dry-run and reports records that would be copied without issuing target INSERT statements. Run the default mode first and resolve every reported mapping or existing-field mismatch before applying. The --apply command itself now performs a complete read-only preflight and aborts before target writes when blockers are found; keep source data quiescent between preflight and apply so the reviewed source snapshot does not drift. Apply only after reviewing the mapping, confirming both schemas, and taking backups. It copies missing rows and never deletes PostgreSQL source records. After the approved copy, run `python scripts/migrate_operational_data_to_hostinger.py --verify` against the same source and target databases. Verification is read-only: it fails if any mapped source rows are missing **or** if an existing target row differs in any mapped field (including account and support-note records). Datetimes are normalized to UTC before comparison to avoid false mismatches between PostgreSQL and MySQL timezone representations. It reports mismatched field names and counts only, never field values. Intentionally ambiguous or unmapped support-note records remain separately reported and are not assigned to an arbitrary customer.
4. Reconcile operational data counts and customer ownership before switching off legacy PostgreSQL operational tables. Do not remove legacy source tables as part of the copy.
5. For new reports, use the Hostinger private storage bridge and Hostinger MySQL metadata path. The application retains legacy PostgreSQL PDF fallback for older reports. Historical PDF-byte backfill and retirement of legacy PostgreSQL PDF bytes require a separately approved, backed-up migration and post-migration verification; do not assume that data migration has run.

The legacy PDF backfill script requires both database connections. It reads the authoritative `report_retention_days` owner setting from Hostinger MySQL and falls back to `REPORT_RETENTION_DAYS` only when no persisted setting exists; this keeps its migration cutoff aligned with the application download and cleanup policy. The default eligibility preview is read-only and does not require storage credentials; the `--apply` pass also requires the configured Hostinger storage bridge. It only uploads objects and clears PostgreSQL binaries when the operator passes `--apply` after reviewing the eligibility count.



### Fresh Hostinger schema versus incremental upgrades

- `migrations/hostinger_operational_schema.sql` is a full fresh-schema baseline, not a starting point to which every historical incremental SQL file should be replayed. It already defines the customer branding storage columns (`logo_storage_key`, `logo_sha256`, `logo_mime_type`, `logo_byte_size`), the logo-cleanup table, and the full customer report metadata shape (`report_id`, `domain`, `finding_count`, `expires_at`, `deleted_at`, `pdf_sha256`, and `storage_key_hash`). It also contains the platform settings, admin action log, and customer billing event tables.
- Therefore, do **not** apply `20261121_hostinger_branding_storage.mysql.sql`, `20261122_hostinger_report_metadata.mysql.sql`, or `20261123_hostinger_brand_logo_cleanup.mysql.sql` after creating a fresh database from that baseline: those upgrade scripts add columns/tables that the baseline already creates and are not all guarded against duplicates. The admin-action/billing-history and platform-settings `CREATE TABLE IF NOT EXISTS` scripts are redundant on a fresh baseline but idempotent at table creation.
- For an existing Hostinger installation, first inspect its actual schema and migration history, then select only the missing upgrade steps whose prerequisites match that installation. The index-alignment and report-storage-key-hash scripts contain conditional logic, but still require a reviewed preflight and post-migration schema check. Do not infer the database's migration state from filenames or from the preview health endpoint alone.
- This distinction is important because the app readiness check validates the resulting ORM contract; it does not certify that a particular historical migration file should be run.

The current migration utility covers legacy customer accounts, billing-event history, login/session/email-change records, WordPress installations, branding, support notes, and admin action history. Generic entity copying streams source rows in batches of 500 and reconciles each batch with one bounded target-key query rather than issuing one target lookup per source row. Account sessions, WordPress installations, billing events, and support notes are also read through streaming cursors; account and support-note target reconciliation uses bounded batches rather than per-row lookups. Account-candidate identities are now deduplicated by a PostgreSQL `UNION ALL` plus `ROW_NUMBER()` query and streamed in deterministic 500-row batches, avoiding a Python dictionary of every distinct account. Candidate precedence is session first, then WordPress installation, then billing email; within a source class the most recently updated/created candidate wins. Legacy entity transforms now resolve source license IDs to stable license keys per 500-row source batch. The migration no longer materializes a global license identity map; each batch queries only the license IDs present in that batch. Support-note email ownership is resolved directly in PostgreSQL: a grouped normalized-email/license-count subquery is outer-joined to streamed note rows, so Python does not materialize either an email-to-license map or an ambiguous-email set. Notes are copied only when exactly one distinct license owns the billing email; ambiguous and unmapped notes remain reported separately. This bounds raw-row working sets without claiming constant memory for high-cardinality identity maps. In `--apply` mode, each 500-row target reconciliation batch is committed independently to bound the SQLAlchemy unit of work and database transaction size. A process interruption can therefore leave a partially copied but consistent migration; rerunning `--apply` is safe because the utility only inserts missing mapped rows and never overwrites existing rows or deletes PostgreSQL sources. Operators must still run the read-only `--verify` mode after the full copy. The migration is deliberately non-destructive. Live migration has not been executed by this code change.

## Runtime database contract

- DATABASE_URL connects to Supabase PostgreSQL through asyncpg and is limited to licensing/audit responsibilities.
- HOSTINGER_DATABASE_URL connects through asyncmy or aiomysql to the same existing Hostinger MySQL database used by WordPress and stores SaaS operational records alongside WordPress tables. It must not point to a separately provisioned database.
- Keep TLS verification enabled for PostgreSQL. Configure database credentials only as encrypted hosting-provider secrets.
- Quota is reserved in a short PostgreSQL transaction; external HTTP/AI work runs outside that transaction.
- Bulk scan inventory, batches, jobs, status, retries, and customer-visible scan history are durable in Hostinger MySQL. Jobs run in bounded concurrent groups according to the plan entitlement; the next batch is not released until the current batch is complete.
- The Paddle event ledger in PostgreSQL prevents duplicate license provisioning and applies subscription entitlement changes. A customer-facing billing history mirror is persisted in Hostinger MySQL.
- Admin/customer operational activity is persisted in Hostinger MySQL.
- New PDF bytes are written to Hostinger private storage and report metadata is persisted in Hostinger MySQL. The older PostgreSQL PDF payload remains available as a compatibility fallback until the separately approved historical backfill and retirement are completed.

## Required production environment

Configure secrets directly in the hosting provider's encrypted environment settings. Never commit secrets or paste their values into support tickets.

| Integration | Required settings |
|---|---|
| PostgreSQL licensing/audit | DATABASE_URL; keep DATABASE_SSL=true |
| Existing Hostinger WordPress MySQL | HOSTINGER_DATABASE_URL using mysql+asyncmy:// or mysql+aiomysql://, pointing to the existing WordPress database |
| Admin console | ADMIN_API_KEY |
| Customer passwordless login | ACCOUNT_AUTH_SECRET (at least 32 characters) |
| Paddle | PADDLE_ENVIRONMENT, PADDLE_API_KEY, PADDLE_WEBHOOK_SECRET, PADDLE_CLIENT_TOKEN |
| Paddle prices | PADDLE_PRICE_ID_STARTER, PADDLE_PRICE_ID_PRO, PADDLE_PRICE_ID_BUSINESS; optional tier quotas via LICENSE_MONTHLY_AUDITS_STARTER/PRO/BUSINESS |
| Email | SMTP_HOST, SMTP_PORT, SMTP_FROM, SMTP_TLS_MODE; optional paired SMTP_USERNAME and SMTP_PASSWORD |
| PageSpeed | GOOGLE_PAGESPEED_API_KEY or PAGE_SPEED_API_KEY |
| AI analysis | GROQ_API_KEY |
| Scan worker application | SCAN_WORKER_TOKEN in Vercel |
| Scan worker scheduler | SCAN_WORKER_URL repository variable and CRON_SECRET repository secret in GitHub Actions; CRON_SECRET must match SCAN_WORKER_TOKEN |
| Hostinger private storage | HOSTINGER_STORAGE_BASE_URL (credential-free HTTPS bridge endpoint); HOSTINGER_STORAGE_HMAC_SECRET (same random 32+ byte secret as Hostinger `config.php`) |

The production readiness script validates the Hostinger private storage HTTPS endpoint and HMAC secret length, along with application-side worker authentication configuration, but cannot inspect GitHub repository variables or secrets. Verify scheduler configuration by running the **Durable scan worker** workflow manually after setting both GitHub values; the workflow fails visibly if either value is missing, the URL is not HTTPS, or the worker returns a non-success response.

Paddle environment, API key, client token, price IDs and webhook secret must all belong to the same sandbox or production environment. SMTP username and password must either both be configured or both be absent.

## Readiness and release boundary

After the operator applies both database schemas and configures the environment, the health endpoint checks PostgreSQL licensing/audit readiness and Hostinger operational readiness independently. Missing mapped tables or columns return a not-ready response.

No production migration, provider secret entry, Paddle transaction, test run, audit run, or deployment is implied by the presence of these source files. Those remain explicit release activities.


## Hostinger report-retention retry fairness — 2026-11-27

- Expired private report files now persist cleanup attempt count and last-attempt timestamp. Cleanup orders never-attempted records first, then the oldest retry timestamp, so repeatedly failing objects do not permanently occupy the first page.
- Detached logo cleanup already stores `last_attempt_at`; the cleanup query now uses that timestamp for the same fair retry ordering.
- Fresh Hostinger installs receive the report retry fields from `migrations/hostinger_operational_schema.sql`. Existing installs must preflight and apply `migrations/20261127_hostinger_report_cleanup_retry.mysql.sql` once; it conditionally adds both columns and the supporting index.
- This migration is Hostinger MySQL only. It is not a Supabase/PostgreSQL migration. Do not replay the incremental migration after the fresh baseline without checking schema state.
- Automated CI verifies source/model contracts. Runtime deletion and retry behavior still require staging verification with controlled test objects; no customer files were deleted during implementation.

- Legacy PostgreSQL `audit_reports` cleanup also persists `pdf_cleanup_attempts` and `pdf_cleanup_last_attempt_at`; existing Supabase installations must apply `migrations/20261127_supabase_report_cleanup_retry.sql`. This is a Supabase PostgreSQL migration only and is separate from the Hostinger MySQL retry migration.
- Cleanup retry timestamps are written before storage deletion and committed even when deletion fails. Each cleanup queue orders never-attempted records first, then oldest retry timestamps, avoiding permanent first-page starvation across Hostinger reports, detached logos, and legacy reports.
