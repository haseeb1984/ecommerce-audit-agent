# Approved application architecture

This document is the implementation source of truth for database and storage ownership.
It supersedes older repository notes that placed general SaaS operational records or
customer PDF files in Supabase.

## Platform responsibilities

- **Hostinger MySQL — primary operational database:** customer accounts and profiles,
  package/customer operational records, customer website inventory, submitted scan
  requests, scan batches, per-URL jobs, queue state, retries, usage history, scan
  history, customer activity, admin/customer operations, WordPress installation
  metadata, and white-label/customer settings.
- **Hostinger private file storage — customer files:** generated PDF reports and
  other customer-owned files. Store opaque storage keys and file metadata in MySQL;
  do not store report file bytes in Supabase.
- **Vercel — application and execution layer:** application hosting, API routing,
  request handling, execution/orchestration, and secure communication between the
  operational database and the specialized audit/licensing services.
- **Supabase PostgreSQL — licensing and audit engine only:** license records,
  license/API-key validation, audit-engine state and the minimum records required
  for those responsibilities. It is not the general SaaS customer database and
  not the customer file store.

## Package and bulk-scan behavior

All three customer packages use the same operational website/scan queue model.
Package entitlements determine allowed website/audit quantities and execution
concurrency; package-specific values remain managed by the existing plan catalogue
and licensing rules rather than being hard-coded into queue storage.

Bulk submissions are persisted in Hostinger MySQL. The application divides
submitted URLs into batches of 10 or 11, persists each URL as an independently
tracked job, and advances queued batches as worker capacity becomes available.
Job identity/idempotency, attempts, retry timing, claim ownership, quota reservation
and quota-consumption state must be persisted so retries/restarts do not create
duplicate work or duplicate usage deductions.

## Database boundary rules

- Never create a cross-database foreign key between Hostinger MySQL and Supabase.
- Use the license key as the stable external reference when operational records
  need to be associated with a Supabase-owned license.
- Validate license and package entitlements through the licensing boundary; persist
  customer operational state in Hostinger.
- Migrations for Hostinger and Supabase must remain separate and explicitly target
  their respective database engines.
- Do not run migrations automatically at application startup.
- Existing customer-facing workflows and business logic must be preserved while
  their persistence is moved to the correct owner.

## Implementation sequence

1. Establish independent Hostinger connection and metadata (implemented).
2. Define Hostinger operational entities and the MySQL schema (foundation added).
3. Move account/session, website inventory, WordPress, branding, admin and activity
   persistence from PostgreSQL to Hostinger while preserving license verification.
4. Implement persistent batch submission, 10/11 URL grouping, worker claiming,
   retries, resume, and idempotent quota accounting on Hostinger (queue/API/worker
   foundation is now in the branch).
5. Run the worker in scheduled groups of up to 10; Supabase package concurrency
   entitlements remain the effective per-package cap. A temporary concurrency
   saturation returns jobs to the queue without consuming a retry attempt.
6. Move report file bytes to Hostinger private storage and retain only the required
   audit-engine metadata in Supabase.
7. Reconcile customer/admin interfaces and API response contracts with the new
   operational data ownership.

This document records the agreed target architecture; it does not claim that all
migration steps or live integrations are already complete.


## Bulk worker runtime configuration

- Configure `HOSTINGER_DATABASE_URL` for the Hostinger MySQL operational database.
- Configure `DATABASE_URL` for the Supabase PostgreSQL licensing/audit database.
- Configure `SCAN_WORKER_TOKEN` as a long random secret. Configure the Vercel Cron
  authorization secret to the same value so the scheduled request is authenticated.
- Vercel Cron invokes `/internal/scan-worker/run` once per minute and requests up to
  10 jobs per invocation. The worker's Supabase quota reservation enforces each
  package's configured monthly allowance and maximum concurrent audits.
- The Hostinger MySQL schema migration and the Supabase idempotency migration are
  separate operator-applied migrations. No application-startup DDL is performed.
