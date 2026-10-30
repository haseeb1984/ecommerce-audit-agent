# Database and external integration rollout

This document follows the product's agreed database boundary. It does not connect to or mutate a production database.

## Authoritative database responsibilities

- **Supabase PostgreSQL (Vercel licensing/audit engine):** license records and entitlements, API keys, quota reservations/consumption, canonical audit leads/results, plan entitlement catalogue, and the minimum Paddle webhook idempotency/lifecycle state needed to provision or update licenses.
- **Hostinger MySQL (SaaS operational database):** customer accounts and sessions, login/email challenges, WordPress installations, white-label branding, customer website inventory, scan batches/jobs/results, usage and activity history, customer billing-event history, admin support notes, and administrator action history.
- **Hostinger private file storage:** customer reports, PDFs, and uploaded/generated files. Report-file metadata belongs in Hostinger MySQL; file bytes must not be stored in Supabase PostgreSQL.
- **Vercel:** application hosting, API execution, scheduled worker invocation, and communication between the customer-facing SaaS, Hostinger operations, and the licensing/audit engine.

No foreign keys cross database boundaries. license_key is the stable operational reference validated against the PostgreSQL licensing service.

## Migration sequence

Take backups of both databases before applying any migration. All migration execution is an explicit operator-controlled release step; application startup and HTTP requests must never mutate schemas.

1. Apply the PostgreSQL licensing/audit schema migrations required for software_licenses, api_keys, audit_leads, audit_quota_reservations, saas_plan_packages, and payment_webhook_events. Keep only the minimal webhook and license lifecycle facts needed by entitlement processing in PostgreSQL.
2. Provision the Hostinger MySQL operational schema from the Hostinger migration files under migrations/hostinger/ and the Hostinger model definitions. This includes customer accounts/sessions, WordPress installations, branding, customer website inventory, scan queue/history, usage/activity, admin notes, admin action logs, and billing-event history.
3. Review the source-to-target mapping in scripts/migrate_operational_data_to_hostinger.py. Its default mode is dry-run and reports records that would be copied. Run it with --apply only after reviewing the mapping, confirming both schemas, and taking backups. It copies missing rows and never deletes PostgreSQL source records.
4. Reconcile operational data counts and customer ownership before switching off legacy PostgreSQL operational tables. Do not remove legacy source tables as part of the copy.
5. Keep report binary migration as a final, separate phase: move report bytes to Hostinger private storage, retain metadata and ownership in Hostinger MySQL, and only then retire any legacy PostgreSQL PDF bytes.

The current migration utility covers legacy customer accounts, billing-event history, login/session/email-change records, WordPress installations, branding, support notes, and admin action history. It is deliberately non-destructive. Live migration has not been executed by this code change.

## Runtime database contract

- DATABASE_URL connects to Supabase PostgreSQL through asyncpg and is limited to licensing/audit responsibilities.
- HOSTINGER_DATABASE_URL connects to Hostinger MySQL through asyncmy or aiomysql and stores SaaS operational records.
- Keep TLS verification enabled for PostgreSQL. Configure database credentials only as encrypted hosting-provider secrets.
- Quota is reserved in a short PostgreSQL transaction; external HTTP/AI work runs outside that transaction.
- Bulk scan inventory, batches, jobs, status, retries, and customer-visible scan history are durable in Hostinger MySQL. Jobs run in bounded concurrent groups according to the plan entitlement; the next batch is not released until the current batch is complete.
- The Paddle event ledger in PostgreSQL prevents duplicate license provisioning and applies subscription entitlement changes. A customer-facing billing history mirror is persisted in Hostinger MySQL.
- Admin/customer operational activity is persisted in Hostinger MySQL.
- PDF bytes are not part of the final database boundary: the remaining report-file migration is intentionally deferred to the final refinement phase.

## Required production environment

Configure secrets directly in the hosting provider's encrypted environment settings. Never commit secrets or paste their values into support tickets.

| Integration | Required settings |
|---|---|
| PostgreSQL licensing/audit | DATABASE_URL; keep DATABASE_SSL=true |
| Hostinger operations | HOSTINGER_DATABASE_URL using mysql+asyncmy:// or mysql+aiomysql:// |
| Admin console | ADMIN_API_KEY |
| Customer passwordless login | ACCOUNT_AUTH_SECRET (at least 32 characters) |
| Paddle | PADDLE_ENVIRONMENT, PADDLE_API_KEY, PADDLE_WEBHOOK_SECRET, PADDLE_CLIENT_TOKEN |
| Paddle prices | PADDLE_PRICE_ID_STARTER, PADDLE_PRICE_ID_PRO, PADDLE_PRICE_ID_BUSINESS; optional tier quotas via LICENSE_MONTHLY_AUDITS_STARTER/PRO/BUSINESS |
| Email | SMTP_HOST, SMTP_PORT, SMTP_FROM, SMTP_TLS_MODE; optional paired SMTP_USERNAME and SMTP_PASSWORD |
| PageSpeed | GOOGLE_PAGESPEED_API_KEY or PAGE_SPEED_API_KEY |
| AI analysis | GROQ_API_KEY |
| Scan worker | SCAN_WORKER_TOKEN; configure Vercel Cron authorization with the same secret |

Paddle environment, API key, client token, price IDs and webhook secret must all belong to the same sandbox or production environment. SMTP username and password must either both be configured or both be absent.

## Readiness and release boundary

After the operator applies both database schemas and configures the environment, the health endpoint checks PostgreSQL licensing/audit readiness and Hostinger operational readiness independently. Missing mapped tables or columns return a not-ready response.

No production migration, provider secret entry, Paddle transaction, test run, audit run, or deployment is implied by the presence of these source files. Those remain explicit release activities.
