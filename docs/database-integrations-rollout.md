# Database and external integration rollout

This phase completes the source-controlled PostgreSQL schema contract and the operator-facing integration setup. It does not connect to or mutate a production database.

## Database migration order

Take a database backup and review every SQL file before applying it. The original `software_licenses`, `api_keys`, and `audit_leads` tables are prerequisites.

For a fresh database, apply the core baseline first, then the feature migrations in this order:

1. `migrations/2026-10-28-core-saas-schema.sql` — core license, API key, audit lead, quota, report, plan, admin log, operation event, webhook, and initial passwordless account tables.
2. `migrations/2026-10-22-audit-reports.sql` — backward-compatible report/webhook alignment for older installations.
3. `migrations/20261023_admin_packages_and_actions.sql` — plan catalogue, operation events, admin action log and billing identifiers.
4. `migrations/20261030_customer_passwordless_auth.sql` — passwordless login challenges and sessions (already present in the core baseline).
5. `migrations/20261031_customer_device_sessions.sql` — opaque public device IDs and user-agent metadata.
6. `migrations/20261031_admin_customer_lifecycle.sql` — append-only support notes.
7. `migrations/20261031_customer_email_change.sql` — verified email-change challenges.
8. `migrations/20261031_wordpress_sites.sql` — connected WordPress installations.
9. `migrations/20261101_saas_database_integrations.sql`
10. `migrations/20261102_plan_entitlements_white_label.sql` — final additive schema alignment for quota reservations, passwordless account challenges/sessions, email changes, WordPress links, support notes, billing-period end, device-session metadata, and all mapped indexes.

For an existing database, compare its applied schema with each migration first and skip only migrations that are already fully applied. The scripts use `IF NOT EXISTS` where possible; the device-session migration also backfills an opaque public ID for existing sessions before making it required.

The final alignment migration is intentionally repeatable: it uses `IF NOT EXISTS`, adds the missing billing-period column without replacing existing values, and does not drop customer data. It assumes the legacy license/account tables already exist. Existing installations may already have some earlier tables; the statements are designed to leave them in place.

Do not apply migrations from an application request or during server startup. Keep migration execution an explicit operator-controlled release step.

## Runtime database contract

- PostgreSQL/Supabase PostgreSQL through SQLAlchemy asyncpg.
- `DATABASE_URL` must use a PostgreSQL connection URL.
- `DATABASE_SSL` defaults to enabled; production must keep TLS certificate verification enabled.
- The application uses short-lived connections and disables asyncpg prepared-statement caching for transaction-pooler compatibility.
- Audit quota is reserved in a short transaction, then external HTTP/AI work runs outside the database lock.
- Reports are persisted as license-owned `audit_reports.pdf_bytes` plus coverage metadata in PostgreSQL. The app does not require a public Supabase Storage bucket for this implementation.
- Paddle webhook records are the idempotency and retry ledger; license email delivery remains recoverable through the admin retry action.

## Required production environment

Configure secrets directly in the hosting provider's encrypted environment settings. Never commit them or paste their values into support tickets.

| Integration | Required settings |
|---|---|
| Database | `DATABASE_URL`; keep `DATABASE_SSL=true` |
| Admin console | `ADMIN_API_KEY` |
| Customer passwordless login | `ACCOUNT_AUTH_SECRET` (at least 32 characters) |
| Paddle | `PADDLE_ENVIRONMENT` (`sandbox` or `production`), `PADDLE_API_KEY`, `PADDLE_WEBHOOK_SECRET`, `PADDLE_CLIENT_TOKEN` |
| Paddle prices | `PADDLE_PRICE_ID_STARTER`, `PADDLE_PRICE_ID_PRO`, `PADDLE_PRICE_ID_BUSINESS`; optional tier quotas via `LICENSE_MONTHLY_AUDITS_STARTER/PRO/BUSINESS` |
| Email | `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM`, `SMTP_TLS_MODE` (`starttls` or `ssl`); optional paired `SMTP_USERNAME` and `SMTP_PASSWORD` |
| PageSpeed | `GOOGLE_PAGESPEED_API_KEY` or `PAGE_SPEED_API_KEY` |
| AI analysis | `GROQ_API_KEY` |

SMTP username and password must either both be configured or both be absent. Use a verified sender identity and TLS. Paddle environment, API key, client token, price IDs and webhook secret must all belong to the same sandbox or production environment.

## Readiness procedure

After the operator applies the migrations and configures the environment:

1. Run `python scripts/check_production_readiness.py` from the repository root in an environment using the deployment's database URL and settings. It is read-only and checks every SQLAlchemy-mapped table, column and index plus the Paddle partial unique index and integration configuration groups.
2. Open `/health-check`; it checks database connectivity and the mapped application schema. A missing table, column or index returns a not-ready response.
3. Complete a Paddle sandbox transaction and verify one license is created, one webhook event is recorded, and a failed email remains visible/retryable without issuing a second license.
4. Verify passwordless sign-in, email change, customer session persistence, WordPress site registration, quota reservation and report persistence against a non-production license.
5. Verify outbound PageSpeed, Groq and SMTP calls with controlled test accounts before enabling paid production traffic.

The code and migration files are prepared in this phase. Migration execution, provider secret entry, sandbox/production transactions and live verification remain operator-controlled release activities and are not represented as completed here.
