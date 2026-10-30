# Database and external integration rollout

This phase completes the source-controlled PostgreSQL schema contract and the operator-facing integration setup. It does not connect to or mutate a production database.

## Database migration order

Take a database backup and review every SQL file before applying it. The original `software_licenses`, `api_keys`, and `audit_leads` tables are prerequisites.

For an installation that has not yet received these SaaS feature migrations, apply in this order:

1. `migrations/2026-10-22-audit-reports.sql` — report storage and Paddle webhook idempotency base table.
2. `migrations/20261023_admin_packages_and_actions.sql` — plan catalogue, operation events, admin action log and billing identifiers.
3. `migrations/20261031_admin_customer_lifecycle.sql` — append-only support notes.
4. `migrations/20261031_customer_email_change.sql` — verified email-change challenges.
5. `migrations/20261031_wordpress_sites.sql` — connected WordPress installations.
6. `migrations/20261101_saas_database_integrations.sql` — final additive schema alignment for quota reservations, passwordless account challenges/sessions, all mapped feature tables, billing-period end, indexes, and support-note persistence.

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
