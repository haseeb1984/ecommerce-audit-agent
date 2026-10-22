# Customer workflow and production acceptance

Billing provider: **Paddle Billing**. Stripe is not part of the intended checkout flow.

## Customer journey

1. Customer opens `/app` and chooses a configured plan.
2. Backend creates a Paddle transaction using a server-side `pri_` price ID and redirects to Paddle Checkout.
3. Paddle sends `transaction.completed` to `POST /api/v1/billing/paddle-webhook`.
4. Backend verifies the raw-body `Paddle-Signature` with timestamp tolerance, checks the completed transaction and actual purchased price, and idempotently provisions one license per event.
5. The license key is emailed to the checkout customer's email address using SMTP.
6. Customer enters the license key, runs an audit, downloads the generated PDF, and revisits saved reports and coverage metadata.
7. Customer can explicitly request report email. Listing, PDF download, coverage, and email operations are scoped to the authenticated license.

## Required runtime configuration

Configure values in Vercel environment settings/secret manager. Never commit credentials or print them to logs.

- Database: `DATABASE_URL`, `DATABASE_SSL` and required trusted CA.
- AI/PageSpeed: existing provider settings required by the audit runner.
- Email: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TLS_MODE`.
- Paddle: `PADDLE_ENVIRONMENT=sandbox` for initial testing; `PADDLE_API_KEY`, `PADDLE_WEBHOOK_SECRET`, optional approved `PADDLE_CHECKOUT_URL`, and `PADDLE_PRICE_ID_<PLAN>`. Configure quotas with `LICENSE_MONTHLY_AUDITS_<PLAN>`.
- Create Paddle catalog products/prices and set corresponding price IDs.
- Create a Paddle notification destination at `https://ecommerce-audit-agent.vercel.app/api/v1/billing/paddle-webhook`, subscribe to `transaction.completed`, and store its destination secret as `PADDLE_WEBHOOK_SECRET`.

Checkout remains unavailable until Paddle API key, webhook secret, SMTP host/sender, and at least one valid Paddle price ID are configured. Do not enable production billing before sandbox acceptance.

## Database migration

Apply `migrations/2026-10-22-audit-reports.sql` once to the intended PostgreSQL database using the established deployment approval process. It creates `audit_reports` and `payment_webhook_events`. Test schema creation alone does not prove the production migration was applied.

## Coverage semantics

The API's `category_signal_coverage_pct` is the percentage of required audit categories with at least one recorded finding, not the percentage of individual checks that passed. Categories with no recorded findings are `not_proven`, never silently counted as passes. Google indexing, field Core Web Vitals, full WCAG conformance, complete software composition analysis, verified analytics event delivery, CPC/ROAS, and actual lost revenue require separate authorized data or testing.

## Go-live acceptance checklist

- [ ] Configure Paddle sandbox API key, price IDs, webhook destination secret, and SMTP settings in deployment secrets.
- [ ] Confirm `/api/v1/billing/plans` lists configured plans and the portal starts Paddle Checkout.
- [ ] Complete one sandbox purchase with a controlled test email and verify one license email.
- [ ] Replay the same signed Paddle event and verify no duplicate license is created.
- [ ] Generate a real audit and verify PDF, history row, and coverage manifest are persisted.
- [ ] Verify another license cannot list or download the report.
- [ ] Send a requested PDF to a controlled test inbox and verify delivery.
- [ ] Review latest GitHub Actions results and the generated PDF before enabling production mode.

No production migration, billing activation, or deployment is performed by a source-code change alone.
