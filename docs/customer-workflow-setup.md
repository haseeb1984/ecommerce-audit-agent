# Customer workflow and production acceptance

This backend now includes a lightweight same-origin customer portal at `/app`, hosted checkout-link discovery, Stripe Payment Link webhook handling, license email delivery, PDF persistence, report history, report download, evidence-coverage metadata, and opt-in report email delivery.

## Customer journey

1. Open `/app`.
2. Choose a configured plan and complete Stripe-hosted checkout.
3. Stripe sends a signed checkout event to `POST /api/v1/billing/stripe-webhook`.
4. The backend verifies the timestamped signature, checks that checkout is paid, maps the configured payment-link ID to a plan, provisions one license per event, and emails the key.
5. The customer enters the license key in the portal.
6. The customer runs an audit, downloads the PDF, reviews saved reports and coverage metadata, and can explicitly request a report email.
7. Report listing, download, coverage, and email endpoints scope records to the authenticated license.

## Required runtime configuration

Copy the placeholders in `.env.example` into the deployment's secret/environment settings. Do not commit actual credentials.

- Database: `DATABASE_URL`, `DATABASE_SSL` and the required trusted CA.
- AI/PageSpeed: existing provider settings required by the audit runner.
- Email: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TLS_MODE`. STARTTLS is the default; SSL is available when the provider requires it.
- Billing: `STRIPE_WEBHOOK_SECRET`, plus both `STRIPE_CHECKOUT_URL_<PLAN>` and `STRIPE_PAYMENT_LINK_ID_<PLAN>` for each enabled plan. Monthly quotas are configurable using `LICENSE_MONTHLY_AUDITS_<PLAN>`.
- Create Stripe Payment Links with actual prices and map each link ID to the corresponding environment variable. Configure Stripe to send `checkout.session.completed` and `checkout.session.async_payment_succeeded` events to the deployed `/api/v1/billing/stripe-webhook` endpoint.

If checkout or SMTP settings are absent, the portal intentionally reports checkout as unconfigured and license delivery remains pending; do not advertise purchases as live until a real checkout and recipient-email test passes.

## Database migration

Before enabling the new report-history and payment routes in production, apply `migrations/2026-10-22-audit-reports.sql` once to the correct PostgreSQL database using the established deployment approval process. It creates `audit_reports` and `payment_webhook_events`. The test suite creates the schema from SQLAlchemy metadata, so CI success alone does not mean the production migration has been applied.

## Coverage semantics

The API returns a `coverage` manifest with every saved report. `category_signal_coverage_pct` is the percentage of required audit categories with at least one recorded finding. It is **not** the percentage of all individual checks that passed. Categories with no recorded findings are marked `not_proven`, never silently counted as passes. Google indexing, field Core Web Vitals, full WCAG conformance, complete software composition analysis, verified analytics event delivery, CPC/ROAS, and actual lost revenue require separate authorized data or testing.

## Go-live acceptance checklist

- [ ] Apply the migration to the intended production database.
- [ ] Configure Stripe Payment Links, webhook signing secret, and SMTP values in the platform secret manager.
- [ ] Test one real low-value checkout with an approved test/customer address and verify one license email.
- [ ] Replay the same signed Stripe event and verify no duplicate license is created.
- [ ] Generate a real audit and verify its PDF, history row, and coverage manifest are persisted.
- [ ] Verify another license cannot list or download the report.
- [ ] Send a requested PDF to a controlled test inbox and verify delivery.
- [ ] Confirm the deployed `/app` is reachable, mobile usable, and all API calls remain same-origin.
- [ ] Review the newest GitHub Actions run and its test results before production release.

No production migration, checkout activation, or deployment is performed by a source-code change alone.
