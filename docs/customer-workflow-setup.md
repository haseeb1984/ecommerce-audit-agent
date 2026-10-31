# Customer workflow and production acceptance

Billing provider: **Paddle Billing**. Stripe is not part of the intended checkout flow.

## Customer journey

1. Customer opens `/app` and chooses a configured plan.
2. Backend creates a Paddle transaction using a server-side `pri_` price ID and redirects to Paddle Checkout.
3. Paddle sends `transaction.completed` to `POST /api/v1/billing/paddle-webhook`.
4. Backend verifies the raw-body `Paddle-Signature` with timestamp tolerance, checks the completed transaction and actual purchased price, and idempotently provisions one license per event.
5. The license key is emailed to the checkout customer's email address using SMTP.
6. Customer can connect with the issued license/API key or request passwordless email sign-in. A matching email receives a single-use token that expires in 10 minutes; successful verification creates a 30-day revocable customer session.
7. Customer can run audits, manage storefronts/background scans, download reports, and revisit saved reports and coverage metadata. Customer API access accepts the license key, API key, or `X-Customer-Session`.
8. Customer email changes require a separate 30-minute verification token. Only after confirmation is the operational account email changed and a license-scoped outbox event queued to synchronize billing history.
9. Customer can disconnect from the portal to revoke the current customer session. Customer can still use the issued license/API key if preferred.

## Required runtime configuration

Configure values in Vercel environment settings/secret manager. Never commit credentials or print them to logs.

- Database: `DATABASE_URL`, `DATABASE_SSL` and required trusted CA; `HOSTINGER_DATABASE_URL` using `mysql+asyncmy` and `HOSTINGER_DB_SSL` for operational customer/scan data.
- AI/PageSpeed: existing provider settings required by the audit runner.
- Email: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TLS_MODE`.
- Paddle: `PADDLE_ENVIRONMENT=sandbox` for initial testing; `PADDLE_API_KEY`, `PADDLE_WEBHOOK_SECRET`, optional approved `PADDLE_CHECKOUT_URL`, and `PADDLE_PRICE_ID_<PLAN>`. Configure quotas with `LICENSE_MONTHLY_AUDITS_<PLAN>`.
- Worker: configure `HOSTINGER_DATABASE_URL`, `CRON_SECRET` (or `SCAN_WORKER_SECRET`), and optionally `SCAN_WORKER_MAX_JOBS` / `SCAN_WORKER_POLL_SECONDS`. Run `python worker_service.py` as a persistent process in a managed Python runtime. If that is unavailable, an external scheduler can call `GET /api/v1/internal/scan-worker` with `Authorization: Bearer <configured-value>`; each HTTP call processes at most one queued scan.
- Create Paddle catalog products/prices and set corresponding price IDs.
- Create a Paddle notification destination at `https://ecommerce-audit-agent.vercel.app/api/v1/billing/paddle-webhook`, subscribe to `transaction.completed`, and store its destination secret as `PADDLE_WEBHOOK_SECRET`.

Checkout remains unavailable until Paddle API key, webhook secret, SMTP host/sender, and at least one valid Paddle price ID are configured. Do not enable production billing before sandbox acceptance.

## Database migration

Apply the PostgreSQL migrations in chronological order using the established deployment approval process. This includes `migrations/20261101_worker_outboxes_and_scan_idempotency.sql`, which adds scan-job idempotency and the customer-lifecycle/billing mirror outboxes, and `migrations/20261102_hostinger_email_identity_scope.sql` for existing Hostinger databases. Hostinger operational models and the additive email-outbox scope column are initialized by the protected worker on first invocation. Test schema creation alone does not prove production migrations or Hostinger initialization were applied.

## Coverage semantics

The API's `category_signal_coverage_pct` is the percentage of required audit categories with at least one recorded finding, not the percentage of individual checks that passed. Categories with no recorded findings are `not_proven`, never silently counted as passes. Google indexing, field Core Web Vitals, full WCAG conformance, complete software composition analysis, verified analytics event delivery, CPC/ROAS, and actual lost revenue require separate authorized data or testing.

## Go-live acceptance checklist

- [ ] Configure Paddle sandbox API key, price IDs, webhook destination secret, SMTP settings, Hostinger MySQL connection, and worker scheduler authentication in deployment secrets.
- [ ] Apply the PostgreSQL worker/outbox migration and invoke the protected worker once in staging to initialize Hostinger operational tables.
- [ ] Confirm `/api/v1/billing/plans` lists configured plans and the portal starts Paddle Checkout.
- [ ] Complete one sandbox purchase with a controlled test email and verify one license email.
- [ ] Verify passwordless sign-in token delivery, single-use behavior, expiry, session-authenticated customer API access, and logout revocation.
- [ ] Verify email-change delivery, unverified-email non-mutation, duplicate-address rejection, and license-scoped billing-history synchronization.
- [ ] Replay the same signed Paddle event and verify no duplicate license is created.
- [ ] Generate a real audit and verify PDF, history row, and coverage manifest are persisted.
- [ ] Verify another license cannot list or download the report.
- [ ] Send a requested PDF to a controlled test inbox and verify delivery.
- [ ] Review latest GitHub Actions results and the generated PDF before enabling production mode.

No production migration, billing activation, or deployment is performed by a source-code change alone.
