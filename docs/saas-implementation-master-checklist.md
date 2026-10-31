# SaaS Implementation Master Checklist

**Repository:** `haseeb1984/ecommerce-audit-agent`  
**Working branch:** `main`  
**Purpose:** Single evidence-based tracker for implementation. This is not a release approval and does not claim production deployment or live-provider acceptance.

## Status rules

- **Implemented / CI verified** — code and relevant automated tests pass on the cited commit.
- **Implemented / verification pending** — code exists, but the latest relevant CI/runtime acceptance has not passed yet.
- **Partial** — useful implementation exists, but agreed scope or acceptance is incomplete.
- **Blocked** — needs production configuration, provider credentials, human approval, or external acceptance.

## SaaS product flows

| Requirement area | Current status | Evidence / remaining gate |
|---|---|---|
| Customer website inventory and background scans | Implemented / verification pending | License-scoped website CRUD/archive, durable scan enqueue/status/history/result APIs, customer portal controls, and admin queue inspection/failed-job retry now use Hostinger operational storage. Hostinger connection/schema initialization and a protected external scheduler are required; staging end-to-end acceptance is pending. |
| Cross-database customer lifecycle and billing synchronization | Implemented / verification pending | Canonical Paddle/admin events now enqueue PostgreSQL outbox records; the worker retries projections into Hostinger. Apply the new PostgreSQL migration and verify retry/idempotency against staging databases. |
| Scheduled worker execution | Partial | A bearer-protected worker endpoint processes one queued scan and reconciles outboxes. No cron schedule is configured in vercel.json; configure an approved external scheduler and verify invocation cadence/recovery. |
| Customer authentication and license/API-key scoping | Implemented / verification pending | Account dependencies and cross-license isolation tests exist; re-run on latest branch head. |
| Customer profile management | Implemented / verification pending | GET/PATCH profile endpoints exist; browser and latest CI acceptance required. |
| Verified customer email identity change | Implemented / verification pending | Rate-limited 30-minute one-time verification, duplicate-address checks, portal controls, and license-scoped billing outbox sync are implemented; SMTP and Hostinger staging acceptance pending. |
| Monthly quota and concurrent audit reservations | Implemented / verification pending | Reservation lifecycle exists in `quota.py`; run PostgreSQL-backed concurrency acceptance. |
| Customer usage and audit activity | Implemented / verification pending | Usage/activity endpoints and portal meters exist; latest CI and browser QA required. |
| Customer report history and evidence coverage | Implemented / verification pending | Scoped/paginated history and evidence endpoints exist; generated report quality is a separate final gate. |
| Customer API-key create/list/revoke | Implemented / verification pending | Customer/admin caps and expired-account recovery paths exist; verify latest CI and PostgreSQL race behavior. |
| Plan catalogue and admin package management | Implemented / verification pending | Package CRUD, validation and quota inheritance logic exist; verify DB constraints against a real staging schema. |
| Checkout and subscription provisioning | Implemented / verification pending | Paddle checkout/webhook handlers exist; sandbox provider acceptance still required. |
| Billing history and billing portal | Implemented / verification pending | Billing-only account ownership allows expired customers to manage billing; Paddle sandbox acceptance pending. |
| Payment webhook idempotency/reconciliation | Implemented / verification pending | Event persistence, cancellation/payment-failure handling and reconciliation exist; run current CI and sandbox lifecycle acceptance. |
| Admin customer and API-key operations | Implemented / verification pending | Client management, key management and action logs exist; browser and staging authorization checks pending. |
| Admin operations/health visibility | Implemented / verification pending | Operational event and overview endpoints exist; production schema/configuration acceptance pending. |
| Email delivery | Implemented / verification pending | Explicit-recipient report delivery and configured sender checks exist; real SMTP inbox delivery requires approved staging credentials. |
| Production schema/configuration readiness | Implemented / verification pending | Read-only readiness script checks required tables/columns/configuration and now critical indexes; run against staging with approved environment. |
| Deployment, production migration and live-provider verification | Blocked / approval required | No production migration or deployment without explicit approval. |

## Audit engine scope

| Requirement area | Current status | Remaining acceptance |
|---|---|---|
| Safe public URL fetching / SSRF protections | Partial | Re-run current security regression suite; staging egress controls and redirect/DNS behavior remain release gates. |
| Homepage technical audit | Partial | Confirm evidence/status semantics and limitations against representative storefronts. |
| Bounded same-origin crawl and sitemap discovery | Partial | Crawl is deliberately bounded; verify duplicate outcomes, route applicability, and disclose unvisited/JS-rendered pages. |
| Technical SEO and ecommerce schema | Partial | Product/category signals exist; continue schema edge-case coverage and never imply indexing certainty. |
| Performance/mobile signals | Partial | Static checks are not rendered browser/Core Web Vitals acceptance; browser test gate remains. |
| Accessibility/ARIA source review | Partial | Source heuristics do not establish WCAG conformance; rendered and JavaScript-generated cases remain. |
| SSL/TLS and transport | Partial | Test coverage exists; production TLS configuration and mixed-content limitations remain. |
| Security/exposure checks | Partial | Passive/bounded checks only; unknown results must remain unverified, not passes. |
| CDN dependency advisory lookup | Partial | Bounded OSV lookup exists; source/version gaps and provider error behavior need acceptance. |
| Trust, analytics/pixel and mobile UX diagnostics | Partial | Source signals exist; runtime payment/trust, event firing/consent and rendered mobile UX are not proven. |

## Reporting discipline

- Do not publish a single completion percentage until every row has a defined weight and current evidence for its status.
- Report **implementation progress** separately from **CI verification** and **production readiness**.
- A passing CI run does not mean the whole SaaS is production-ready.
- Keep PDF/audit-report presentation refinement for the final phase, as requested.
- Do not merge, deploy, run production migrations, trigger real payments, or run live customer-site audits without explicit approval.

## Latest known verification snapshot

- CI run [40791577713](https://github.com/haseeb1984/ecommerce-audit-agent/actions/runs/40791577713) passed on commit `d9430c2949d7ec80eadada868a65f847a3ea708a`, reporting **661 passed** and 55 warnings. This run includes the expanded required-column/index readiness checks and their tests.
- Documentation-only checklist/gap-matrix commits followed that code commit. Staging database/schema verification, provider sandbox journeys, browser QA, and production readiness remain unverified.


## Latest repository implementation batch — 2026-11-01

- Added license-scoped customer website registration, rename, archive, scan enqueue, scan history/status, and scan-result endpoints backed by Hostinger MySQL.
- Added customer portal controls to register storefronts, queue background scans, review recent job state, and inspect a bounded preview of completed findings.
- Added a protected /api/v1/internal/scan-worker entrypoint. It processes at most one scan per invocation and reconciles lifecycle/billing/email outboxes.
- Paddle billing/lifecycle events and admin suspend/reactivate actions now create PostgreSQL outbox records for retryable Hostinger projection.
- Added migrations/20261101_worker_outboxes_and_scan_idempotency.sql for scan idempotency and outbox persistence.
- Added contract/API tests, but the latest Actions jobs have no runner allocation (runner_id=0, steps=[]); no tests are claimed as executed or passed.
- No production migration, Hostinger initialization, external scheduler setup, deployment, live payment, or live website scan was performed.


## Customer identity implementation batch — 2026-11-01

- Added authenticated email-change requests with per-account hourly throttling and a 30-minute single-use verification token.
- Account email remains unchanged until the new address is verified; delivery failures invalidate the issued challenge and return a safe error.
- Added duplicate-email checks across operational customer accounts and customer-portal controls for requesting and confirming the change.
- Verified identity changes enqueue a Hostinger outbox projection scoped to the owning license. The worker updates only that license's PostgreSQL billing events, avoiding cross-account email changes.
- Added additive Hostinger schema initialization and migration `migrations/20261102_hostinger_email_identity_scope.sql`.
- Added API contract tests for unauthenticated requests and invalid input. Full CI execution is pending the current runner jobs; no test pass is claimed yet.
