# SaaS Implementation Master Checklist

**Repository:** `haseeb1984/ecommerce-audit-agent`  
**Active implementation branch:** `feat/hostinger-private-report-storage` at `0d3eaa1c05a03959e31c587c62642157fdb7fe2e` (PR #364, draft/unmerged)  
**Purpose:** Single evidence-based tracker for implementation. This is not a release approval and does not claim production deployment or live-provider acceptance.

## Status rules

- **Implemented / CI verified** — code and relevant automated tests pass on the cited commit.
- **Implemented / verification pending** — code exists, but the latest relevant CI/runtime acceptance has not passed yet.
- **Partial** — useful implementation exists, but agreed scope or acceptance is incomplete.
- **Blocked** — needs production configuration, provider credentials, human approval, or external acceptance.

## Latest automated verification — 2026-11-26
- Follow-up hardening: uninstall now accepts HTTP 404 as an idempotent disconnect only when the JSON `detail` exactly matches the relevant standard/agency "connection not found" response. Generic/misrouted 404s remain failures so the plugin retains its only local revocation credential. Regression test updated; latest CI is pending.

- Current branch head is `0d3eaa1c05a03959e31c587c62642157fdb7fe2e`. CI run [#45872337889](https://github.com/haseeb1984/ecommerce-audit-agent/actions/runs/45872337889) is running; do not mark the new source changes CI-verified until it completes.
- Latest source-only fixes add strict DNS-label validation to both standard WordPress registration and one-time identity-link claims, and make plugin uninstall treat HTTP 404 (already disconnected) as idempotent success for both standard and agency connections. Focused regression tests were added.

- Backend CI run [#45763106471](https://github.com/haseeb1984/ecommerce-audit-agent/actions/runs/45763106471) passed on the exact PR/branch head `0d3eaa1c05a03959e31c587c62642157fdb7fe2e`: **1,536 passed, 216 warnings**. Dependency vulnerability audits and dependency pin/hash verification passed; Python compilation, PHP lint (including the Hostinger storage bridge, WordPress plugin and theme), frontend JavaScript syntax, synthetic PDF generation/upload, and WordPress theme package build/upload passed.
- The exact PR-head Vercel preview is READY at [preview deployment](https://ecommerce-audit-agent-pexnr5ucm-junction-tec.vercel.app). Its read-only `/health-check` returned HTTP 503: Supabase PostgreSQL is connected but lacks `billing_mirror_sync_outbox` and `customer_lifecycle_sync_outbox`; Hostinger MySQL is not configured/connected in that preview. This is environment/schema readiness, not a passing runtime acceptance.
- User confirms the WordPress theme was already uploaded to `https://audit.juncsys.com/`; do not re-upload it. The public site could not be independently fetched in this review, so the URL is recorded as user-reported installation evidence, not independently verified runtime acceptance.
- Real-public-site PDF smoke tests were skipped by the pull-request workflow. No migration, Hostinger deployment, production change, external payment, or real email action was performed.

- Backend CI run [#45375145059](https://github.com/haseeb1984/ecommerce-audit-agent/actions/runs/45375145059) completed successfully for PR #364 at commit `18294acdaeb31619595a5feeb68081c069462f7a`.
- The run reports **1,523 passed, 216 warnings**. Both dependency vulnerability-audit commands reported no known vulnerabilities. Python compilation, PHP lint for the WordPress plugin/storage bridge/marketing theme, embedded frontend JavaScript syntax checks, synthetic PDF generation/upload, and WordPress theme package build/upload all passed.
- The WordPress marketing theme customer-login CTA now derives its `/app` destination from the configured SaaS API origin rather than embedding the Vercel hostname. A regression assertion protects this contract.
- Vercel reported the preview deployment completed for this commit. This is deployment/check status only; it does not establish live WordPress installation or customer journey acceptance.
- Real-public-website PDF smoke tests were skipped because this was a pull-request workflow. Staging database schemas/migrations, SMTP inbox delivery, Paddle sandbox lifecycle, WordPress runtime, worker scheduling and Hostinger private-storage deployment remain separate acceptance gates.
- The scheduled Durable scan worker run [#45334487612](https://github.com/haseeb1984/ecommerce-audit-agent/actions/runs/45334487612) failed before invocation because repository variable `SCAN_WORKER_URL` and repository secret `CRON_SECRET` are not configured. No worker request was sent.

## Read-only Vercel configuration review — 2026-11-24

- The Vercel project environment-variable inventory was inspected with decryption disabled; no secret values were read. The project lists 21 variable names, including `DATABASE_URL`, Paddle, SMTP, `ADMIN_API_KEY`, `GROQ_API_KEY`, and `GOOGLE_PAGESPEED_API_KEY`.
- Required names absent from the Vercel inventory: `HOSTINGER_DATABASE_URL`, `HOSTINGER_STORAGE_BASE_URL`, `HOSTINGER_STORAGE_HMAC_SECRET`, `ACCOUNT_AUTH_SECRET`, `CRON_SECRET`, `PUBLIC_APP_URL`, `EAA_CONTACT_FORM_SECRET`, and `EAA_CONTACT_TO_EMAIL`. `REPORT_RETENTION_DAYS` is also not set; code defaults retention to seven days.
- `PAGE_SPEED_API_KEY` is absent, but `GOOGLE_PAGESPEED_API_KEY` is present and the production-readiness script accepts either name.
- The scan-worker workflow independently confirmed that GitHub repository variable `SCAN_WORKER_URL` and repository secret `CRON_SECRET` are missing. No worker request was sent.
- This inventory proves only that the variable names are absent/present; secret values and provider connectivity were not inspected. Do not infer that listed Paddle, SMTP or database credentials are valid.
- These missing settings block customer passwordless auth, Hostinger operational DB access, private report storage, agency invitation URLs, the WordPress contact form, and scheduled worker operation until configured. No environment variables were changed.

## SaaS product flows

| Requirement area | Current status | Evidence / remaining gate |
|---|---|---|
| Customer authentication and license/API-key scoping | Implemented / verification pending | Account dependencies and cross-license isolation tests exist; passwordless sign-in now bounds each operational/legacy license-identity lookup to two rows while preserving fail-closed ambiguity handling; re-run on latest branch head. |
| Customer profile management | Implemented / verification pending | GET/PATCH profile endpoints exist; email-change ownership collision checks now stream Hostinger identity keys in 500-row batches and query PostgreSQL for any conflicting license without materializing full account identity sets; browser and latest CI acceptance required. |
| Monthly quota and concurrent audit reservations | Implemented / verification pending | Reservation lifecycle exists in `quota.py`; run PostgreSQL-backed concurrency acceptance. |
| Customer usage and audit activity | Implemented / verification pending | Usage/activity endpoints and portal meters exist; latest CI and browser QA required. |
| Customer report history and evidence coverage | Implemented / verification pending | Scoped/paginated history and evidence endpoints exist; generated report quality is a separate final gate. |
| Customer API-key create/list/revoke | Implemented / verification pending | Customer/admin caps, license-first revocation locks, one-time secret handling and stale-selection/session guards are integrated; verify latest CI and PostgreSQL race behavior. |
| Agency admin inventory and tenant detail inspection | Implemented / verification pending | Searchable/paginated inventory, latest-100 website connections per workspace with full counts, bulk suspension cleanup, and sanitized lifecycle audit logging are integrated; latest CI and admin browser acceptance pending. |
| Agency team/workspace lifecycle | Implemented / verification pending | Role changes, invitation/revocation, workspace grants, archive revocation and consistent row-lock ordering are integrated; customer-facing agency usage and client inventory now paginate workspace rows at 100 per page while retaining global quota totals and accumulated client selections; team member inventory now paginates at 100 per page, and workspace grants returned by the API are scoped to currently loaded client pages; saves preserve off-page grants; each client page includes latest WordPress connection health in one page-scoped query rather than triggering one status request per workspace. PostgreSQL concurrency acceptance pending. |
| WordPress connection lifecycle | Implemented / verification pending | Connection health, stale heartbeat visibility, token replacement and archive credential/challenge revocation are integrated; agency workspace archive and disconnect now revoke pending connection challenges with scoped SQL updates instead of loading every challenge row. Browser/plugin acceptance pending. |
| Admin activity and sync operations | Implemented / verification pending | Activity filters, cross-database outbox retries, billing-mirror queue, retry-pressure diagnostics and session-safe controls are integrated; runtime acceptance pending. |
| Customer usage history | Implemented / verification pending | Defensive metadata decoding/redaction and safe customer-portal rendering are integrated; latest CI and browser acceptance pending. |
| Customer/agency/admin session race protection | Implemented / verification pending | Request generations and session guards cover customer connection, billing, devices, agency OTP and admin selection/queue flows; browser race reproduction pending. |
| Plan catalogue and admin package management | Implemented / verification pending | Package CRUD, validation and quota inheritance logic exist; verify DB constraints against a real staging schema. |
| Checkout and subscription provisioning | Implemented / verification pending | Paddle checkout/webhook handlers exist; legacy duplicate-license conflict detection is capped at two rows instead of materializing all matches; sandbox provider acceptance still required. |
| Billing history and billing portal | Implemented / verification pending | Billing-only account ownership allows expired customers to manage billing; Paddle sandbox acceptance pending. |
| Payment webhook idempotency/reconciliation | Implemented / verification pending | Event persistence, cancellation/payment-failure handling and reconciliation exist; stale billing-attention recovery now selects only the latest recovery per affected subscription in each database rather than loading all historical recoveries. Run current CI and sandbox lifecycle acceptance. |
| Admin customer and API-key operations | Implemented / verification pending | Client management, key management and action logs exist; customer-directory license counts are page-batched, cross-database customer totals use constant-memory sorted streams, and account-wide lifecycle actions now stream/lock licenses in 500-row batches. Browser and staging authorization checks pending. |
| Admin operations/health visibility | Implemented / verification pending | Operational event and overview endpoints exist; production schema/configuration acceptance pending. |
| Admin billing and overview scalability | Implemented / verification pending | Payment-event and customer-email union totals use constant-memory sorted streams; overview aggregates are page-scoped, contact selection uses deterministic per-license ranking, and admin overview email search now streams Hostinger license identities in 500-row batches into a temporary PostgreSQL table. Regression tests are committed but not executed; verify on CI and staging data. |
| Email delivery | Implemented / verification pending | Explicit-recipient report delivery and configured sender checks exist; real SMTP inbox delivery requires approved staging credentials. |
| Production schema/configuration readiness | Implemented / verification pending | Read-only readiness script checks PostgreSQL and Hostinger tables/columns/indexes plus application configuration; run against staging with approved environment. |
| Legacy operational-data migration | Implemented / verification pending | `scripts/migrate_operational_data_to_hostinger.py` is dry-run by default and preserves PostgreSQL sources. Ambiguous email-to-license support-note ownership is now skipped and reported separately; run dry-run and reconcile counts in staging before any `--apply`. |
| Durable scan worker scheduling | Implemented / verification pending | GitHub Actions invokes `/internal/scan-worker/run` every five minutes, validates the HTTPS URL and bearer secret visibly, and has a bounded retry window. Verify GitHub/Vercel configuration and run controlled staging acceptance; no live worker invocation has been performed. |
| Durable scan worker lease ownership and recovery | Implemented / verification pending | Worker renewal, completion, retry/failure and defer require a still-live 900-second lease; stale recovery is ordered, bounded to 100 rows and uses `SKIP LOCKED`. Customer lifecycle outbox claims now preserve deterministic per-license event order, including when an older event is deferred. Independent scan slots now isolate unexpected per-slot exceptions so one failed claim cannot hide successful sibling work; a fully failed poll returns an error for scheduler retry. Regression tests were added but not executed; run CI and controlled multi-worker staging acceptance. |
| Deployment, production migration and live-provider verification | Blocked / approval required | No production migration or deployment without explicit approval. |

## Audit engine scope

| Requirement area | Current status | Remaining acceptance |
|---|---|---|
| Safe public URL fetching / SSRF protections | Partial | Re-run current security regression suite; staging egress controls and redirect/DNS behavior remain release gates. |
| Homepage technical audit | Partial | Confirm evidence/status semantics and limitations against representative storefronts. |
| Bounded same-origin crawl and sitemap discovery | Partial | Crawl is deliberately bounded; verify duplicate outcomes, route applicability, and disclose unvisited/JS-rendered pages. |
| Technical SEO and ecommerce schema | Partial | Product/category signals exist; continue schema edge-case coverage and never imply indexing certainty. |
| Performance/mobile signals | Implemented in code / verification pending | Licensed synchronous audits and bulk scan workers invoke the isolated signed Playwright service for bounded rendered viewport/DOM checks. Field Core Web Vitals and INP remain unmeasured; run CI and browser acceptance. |
| Accessibility/ARIA source review | Partial | Source heuristics and bounded rendered-browser signals do not establish WCAG conformance; manual WCAG 2.2 A/AA review remains required. |
| SSL/TLS and transport | Partial | Test coverage exists; production TLS configuration and mixed-content limitations remain. |
| Security/exposure checks | Partial | Passive/bounded checks include CORS review signals and OWASP Top 10:2025 awareness references; this is not full-category testing, exploit validation or certification. Unknown results remain unverified, not passes. |
| CDN dependency advisory lookup | Partial | Bounded OSV lookup exists; source/version gaps and provider error behavior need acceptance. |
| Trust, analytics/pixel and mobile UX diagnostics | Partial | Source trust/pixel signals and bounded rendered mobile checks exist; badge authenticity, payment completion, consent-dependent event delivery and manual review remain unverified. |
| Content quality signals | Partial | Bounded source-text volume and exact duplicate-copy review are implemented; CSS visibility, JS-rendered text, near-duplicates and subjective writing quality are not assessed. |

## Reporting discipline

- Do not publish a single completion percentage until every row has a defined weight and current evidence for its status.
- Report **implementation progress** separately from **CI verification** and **production readiness**.
- A passing CI run does not mean the whole SaaS is production-ready.
- Keep PDF/audit-report presentation refinement for the final phase, as requested.
- Do not deploy, run production migrations, trigger real payments, or run live customer-site audits without explicit approval. Source consolidation PRs may be merged when the requested implementation is complete and checks are reviewed.

## Latest known verification snapshot

- Current `main` baseline: `80d4242d7b9ac4c006d83703292df02d6baf903a`.
- PR [#197](https://github.com/haseeb1984/ecommerce-audit-agent/pull/197) consolidated admin billing session-race protection and regression tests.
- PR [#198](https://github.com/haseeb1984/ecommerce-audit-agent/pull/198) made missing scan-worker scheduler configuration fail visibly and aligned the architecture/runbook with the actual GitHub Actions five-minute schedule.
- PR [#199](https://github.com/haseeb1984/ecommerce-audit-agent/pull/199) made legacy support-note migration tenant-safe: emails tied to multiple license keys are reported as ambiguous and are not copied to an arbitrary customer.
- PR [#200](https://github.com/haseeb1984/ecommerce-audit-agent/pull/200) aligned the scheduler timeout with its bounded retry window, stopped retrying all HTTP errors, and added a scheduler contract test.
- Vercel preview checks were successful on the PR heads for #198, #199 and #200. This is not evidence that Python tests ran. The latest backend CI execution previously failed before runner allocation with zero executed steps; current full-suite CI is still not established.
- No live GitHub worker invocation, staging database migration, Hostinger/Supabase schema acceptance, Paddle sandbox lifecycle, SMTP inbox acceptance, WordPress runtime acceptance, or production deployment was performed.
- PDF/private-storage refinement remains reserved for the final phase.



## Latest implementation baseline — 2026-11-08

- Current `main`: `088da70f973255cd79eabe01c1e11330484a330b`.
- PR #247: agency team OTP request/verification now serialize on the shared per-email login lock; regression coverage added.
- PR #248: expired scan-worker leases cannot be renewed after the persisted lease deadline.
- PR #249: stale scan lease recovery is deterministic, bounded to 100 rows per claim, and nonblocking across competing claimers through `SKIP LOCKED`.
- PR #250: completion, retry/failure and defer paths also enforce active lease expiry, using one strict lease-duration validator.
- The relevant regression tests are committed but have not been executed. Backend workflow runs were unavailable; Vercel preview/deployment status is blocked by its daily deployment-rate limit. Neither is reported as a passing test suite.
- No live worker invocation, production migration, database mutation, external payment/email action, or production deployment was performed. All implementation areas remain subject to CI and controlled staging acceptance.
- PDF/private-storage and final audit-result presentation remain deferred to the final phase.



## Latest admin scalability baseline — 2026-11-08

- Current `main`: `528f54fd9d819a7459b380aad84f0241ed8d4895`.
- PR #252: admin payment-event totals no longer materialize every PostgreSQL and Hostinger event ID in Python sets; the sorted-stream union counter uses constant application memory.
- PR #253: per-license dashboard aggregates are scoped to the visible customer page; latest Hostinger and legacy PostgreSQL billing contacts are selected with deterministic row ranking.
- Regression coverage is committed but not executed. Vercel deployment-rate limiting is not a Python test result; no CI pass is claimed.
- No production customer data, migrations, external billing/email action, or production deployment was touched. PDF/private-storage and final report presentation remain reserved for the final phase.


## Latest customer and agency scalability baseline — 2026-11-08

- Current `main`: `9a4ca72492c27e82d18d5de5b941d5efce730a7e`.
- PR #255: admin customer-directory license counts now use one batched lookup for the current page.
- PR #256: cross-database distinct customer-email totals are counted from sorted streams without materializing all identities in Python.
- PR #257: agency detail limits website connections to the latest 100 per workspace and exposes full counts plus truncation status in the operator console.
- PR #258: agency suspension invalidates sessions, pending login challenges, and invitations using targeted SQL updates rather than unbounded ORM row loading.
- Tests were added/updated but not executed. No CI pass, production data verification, live migration, external provider acceptance, or production deployment is claimed.
- PDF/private-storage and final audit-result presentation remain reserved for the final phase.


## Latest customer-account detail batch — 2026-11-08

- Current `main`: `9a4ca72492c27e82d18d5de5b941d5efce730a7e`.
- PR #260 and #263: linked-license inventory in admin customer detail is paginated at 100 per request with SQL-side deduplicated totals and a Load more control. PR #263 removed the temporary 1,000-key ceiling by streaming all Hostinger identity keys in batches of 500 into a transaction-scoped PostgreSQL temporary table.
- PR #261: support-note identity selection uses SQL `MIN` aggregates across Hostinger and PostgreSQL instead of loading all keys into Python.
- Session/payment/WordPress/support-note sublists still have fixed caps (200/200/100/100) without independent pagination metadata; this is a known follow-up.
- Regression tests were added but not executed. No CI pass, production database verification, migration, external provider acceptance, or production deployment is claimed.
- PDF/private-storage and final audit-result presentation remain reserved for the final phase.


## Latest customer-account detail implementation — 2026-11-08

- Current `main`: `9a4ca72492c27e82d18d5de5b941d5efce730a7e`.
- PR #260: linked-license inventory paginated at 100 per request, with SQL-side deduplicated counts and Load more UI.
- PR #261: support-note identity selection uses database-side minimum-key aggregates rather than loading every key into Python.
- PR #263: all Hostinger customer identity keys are streamed in batches of 500 into a transaction-scoped PostgreSQL temporary table; PostgreSQL combines them with legacy billing identities for exact deduplicated license totals and stable pagination. The earlier 1,000-key cap has been removed.
- The temporary-table/cross-database path has regression contract coverage but tests have not been executed and live MySQL/PostgreSQL runtime acceptance is pending.
- Customer detail sublists remain bounded: sessions 200, billing events 200, WordPress sites 100, support notes 100. Independent pagination/count metadata for these sublists remains follow-up work.
- No CI pass, production database verification, migration, external provider acceptance, or production deployment is claimed. PDF/private-storage and final audit-result presentation remain reserved for the final phase.


### Agency WordPress disconnect hardening

The client-site disconnect endpoint now resolves tenant identity without locking, then serializes mutations in agency → workspace → website order (matching heartbeat, connection-token issuance, archive and suspension). It also consumes any pending connection challenges for that workspace before commit so a token issued concurrently cannot be used to reconnect after the disconnect.


### Admin WordPress disconnect serialization

Admin-initiated customer-site disconnect now locks the canonical PostgreSQL license before the Hostinger installation, matching registration, identity claim and customer disconnect ordering. It also consumes outstanding single-use WordPress identity challenges before the site disconnect commits, preventing a pending claim from reconnecting the site immediately after an operator revokes it.


### Agency suspension revokes WordPress credentials

Suspending a Business agency now disconnects every active client WordPress site, clears its site-token hash, and consumes all outstanding workspace connection challenges in the same Hostinger transaction as team-session/invitation revocation. Reactivating the agency therefore does not restore old plugin credentials; each client site must be explicitly connected again.


## Latest preview readiness diagnostics — 2026-11-24

- Backend CI run [#45377765113](https://github.com/haseeb1984/ecommerce-audit-agent/actions/runs/45377765113) completed successfully for branch `feat/hostinger-private-report-storage`, commit `13e64fa601043356e24320337cc01ef0fed552eb`: **1,524 passed, 216 warnings**. Dependency vulnerability audits, Python compilation, PHP lint, frontend JavaScript syntax, synthetic PDF generation/upload, and WordPress theme packaging passed. Real-public-website PDF smoke tests were skipped by the pull-request workflow.
- The matching Vercel preview deployment is READY: [preview deployment](https://ecommerce-audit-agent-m3hzitjn8-junction-tec.vercel.app). A read-only request to `/health-check` returned HTTP 503 and safely identified two separate blockers: PostgreSQL connects but reports missing tables `billing_mirror_sync_outbox` and `customer_lifecycle_sync_outbox`; Hostinger MySQL is not connected/configured.
- The missing PostgreSQL tables correspond exactly to existing migrations `migrations/20261106_billing_mirror_sync_outbox.sql` and `migrations/20261105_customer_lifecycle_sync_outbox.sql`. The later `migrations/20261121_billing_mirror_recovery.sql` adds the billing mirror recovery watermark/index and is also listed in PR #364's rollout order. These are PostgreSQL migrations; do not run them against Hostinger MySQL.
- No schema was changed, no migration was run, no secret was read, and no production resource was modified. The preview response proves the currently connected PostgreSQL schema is missing the two required tables; it does not establish whether the recovery migration or any other migration is applied.
- Next authorized acceptance: obtain staging/production owner approval and a backup, apply the ordered PostgreSQL migrations to the intended Supabase database and Hostinger MySQL migrations to the separate operational database, configure the missing runtime variables, then recheck health and run the signed private-storage lifecycle tests. Do not treat preview readiness as production release approval.
