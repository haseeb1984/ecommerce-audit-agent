# Current Phase Gap Matrix — Ecommerce Audit Agent

**Baseline reviewed:** `main` at `9a4ca72492c27e82d18d5de5b941d5efce730a7e` after the 2026-11-08 admin billing, customer-directory, and agency scalability work. Re-run CI and real-result acceptance before release claims.  
**Purpose:** Record evidence-backed next steps against the existing agreed scope. This is a planning/acceptance document; it does not claim a live production test was run.  
**Operational constraint:** This phase changes application code and documentation only; it does not deploy, alter infrastructure, or run live customer-site audits.

## Status meanings

- **Implemented, verify release:** code/tests exist, but acceptance evidence for the whole production workflow is still needed.
- **Partial:** a limited checker or workflow exists; agreed coverage remains incomplete by design or by implementation.
- **Not established in repository:** current backend files/routes do not demonstrate the feature; inspect connected frontend/product work before assuming no work exists elsewhere.
- **Blocked / hold:** do not proceed until the stated dependency or approval is resolved.

## Latest implementation batch — audit target privacy and validation

- The audit API rejects query-bearing targets with HTTP 422 before quota reservation, lead persistence, or external audit-provider work. This avoids silently changing a user-supplied parameterized URL into a different page while preventing query parameters from reaching downstream providers.
- The lower-level canonical audit URL normalizer removes query strings and fragments from the provider-facing URL as defense in depth.
- Existing regression coverage includes a query-bearing audit target in the pre-quota rejection cases and explicit normalizer assertions that query/fragment values are omitted. Source changes were read back from the branch; a fresh CI run and runtime tests are still pending.
- This does not authorize auditing private/local hosts, expand crawl scope, or imply production verification. No deployment, production migration, live-site audit, or PDF generation was performed.

## Additional repository-only work completed (no deployment or workflow run)

- Customer report history now uses the API's `limit`/`offset` pagination and `total` count, with a load-more control instead of silently stopping at the first 50 records.
- The customer portal refreshes the usage meter after a successful new audit so the quota display does not remain stale.
- Authenticated customer usage, report-list, and evidence-coverage responses now set `Cache-Control: no-store, private` and `Pragma: no-cache`. Stored PDF downloads also set `no-store` and `X-Content-Type-Options: nosniff`.
- Added a focused report-pagination API test and assertions for privacy/cache headers. These new tests are **not executed**; no CI minutes were consumed for these commits.
- One signature-order correction was committed after manual source inspection. Full syntax/runtime validation is still required before these changes can be treated as verified.

## Repository-only work completed without deployments/workflow minutes

- Customer API-key creation now takes a per-license row lock before counting existing keys, preventing concurrent create requests from bypassing the 10-key cap on databases that support row-level locking. This is source-only; concurrency behavior has not been tested, and SQLite does not enforce `FOR UPDATE` semantics.
- Admin-issued API-key creation now also locks the owning license row before counting keys, so customer and operator key-creation paths both enforce the same 10-key cap under concurrent requests on databases with row-level locking. SQLite does not enforce `FOR UPDATE`; concurrency behavior is not tested.
- Updating a plan package now propagates the new monthly allowance only to clients whose current limit still equals the package's previous allowance. This preserves explicit per-client quota overrides made through admin client management instead of silently overwriting every customer's customized limit. Existing clients matching the old package allowance continue to inherit the new default. Source-only; behavior has not been tested against production data.
- Paddle checkout creation now validates the provider-returned checkout URL as HTTPS on a `paddle.com` host/subdomain and rejects embedded URL credentials; it also requires the returned transaction ID to match the expected `txn_` identifier format before exposing the checkout link to the browser. This reduces risk from malformed/unexpected provider responses. Source-only; sandbox checkout was not rerun.
- Creating a plan package no longer updates existing licenses that happen to share its tier identifier. Package creation sets the default for future assignments; existing client entitlements must be changed explicitly through client management or a package update with a known prior default. This prevents legacy/manual quotas from being silently overwritten when a tier is introduced. Source-only; behavior has not been tested against production data.
- Customer API-key revocation now uses a narrowly scoped account-ownership dependency that still authenticates an existing license/API key after license expiry or deactivation. It is used only by `DELETE /api/v1/account/api-keys/{key_id}`; audit/report endpoints retain the normal active-and-unexpired entitlement checks. This closes the account-recovery gap for invalidating a compromised key after expiry. Source-only; authorization regression coverage and runtime behavior remain unverified.
- Customer billing history and Paddle billing-portal session creation now use a separate billing-only account-ownership dependency. Customers can reach billing self-service after license expiry/deactivation, while revoked API keys remain invalid and audit/report endpoints keep their active-and-unexpired entitlement checks. The dependency grants no audit or report access. Source-only; authorization regression coverage and Paddle portal behavior remain unverified.
- Admin payment reconciliation now verifies the returned Paddle transaction ID matches the stored transaction before changing anything, and backfills only missing, format-validated subscription/customer IDs from the authenticated Paddle API response. It does not overwrite existing links or alter license entitlement/payment status; the backfill is recorded in the sanitized admin action log. This can help repair incomplete webhook metadata without repeating a payment. Source-only; provider response shape and workflow remain unverified.


- Corrected an audit-coverage false-positive: general accessibility findings no longer automatically mark the separate ARIA and image-alt categories as observed. Added a regression test requiring those categories to remain `not_proven` unless their own signals/check execution support them. Test is committed but **not executed**.
- Coverage manifests now sanitize the target URL, sampled page URLs, and finding evidence URLs through one helper: query strings/fragments are stripped, credential-bearing URLs and non-HTTP(S) values are excluded, and the page count reflects only retained unique safe URLs. A regression test covers token-like query values, fragments, URL userinfo, and a `javascript:` URL. The test is committed but **not executed**.

- Added an isolated API journey regression test that mocks external audit/network work and checks license-authenticated audit quota consumption, persisted PDF retrieval, history/coverage visibility, cross-license isolation, and explicit-consent email delivery without sending real email. The test is committed but **not executed**; production migration, actual SMTP inbox delivery, live crawl coverage, and full browser QA remain separate acceptance gates.


- Customer portal now displays a license-scoped monthly quota meter and a report-history summary/filter. The browser keeps the entered credential in memory only.
- `GET /api/v1/account/usage` reports monthly limit, completed usage, active reservations, remaining quota, reset date, and license active/expiry metadata; it never returns the license key.
- PDF download object URLs are revoked after a short delay instead of immediately, reducing browser download race conditions.
- Added focused API tests for quota accounting and unauthenticated access. These tests were **added but not executed** because workflow minutes were intentionally conserved.
- These commits use GitHub's `[skip ci]` convention. No Vercel deployment was requested or performed. The latest prior test workflow still needs a future authorized run before these changes can be considered CI-verified.

- Admin package creation/editing now validates the tier slug, display-label length, quota/concurrency bounds, and Paddle `pri_` identifier format in the browser before sending the request; backend validation remains authoritative. This reduces avoidable admin errors but has not been browser-tested.
- Added an explicit admin-console disconnect action that clears the in-memory admin key, client/package/operations/activity/history data, disables authenticated refresh controls, and returns the console to its disconnected state. A failed reconnect also clears previously displayed admin data to avoid leaving a stale sensitive dashboard visible after authentication fails. This is source-reviewed only; browser/session behavior and accessibility have not been tested.
- The admin client overview now displays each account's expiry timestamp (or `No expiry`) alongside its active/inactive/expired status, making entitlement troubleshooting visible without opening each client record. The table empty-state column span was updated to match the new column. Source-reviewed only; browser rendering is not verified.


- The admin overview now aggregates monthly audit counts, all-time audit counts/latest-audit timestamps, saved-report counts, and active reservations in four grouped SQL queries rather than issuing up to four additional queries per client. This removes the overview's per-client N+1 query pattern at source level; query-plan/runtime performance and regression tests remain unverified.

- Added a focused API regression test for the admin overview's per-license usage, all-time audit, report, active-reservation, and last-audit fields. It is committed but deliberately not executed while workflow minutes are being conserved.

- Admin API responses now receive `Cache-Control: no-store, private`, `Pragma: no-cache`, and `X-Content-Type-Options: nosniff` through middleware, including error responses. Admin PDF downloads also declare private no-store headers explicitly. Regression assertions were added for overview and PDF headers; they are committed but not executed under the no-workflow constraint.
- Newly generated comprehensive-audit PDF downloads now also declare `Cache-Control: no-store, private`, `Pragma: no-cache`, and `X-Content-Type-Options: nosniff`, aligning their response policy with saved customer/admin PDF downloads. This is source-reviewed only; the API tests have not been executed.
- The no-store middleware now covers customer account and report API paths as well as admin APIs, so report API error responses receive the same privacy headers. Added assertions to the unauthenticated report-history test; committed but not executed.
- Baseline browser security headers (`nosniff`, frame denial, strict-origin referrer policy, and a restrictive camera/microphone/geolocation permissions policy) are now applied to responses. The customer `/app` and operator `/admin` pages also receive private no-store headers. Added focused portal-header assertions; tests are committed but not executed, and browser compatibility is not yet verified.

## Repository-only work completed — bounded dependency advisory response

- The frontend CDN dependency advisory checker now streams the OSV batch response and stops reading once it exceeds the 1,000,000-byte budget, before JSON parsing. An oversized response is handled as an incomplete/not-tested lookup, never as a clean dependency scan. The regression test covers this path; neither the new test nor the broader suite has been executed in this batch.
- This is a defensive reliability improvement, not full software composition analysis. Lockfiles, bundled/self-hosted assets, server dependencies, and live release acceptance remain open.

## Latest SaaS integration and operational-safety batch — 2026-11-08

- PR #198 is merged: the GitHub Actions scan-worker scheduler no longer silently skips when `SCAN_WORKER_URL` is absent. It validates the HTTPS endpoint and bearer secret before invocation. Architecture and rollout docs now identify GitHub Actions as the five-minute scheduler rather than Vercel Cron.
- PR #199 is merged: legacy support notes are copied only when the billing-event history maps the email to exactly one license. Multi-license email collisions are counted as ambiguous and left in PostgreSQL/uncopied rather than assigned to an arbitrary tenant. The migration remains dry-run by default and does not delete source rows.
- PR #200 is merged: the scheduler timeout now accommodates its bounded curl retry window, and authentication/configuration HTTP failures are not retried indiscriminately. A scheduler contract test was added.
- The migration utility `scripts/migrate_operational_data_to_hostinger.py` already exists on `main`; it was not recreated. Its mapping is limited to the operational records explicitly handled in that script. A dry-run, count reconciliation, schema verification and live migration have not been executed.
- Vercel preview checks were successful for PR heads #198–#200. This is not a Python test-suite result. Backend CI execution remains unestablished because the previously inspected run failed before runner allocation with no test steps.
- No GitHub worker workflow was manually dispatched, no customer scan was triggered, no production credentials or databases were accessed, and no production migration/deployment was performed. PDF/private report storage remains deferred to the final phase.

## Current evidence-backed matrix

| Workstream | Evidence in current repository | Status | Acceptance gate / next action |
|---|---|---|---|
| Vercel infrastructure and Functions Storage | User confirmed Functions Storage is resolved and is no longer a project blocker. A Vercel deployment-rate-limit status may appear on commits; that status is not a Python test result and does not block repository code work. | Not a code-phase blocker | Continue development on `main`. Do not change infrastructure or trigger production deployment without explicit approval. |
| API and database foundation | `main.py` exposes root, `/health-check`, `/api/v1/audit-lead`, and `/api/v1/comprehensive-audit`; SQLAlchemy models cover licenses, API keys, audit leads, and quota reservations. | Implemented, verify release | Verify current production health/configuration only when authorized and without consuming audit quota; confirm required migration is applied. |
| Authentication and quota | `auth.py`, `quota.py`, reservation model/migration, and `tests/test_api.py` cover license/API-key auth, quota exhaustion, failed-run release, and concurrent quota requests. | Implemented, verify release | Confirm production migration and approved, isolated live concurrency test results; clean up test records afterward. Do not use a production license for exploratory tests. |
| Safe target URL fetching / bounded crawl | `audit_checks.py` and `crawl_checks.py` enforce public-address checks, redirect validation, response/time limits, DNS-pinned fetching, same-origin sitemap discovery, a capped recursive HTML-link queue, and explicit findings when the homepage responds with a non-2xx status or non-HTML content. Tests cover homepage HTTP failures (403/404/503), non-HTML responses, same-origin isolation, and bounded discovery. | Partial; error-path reporting improved, release verification pending | Verify nested-link discovery, origin isolation, malformed-link resilience, duplicate URL normalization, and the hard page cap in CI. No claim of complete SSRF immunity or whole-site coverage. |
| Technical SEO and crawl | Homepage signals, bounded same-origin crawl, sitemap expansion, canonical/robots directives, structured-data and hreflang signals exist. Canonical checks flag cross-origin targets for manual review while accepting default-port normalization; bounded discovery inspects up to three robots-declared same-origin sitemap documents; off-origin Sitemap directives are flagged but never fetched. The primary sitemap index now reports missing, malformed, or off-origin child locations and deduplicates equivalent child sitemap URLs before fetching. | Partial | Verify canonical target findings, multi-sitemap discovery, and off-origin Sitemap non-fetch behavior against representative storefronts; preserve explicit crawl/page caps and do not infer Google index status without authorized Search Console data. |
| Performance / Core Web Vitals | PageSpeed mobile Lighthouse score and Speed Index are collected by the existing checker; the live-site PDF QA script now also inspects a real 390px Chromium viewport for horizontal overflow and viewport metadata. Browser requests are intercepted and non-public/failed-DNS destinations are aborted; this is defense-in-depth, not a guarantee against DNS rebinding or a replacement for the pinned HTTP fetcher. It does not claim field Core Web Vitals or browser-rendered LCP/INP/CLS. | Partial / verify release | Run the browser QA workflow and inspect its generated PDFs. Add/verify browser performance metrics and console/network findings; distinguish lab from field data. |
| Accessibility / WCAG / ARIA | `accessibility_checks.py` contains source-level accessible-name, label, language, image-alt, ID-reference, duplicate-ID and `aria-hidden` focusable-element signals. Regression cases cover focusable descendants of hidden containers and nonfocusable decorative content. | Partial / verify release | Run CI and continue rendered accessibility-tree/keyboard checks; never claim WCAG 2.2 A/AA conformance from source checks alone. |
| SSL/TLS and passive security | `security_checks.py` and transport checks observe selected headers, TLS/redirect behavior and a limited set of exposure paths. | Partial | Unknown/unreachable checks remain unverified; validate report wording and coverage. No penetration-test or “fully secure” claim. |
| Target-side dependency advisory check | `dependency_checks.py` checks a bounded set of explicitly versioned frontend CDN scripts against OSV; malformed per-item OSV responses are rejected as `not_tested` rather than treated as a clean scan. Regression tests cover service failure and malformed response shapes. | Partial / verify release | CI must pass on the intended commit; verify bounded requests and PDF rendering. Coverage still excludes lockfiles, bundled/self-hosted assets and server-side dependencies, so this is not full software composition analysis. |
| Trust / pixel / conversion / mobile UX | `trust_checks.py`, `conversion_checks.py`, and `mobile_ux_checks.py` inspect limited source-level cues. | Partial | Test real examples and disclose that detected tags do not prove events, consent behavior, attribution or revenue impact. Checkout tests require explicit authorization and must not place real orders. |
| PDF content and layout | `report_generator.py` and PDF regression tests exist. The completion gate cites a passing 190-test run and a visually inspected synthetic four-page PDF. | Implemented, verify release | Run final QA on a safely obtained real audit result shape; verify evidence, status, limitations, recommendations, optional benefit/risk fields and final disclaimer. Synthetic PDF review alone is not end-to-end acceptance. |
| Report persistence / customer history | `AuditReport` stores PDF bytes, category coverage JSON and finding count; authenticated `/api/v1/reports`, `/pdf`, and `/coverage` routes scope reads to the owning license. The PDF includes the same category-signal manifest. | Implemented in code; production migration pending | Apply `migrations/2026-10-22-audit-reports.sql` only through the approved production migration process; verify ownership isolation against the deployed database. Category-signal coverage is not individual-check pass coverage. |
| Email delivery | Authenticated `POST /api/v1/reports/{id}/email` supports explicit-consent PDF email; Paddle `transaction.completed` webhook provisioning sends license keys through environment-configured SMTP and leaves failed deliveries retryable by Paddle notification replay. User confirmed the sandbox license email arrived and the matching `payment_webhook_events` row reached `delivered`; an earlier Paddle notification still showed HTTP 503, so the exact response path is not conclusively reconciled. | Implemented in code; license email verified once, webhook 503 discrepancy and report-email inbox test remain open | Do not repeat a payment just to retest. Verify the exact Paddle notification response and test report email separately with a controlled recipient. Never log credentials or license keys. |
| Customer-facing frontend / purchase / dashboard | `customer_portal.html` served at `/app` provides configured Paddle plans and transaction checkout, license/API-key entry, audit submission, PDF download, license-scoped history, coverage view and opt-in email. The signed Paddle webhook verifies timestamp/signature and purchased price, then provisions a license idempotently. User confirmed a Paddle Sandbox transaction/subscription and receipt of the license email; the complete audit → saved PDF → history → ownership isolation → report email journey is not yet evidenced end-to-end. | Implemented in code; sandbox purchase and license email verified, full customer workflow and webhook response reconciliation pending | Verify the existing Sandbox transaction/webhook without placing another payment; then complete a licensed audit/report workflow and ownership-isolation check with approved test credentials. Confirm production migration before release. |
| Final release acceptance | Code-level customer workflow and conservative coverage manifest are committed on `main`. User confirmed Paddle Sandbox checkout/subscription, successful license email, and `payment_webhook_events.status=delivered`; one Paddle notification response still showed HTTP 503, and production migration plus the complete audit/report/ownership/email acceptance journey are not yet independently evidenced. | **Release blocked pending CI and complete workflow acceptance** | Verify current CI evidence; confirm the production migration is applied; reconcile the Paddle 503 against the delivered event without repeating payment; test audit, stored PDF, history, license ownership isolation and opt-in report email; request explicit production release approval. |

## Recommended sequence (Vercel infrastructure remains on hold)

1. Continue repository-only work on the single `main` branch; do not deploy or trigger CI/workflows while the user is conserving deployment/workflow allowance.
2. Complete a focused source review of the admin console's account/package/usage controls and reconcile every visible action with an admin-authenticated backend route.
3. Continue license-email recovery acceptance: retry controls now appear in operations diagnostics and client payment history for `email_pending` events with a linked license. Browser behavior, authorization regression tests, and end-to-end delivery still require verification.
4. Review PDF redaction and metadata behavior for every URL-bearing output location. The sanitizer strips userinfo, query strings and fragments, but the added regression test has not been executed.
5. Continue filling audit coverage gaps while preserving the audit-only boundary; never execute remediation against customer sites or imply unmeasured conversion/revenue impact.
6. When testing is authorized, run the targeted unit/API tests first, then the full CI suite and browser QA workflow. Inspect generated PDFs and verify the complete licensed audit → saved PDF → history → ownership isolation → opt-in email journey.
7. Confirm production migrations and reconcile the previously observed Paddle HTTP 503 against the delivered event without placing another payment. Require explicit approval before production deployment or destructive operations.

## Admin SaaS controls — current boundaries

- Existing backend/admin UI covers overview diagnostics, client/license account management, plan package CRUD, usage/history inspection, sanitized admin action history, operational event review, payment-event reconciliation, and admin PDF retrieval.
- Verified Paddle `subscription.canceled` webhooks now deactivate the linked license, emit a sanitized operational event only on the first state change, and return a retryable `503` when the cancellation cannot yet be reconciled to a license. Source-level implementation only; webhook replay, provider payload fixtures, and live subscription cancellation remain untested.
- The license-email retry endpoint is exposed in operations diagnostics and client payment history for events in `email_pending` state when a linked license exists. The controls call the admin-authenticated endpoint, disable themselves during the request, show the returned status, and refresh operations diagnostics. The client-history API now includes the linked license ID in its already license-scoped payment records. Browser behavior and end-to-end email delivery remain untested; active `email_sending` events do not show the retry control.
- Package removal is a soft deactivation to preserve historical references. Package edits can affect quota settings for clients on that tier; these changes should be treated as privileged administrative actions.
- The admin key is entered in the browser and held in page memory, not persisted to browser storage. It must never be included in URLs, application logs, or error details.
- Admin console GET requests now explicitly use browser `cache: "no-store"` for JSON API reads and PDF downloads. After connection succeeds or fails, the password input is cleared; the active key remains only in the page's in-memory variable for the connected session. This is source-level hardening and has not been browser-tested.
- Production readiness remains unproven until targeted tests, CI, migrations, and end-to-end ownership/security acceptance are verified.

## Package entitlement guard — source-level implementation

- The admin client-update endpoint now refuses to assign a package marked inactive in `saas_plan_packages`. Operators must reactivate the package first or select an active package; this avoids creating new entitlements against a deliberately retired package. Existing clients on a subsequently deactivated package are not automatically changed.
- This guard is a source-level change only. No tests have been run and the change has not been deployed.

## Self-service Paddle billing portal — source-level implementation

- Added a nullable `paddle_customer_id` field to the payment-event model and an idempotent migration at `migrations/20261027_paddle_customer_portal.sql`. The migration is committed only; it has not been applied to any database.
- Verified Paddle transaction webhooks now persist the customer reference, and the authenticated account endpoint requests a Paddle portal session scoped to that customer's linked subscription IDs. Returned portal URLs are accepted only over HTTPS on a `paddle.com` subdomain.
- The customer dashboard now offers “Manage subscription & billing” and a billing-history refresh action.
- Release dependency: apply the reviewed migration before deploying code that queries `paddle_customer_id`. Older transactions that predate customer-ID capture may not support portal access until reconciled. No live Paddle portal session or browser behavior has been tested.

## Customer billing history — source-level implementation

- The authenticated `/api/v1/account/billing-history` endpoint is scoped to the verified license and now supports bounded `limit`/`offset` pagination with total count and `has_more` metadata, plus account tier/status/expiry metadata. It does not return recipient email or payment instrument details and sends private no-store headers.
- The customer portal shows event status, transaction/subscription identifiers, and created/updated timestamps, with a Load more control and refresh-from-first-page behavior. Billing data is cleared when account data is reset or credentials change.
- Added API regression coverage for ordering, multiple pages, ownership isolation, authentication, invalid pagination, and no-store headers. Tests are committed but have not been run; browser/runtime behavior and production migration compatibility remain unverified.

## Operator API key lifecycle — source-level implementation

- Added admin-authenticated endpoints to list a client's API-key metadata, create a key with a one-time secret response, and revoke only a key belonging to the client in the URL. Create/revoke actions write sanitized admin audit records and never persist the raw key.
- The operator console's selected-client history panel now exposes key listing, create/copy/hide controls, and reasoned, confirmed revocation. Disconnect clears the displayed secret and client key metadata.
- Source-level implementation only: admin authentication, one-time secret handling, account scoping, concurrency at the 10-key limit, browser behavior, and database compatibility still require the deferred verification phase.

## Customer API key lifecycle — source-level implementation

- Added license-scoped customer endpoints to list API key metadata, create an API key with a one-time secret response, and revoke a key only when it belongs to the authenticated license.
- The customer portal now exposes key creation, refresh, one-time copy/hide controls, and confirmed revocation. Full secrets are not persisted in browser storage or returned by the list endpoint; key metadata is cleared when the customer switches credentials or a reconnect fails.
- A per-account limit of 10 API keys is enforced at creation time. API key management is available to an authenticated license key or API key, so account owners can bootstrap integrations from the license credential.
- Source-level implementation only: no tests or browser verification have been run. Concurrent creation at the key limit, cross-account revocation, and compatibility with the deployed schema still require the planned verification phase.

## Non-negotiable reporting rules

- Audit/finding only: do not implement fixes on customer websites in this phase.
- Do not invent metrics, indexing state, vulnerability coverage, conversion losses, or business impact.
- Distinguish `verified`, `manual_review_required`, and `not_tested` / insufficient evidence.
- Preserve existing license/quota reservation behavior and regression tests.
- No production deploy, database migration, credential rotation, or infrastructure cleanup without the appropriate explicit approval.

- Customer portal clears the previously displayed report list and quota summary when switching credentials, and also clears account data after a failed reconnect, reducing accidental exposure on shared browsers.
- PDF evidence-source URLs are normalized before inclusion; userinfo, query strings, and fragments are omitted so signed links, reset tokens, tracking values, or email-like query data are not embedded in the evidence index. Added a focused helper test. The report target URL, cover metadata, sampled-page list, and evidence index use the same query/fragment-stripping policy.
- These changes are committed on `main` with `[skip ci]`; the new tests remain unexecuted under the no-workflow constraint.
- PDF public-link sanitization now rejects URL userinfo even when the username is empty (for example, `https://@host/`), rather than relying on truthiness of parsed credentials. A regression assertion covers this edge case. Both code and test are committed to `main`; the test has not been run because CI/workflow minutes remain on hold.

- Added an admin-authenticated endpoint to retry a recorded pending license email. It uses a short-lived `email_sending` claim to reject concurrent retries, returns already-delivered events without sending again, resets failures to `email_pending`, records a sanitized admin action on success, and never returns the license key in the API response.
- Admin controls are available in both operations diagnostics and the selected client's payment history for eligible `email_pending` events with a linked license. After a successful retry, diagnostics are refreshed and the client history is refreshed only if that panel was already open; a background refresh failure is reported separately from the email retry result. Source-level presence is verified; browser behavior, auth regression tests, concurrency behavior under load, and actual email delivery remain unverified.

## Latest release verification — 2026-10-23

- Vercel production deployment for commit `74caad9827d301afe3e5f8585baeae479be94205` reached `READY`.
- The most recent successful GitHub Actions run observed before this entry was for commit `e10138735a91335514e915e2a64ef722dad8c3d4`, not the current `main` commit. The current source therefore still requires a fresh full workflow run before it can be considered verified.
- URL evidence privacy regression coverage is present in `tests/test_api.py`; it must be confirmed by the full test suite rather than treated as passed based on source inspection.
- Release acceptance remains incomplete until the latest-commit workflow result and live customer audit/PDF/history/ownership/email-consent journey are reviewed. A `READY` deployment alone does not prove feature correctness.

## Static checker outcome recording — source-level implementation

- The bounded crawler now emits explicit per-page outcome records for standard security headers, header quality, viewport declarations, static performance resource signals, static accessibility signals, and visible trust-signal inventory.
- A successfully executed checker with no findings records `pass`; emitted verified findings record `issue`; review prompts record `warning`; and unavailable checker results remain `not_assessed`. These records use the actual sampled page URL and method description.
- This improves the denominator and check-level coverage evidence without treating the absence of a finding as a pass. It does not replace rendered-browser, manual, authenticated, or external-dataset verification. Source-level change only; no tests have been run.

## Explicitly unassessed verification methods — source-level implementation

- Added `unavailable_checks.py` and wired it into the comprehensive audit pipeline. Each audit now records individual `not_assessed` outcomes for rendered JavaScript DOM comparison, real-browser viewport matrix, browser console/network diagnostics, manual WCAG review, owner-authorized Google Search Console status, backlink/competitor datasets, authorized checkout testing, consent-dependent analytics event verification, active security testing, and trust-mark authenticity review.
- The outcome records carry the exact reason the check was not performed and appear in the same persisted check-outcome/coverage data as other checks. One bounded limitation summary is also added; no missing capability is represented as a pass or as a verified issue.
- This makes the current capability boundary explicit but does not implement a browser runner, connect owner accounts, acquire external SEO datasets, or perform manual/active testing. Those remain separate implementation/authorization gaps. Source changes only; tests, deployment, and migrations have not been run/applied.


## Core HTML document checks — source-level implementation

- Added a bounded parser for sampled HTML pages that records review findings for missing document language, missing explicit character-encoding metadata, missing/duplicate non-empty page titles, and absence of common semantic landmark elements.
- Integrated these findings into the existing same-origin crawl and per-check outcome recording. This improves baseline technical SEO/accessibility signals without claiming rendered behavior or WCAG conformance; HTTP charset headers and runtime DOM changes still need contextual review.
- Added focused regression cases for missing metadata, valid metadata/landmarks, and duplicate titles. Tests are committed but **not run** under the current implementation-first instruction. No deployment or database migration was performed.


## Report evidence workflow — backend, persistence and portals implementation batch

- Added an authenticated administrator endpoint at `/api/v1/admin/reports/{report_id}/evidence` that reads the report's persisted `coverage_json`, validates report existence, restricts evidence kind and pagination, returns explicit recorded outcome counts, sets private no-store headers, and allowlists response fields rather than returning arbitrary stored metadata. No schema change is required because report evidence is already persisted with each `AuditReport`.
- Extended the admin client-history report cards with a bounded outcome preview, explicit state counts, page URL, and evidence excerpt alongside PDF download. The customer report cards now provide a direct `View check outcomes` action as well as findings, using the existing license-scoped paginated evidence endpoint.
- Added API regression coverage for admin authentication, bounded pagination, outcome counts, sensitive-field exclusion, cache headers and missing-report behavior. Tests have **not been run** under the current implementation-first instruction; behavior remains unverified until the planned test phase. No migrations or deployment performed.


## Saved-report evidence resilience — backend and regression coverage

- Centralized defensive parsing of persisted report coverage JSON. Customer coverage, customer evidence pagination, admin evidence previews, and report-card outcome summaries now treat malformed JSON or a non-object JSON payload as unavailable saved metadata rather than raising a server error.
- Added an API regression test covering malformed saved coverage across the customer coverage endpoint, customer paginated evidence endpoint, and admin evidence endpoint. The test is committed but **not run** per the implementation-first instruction.
- This is resilience for legacy/corrupted report metadata; it does not fabricate evidence or pass outcomes. No schema migration, deployment, or test run was performed.


## Saved-report lifecycle phase — bounded evidence and private delivery

- Completed the saved-evidence response boundary for customer and administrator APIs: only approved evidence fields are serialized, strings are bounded and passed through the existing credential/query-string redactor, affected URL arrays are capped, and arbitrary nested metadata is not returned to either portal.
- Malformed non-object entries are excluded from outcome totals and the returned evidence collection so the denominator represents actual saved object records. Explicit recorded outcomes retain their pass/issue/warning/not_assessed/error states; no outcome is inferred from absence.
- The customer report-email endpoint now also sets private no-store response headers. The existing report ownership check, recipient confirmation, email validation, and attachment-size cap remain in place.
- Added API regression coverage for allowlisting, credential/query redaction, malformed outcome entries, customer outcome denominator, and private report-email responses. These tests are committed but **not run** under the current implementation-first instruction. No migrations or deployment performed.
- Phase boundary: this completes the source implementation batch for saved-report evidence access/delivery, not overall SaaS completion. End-to-end acceptance still depends on the later planned verification phase.


## Audit run reproducibility metadata — source implementation batch

- Coverage manifests now carry an audit_run_context object with start/completion timestamps, the public unauthenticated audit scope, the declared user agent, bounded crawl/response/evidence limits, measurement-mode notes, recorded check IDs, explicit outcome-state totals, and the limitation count.
- The metadata is bounded and type-checked before persistence; target/page URLs continue to be normalized without query strings or fragments. This gives saved reports and downstream report rendering a repeatable description of what the run did and did not attempt.
- The context is descriptive, not a claim that every listed limit was reached or that browser/manual/authorized checks ran. Check outcomes remain the source of execution evidence. Regression coverage was added but not run; no deployment or migration was performed.



## Audit module lifecycle and run timestamps — source implementation batch

- The comprehensive-audit orchestration now records a start timestamp before checker execution and records a bounded lifecycle state for core homepage/discovery checks, PageSpeed, bounded crawl, and conversion/paid-traffic checks.
- Each module state is restricted to not_started, running, completed, unavailable, or error. The saved coverage context preserves these statuses separately from findings and check outcomes, so a module-level failure cannot be mistaken for a clean result.
- A regression test covers the module-state allowlist. Tests remain unrun, and no deployment or migration was performed.


## Finding contract traceability — source implementation batch

- Coverage manifests now preserve a bounded, allowlisted finding contract: stable finding/check ID, category, status/severity, source URL with query/fragment removed, evidence and explanation, recommendation, verification steps, standards references, qualitative benefit/risk, effort, and dependencies.
- IDs are deterministic for the same category/title/sanitized source URL. This is source-level traceability, not proof that each field is populated by every checker.
- A focused regression test covers the key contract fields and URL query-secret removal. Tests remain unexecuted; runtime/production acceptance is still pending.



## Finding text redaction — source implementation batch

- Extended the coverage-manifest text boundary to redact bearer credentials, common token/key/password assignments, and query/fragment data embedded in URLs in evidence, explanation, recommendation and related finding text fields.
- Added regression coverage for representative bearer, API-key, URL-query and secret assignment patterns. This is defense-in-depth, not a guarantee against every possible secret format; tests remain unexecuted and deployment is unchanged.



- PageSpeed field-data identifiers and final displayed URLs now pass through a public-URL allowlist that removes query strings/fragments and rejects URL credentials/non-HTTP(S) values. Provider field-data categories are allowlisted before being surfaced. Regression cases added; tests have not been run, and no deployment occurred.

- Follow-up compatibility correction: allow documented PageSpeed overall categories (FAST/AVERAGE/SLOW) separately from field-metric categories (GOOD/NEEDS_IMPROVEMENT/POOR), with regression coverage for both formats.



## Accessibility manual-review checklist — source implementation batch

- Static accessibility inspection now emits a clearly labeled manual-review checklist covering keyboard/focus behavior, contrast, reflow/zoom, contextual image alternatives, dynamic UI and assistive-technology behavior, media alternatives, and representative keyboard/screen-reader shopping journeys.
- The checklist is explicitly marked manual_review_required and states that static source checks do not establish WCAG conformance. It is linked to the W3C WCAG 2.2 reference. Regression coverage was added; tests remain unexecuted and deployment unchanged.


## Conversion form-action evidence redaction — source implementation batch

- Corrected the HTTP form-downgrade finding to rebuild evidence destinations from validated hostname and non-default port instead of echoing the raw URL authority. This prevents embedded username/password userinfo from entering the report and continues to omit query strings.
- Added regression coverage for an HTTP form action containing synthetic userinfo, query token and a non-default port. Tests remain unexecuted; no deployment or migration performed.


## On-page SEO metadata implementation batch — 2026-10-27

- Extended the sampled HTML document checker to detect missing/empty meta descriptions and multiple non-empty description elements.
- Findings are labeled as low-priority manual review, with explicit caveats that search engines may generate alternate snippets and absence alone does not prove a ranking penalty.
- Added regression cases for absent, single valid, and duplicate meta descriptions. Tests are committed but not run, consistent with the implementation-first sequence. No migration or deployment performed.


## On-page metadata follow-through and next bounded SEO batch — 2026-10-27

- Added an advisory source-level finding for meta descriptions longer than 320 characters. The check intentionally uses a conservative threshold for clearly excessive content, labels it informational/manual review, avoids echoing the description into evidence, and explicitly states that length alone does not prove a ranking impact.
- Corrected the existing valid-metadata test fixture to include a description now that absence is checked; added coverage for the long-description advisory and its non-ranking claim.
- The on-page metadata implementation batch now covers missing/empty descriptions, duplicate declarations, and unusually long descriptions. Test cases are committed but not executed; this phase is source-implemented, not runtime-verified. No deployment or migration performed.
- Next phase focus: close remaining core SaaS workflow gaps outside PDF/report styling, then perform integrated tests and fixes after implementation coverage is complete.


## Canonical URL consistency review batch — 2026-10-27

- Added a source-level review finding when a page's valid same-origin canonical points to a different path or query than the inspected URL.
- The finding is low severity and manual-review-only: parameterized and duplicate URLs can legitimately canonicalize to a preferred URL. The checker does not fetch the canonical target or claim that a non-self canonical is automatically wrong.
- Added regression cases for a non-self same-origin canonical and a self-canonical. Tests are committed but not run. No deployment, migration, or production audit performed.


## Sitemap coverage transparency batch — 2026-10-27

- The bounded crawl now explicitly counts discovered sitemap URLs that were not fetched within the shared page budget and records a limitation stating that sitemap inclusion alone does not establish HTTP status, canonical consistency, or indexability.
- Added a bounded integration regression case with more sitemap URLs than the crawler can inspect. The test and implementation are committed but not run. No production site was crawled and no deployment or migration was performed.
- This improves coverage transparency; it does not yet implement exhaustive sitemap URL status validation. Remaining URLs stay explicitly unassessed rather than being presented as checked.

## Core SaaS operator client-management scalability batch — 2026-10-27

- Admin overview now accepts validated `limit` (1–200), `offset`, and bounded `search` parameters. Search covers client display name, tier and numeric license ID; SQL wildcard characters in user input are removed so the search remains literal.
- Client rows are fetched in a bounded database page while platform-wide client totals and active/inactive counts remain global and are not incorrectly reduced to the visible page.
- The operator console now provides server-side search (press Enter), result counts, and previous/next pagination. This replaces the previous behavior that loaded every license into the browser and searched only the currently loaded in-memory collection.
- Added API regression cases for page bounds, literal client-ID search, global summary preservation, and invalid pagination parameters. Tests are committed but not run; no deployment or migration was performed.
- Remaining acceptance: run targeted API tests and browser QA later as part of the full integration verification phase. This is a core SaaS/admin workflow change, not PDF/report presentation work.
## Customer account session cleanup batch — 2026-10-27

- Added an explicit customer-portal disconnect action so shared-browser users can clear account-specific report, quota, billing and API-key data without switching identities first.
- After successful connection, the credential input is cleared from the visible form while the in-memory credential remains available for authenticated requests. On failed connection, the credential is cleared from both the form and in-memory state to avoid a stale failed identity.
- Account-only controls are disabled while disconnected; disconnect also clears the target URL and returns the audit UI to its disconnected state.
- Added a portal regression test for disconnect affordance and credential cleanup behavior. Tests have not been run and no deployment was performed.

## Customer billing recovery and partial account access — 2026-10-27

- Customer account connection now loads billing history independently before attempting audit/report/usage/API-key features. A restricted or expired audit entitlement no longer necessarily blocks the customer from reaching billing management.
- The dashboard reports which account features are unavailable and disables audit/API-key actions unless report history and usage access both load; billing controls remain available after billing authentication succeeds. Credentials are cleared from the visible input after the attempt, and failed overall authentication clears in-memory credentials.
- Added a portal regression assertion for partial-access handling. Tests have not been run and no deployment or migration was performed.
- Remaining release work is still substantial: run the complete test suite, browser acceptance, validate subscription/webhook lifecycle against the existing Sandbox records, confirm production schema migration state, and execute the licensed audit → saved report → ownership isolation → consented email journey before any release approval.

## Subscription cancellation lifecycle regression coverage — 2026-10-27

- Added an integration regression test that provisions a test license from a signed Paddle transaction, applies a signed `subscription.canceled` event to the linked subscription, and verifies repeat delivery remains idempotent.
- Test added; not run in this batch. This is coverage, not confirmation of live Paddle configuration or production readiness. Remaining release gate: execute full CI/test suite, verify migration/schema state and sandbox event mappings, then perform browser-based customer/admin acceptance before deployment.


## Production operations diagnostics — 2026-10-27

- Admin operations diagnostics now validate SMTP configuration completeness rather than checking only host and sender. They flag invalid ports, unsupported TLS modes, and incomplete username/password pairs without returning secret values.
- Added focused regression tests for missing configuration, invalid settings, and a valid STARTTLS setup. Tests have not been executed in this batch; live SMTP delivery and provider connectivity remain unverified.
- No production environment variables, database migrations, or deployment settings were changed.

- Operator console now displays the specific non-secret SMTP configuration issues returned by the diagnostics endpoint, rather than showing only a generic missing/configured state.


## Audit target validation phase — 2026-10-27

- Added a shared target-normalization gate before calling PageSpeed: only HTTP(S) URL input is accepted, embedded credentials/query/fragment/custom ports are rejected, local/private IP literals and common local hostnames are blocked, and internationalized hostnames are canonicalized.
- Audit requests now pass the normalized URL to PageSpeed instead of naïvely concatenating arbitrary input into a URL. This is a defense-in-depth input gate, not a claim of complete DNS-rebinding/SSRF protection for a future direct crawler; DNS resolution and redirect-safe fetching remain required before implementing direct crawling.
- Added parameterized positive and negative regression coverage. Tests are not run in this implementation batch; do not treat this as release verified.


## Licensed audit entry-point validation — 2026-10-27

- The legacy `/api/v1/audit-lead` endpoint now applies the same bounded public-target normalization used by the comprehensive audit before reserving quota or calling external providers. Invalid targets return HTTP 422 without creating an audit lead or quota reservation.
- Added API-level regression coverage for local/private addresses, URL userinfo, query strings, and custom ports, including assertions that rejected requests do not reserve quota or persist leads.
- This closes a gap at the older API boundary; it does not replace the DNS-pinned resolver and redirect checks used by the bounded crawler. Tests have not been run in this batch; no production data or deployment was changed.


## Paddle recurring-payment account continuity batch — 2026-10-27

- Completed subscription-linked recurring transaction handling in the webhook: when a verified completed transaction belongs to an already provisioned subscription, the existing license is reused and its active status and plan allowance are refreshed from the server-managed price catalogue.
- Recurring renewals are recorded as delivered billing events without sending the original license secret again. This prevents a new license and duplicate credential email for each new recurring transaction ID.
- Added a regression journey covering initial purchase, a separate renewal transaction, duplicate webhook delivery, account count, event history and no repeat credential email.
- Tests are committed but have not been executed. Paddle sandbox renewal payloads and production event ordering still require verification before release; no deployment, environment change or migration was performed.

## Paddle subscription lifecycle consistency — implementation batch

- Renewal and cancellation handlers now take the same PostgreSQL transaction-scoped advisory lock keyed by subscription ID, serializing these two lifecycle transitions.
- Applying a verified cancellation records a sticky `subscription_canceled` state on the linked subscription event and deactivates the linked license. A delayed or replayed `transaction.completed` event for that subscription is acknowledged without reactivating the license or issuing another license.
- Added regression coverage for the ordering case: purchase → cancellation → late renewal; the test asserts the license remains inactive and no renewal event is recorded.
- This is source-level implementation only. The new regression test has not been run, Paddle sandbox event ordering has not been exercised, and the advisory-lock behavior assumes the production PostgreSQL database. A legitimate subscription resumption must be handled through a separately verified lifecycle/reconciliation flow; payment completion alone is not treated as proof of resumption. No deployment, migration, or infrastructure change was performed.

## Paddle cancellation history integrity — implementation batch

- Cancellation webhooks now create their own idempotent billing-event row instead of overwriting the original purchase/renewal event status. Customer billing history can distinguish a successfully delivered payment event from the later subscription cancellation.
- Repeated delivery of the same cancellation event ID returns the existing canceled state without creating a duplicate record. Cancellation remains the latest subscription lifecycle event, so a late `transaction.completed` event cannot reactivate access.
- Regression coverage now asserts that a purchase remains `delivered`, cancellation is separately recorded as `subscription_canceled`, and a late renewal leaves the license inactive.
- Source-level implementation and tests are committed; tests have not been executed. Sandbox payload/order verification, production migration checks, full customer workflow acceptance, and deployment remain pending. No database migration or deployment was performed.



## Source-level link destination review — 2026-10-27

- The homepage HTML checker now reviews a bounded sample of up to 500 anchor destinations without fetching external URLs. It reports counts for script/data/file schemes, HTTP(S) URLs containing embedded credentials, and malformed/unsupported schemes.
- Raw destination strings are intentionally excluded from evidence so credentials and query tokens are not copied into findings. Ordinary external-link availability/status is still not checked, and browser-driven navigation behavior remains outside this source-only check.
- Added a regression test for a JavaScript URL and a credential/query-bearing external URL. Test is committed but has not been run; no deployment or migration was performed.


## New-tab link opener isolation — 2026-10-27

- Homepage source inspection now retains a bounded set of up to 500 anchor attributes and reports links using `target="_blank"` without an explicit `rel="noopener"` or `rel="noreferrer"` token.
- The result is intentionally low-severity manual review: modern browsers commonly imply noopener behavior, so this is not treated as proof of an exploitable vulnerability. Destinations are not included in the evidence.
- Added parameterized regression coverage for missing rel, unrelated rel, noopener, noreferrer, and combined rel tokens. Tests are committed but have not been run; deployment and database migration remain untouched.


## 100% completion acceptance gate — 2026-10-27

A 100% completion claim is withheld until every applicable requirement below has implementation evidence and the release gates are satisfied. A source-code commit or the existence of a test is not a passing test result.

| Gate | Required evidence | Current status |
|---|---|---|
| Requirement traceability | Every requirement in `comprehensive-audit-requirements.md` mapped to implementation, test, limitation, or an explicitly approved out-of-scope decision | Open; existing matrix is partial and not a line-by-line acceptance trace |
| Backend and database | API contract tests, persistence/ownership isolation, quota reserve/release, migration compatibility and rollback plan | Code exists; full integrated acceptance and production migration confirmation pending |
| Billing lifecycle | Sandbox webhook signature/idempotency, cancellation/renewal ordering, payment failure/recovery, portal and customer entitlement tests | Source and selected regression tests exist; complete sandbox event-path reconciliation pending |
| Customer/admin UX | Login/account access, audit submission, usage, report history, evidence coverage, PDF download/email, admin search/pagination and authorization | Features exist; complete cross-role end-to-end acceptance pending |
| Audit engine | Each module's check IDs, evidence provenance, unavailable/error classification, crawl caps, redirect/DNS safeguards and module-isolation tests | Partial; full module-by-module acceptance pending |
| Report/PDF | Evidence fidelity, category/check coverage, limitations, reproducible metadata, rendering and download ownership | PDF code/tests exist; final real-result report QA intentionally deferred until the end |
| Automated verification | Intended commit's Python suite and relevant static/build checks pass with recorded output | **Not established**; recent changes have committed tests but no fresh test run is evidenced |
| Deployment readiness | Required environment/configuration, production migration confirmation, webhook response reconciliation, monitored release and explicit user approval | Blocked/pending; no deployment performed |

### Immediate next sequence

1. Establish an executable test environment against the latest `main` revision without deploying production or running migrations.
2. Run the full test suite and relevant static/build checks; fix failures before adding unrelated features.
3. Turn every requirement into a traceable pass/partial/not-tested acceptance row, including limitations that cannot safely be automated.
4. Close backend, billing, database, customer and admin workflow gaps in coherent implementation batches, with regression tests for each batch.
5. Complete audit-module acceptance and only then do the final PDF/report review.
6. Claim 100% implementation only when all in-scope requirement rows pass code/test acceptance. Keep production rollout readiness as a separate gate requiring approved environment/migration and live-workflow evidence.

No deployment, database migration, payment, or production-site audit was run as part of this checklist update.


## Bounded homepage anchor retention — 2026-10-28

- The HTML parser now retains at most 500 anchor href values as well as at most 500 anchor attribute records. It still counts all anchors, so link-count reporting is not silently truncated.
- The cap matches existing homepage source-review and crawl-discovery limits; anchors beyond the retained window do not affect these bounded checks.
- Added a regression test with 750 links to assert total counting and bounded retained state.
- Verification status: source/test committed only; this new test and the full suite have not yet been executed in a clean environment.


## llms.txt check-level coverage — implementation batch

- The bounded crawl now records an individual `llms_txt.basic_format` check outcome alongside findings. A same-origin HTTP response is classified through the existing conservative outcome recorder; an off-origin redirect is recorded as `not_assessed`, and fetch exceptions are recorded as `error`.
- Added a crawl regression test for the optional file being absent (HTTP 404), asserting that the check outcome and finding are both present. The test is committed but has **not been executed**.
- This is a proposed convention/basic-format check only. It does not imply ranking value, indexing control, or AI crawler usage. No deployment, migration, or workflow run was performed.


## Robots.txt discovery outcome lifecycle — feature batch

- The bounded crawl now records the `robots_txt.discovery_rules` check outcome alongside existing robots findings and sitemap discovery.
- Successful same-origin responses are classified using the existing static outcome recorder. Access-denied responses and non-success responses are explicitly marked `not_assessed`; server errors and fetch exceptions are marked `error`; successful HTTP responses redirected off-origin are not assessed.
- Added parametrized regression coverage for HTTP 200, 403, 404, and 500. Tests are committed but **not yet executed**.
- This is source-level directive analysis only; it does not prove search-engine behavior or live indexing status. No deployment or database migration was performed.

## Sitemap-listed page HTTP status evidence — implementation batch

- The bounded crawl now retains sitemap provenance for URLs that make it into the capped page sample and emits `sitemap.discovered_url_status` outcomes for those URLs.
- Sampled sitemap URLs returning 4xx are recorded as issues, 5xx/fetch failures as errors, successful same-origin responses as passes, and off-origin redirects as not assessed. The outcome explicitly distinguishes HTTP reachability from search-engine indexing.
- Added a regression test for a sitemap-listed URL returning HTTP 404, checking both the finding and check-level outcome. Test is committed but has not been run.
- Scope remains bounded by the existing page cap; URLs beyond the sampled crawl budget are not individually tested. No deployment or database migration was performed.


## Sitemap URL reachability outcome regression coverage — extension batch

- Extended the sitemap-listed URL lifecycle tests to cover successful same-origin responses, HTTP 503 server failures, off-origin redirects, and fetch timeouts in addition to the existing HTTP 404 case.
- Expected outcomes remain conservative: 2xx same-origin is a reachability pass only (not proof of indexing), 5xx/fetch exceptions are errors, and off-origin redirects are not assessed.
- Regression tests have been committed but have **not been executed** in this session. No production crawl, migration, deployment, or PDF/report-layout work was performed.


## Database schema readiness endpoint — implementation batch

- Extended /health-check beyond a SELECT 1 connectivity probe: it now checks the current schema for the nine application tables used by licensing, API keys, audit lifecycle, plans, operations, and payment events.
- A connected database with missing required tables returns HTTP 503 with schema_ready: false and a bounded list of missing table names; database connectivity failures remain HTTP 500 and do not expose connection details.
- Updated the existing health endpoint regression assertion for the successful readiness response. This does not prove that every migration has been applied or that columns/indexes match the latest migration files; those checks remain open. The tests have not been executed in this session.

- Added a direct endpoint regression test with a deliberately incomplete schema response to assert HTTP 503, explicit not-ready status, and missing-table reporting. The test is committed but remains unexecuted pending CI evidence.

## Database schema readiness — column compatibility extension

- The health-check endpoint now compares every mapped column required by the nine application tables against information_schema.columns, after checking connectivity and table presence. A connected database with missing mapped columns returns HTTP 503 and names missing table/column metadata without returning connection strings or raw database errors.
- Added a focused regression test that supplies all required tables but omits software_licenses.license_key, and asserts the endpoint reports the exact missing column. The earlier missing-table test remains in place.
- This check verifies table and mapped-column presence only; it does not validate SQL types, nullability, indexes, constraints, migration ordering, or data correctness. Tests have not been executed, so the change is source-level until the suite runs.

### Audit-engine branch — robots.txt crawl-policy enforcement

- Added a bounded robots.txt rule parser for the crawler's own product token and wildcard group, including Allow/Disallow precedence by longest matching path, wildcard patterns, query matching, and end-of-pattern anchors.
- Both sitemap/homepage-discovered candidate pages and subsequently discovered internal links are filtered against applicable robots rules.
- If robots.txt returns a server error, redirects off-origin, or cannot be fetched, additional page crawling is conservatively stopped rather than assuming permission.
- Added focused unit cases for blocked/allowed paths, more-specific Allow rules, wildcard query patterns, and crawler-specific groups.
- Regression tests have not been executed. The homepage is still fetched as the explicitly requested audit target; robots policy controls additional page crawling. Passive exposure probes now use the same robots path filter, with a focused test that disallowed probes are skipped. Full RFC edge-case conformance remains a review item.

### Billing branch — payment-failure lifecycle visibility

- The verified Paddle webhook now persists `transaction.payment_failed` and `subscription.past_due` events against the linked license, so customer billing history and operator event history can show failures instead of silently ignoring them.
- Duplicate event IDs are idempotent. A failure event that cannot yet be linked to a provisioned subscription returns retryable HTTP 503 rather than acknowledging and losing the event.
- A single failed transaction is recorded but does not automatically deactivate the license; Paddle's retry/dunning policy remains authoritative.
- Added a regression test for payment-failure persistence, duplicate delivery and license access continuity. Tests have not been run.

### Customer branch — expired-account API key recovery

- The API-key list endpoint now uses the narrowly scoped account-ownership dependency already used for revocation. It allows an expired/inactive account to view key metadata and revoke compromised keys without granting audit/report access or returning stored key secrets.
- The customer portal keeps key-list refresh available when audit usage/report access is expired, while key creation remains disabled unless normal audit access is available.
- Added an API regression test covering list → revoke → empty list for an expired, inactive license. Tests have not been run.

### Admin branch — bounded payment event queue

- Added a protected `/api/v1/admin/payment-events` endpoint with bounded limit/offset pagination and exact status filtering. Response fields are allowlisted to event/lifecycle identifiers and timestamps; customer email and license secrets are not returned.
- Added an operator-console queue with status filtering, paging, reconciliation and pending license-email retry actions.
- Added API regression coverage for pagination, filtering, validation and response minimization. Tests have not been run.


## Administrator activity history — implementation batch

- `GET /api/v1/admin/actions` now supports bounded `limit`/`offset` pagination, total count, and `has_more`, retaining newest-first deterministic ordering by creation timestamp and ID.
- The operator console now supports Load more activity and clears its pagination state when disconnecting, alongside the existing refresh behavior.
- Added regression coverage for page ordering, pagination metadata, unauthenticated requests, invalid pagination values, and private no-store response headers.
- Hardened legacy activity-log reads: malformed JSON and non-object payloads no longer break the entire page; stored detail values are re-sanitized before returning to the operator console.
- Added regression coverage for malformed legacy details and secret-key redaction. Tests have not been executed; this is source-level implementation, not release acceptance.


## Report evidence pagination hardening — implementation batch

- Customer and administrator saved-evidence endpoints now cap `offset` at 10,000,000, matching the other paginated SaaS endpoints and rejecting unbounded integer offsets at request validation.
- Added regression assertions for oversized offsets on both endpoint families. Tests have not been executed; implementation remains unverified until the suite/CI is run.


## Per-page audit outcome applicability — implementation batch (2026-10-28)

- Added an explicit `technical_seo.meta_refresh` outcome for each successfully inspected HTML page, including a pass only when the static source check completed without a signal.
- Corrected the generic outcome recorder so product structured-data, catalog navigation, and hreflang outcomes are only emitted when the URL/source makes those checks applicable; homepage-only checks no longer imply product/catalog checks passed.
- Added a focused crawl regression test for outcome presence and non-applicable check suppression. Tests have not been executed; this remains source-level implementation pending CI and representative audit acceptance.



## Audit evidence URL privacy hardening — 2026-10-28

- Persisted audit metadata URLs now reject loopback, private, link-local, reserved/non-global IP literals and local/test-only hostnames, in addition to rejecting credentials and non-HTTP(S) schemes.
- Public HTTP(S) metadata URLs still have query strings and fragments removed before persistence, and default ports remain normalized.
- Added regression cases for common private IPv4/IPv6 targets, cloud metadata IPs, local hostnames, and public URL normalization/redaction.
- Source and tests are committed; the tests have not been executed. This is a metadata-safety boundary, not a substitute for the crawler's DNS-pinned fetch and redirect checks. No deployment, migration, live crawl, or PDF work was performed.


## Coverage-manifest evidence URL privacy — 2026-10-28

- The coverage manifest now applies the same private/non-public host exclusion used by persisted audit metadata: loopback, non-global IP literals, and local/internal/test-only hostnames are excluded from target URLs, sampled page URLs, and page-scoped outcome summaries.
- Public URL query strings and fragments continue to be removed; public IPv6 literals remain supported.
- Added regression coverage for local/private hosts and safe public-page retention. Tests are committed but have not been executed.
- This is evidence-output hygiene only. It does not replace crawler-side DNS resolution, redirect validation, or network egress controls.


## Payment webhook schema alignment — implementation batch (2026-10-28)

- Updated the existing report-history migration to add the current payment webhook transaction, subscription, and Paddle customer identifier columns with idempotent `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` statements. This matters because `CREATE TABLE IF NOT EXISTS` alone does not update an already-created table.
- Added idempotent indexes for those three identifiers to align with the SQLAlchemy model.
- Source-to-model checks were performed by re-reading both files. SQL has **not** been applied to production, and database integration tests have not been run. Apply only through the approved migration process.


## Subscription cancellation ordering hardening — 2026-10-28

- Hardened the completed-transaction handler to check for any recorded `subscription_canceled` event for the subscription, rather than relying only on whichever lifecycle event has the latest timestamp.
- This closes an ordering gap where a payment-failure or `past_due` event delivered after cancellation could become the newest record and hide the cancellation guard from a later delayed `transaction.completed` event.
- Added a regression journey for purchase → cancellation → payment failure → late completed transaction. It asserts that the failure remains visible in billing history, the late transaction is not recorded as a renewal, and the license remains inactive.
- Source edits and regression coverage are committed. The test has not been executed in this environment; Paddle sandbox ordering, PostgreSQL concurrency behavior, full suite results, schema migration state, and customer/admin end-to-end acceptance remain pending. No production migration, deployment, or infrastructure change was performed.


## Customer billing-history privacy regression coverage — 2026-10-28

- Strengthened the billing-history pagination/ownership test so it checks the exact seeded foreign-account event ID, transaction identifier, and email are absent from the authenticated customer's response.
- Added explicit allowlist assertions that customer billing-history items omit recipient email and Paddle customer ID; the API response remains scoped to the authenticated license and retains private no-store caching.
- This batch tightens regression coverage around an existing backend security boundary; it does not change the customer API contract. The tests have not been executed, so assertions are source-reviewed only. Full suite, browser acceptance, and production readiness remain pending.

## Customer portal identity-switch race guard — implementation batch (2026-10-28)

- Authenticated customer-portal requests now capture an account-session generation before sending the request and reject late responses if the user starts another connection attempt or disconnects before the response returns.
- This prevents an in-flight response for a prior credential from repopulating saved reports, activity, usage, billing, or API-key UI after account data was cleared or another identity was selected.
- The source was committed and read back from the feature branch. Browser-level race reproduction and automated JavaScript tests have not been run; complete customer workflow acceptance remains pending. No database migration, production audit, PDF/report refinement, or deployment was performed.

## Customer + administrator portal session-race hardening — multi-gap batch (2026-10-28)

- Customer portal: authenticated API requests now validate the account-session generation after response arrival and after asynchronous JSON/PDF-body parsing. This blocks late account data from rendering after a connect/disconnect, and blocks an old audit PDF from being downloaded after the user switches accounts mid-response.
- Customer portal: obsolete connection attempts no longer clear a newer session's credential/state or re-enable the Connect button while a newer attempt is still active. Empty credential submissions do not invalidate an in-progress session.
- Administrator portal: the shared API helper checks the administrator-session generation after response parsing; connect attempts are generation-scoped, and disconnect/clear invalidates pending requests. Obsolete connect failures no longer clear a newer administrator session.
- Code changes were committed and read back from the feature branch. Browser-based race reproduction and JavaScript syntax/runtime checks have not been executed. Some administrator action handlers use direct fetch calls outside the shared API helper and remain a separate review item; full admin workflow acceptance is still pending. No deployment, database migration, production audit, or PDF/report refinement was performed.



## Full administrator action session isolation + API-key lifecycle acceptance coverage — 2026-10-28

- The operator console now routes all direct request paths (client edits, package changes, payment reconciliation/email retry, report PDF/evidence downloads, and client API-key management) through a generation-guarded fetch wrapper, not only requests using the shared JSON API helper.
- The wrapper rejects responses when the administrator disconnects or starts a different connection attempt, and re-checks session identity after JSON, text, or PDF blob parsing and before evaluating response success. This prevents a delayed response from an old admin session from being treated as current.
- Added API regression coverage for the complete admin-issued API-key lifecycle: create once-only secret, no-store response, metadata-only listing, foreign-client revoke rejection, successful scoped revoke, empty post-revoke listing, audit-log entries, and secret absence from audit details.
- Source files were committed and read back. The Python suite and browser-based session-race tests have **not** been executed in this environment; the new test remains unverified until CI runs. This batch does not imply full SaaS completion or production readiness.
- Remaining broad gates: line-by-line requirement traceability, integrated customer audit-to-report/email journey, complete audit-module acceptance, current full-suite/static/browser verification, migration readiness, and deployment approval. PDF/report refinement remains intentionally reserved for the final phase; no deployment, migration, or live customer-site audit was run.

## Latest implementation batch — checkout redirect hardening

- Customer plan loading now uses no-store fetches, validates the plans payload before replacing the existing view, builds the updated plan list off-DOM, and shows a controlled fallback for malformed/empty responses rather than partially rendering data.
- The customer checkout flow now handles non-JSON error responses, validates the returned checkout URL as HTTPS on the exact `paddle.com` domain or a true subdomain, and rejects credentials or non-Paddle destinations before browser navigation.
- Regression tests cover malicious checkout destinations including lookalike domains, embedded credentials, HTTP, and JavaScript URLs; the existing positive test continues to assert that checkout uses the server-configured price rather than client-supplied amounts.
- Source changes committed on `integration/saas-feature-batch`: customer portal `6e3c8a6`; checkout destination regression tests `ee6c6ec`.
- Verification status: source readback and diff intent checked through GitHub. A fresh GitHub Actions run has not been produced for this branch update, so these new tests are **not yet reported as executed**. Vercel remains out of scope because its build quota is exhausted. PDF generation/report refinement remains deferred to the final phase.

## Latest implementation batch — shared Paddle redirect validation

- Extracted a shared backend URL validator for Paddle-hosted checkout and customer billing-portal links. It requires a trimmed HTTPS URL, validates malformed port syntax, rejects embedded username/password credentials, normalizes hostname case, and accepts only `paddle.com` or a true subdomain.
- Checkout creation and self-service billing portal now use the same policy, closing the previous inconsistency where the portal URL accepted embedded credentials.
- Added parametrized regression coverage for valid Paddle URLs, mixed-case hostnames, lookalike domains, embedded credentials, HTTP, JavaScript URLs, malformed ports, whitespace, and non-string values.
- Source commits on `integration/saas-feature-batch`: backend `dd6d4db`; tests `35f6516`.
- Verification status: changes are committed and the files were read back from GitHub. No fresh Actions run has been returned for this branch update, so the new tests are not claimed as executed. PDF/report refinements remain deferred until the final phase.


## Latest implementation batch — bounded report-email input

- The customer saved-report email request now constrains recipient email input to 3–254 characters at request-model validation, before report lookup and SMTP work. Existing route-level syntax validation and explicit recipient confirmation remain in place.
- Added parameterized API regression cases for empty, too-short, and overlong recipient values; these assert HTTP 422 and no SMTP invocation. Source changes are committed, but a fresh GitHub Actions run/runtime verification is still pending. PDF generation/refinement remains deferred to the final phase.


## Latest implementation batch — customer API-key cap regression coverage

- Added an API-level regression test that seeds ten keys for one license, attempts an eleventh through the customer endpoint, expects HTTP 409, and confirms the database still contains exactly ten keys.
- The existing creation path uses a per-license row lock on databases supporting row locks before counting and inserting, protecting the cap against simultaneous requests in production PostgreSQL.
- Verification in this batch is source/test review and GitHub readback only. The test has been added but **has not been executed** because no fresh GitHub Actions run is available for the latest branch changes. Vercel is not used. PDF/report refinement remains deferred to the final phase.


## Latest implementation batch — admin-issued API-key cap coverage

- Added a matching regression test for the administrator API-key creation endpoint: with ten existing keys for a customer, a new admin-issued key must return HTTP 409 and the database must remain at ten keys.
- This covers the second entry point to the same account key limit; the backend already serializes admin key creation on the customer license row and records creation/revocation in the admin action log.
- GitHub source and test changes are reviewed/read back, but this new test is not claimed as executed: no fresh Actions run is available for the latest branch. Vercel is not used. PDF/report refinement remains deferred.



## Checkout launch URL cache protection — implementation batch (2026-10-28)

- The shared response-security middleware now applies `Cache-Control: no-store, private` and `Pragma: no-cache` to the Paddle `/checkout` launch page as well as the authenticated customer/admin/report surfaces.
- This matters because checkout launch URLs can contain a short-lived Paddle transaction identifier in the query string; the browser should not retain the launch response in a reusable cache.
- Extended the existing browser-security-header API regression test to cover `/checkout?_ptxn=...` alongside customer and administrator portal pages.
- Source and regression test are committed and read back from the feature branch. Tests have **not** been executed and no fresh GitHub Actions run is available. No Paddle transaction, migration, deployment, or PDF/report work was performed.

## Configured Paddle checkout destination validation — implementation batch (2026-10-28)

- The backend now validates `PADDLE_CHECKOUT_URL` with the same strict HTTPS/Paddle-host allowlist used for URLs returned by Paddle, rejecting lookalike domains and embedded credentials before making the transaction API request.
- Added API regression coverage for trusted configured destinations and parameterized untrusted destinations; invalid configuration must return HTTP 503 before the Paddle request is called.
- Code and tests are committed to `integration/saas-feature-batch`. Tests have **not** been executed in this environment; no fresh GitHub Actions run is available. Vercel remains unused due to the build-quota limitation. PDF/report refinement remains deferred to the final phase.

## Saved-report ownership isolation acceptance extension — implementation batch (2026-10-28)

- Extended the existing two-license report isolation API test beyond listing, PDF download, and coverage metadata to also request the foreign license's detailed evidence and email endpoints.
- The regression asserts both foreign-report endpoints return 404 and that the email sender is never invoked, protecting stored report contents and preventing cross-account email delivery.
- Test source is committed and read back from the feature branch. The test has **not** been executed; fresh GitHub Actions runs remain unavailable and the Vercel build quota remains exhausted. This is source-level acceptance coverage, not a claim of runtime verification. PDF/report refinement remains deferred to the final phase.

## Customer account profile — source-level implementation

- Added authenticated `GET /api/v1/account/profile` and `PATCH /api/v1/account/profile` endpoints. Responses expose only the customer display name, plan tier, account status, creation date, and expiry; credentials and payment secrets are not returned.
- The customer portal now loads profile metadata on connect, lets the customer update the account display name, and clears profile data when disconnecting or switching credentials. Profile responses use private no-store cache headers.
- The editable field is the account display name only. Billing-provider identity, email address, subscription plan, and payment details are not changed by this feature.
- Source-level implementation only; API validation, ownership isolation, browser session switching, and persistence require the planned verification phase.


## Customer billing attention summary — implementation batch

- The authenticated billing-history response now includes a separate, bounded list of the ten most recently updated payment-failure, past-due, cancellation, or license-email-delivery events for that same license. It uses the existing account ownership filter and private no-store response policy.
- The customer portal surfaces those events above the full billing history with plain-language labels and safe next steps. It does not claim a failed payment automatically disables access, does not expose recipient email or credentials, and directs payment actions to the Paddle billing portal.
- The attention list is cleared when the customer disconnects or switches identity. The full paginated event history remains unchanged.
- Source-level implementation only; database-backed ownership, browser session-switching, and real Paddle lifecycle behavior still require the planned verification phase. No migration, deployment, payment action, or PDF/report refinement was performed.


## Administrator billing operations visibility — implementation batch

- Corrected operational diagnostics so the pending license-email metric and recovery list include only `email_pending` and `email_sending` states. Payment failures, past-due notices, and cancellations are not mislabeled as undelivered license emails.
- Added bounded lifecycle attention records and counts for payment failures, past-due subscriptions, and cancellations, plus a count of email-send markers older than ten minutes.
- Updated the administrator console to show separate license-email recovery and billing-lifecycle queues. Email retry controls are shown only for pending email delivery; ordinary lifecycle events are informational and do not expose recipient email addresses in the lifecycle queue.
- Source-level implementation and GitHub readback only. No automated test, live Paddle reconciliation, production database migration, or deployment was run. PDF/report work remains deferred.


## Admin license expiry operations — implementation batch

This batch adds separate counts for expired licenses, active licenses expiring within seven days, active licenses expiring within thirty days, licenses without expiry dates, and licenses with the inactive flag. The operator account-status filter now includes seven-day expiry, thirty-day expiry, and no-expiry cohorts. No automatic suspension, renewal, payment mutation, or entitlement extension is performed.

Issue checklist:
1. Separate expired-license metric.
2. Seven-day expiry metric.
3. Thirty-day expiry metric.
4. Missing-expiry metric.
5. Explicit inactive-flag metric.
6. Seven-day expiry filter.
7. Thirty-day expiry filter.
8. Missing-expiry filter.
9. Preserve authenticated admin access.
10. Keep expiry filters server-side.
11. Preserve existing bounded pagination.
12. Keep exact package-tier filtering.
13. Preserve sanitized search matching.
14. Keep existing active/inactive filters.
15. Keep expired status precedence.
16. Use UTC-aware comparison boundaries.
17. Make renewal urgency visible in summary metrics.
18. Distinguish expiry from inactive status.
19. Avoid exposing customer credentials in metrics.
20. Avoid automatic account suspension.
21. Avoid automatic entitlement extension.
22. Keep billing lifecycle actions separate.
23. Preserve existing account-management controls.
24. Keep changes confined to source and docs.
25. Explicitly record unverified runtime and production boundaries.

Verification boundary: GitHub source changes and readback only. No automated tests, live database acceptance, production migration, deployment, or live billing actions were run. PDF/report refinement remains deferred to the final phase.


## Customer entitlement and quota visibility — implementation batch

Expanded the authenticated account-usage response with plan label/availability, concurrent audit limit, consumed count, normalized quota state, and a customer-safe entitlement state. The customer portal now explains near-limit, exhausted quota, expired/inactive account, inactive plan, and unconfigured quota states instead of showing only a numeric usage bar. This is explanatory visibility; it does not change the audit reservation policy or automatically suspend existing subscriptions when a plan is hidden from new purchases.

Issue checklist addressed:
1. Expose human-readable plan label.
2. Expose whether the current plan is available in the catalogue.
3. Expose the configured monthly limit.
4. Expose completed audits.
5. Expose in-progress reservations.
6. Expose total consumed slots.
7. Expose remaining monthly slots.
8. Expose normalized usage percentage.
9. Expose near-limit state at 80% usage.
10. Expose exhausted quota state.
11. Expose account inactive state.
12. Expose expired license state.
13. Expose inactive plan state.
14. Expose missing/zero quota configuration.
15. Expose configured concurrent audit limit.
16. Normalize naive expiry timestamps as UTC.
17. Keep account usage response private/no-store.
18. Avoid returning license/API key secrets.
19. Retain fallback allowance for legacy/unlisted tiers.
20. Retain month-boundary reset calculation.
21. Keep account usage authentication requirement.
22. Distinguish plan availability from license active flag.
23. Distinguish quota exhaustion from account expiry.
24. Render clear customer-facing status explanations.
25. Document that this batch adds visibility, not automatic entitlement mutations.

Verification boundary: source changes were committed and readback verification is pending. Automated tests, browser runtime checks, and database-backed acceptance have not been run. No production migration/deployment or live billing action was performed. PDF/report refinement remains reserved for the final phase.


## Plan availability enforcement — cohesive feature completion

Closed a consistency gap between the operator-managed plan catalogue, customer usage display, and audit-slot reservation. New audit reservations now read the plan's `is_active` flag from the same catalogue row as the monthly/concurrent limits. If an operator disables a plan, existing licenses on that tier can no longer reserve new audit work; the request is rejected with HTTP 403 and a safe customer-facing message. Unknown/unlisted legacy tiers retain the existing fallback allowance behavior.

Feature issue checklist:
1. Read plan availability in quota reservation.
2. Use the plan catalogue as the source of truth when a tier row exists.
3. Reject reservations for operator-disabled plans.
4. Return a controlled HTTP 403 response for unavailable plans.
5. Keep the message free of secrets and database details.
6. Preserve legacy-tier fallback when no plan row exists.
7. Preserve the license active-flag check.
8. Preserve expiry enforcement before external audit work.
9. Preserve monthly quota enforcement.
10. Preserve concurrent audit enforcement.
11. Preserve expired reservation cleanup.
12. Preserve license-row locking around reservation.
13. Commit reservations before slow external work.
14. Keep reservation release after failed audits.
15. Avoid schema creation on the request path.
16. Keep operator-managed monthly allowance behavior.
17. Keep operator-managed concurrency allowance behavior.
18. Align backend plan availability with the customer usage status.
19. Keep new audits blocked without changing existing subscription/payment state.
20. Avoid automatic license revocation when a plan is hidden.
21. Preserve bounded diagnostics and existing audit event behavior.
22. Keep plan state read-only in the audit submission flow.
23. Avoid leaking billing identifiers into customer error text.
24. Document this as enforcement, not just UI visibility.
25. Record that live database and end-to-end acceptance remain outstanding.

Verification boundary: quota.py was updated and read back from the feature branch. Automated tests, database-backed acceptance, concurrent-request testing, and browser checks were not run. No migration, deployment, or live billing action was performed. PDF/report refinement remains deferred to the final phase.


## Test-blocking fixes — current CI validation batch

Current full GitHub Actions run 40740545876 exposed regressions on the current feature-chain head. Fixes in this batch address the common causes first: ReportLab multiBuild bookmark stability and monkeypatch-safe Paragraph type checks; optional business-context normalization; external form actions with URL userinfo are still identified while evidence omits credentials/query strings; missing trust cues explicitly distinguish absence from authenticity; and environment-configured Paddle plans remain available only when the plan catalogue is empty. Customer portal assertions now include the profile loader added by the account-profile feature.

Validation result before fixes: dependency installation and dependency vulnerability audit passed; the backend test step failed. The failures include report rendering, crawl discovery/outcomes, payment lifecycle setup, conversion evidence, trust wording, and stale portal/admin expectations. This batch is not considered fully verified until a fresh CI run completes. No deployment, production migration, or real payment action was performed.

## Latest bounded-crawl and schema-readiness batch

- The crawler now deduplicates canonical URLs during page processing and avoids adding a generic outcome when a specialized outcome for the same check and page already exists. This addresses duplicate product structured-data outcomes while retaining route-specific applicability.
- The production readiness CLI now checks the full set of runtime-used columns across licenses, API keys, audit leads, quota reservations, reports, billing webhook events, plan packages, operation events, and admin action logs.
- The readiness CLI also checks critical operational indexes, including unique Paddle price mapping and account-scoped report/quota indexes, by reading PostgreSQL's `pg_indexes` view. It remains read-only and never applies schema changes.
- Core schema migration now defines a partial unique index for non-NULL Paddle price IDs, preventing two plans from sharing one provider price. Existing duplicate mappings, if any, must be reconciled before that index can be applied.
- CI run [40790960269](https://github.com/haseeb1984/ecommerce-audit-agent/actions/runs/40790960269) passed on commit `8351ba6d9f6ed57596229cce80192cb91812f1b4` with **660 passed** and 55 warnings. The expanded schema/index readiness checks were committed after that run and are **awaiting their own CI result**.
- No production database was queried or modified, no migration was executed, and no deployment was performed.



## 2026-11-06 — integrated SaaS and audit-engine implementation batch

- Consolidated the existing agency/admin/customer implementation chain (PRs #163–#191), plus admin billing response cache controls and passive CORS review, into PR #194. The integration branch is 22 commits ahead of main, contains 38 changed files, has no base divergence, and is marked mergeable; it has not been merged.
- SaaS implementation consolidated: agency inventory/detail/lifecycle audit, workspace/team role/grant/revoke locking, WordPress connection health and archive revocation, customer/admin API-key ownership and session-race controls, passwordless customer actions, usage-history safety, admin activity filters, cross-database sync retry and queue diagnostics.
- Audit-engine implementation: synchronous licensed audits now call the isolated signed Playwright browser service already used by bulk workers; browser unavailability/failed navigation remains explicit. Added bounded source-text volume and exact duplicate-copy review signals. CORS response combinations are low-severity manual review signals, and security references point to OWASP Top 10:2025 as an awareness taxonomy only.
- Evidence boundaries remain: no Google Search Console index status without owner-authorized data; no backlink/competitor dataset without a provider/export; no manual WCAG conformance, authenticated checkout completion, consent-dependent event-delivery verification, active penetration testing, field Core Web Vitals or INP. These remain not assessed rather than inferred passes.
- Verification is blocked by CI infrastructure: latest backend run [42227554897](https://github.com/haseeb1984/ecommerce-audit-agent/actions/runs/42227554897) failed before runner startup (runner_id=0, blank runner name, zero steps). No test results were produced. Vercel reports its build-rate-limit failure; it is not being bypassed.
- No production migration, deployment, real payment, or live customer-site audit was performed. PDF/report layout and final audit-result refinement remain deferred to the final phase.



## 2026-11-08 — agency OTP and durable scan-worker ownership hardening

- PR #247 is merged: agency team OTP requests and verification now share the stable per-email login throttle lock used by customer login, serializing cross-agency OTP activity for the same address. Membership/challenge selection happens after the email lock, with agency/member/challenge row-lock ordering preserved.
- PR #248 is merged: scan-worker lease renewal now rejects an owner whose persisted `locked_at` is already outside the configured lease window; an expired worker cannot revive its lease simply because another worker has not reclaimed the job yet.
- PR #249 is merged: stale lease recovery is bounded to 100 jobs per claim transaction, ordered by lease timestamp and job ID, and uses `FOR UPDATE SKIP LOCKED` to avoid multiple claimers waiting on the same stale rows.
- PR #250 is merged: the same active-lease cutoff is enforced for completion, retry/failure, defer and renewal mutations. Lease durations are validated as bounded integers.
- Regression tests were added to `tests/test_agency_team_revocation.py` and `tests/test_scan_queue.py`. They have **not been executed** in this batch; relevant workflow runs were unavailable and Vercel reported its daily deployment-rate limit. These statuses are not evidence of Python test failures or passes.
- No live Hostinger/Supabase database, migration, SMTP, Paddle action, WordPress installation, live customer-site audit, or production deployment was performed. The durable worker remains **implemented / verification pending** until controlled staging and CI acceptance are available.
- PDF/private-storage and final audit-result presentation work remain reserved for the final phase.



## 2026-11-08 — admin billing and overview scalability

- PR #252 is merged: the admin payment-events endpoint now counts the union of canonical PostgreSQL and Hostinger event IDs with the existing constant-memory sorted-stream helper. It preserves the status filter, canonical PostgreSQL precedence, bounded page fetch and response pagination.
- PR #253 is merged: admin overview's monthly audit, all-time audit, saved-report and active-reservation aggregates are scoped to the visible license page. Global summary counters remain global.
- PR #253 also replaces loading every billing event for each visible customer with deterministic SQL `ROW_NUMBER()` selection of one latest contact per license, for both Hostinger operational events and the legacy PostgreSQL fallback.
- Regression contracts were added in `tests/test_billing_attention_recovery.py` and `tests/test_admin_overview_scalability.py`. They have **not been executed**; no Python CI pass is claimed.
- No live billing/customer data, production migration, external provider action, or production deployment was performed. Admin operations remain **implemented / verification pending** pending CI and staging acceptance.
- PDF/private-storage and final audit-result presentation remain reserved for the final phase.


## 2026-11-08 — customer directory and agency detail scalability

- PR #255 is merged: admin customer-directory license counts now resolve all license keys on the visible page in one PostgreSQL query rather than issuing one query per customer.
- PR #256 is merged: the exact cross-database customer-email union total is counted by merging ordered Hostinger and PostgreSQL email streams. Application memory remains constant with respect to the total number of distinct customer emails, and both streams are closed even if the second stream fails to initialize.
- PR #257 is merged: agency detail now returns at most the latest 100 website connections per workspace, while separate grouped counts expose the full number of connections and clearly mark truncated workspace lists in the admin portal.
- PR #258 is merged: agency suspension now revokes active team sessions, consumes pending login challenges, and revokes outstanding invitations through three targeted SQL updates instead of loading every affected row into Python.
- Regression tests were added/updated in `tests/test_admin_customer_directory_races.py` and `tests/test_agency_access.py`. They have **not been executed**; no Python CI pass is claimed. Vercel preview attempts continue to report the daily deployment-rate limit, which is not a code/test result.
- No live customer data, production database, migration, Paddle/SMTP action, WordPress installation, live-site audit, or production deployment was performed. Admin/customer and agency workflows remain **implemented / verification pending** until CI and controlled staging acceptance.
- PDF/private-storage and final audit-result presentation remain reserved for the final phase.


## 2026-11-08 — admin customer detail pagination

- PR #260 is merged: admin customer account detail now paginates linked licenses in pages of 100, uses a SQL-side deduplicated license-ID union/count, and exposes a Load more control.
- Operational identity-key transfer is capped at 1,000 keys and explicitly marked as truncated when the cap is exceeded. In that exceptional case, the displayed total is not complete; this remains a known edge case for follow-up streaming/chunked cross-database resolution.
- Related sessions and billing events remain bounded to 200 each, WordPress sites to 100, and support notes to 100. Full independent pagination/count metadata for those sublists remains a follow-up.
- PR #261 is merged: support-note identity selection now uses database-side minimum-key aggregates rather than materializing all operational and legacy license keys.
- Regression tests were added but not executed. CI, live data, production migration, provider acceptance, and deployment remain unverified.


## 2026-11-08 — unbounded customer identity streaming

- PR #263 is merged: admin customer detail now streams the full distinct Hostinger identity-key union in batches of 500 into a transaction-scoped PostgreSQL temporary table. The canonical PostgreSQL query unions those identities with legacy billing identities, calculates the deduplicated total, and paginates 100 licenses per request.
- This removes the prior 1,000-key ceiling; application memory for the cross-database identity transfer is bounded by the 500-key batch.
- Temp-table transaction commit/rollback and Hostinger stream closure are implemented. Production PostgreSQL/MySQL runtime acceptance is still pending; the temporary-table path is not claimed as production verified.
- PR #260 and #261 remain merged: customer license pagination and database-side support-note identity selection.
- Regression tests were added/updated but not executed. Vercel deployment attempts remain blocked by the daily deployment-rate limit; this is not a test result.


## 2026-11-08 — admin license-email recovery visibility

- The admin retry endpoint already permits recovery of a stale `email_sending` claim after 10 minutes, with a database row lock preventing concurrent retry claims.
- The global payment-event queue exposed retry for both `email_pending` and `email_sending` without distinguishing a fresh in-progress delivery from a stale claim. Customer-detail billing history did not expose the retry action.
- The admin console now shows retry only for linked-license `email_pending` events or `email_sending` events whose `updated_at` is at least 10 minutes old. The same eligibility helper is used in the global queue, payment-history cards, and selected customer billing history.
- Added a frontend contract regression test. CI and browser behavior have not been verified; no SMTP message was sent and no payment event was changed.


## 2026-11-08 — operational migration scalability completion batch

- PR #275 streams legacy account sessions, WordPress installations, billing events, support notes, and license identity projections; account and support-note reconciliation uses bounded target batches.
- PR #276 commits each 500-row apply batch independently, making interrupted migrations safely resumable without overwriting existing target rows or deleting source records. `--verify` remains read-only.
- PR #277 moves normalized billing-email ownership aggregation into PostgreSQL.
- PR #279 replaces the Python customer-account candidate dictionary with a PostgreSQL `UNION ALL` / `ROW_NUMBER()` deduplication query and streams 500-row candidate batches.
- PR #280 limits license mapping to referenced legacy IDs; PR #282 goes further and resolves license keys per 500-row source batch, removing the global license identity map.
- PR #281 joins support notes directly to grouped billing-email ownership in PostgreSQL. The migration no longer materializes a Python email-to-license map or ambiguous-email set; notes are copied only when exactly one license owns the email.
- PR #278 exposes safe stale license-email retry in admin customer history and the global payment-event view.
- All listed PRs are merged to `main`. Regression contracts were added, but backend CI continues to fail before runner startup (`steps: null`); no Python tests are claimed as executed. Vercel preview attempts remain blocked by the daily build-rate limit.
- No live Hostinger/Supabase migration, SMTP send, Paddle action, WordPress install, or production deployment was performed. PDF/private-storage and final audit-result refinement remain deferred.


## 2026-11-08 — isolated browser-worker client hardening

- Browser service configuration is now parsed as an HTTPS origin only. Embedded credentials, custom paths, query strings, fragments, malformed ports, whitespace, and backslash-based authority/path ambiguity are rejected before any signed request is sent.
- The client appends the fixed `/v1/audit` endpoint and continues to disable redirects, preventing an environment value from silently changing the signed request destination.
- Browser responses must be JSON objects with the expected request ID and list-shaped `findings` and `check_outcomes`; a present `summary` must be an object. Non-object JSON and malformed result shapes fail closed as `BrowserAuditUnavailable`.
- Regression coverage now includes invalid service URL variants, non-object JSON payloads, malformed result shapes, valid origin normalization, and the existing HMAC request-signing contract.
- Tests are committed but have not been executed. No browser service deployment, live Chromium acceptance, customer-site audit, or production configuration change was performed. Browser-worker integration remains **implemented / verification pending**.
- PDF/private-storage and final audit-result presentation remain reserved for the final phase.


## 2026-11-08 — bounded admin account-wide lifecycle actions

- Account-wide suspend, reactivate, and session-revocation actions no longer materialize every operational license key or canonical license ID in Python sets/lists.
- Hostinger billing/account identity keys are streamed into a transaction-scoped PostgreSQL temporary table in batches of 500. Matching canonical license rows are then streamed and locked in ascending license-ID order, with outbox records and entitlement changes prepared in bounded 500-license batches.
- Hostinger mirror updates use database-side email-to-license subqueries after the canonical PostgreSQL commit, avoiding reconstruction of an unbounded cross-database key list. Admin action metadata records the affected license count rather than an account-sized ID array.
- Added source-contract regressions for bounded identity transfer, ordered row locking, batch outbox creation, and operational-side mirror subqueries. Tests are committed but have not been executed; live MySQL/PostgreSQL transaction and high-cardinality acceptance remain pending.
- No customer data, live migration, external provider, production deployment, PDF, or audit-result workflow was changed.


## 2026-11-08 — canonical license locking during lifecycle reconciliation

- Customer lifecycle outbox reconciliation now obtains a PostgreSQL row lock on the canonical `SoftwareLicense` record before deciding whether a pending suspend/reactivate action still applies.
- The worker retains that lock while applying the corresponding Hostinger account/session mutation and committing the outbox event. This serializes the mirror operation against concurrent admin lifecycle actions, which already lock canonical license rows before their operational mirror writes.
- Stale lifecycle events continue to be evaluated against the canonical active flag, and per-license outbox ordering remains in place. Explicit session revocation remains independent of active/suspended state.
- Added a PostgreSQL SQL-compilation regression asserting the canonical row lock and a source-order contract asserting the lock read precedes the Hostinger mutation.
- Tests are committed but have not been executed in this batch. CI runner availability remains unverified; no live database, migration, deployment, or customer account mutation was performed.
- PDF/private-storage and final audit-result presentation remain reserved for the final phase.


## 2026-11-08 — serialize customer email identity projection updates

- Email-identity outbox reconciliation now locks the canonical PostgreSQL `SoftwareLicense` row before rewriting that tenant's billing-recipient identity projection.
- The row lock is retained through the scoped `PaymentWebhookEvent` update and canonical transaction commit. The Hostinger outbox event is marked completed only after the canonical projection commit succeeds.
- Missing canonical licenses continue to defer for retry; the update remains license-scoped and does not use email address as a tenant identifier.
- Added PostgreSQL SQL-compilation and worker-order regression coverage. Tests are committed but have not been executed in this batch; no live database or customer records were changed.
- PDF/report and final audit-result work remain reserved for the final phase.


## 2026-11-08 — operational migration transform and timestamp integrity

- Found and corrected an admin action-log migration call that incorrectly enabled per-row license-ID resolution even though its transform accepts only the source row. This mismatch would raise a runtime argument-count error when the migration reached admin action logs.
- Corrected legacy customer-account projection to carry the selected candidate's source update timestamp through the database-side ranking query and persist it as `updated_at`; `created_at` remains sourced independently.
- Added regression contracts for both the transform arity and timestamp preservation. Existing bounded batching, resumable commits, read-only verification and source-retention behavior are unchanged.
- This is a source-level correction only. Backend CI has not executed these tests, and no live Hostinger/Supabase migration or data mutation was performed. Migration remains **implemented / verification pending**.
- PDF/private-storage and final audit-result refinement remain reserved for the final phase.


## 2026-11-08 — accessibility embedded-content and image-map coverage

- Extended the static accessibility parser to inspect iframe accessible names (title, aria-label, or a resolvable aria-labelledby reference).
- Added a separate review signal for linked image-map area elements without a meaningful accessible name; non-linked area elements are not treated as interactive links.
- Added regression coverage for unnamed and named frames, broken frame label references, unnamed linked areas, and non-linked map areas.
- These are conservative source-level review signals only. They do not assess embedded third-party document accessibility, image-map coordinate accuracy, or establish WCAG conformance. Tests are committed pending CI execution; no production audit or external payment/video content was accessed.
- PDF/report and final audit-result refinement remain reserved for the final phase.


## 2026-11-08 — validate standard browser security-header values

- Strengthened baseline response-header review so a non-empty but unrecognized Referrer-Policy is not treated as configured.
- Empty Permissions-Policy values are treated as missing.
- Framing protection now requires a non-empty effective CSP `frame-ancestors` source list or a supported X-Frame-Options value (`DENY` / `SAMEORIGIN`); empty CSP directives and arbitrary X-Frame-Options strings no longer count as protection.
- Added regression cases for malformed values, empty frame-ancestors, and valid X-Frame-Options fallback. Signals remain low-severity hardening advice, not vulnerability or compliance claims.
- Tests are committed pending CI execution; no live site headers or production configuration were changed. PDF/report work remains reserved for the final phase.


## Durable scan enqueue boundary hardening

- The operational queue now validates persisted identifier lengths and types before opening its transaction: license key, request ID, package tier, requester, workspace ID, and target URL are checked against their Hostinger column limits.
- Scan batch size and retry-attempt limits reject booleans, non-integers, and out-of-range values rather than allowing implicit Python type coercion or invalid retry configuration into durable jobs.
- Standard-license website binding now canonicalizes both historical inventory hostnames and submitted URL hostnames through the same IDNA normalization path, including case and trailing-dot normalization. Malformed legacy authority-like values fail closed instead of being treated as hostnames.
- Regression contracts cover invalid retry limits, overlong request IDs, Unicode/punycode hostname equivalence, and malformed legacy hostname values. These tests are committed for CI; they have not yet been executed.
