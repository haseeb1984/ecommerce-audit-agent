# Current Phase Gap Matrix — Ecommerce Audit Agent

**Baseline reviewed:** `main`; bounded-crawl expansion committed during the 2026-10-21 implementation session. Re-run CI and real-result acceptance before release claims.  
**Purpose:** Record evidence-backed next steps against the existing agreed scope. This is a planning/acceptance document; it does not claim a live production test was run.  
**Operational constraint:** This phase changes application code and documentation only; it does not deploy, alter infrastructure, or run live customer-site audits.

## Status meanings

- **Implemented, verify release:** code/tests exist, but acceptance evidence for the whole production workflow is still needed.
- **Partial:** a limited checker or workflow exists; agreed coverage remains incomplete by design or by implementation.
- **Not established in repository:** current backend files/routes do not demonstrate the feature; inspect connected frontend/product work before assuming no work exists elsewhere.
- **Blocked / hold:** do not proceed until the stated dependency or approval is resolved.

## Current evidence-backed matrix

| Workstream | Evidence in current repository | Status | Acceptance gate / next action |
|---|---|---|---|
| Vercel infrastructure and Functions Storage | Support case is open; latest reviewed `main` is commit `ca60d84a48fd2d380ca4425d49124c80b12d3a7f`. | **Blocked / hold** | Wait for support response. No cleanup, redeploy, or infrastructure change in this workstream without explicit decision. |
| API and database foundation | `main.py` exposes root, `/health-check`, `/api/v1/audit-lead`, and `/api/v1/comprehensive-audit`; SQLAlchemy models cover licenses, API keys, audit leads, and quota reservations. | Implemented, verify release | Verify current production health/configuration only when authorized and without consuming audit quota; confirm required migration is applied. |
| Authentication and quota | `auth.py`, `quota.py`, reservation model/migration, and `tests/test_api.py` cover license/API-key auth, quota exhaustion, failed-run release, and concurrent quota requests. | Implemented, verify release | Confirm production migration and approved, isolated live concurrency test results; clean up test records afterward. Do not use a production license for exploratory tests. |
| Safe target URL fetching / bounded crawl | `audit_checks.py` and `crawl_checks.py` enforce public-address checks, redirect validation, response/time limits, DNS-pinned fetching, same-origin sitemap discovery, and a capped recursive HTML-link queue. | Partial; broader traversal implemented, release verification pending | Verify nested-link discovery, origin isolation, malformed-link resilience, duplicate URL normalization, and the hard page cap in CI. No claim of complete SSRF immunity or whole-site coverage. |
| Technical SEO and crawl | Homepage signals, bounded same-origin crawl, sitemap expansion, canonical/robots directives, structured-data and hreflang signals exist. Canonical checks now also flag cross-origin targets for manual review while accepting default-port normalization. | Partial | Verify canonical target findings against representative storefronts; preserve explicit crawl/page caps and do not infer Google index status without authorized Search Console data. |
| Performance / Core Web Vitals | PageSpeed mobile Lighthouse score and Speed Index are collected; other checks use static HTML/CSS signals. | Partial | Clearly distinguish lab from field data. Browser-rendered LCP/INP/CLS, responsive reflow, overflow and console/network checks need browser-runner evidence before being claimed. |
| Accessibility / WCAG / ARIA | `accessibility_checks.py` contains source-level accessible-name, label, language, image-alt and ID-reference signals. | Partial | Add/verify manual-review checklist and edge cases; never claim WCAG 2.2 A/AA conformance from source checks alone. |
| SSL/TLS and passive security | `security_checks.py` and transport checks observe selected headers, TLS/redirect behavior and a limited set of exposure paths. | Partial | Unknown/unreachable checks remain unverified; validate report wording and coverage. No penetration-test or “fully secure” claim. |
| Target-side dependency advisory check | `dependency_checks.py` checks a bounded set of explicitly versioned frontend CDN scripts against OSV; the scope document says CI verification is pending. | Partial / verify | Verify parsing, unavailable-service behavior, bounded requests, false-positive handling and PDF rendering. Do not present this as full software composition analysis. |
| Trust / pixel / conversion / mobile UX | `trust_checks.py`, `conversion_checks.py`, and `mobile_ux_checks.py` inspect limited source-level cues. | Partial | Test real examples and disclose that detected tags do not prove events, consent behavior, attribution or revenue impact. Checkout tests require explicit authorization and must not place real orders. |
| PDF content and layout | `report_generator.py` and PDF regression tests exist. The completion gate cites a passing 190-test run and a visually inspected synthetic four-page PDF. | Implemented, verify release | Run final QA on a safely obtained real audit result shape; verify evidence, status, limitations, recommendations, optional benefit/risk fields and final disclaimer. Synthetic PDF review alone is not end-to-end acceptance. |
| Report persistence / customer history | Current `AuditLead` stores selected lead/performance fields. The comprehensive endpoint returns PDF bytes and saves an audit lead record; no report-file/object storage or report-history retrieval route is established by the inspected API routes. | Not established in current backend API | Define bounded report metadata and storage, secure customer/license ownership checks, retrieval/retention policy, and failure handling before implementation. |
| Email delivery | No email-delivery route/provider workflow is established by the inspected `main.py` API routes. | Not established in current backend API | Define recipient verification, provider/config, delivery failure/retry behavior, and report-link security. Do not send email in tests without an explicit test recipient. |
| Customer-facing frontend / purchase / dashboard | The reviewed repository root is a backend FastAPI project; its API routes do not establish marketing pages, checkout, customer dashboard, or frontend report history. | Not established in this repository | Locate/confirm any separate frontend repository or implement the agreed Hostinger-compatible frontend as a separate deliverable. Do not assume it is complete merely because the backend works. |
| Final release acceptance | Existing test workflow and many regression tests exist; documentation marks release acceptance blocked pending latest CI/artifact and real-result review. | **Release blocked** | Confirm current CI on the intended commit, review PDF using representative data, verify production migration/config safely, complete user workflows, then request explicit production release approval. |

## Recommended sequence (Vercel infrastructure remains on hold)

1. Finish the audit-engine/PDF acceptance review without running quota-consuming production audits.
2. Verify dependency-check tests and output handling; resolve any failing or missing CI evidence.
3. Specify report storage/history and email contracts, including authorization and retention, before coding.
4. Confirm the intended frontend location and map the marketing → demo → purchase/license → dashboard → audit → report/email journey.
5. Complete a release checklist with explicit evidence for each gate; ask for approval before any production deployment or destructive operation.

## Non-negotiable reporting rules

- Audit/finding only: do not implement fixes on customer websites in this phase.
- Do not invent metrics, indexing state, vulnerability coverage, conversion losses, or business impact.
- Distinguish `verified`, `manual_review_required`, and `not_tested` / insufficient evidence.
- Preserve existing license/quota reservation behavior and regression tests.
- No production deploy, database migration, credential rotation, or infrastructure cleanup without the appropriate explicit approval.
