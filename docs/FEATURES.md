# Ecommerce Audit Agent — Implemented Feature Register

> Reconciled against the FastAPI application, audit engine, browser worker, portals, migrations, package contract and existing implementation documentation. This lists source-backed capabilities and clearly separates bounded checks from methods the product does not claim to perform.

## Public product and API
- Public marketing/home and pricing pages.
- Health/readiness endpoint.
- FastAPI API with OpenAPI schema customization.
- Lead audit endpoint and comprehensive audit PDF endpoint.
- License validation and optional WordPress-site association.
- Standardized audit finding/check-outcome data models with stable finding IDs, categories, statuses, severity and evidence semantics.

## Audit orchestration and diagnostics
- FastAPI audit lifecycle and modular audit checks.
- Bounded same-origin crawling with page/link/response-size/time limits.
- Safe HTTP target normalization, public-host DNS resolution and SSRF-aware fetching.
- Technical SEO and crawlability signals.
- Page titles, meta descriptions, headings, canonical/redirect/HTTP response and link diagnostics where covered by the checker.
- Robots.txt and XML sitemap discovery/inspection.
- LLMs.txt availability/basic-format inspection.
- Structured-data and ecommerce product/catalog signals.
- Hreflang/international SEO declarations.
- Image/alt and accessibility/ARIA signals.
- Selected WCAG-oriented automated checks and manual-review flags.
- Mobile viewport/responsive signals where measurable.
- Performance diagnostics including PageSpeed/Lighthouse-derived metrics where configured.
- SSL/TLS, HTTPS and mixed-content observations.
- Security-header, cookie-attribute, exposed-path and public-configuration signal checks.
- Analytics/pixel tag detection and visible consent-interface signals.
- Conversion/checkout and trust-signal observations limited to publicly observable evidence.
- Content visible-text volume and exact duplicate-copy comparisons within the bounded fetched sample.
- Cross-page duplicate title/meta-description comparisons within the bounded crawl sample.
- Explicit per-check outcomes: pass, issue, warning, not_assessed or error; missing findings are not silently treated as passes.
- Evidence, affected URLs, test method, confidence/limitations and remediation guidance in the audit result model.

## Rendered browser inspection
- Separate Playwright browser-worker service.
- Signed/isolated browser-service integration with bounded rendered-page inspection.
- Configurable viewport-width checks.
- Browser findings/outcomes merged with static audit coverage when the worker is configured and succeeds.
- If the browser service is unavailable or navigation fails, rendered checks remain unavailable/not assessed rather than being represented as passes.

## Reports and customer experience
- PDF audit report generation and report download/email request workflow.
- Customer portal and account login by email verification code.
- Account profile and email-change verification flows.
- Customer device-session listing and revocation, including logout/revoke-other-sessions.
- Customer WordPress site registration, status, disconnect and plugin guide/download.
- Customer billing history/portal and account-facing site/license surfaces.
- Report and customer data persistence through PostgreSQL and operational database integrations.

## SaaS licensing, packages and billing
- License validation and quota/usage controls.
- Audit quota reservation/release behavior.
- Canonical Starter, Pro and Business package IDs.
- Package feature/entitlement mapping and operator-managed package pricing/Paddle price IDs.
- Paddle checkout/customer portal integration foundations and billing event/mirror/outbox processing.
- Subscription and billing lifecycle records, event fingerprints and operational reconciliation paths.
- Paid feature/entitlement enforcement paths; production payment acceptance remains dependent on configured provider credentials and lifecycle verification.

## Agency and multi-client workflows
- Agency portal and business-agency workspace foundations.
- Agency team authentication by verification code.
- Team invitations, membership roles, workspace access and session controls.
- Agency client workspaces and client inventory.
- Agency usage and audit-result views.
- Agency website connection token, WordPress registration/status/disconnect paths.
- Agency branding settings and customer-facing branding entitlement for eligible plans.
- Agency team activity and access controls.
- Multiple-client management is package-gated by the Business plan contract.

## Administration and operations
- Admin portal and admin scan API.
- Admin package/price management and package actions.
- Admin customer lifecycle/session controls and customer identity search.
- Admin agency inventory/status and team operations.
- Admin audit/activity logs and billing/operational diagnostics.
- Database migrations for core SaaS, billing, customer identity/session, WordPress, agency, scan jobs and outbox operations.
- Operational runbooks, backup/restore and launch preflight documentation.
- Backend automated test suite and browser-worker tests are present in the repository.

## Explicit scope boundaries
- Audits are bounded public, unauthenticated HTTP(S) checks unless a separately authorized integration is configured.
- Google Search Console index/performance status requires owner-authorized data; public crawling does not prove index status.
- Backlink/competitor datasets require a suitable provider/API or user-provided export.
- The browser worker does not claim full cross-browser/device coverage, field INP/Core Web Vitals in all cases, manual WCAG conformance, authenticated checkout completion or active penetration testing.
- Detected analytics tags do not prove events or attribution work.
- Security-header checks do not constitute a complete OWASP assessment or compliance certification.
- Reports do not guarantee rankings, revenue, conversions, security or legal compliance.
