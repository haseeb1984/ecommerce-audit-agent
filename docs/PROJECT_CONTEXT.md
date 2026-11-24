# Ecommerce Audit Agent — Project Context

> Reviewed 2026-11-24. This is a navigation and architecture summary, not a release approval. For implementation details, the linked source-of-truth documents take precedence.

## Purpose

AI-assisted ecommerce audit SaaS for store owners and agencies. It inspects authorized public storefronts and returns structured, evidence-backed findings across technical SEO, crawlability, accessibility, performance and conversion/UX. Findings must distinguish measured evidence from inference, and unavailable checks must never be represented as passes.

## Source-of-truth documents

- Approved application architecture: architecture-source-of-truth.md — database and storage ownership.
- Product scope and package contract: product-scope-and-package-contract.md — Starter/Pro/Business entitlements and agency boundaries.
- SaaS implementation master checklist: saas-implementation-master-checklist.md — implementation and verification status.
- Current phase gap matrix: current-phase-gap-matrix.md — remaining work and acceptance gates.
- Deployment operations runbook: DEPLOYMENT_OPERATIONS_RUNBOOK.md — controlled operational procedures.
- Audit engine coverage: audit-engine-coverage.md — bounded checks and evidence semantics.

If a summary document conflicts with one of these source-of-truth documents or the current code, investigate and correct the summary; do not silently change the approved architecture.

## Stack

- API and orchestration: Python / FastAPI, entrypoint main:app.
- Browser inspection: separate Python Playwright worker.
- Portals: static HTML/CSS/JavaScript; preserve this architecture rather than introducing a frontend framework rewrite.
- Runtime manifests: requirements.txt, requirements.in, requirements-dev.txt, requirements-dev.in, and browser-worker/requirements.txt.
- WordPress deliverables are separate: the customer integration plugin is under wordpress-plugin/ecommerce-audit-agent/; the public marketing theme is under wordpress-theme/ecommerce-audit-agent/.

## Database and storage boundaries

- Hostinger MySQL owns operational SaaS data: customer/account operations, website inventory, WordPress operational metadata, scan submissions, batches/jobs, queue/lease/retry state, usage/activity mirrors and other operational records.
- Supabase PostgreSQL owns canonical licensing, audit-engine and billing/webhook state.
- Hostinger private storage owns generated PDF reports, customer logos and other private customer files. Store opaque keys/metadata in the appropriate database; do not put report bytes in Supabase.
- Screenshots are held in memory and embedded in the PDF; they are not persisted as standalone files.
- These are separate databases. Do not create cross-database foreign keys or issue one SQL query that joins/unions tables across them. Use independent sessions and bounded/streaming reconciliation where cross-store views are required.
- Migrations for Hostinger MySQL and Supabase PostgreSQL are separate operator-applied operations. Do not run production migrations automatically at application startup.

## Typical audit flow

1. A customer or authorized agency member submits one storefront and a bounded set of same-site page URLs.
2. The API validates identity, license, package entitlement and quota.
3. Operational batches and jobs are persisted in Hostinger MySQL; canonical licensing/quota/audit state is handled through the Supabase boundary.
4. The worker performs bounded, SSRF-aware inspection and records module/check outcomes with evidence and limitations.
5. Structured findings are assembled into a report; unavailable modules remain unavailable/not assessed.
6. A PDF is generated, screenshots are embedded from memory, and the report is stored in Hostinger private storage.
7. Customer, agency and admin APIs enforce ownership and role permissions when listing or downloading results.

## Product boundaries

- Starter, Pro and Business are the canonical package IDs. Business is the agency/multi-client plan; individual licenses remain tied to one ecommerce website. A bulk audit may cover multiple pages of that same website.
- Backend APIs—not just portal visibility—must enforce entitlements and tenant isolation.
- Public crawling does not prove Google indexing or Search Console performance. Owner-authorized integrations or provider datasets are required for those claims.
- Browser/static checks are bounded diagnostics, not full manual WCAG certification, penetration testing, authenticated checkout completion or guaranteed field Core Web Vitals.
- The product does not guarantee rankings, revenue, conversions, security or legal compliance.

## Email and marketing-site contact

- The shared SMTP service is platform-owned. Customer-specific SMTP is not implemented by the recent SMTP consolidation.
- The marketing theme submits contact messages server-to-server to POST /api/v1/public/contact, signed with HMAC-SHA256 and a short timestamp window. FastAPI verifies the signature and sends a branded HTML email through the shared platform SMTP service; the visitor's address is Reply-To.
- Contact delivery requires EAA_CONTACT_FORM_SECRET (same random value in WordPress theme settings and Vercel) and EAA_CONTACT_TO_EMAIL in Vercel, in addition to the existing platform SMTP environment. The public contact email is display-only; leaving it blank must not expose the WordPress admin email or disable the form.
- No real SMTP delivery has been performed as part of repository CI.

## Current engineering constraints

- Work on feat/hostinger-private-report-storage; keep main unchanged until explicit approval.
- Do not deploy, apply production migrations, change DNS or alter production secrets without explicit approval.
- The owner/admin experience must remain distinct from a normal customer Store Account; owner workflows must not force a customer subscription.
- Do not claim BYOK, automated fixes, professional-services execution, customer SMTP or other planned capabilities as implemented unless the current backend and acceptance tests prove them.
