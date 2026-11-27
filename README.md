# Ecommerce Audit Agent

AI-assisted ecommerce audit SaaS for store owners and agencies. The platform performs bounded, evidence-backed checks on authorized public storefronts and returns structured findings and PDF reports.

## Architecture at a glance

- **API:** Python / FastAPI (entrypoint main:app).
- **Portals:** static HTML, CSS and JavaScript.
- **Browser worker:** separate Python / Playwright service.
- **Hostinger MySQL:** operational SaaS/customer data, website inventory, WordPress operational metadata, scan batches/jobs and queue state.
- **Supabase PostgreSQL:** canonical licensing, audit-engine and billing/webhook state.
- **Hostinger private storage:** generated PDF reports, customer logos and private customer files.
- **WordPress customer plugin:** wordpress-plugin/ecommerce-audit-agent/.
- **Public marketing theme:** wordpress-theme/ecommerce-audit-agent/.

These database and storage boundaries are deliberate. Do not use cross-database foreign keys or one SQL query that joins/unions Hostinger and Supabase tables. See the approved architecture in docs/architecture-source-of-truth.md.

## Audit flow

1. The API validates account/license ownership, package entitlements and quota.
2. Scan batches and jobs are persisted in Hostinger MySQL.
3. The worker performs bounded, SSRF-aware inspection and records evidence/check outcomes.
4. The audit engine and licensing boundary retain canonical state in Supabase PostgreSQL.
5. Structured findings are assembled into a PDF; screenshots are embedded from memory, not stored separately.
6. Reports and logos use Hostinger private storage with authorization enforced by the API.

## Install and verify

Use Python 3.12 as in CI.

    python -m pip install --require-hashes -r requirements.txt
    python -m pip install --require-hashes -r requirements-dev.txt
    python -m pytest -q

Install browser-worker/requirements.txt separately in the browser-worker runtime. CI also runs the dependency audit, Python compilation, PHP lint for the plugin/theme/storage bridge, embedded frontend JavaScript syntax checks and synthetic PDF generation.

## Marketing contact configuration

The public WordPress theme posts signed requests to POST /api/v1/public/contact. To enable delivery, configure:

- EAA_CONTACT_FORM_SECRET in Vercel and the same value in WordPress → Appearance → EAA Website Settings.
- EAA_CONTACT_TO_EMAIL in Vercel.
- Existing platform SMTP environment variables.

The public contact email field is display-only; leaving it blank hides it and must not expose the WordPress admin email. The contact API sends through platform SMTP with the visitor's address as Reply-To. Customer-specific SMTP is not part of this implementation.

## Documentation

- docs/PROJECT_CONTEXT.md — project context and architecture summary.
- docs/FEATURES.md — implemented feature register and explicit scope boundaries.
- docs/GAPS.md — review gaps and verification register.
- docs/ROADMAP.md — release acceptance order.
- docs/DEPENDENCIES.md — dependency map.
- docs/architecture-source-of-truth.md — approved database/storage architecture.
- docs/product-scope-and-package-contract.md — product and package contract.
- docs/saas-implementation-master-checklist.md — implementation checklist.
- docs/DEPLOYMENT_OPERATIONS_RUNBOOK.md — deployment operations.

## Important release boundary

Repository CI does not prove production migrations, live SMTP delivery, live provider acceptance, DNS changes or deployment. Apply migrations and deploy only through the approved operational process after backup and explicit approval. Do not merge this working branch to main without approval.
