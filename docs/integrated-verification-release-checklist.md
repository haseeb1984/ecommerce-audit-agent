# Integrated SaaS verification and release checklist

This checklist applies to the consolidated implementation candidate in PR #89. It separates repository verification from production acceptance.

## Consolidated source scope

The candidate includes customer account recovery and verified email changes, admin customer lifecycle controls, WordPress site registration and the installable plugin, audit engine coverage/evidence, PostgreSQL schema alignment, report/PDF results, plan entitlement enforcement, and per-license white-label branding.

The legacy `wordpress/ai-ecommerce-audit-bridge` plugin branches are superseded by `wordpress-plugin/ecommerce-audit-agent`. Do not install both plugins on one WordPress site. The newer plugin uses the `wordpress_sites` registration contract; the older `wordpress_site_links` challenge schema is not part of the current integration.

## Repository verification sequence

Run from a clean checkout of the PR head:

1. `python -m compileall -q .`
2. `python -m pytest -q`
3. `php -l wordpress-plugin/ecommerce-audit-agent/ecommerce-audit-agent.php`
4. `php -l wordpress-plugin/ecommerce-audit-agent/uninstall.php`
5. `python scripts/check_production_readiness.py` with a non-production database and test environment configuration.
6. Review GitHub Actions results for the exact candidate commit. A Vercel preview build is a separate deployment signal and does not substitute for backend tests.

## Database rollout

Back up the target database and apply reviewed migrations in the order documented in `docs/database-integrations-rollout.md`, including `migrations/20261102_plan_entitlements_white_label.sql`. Do not run migrations from an application request or against production without owner approval.

## Controlled integration acceptance

Use non-production credentials and test licenses to verify:

- Starter can run standard audits but cannot run conversion dossiers, create direct API keys, or configure white-label branding.
- Pro can run standard audits and conversion dossiers but cannot configure white-label branding or direct API access.
- Business can use the full feature set and save per-license white-label settings.
- Unknown plan tiers fail closed.
- Customer email recovery/change, session revocation, one-customer/one-license identity, and report ownership isolation.
- Admin suspension/reactivation, cancellation requests, support notes, and audit logs.
- WordPress registration, status heartbeat, quota enforcement, audit submission, report download, disconnect, and plan-gated branding.
- Paddle sandbox checkout/webhook reconciliation, SMTP delivery/retry, PageSpeed and Groq integrations.
- A controlled real audit produces a PDF whose finding-to-page evidence mappings and disclaimer are reviewed.

## Release gate

Repository tests, schema readiness, external-provider sandbox checks, WordPress runtime checks, and real-result PDF acceptance must all pass before production release. Production secrets, live migrations, PR merge, and deployment remain owner-controlled actions. A failed or unavailable preview deployment must not be described as a successful release.
