# AI Ecommerce Audit SaaS Bridge (WordPress)

This plugin adds a server-side WordPress bridge to the Ecommerce Audit Agent FastAPI service.

## Install

1. Copy this directory into `wp-content/plugins/ai-ecommerce-audit-bridge/`.
2. Activate **AI Ecommerce Audit SaaS Bridge** in WordPress.
3. Open **Settings -> Ecommerce Audit Bridge**.
4. Set the HTTPS API base URL and a license/API credential. The credential is stored server-side and is not emitted into page markup.
5. Add `[ai_ecommerce_audit_dashboard]` to a page that only authenticated customers can access.

## Current functionality

- Authenticated request for `GET /api/v1/account/usage`.
- Monthly quota display including active reservations when returned by the API.
- Nonce-protected audit form for signed-in WordPress users.
- Server-side request to `POST /api/v1/comprehensive-audit?domain=...` and validation of the returned PDF content type and PDF signature before download.
- HTTPS-only API base URL, bounded HTTP timeout, no automatic redirects, generic error messages, private/no-cache download headers, and no credential in browser JavaScript.

## Boundaries and remaining work

- Billing and package entitlement authority remains in the FastAPI/Paddle backend; the plugin does not create or validate payment events independently.
- Configure the WordPress page to require login and use an appropriate membership/access-control policy for the intended customer group.
- The API credential is configured by a WordPress administrator and is shared by the WordPress site. Customer-specific WordPress account linking and automated WordPress/Paddle identity lifecycle are not implemented in this initial bridge.
- Feature-gated Full Dossier and white-label branding controls are not implemented in this initial bridge.
- PHP/WordPress integration tests and an end-to-end sandbox run are still required before production use.

## Security notes

Use HTTPS for the FastAPI service. Do not expose the license credential in page content or client-side scripts. Restrict the dashboard page to authenticated users and keep WordPress, PHP, and the plugin updated.
