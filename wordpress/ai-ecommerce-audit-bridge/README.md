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
- Hide audit submission unless the live account entitlement is active and quota remains; re-check entitlement server-side on form submission.
- Nonce-protected audit form restricted to trusted site operators by default (`manage_options`); a site administrator may deliberately grant a narrower or broader capability with the `aieab_dashboard_capability` filter.
- Server-side request to `POST /api/v1/comprehensive-audit?domain=...` and validation of the returned PDF content type and PDF signature before download.
- HTTPS-only API base URL, bounded HTTP timeout, no automatic redirects, generic error messages, private/no-cache download headers, and no credential in browser JavaScript.

## Boundaries and remaining work

- Billing and package entitlement authority remains in the FastAPI/Paddle backend; the plugin does not create or validate payment events independently.
- The dashboard and audit submission both require the `manage_options` capability by default because the API credential is shared at site level. A site owner can use the `aieab_dashboard_capability` filter to delegate access to a trusted role; do not grant it to general storefront customers.

For example, to delegate the dashboard to a trusted custom capability, add this to a site-specific plugin after reviewing your role policy:

```php
add_filter('aieab_dashboard_capability', static function (): string {
    return 'manage_woocommerce';
});
```

Only use a capability that is assigned exclusively to trusted operators. The filter changes the WordPress-side access boundary; it does not create separate SaaS identities or separate billing accounts.
- The API credential is configured by a WordPress administrator and is shared by the WordPress site. Customer-specific WordPress account linking and automated WordPress/Paddle identity lifecycle are not implemented in this initial bridge.
- Feature-gated Full Dossier and white-label branding controls are not implemented in this initial bridge.
- PHP/WordPress integration tests and an end-to-end sandbox run are still required before production use.

## Security notes

Use HTTPS for the FastAPI service. Do not expose the license credential in page content or client-side scripts. Restrict the dashboard page to authenticated users and keep WordPress, PHP, and the plugin updated.
