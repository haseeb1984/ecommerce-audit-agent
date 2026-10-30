# WordPress and WooCommerce integration

## Plugin package

The installable plugin source is in `wordpress-plugin/ecommerce-audit-agent/`:

- `ecommerce-audit-agent.php` — admin dashboard, authenticated SaaS client, site registration, usage display, audit execution, and saved-report download.
- `readme.txt` — WordPress.org-style installation and security documentation.
- `uninstall.php` — attempts to disconnect the remote SaaS site identity, then removes plugin-local credentials and settings. If the WordPress host is offline during uninstall, the customer can disconnect the stale site from the SaaS customer portal.

The plugin requires WordPress 6.2+, PHP 7.4+, and outbound HTTPS. WooCommerce is optional; when active, its version is registered as site metadata.

## Customer setup

1. Complete a SaaS checkout and receive the provisioned license key.
2. Install and activate the plugin on the customer's WordPress site.
3. Open **Ecommerce Audit** in the WordPress administrator menu.
4. Enter the license key and keep the API base URL on HTTPS. The hosted service URL is prefilled.
5. Save and connect. The plugin registers the WordPress installation against the authenticated license.
6. Use the dashboard to view plan/quota and billing state, run a comprehensive audit, and download saved reports. The customer portal also lists linked WordPress sites and lets the account owner disconnect an installation.

The plugin encrypts the saved license credential at rest with AES-256-GCM using a key derived from the WordPress authentication salt, and decrypts it only when making a server-side API request. The license key is sent server-to-server in the `X-License-Key` header. It is never rendered into the admin HTML, public page markup, browser JavaScript, shortcode output, or report URLs. Rotating WordPress salts requires the administrator to enter the license key again. A site connection is scoped to the exact license that authenticated the request. The SaaS backend derives the billing customer email from the verified Paddle provisioning event for that license; the plugin does not let a site submit an arbitrary customer identity.

## SaaS API

All integration endpoints require the existing license or API-key authentication:

- `POST /api/v1/integrations/wordpress/sites/register` — creates or refreshes the site identity. Payload includes the HTTPS site URL, WordPress administrator email, WordPress/WooCommerce versions, and plugin version.
- `GET /api/v1/integrations/wordpress/sites/status?site_id=...` — returns the registered site's connection and current license entitlement metadata. It supports expired entitlements for status visibility while keeping audit access blocked by the regular audit authentication dependency.
- `POST /api/v1/integrations/wordpress/sites/disconnect` — disconnects the site without deleting the license, billing history, reports, or customer account.
- `GET /api/v1/account/usage` — returns the license-scoped monthly quota.
- `GET /api/v1/account/wordpress-sites` and `POST /api/v1/account/wordpress-sites/{site_id}/disconnect` — let signed-in customers inspect and revoke connected WordPress installations from the customer portal.
- `POST /api/v1/comprehensive-audit?domain=...` — executes the existing licensed audit and returns a PDF.
- `GET /api/v1/reports` and `GET /api/v1/reports/{id}/pdf` — list and download reports scoped to the authenticated license.
- `GET /api/v1/account/billing-history` and `POST /api/v1/account/billing-portal` — show license-scoped billing lifecycle information and open the Paddle customer portal.

The API enforces a maximum of ten active WordPress installations per license. WordPress sends its registered site ID with audit and report requests; disconnected or mismatched site IDs are rejected, while normal customer-portal/API-key workflows continue to use their existing license-scoped authentication. Registration is serialized per license, and a unique license/hostname index prevents duplicate records. Reconnecting the same hostname reactivates its existing site record.

## Identity and subscription synchronization

Each WordPress site is associated with the authenticated SaaS `software_licenses.id`. The site record stores the verified checkout email derived from Paddle's payment provisioning event, plus the site administrator email as operational metadata. A verified customer email change updates the linked WordPress site identity in the same database transaction as the checkout identity change. License tier, active state, expiry and billing-period end remain SaaS-owned. Paddle webhook reconciliation updates the underlying license, and the WordPress status endpoint reflects the current entitlement on its next refresh.

Disconnecting a WordPress site does not cancel a Paddle subscription or delete the license. Subscription cancellation and billing changes remain provider-owned and are managed through the SaaS billing workflows.

## WordPress administrator experience

The plugin dashboard includes:

- Connection status and site identifier.
- License entitlement and plan/quota display.
- Subscription period, recent billing-attention indicators, and a secure Paddle customer-portal handoff.
- Store URL audit submission; the returned PDF is streamed directly to the authenticated administrator.
- Recent saved reports with authenticated proxy downloads.
- HTTPS API endpoint configuration for self-hosted SaaS deployments.
- Local admin display name and accent-color settings.
- Nonce-protected save, connect, disconnect, audit, and download actions restricted to `manage_options`.
- Twice-daily WordPress scheduled entitlement/status heartbeat, with status visible in the dashboard.

The WooCommerce version is detected automatically. The plugin does not modify WooCommerce checkout, customer orders, payment methods, or storefront output.

## Database rollout

Apply `migrations/20261031_wordpress_sites.sql` before deploying the backend revision. The migration creates the site identity table, foreign key, unique per-license hostname index, and lookup indexes. The application schema readiness endpoint includes this table.

## Security and operational notes

- The plugin makes outbound requests only to a validated HTTPS API base URL, with TLS certificate verification and redirects disabled. The saved license credential is authenticated-encrypted at rest with AES-256-GCM.
- The backend authenticates every registration, status, disconnect, audit, usage, and report request. Plugin audit and report calls also carry `X-WordPress-Site-ID`; the backend checks that the site belongs to the authenticated license and remains active before permitting audit or report access.
- Customer report downloads are proxied through the authenticated WordPress administrator action. PDFs are not written to public WordPress uploads.
- Site registration and disconnect operations do not reveal license secrets or customer billing-provider credentials.
- No production migration, customer installation, provider transaction, merge, or deployment is performed by a source change alone.
