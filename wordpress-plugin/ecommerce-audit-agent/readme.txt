=== Ecommerce Audit Agent ===
Contributors: ecommerceauditagent
Tags: ecommerce, woocommerce, seo, performance, accessibility, audit
Requires at least: 6.2
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Connect a WordPress or WooCommerce store to Ecommerce Audit Agent. Manage your license, view usage, run an audit, and download saved PDF reports from the WordPress administrator dashboard.

== Installation ==

1. Download the plugin ZIP from the SaaS customer portal or `/wordpress-plugin.zip` on your Ecommerce Audit Agent deployment.
2. In WordPress, open Plugins > Add New > Upload Plugin, upload the ZIP, install, and activate it.
3. Open **Ecommerce Audit** in the WordPress administrator menu.
4. For a standard Starter or Pro customer account, enter the SaaS license key issued to your customer account. The API base defaults to the hosted Ecommerce Audit Agent service and must use HTTPS.
5. For a Business agency client workspace, generate a one-time WordPress connection token in the SaaS customer portal, then paste it into the plugin's **Connect this site to a Business agency client** section. Do not use the agency owner's license key on a client site.
6. Save and connect. The plugin registers the WordPress installation either to the standard license or to the selected agency client workspace using a separate site credential.
7. Standard license connections can run a store audit or download saved reports. Agency client connections can queue page audits under the shared Business allowance; audit progress and structured findings are available in the SaaS agency dashboard. The agency plugin mode does not issue PDF downloads.

== Features ==

* License-authenticated standard site registration and separate one-time-token agency client site registration.
* Agency client sites use independent, encrypted site credentials and can be revoked by the agency owner.
* Site-bound audit and report authorization, with a twice-daily entitlement heartbeat.
* Site identity bound to the authenticated SaaS license; one customer license connects one active WordPress website.
* WordPress and WooCommerce version metadata for support visibility.
* Live monthly quota, plan and entitlement information.
* Billing history, subscription period visibility, and a secure Paddle customer-portal handoff.
* Run a comprehensive audit and stream its PDF directly to the administrator browser.
* List and securely proxy-download saved reports belonging to the connected license.
* Customer portal visibility and remote disconnect for connected installations.
* Admin-only connection settings, nonce-protected actions and local admin display branding.
* TLS verification enabled, no API credentials placed in public-page markup, and no public uploads of audit PDFs.

WooCommerce is detected automatically and its version is sent as integration metadata. WooCommerce is not required for the plugin's core audit functions.

== Security and privacy ==

The license key is stored in the site's WordPress options table and sent server-to-server only to the configured HTTPS API. Only users with the `manage_options` capability can access the dashboard or trigger actions. All state-changing administrator forms use WordPress nonces. PDF files are streamed through authenticated admin actions rather than placed in public uploads.

The SaaS backend authenticates the license on every request and scopes usage, audit generation and report retrieval to that license. A site registration cannot access another license's site records.

== Requirements ==

* WordPress 6.2 or later.
* PHP 7.4 or later.
* Outbound HTTPS access from the WordPress host.
* A valid Ecommerce Audit Agent license and an active SaaS entitlement.
* The SaaS database migration `migrations/20261031_wordpress_sites.sql` must be applied before enabling the integration.

== Changelog ==

= 1.0.0 =
* Initial installable plugin.
* SaaS license connection, WordPress site registration, quota dashboard, audit execution and report downloads.
