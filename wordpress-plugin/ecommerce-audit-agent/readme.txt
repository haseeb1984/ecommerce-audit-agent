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

1. Upload the `ecommerce-audit-agent` folder to `/wp-content/plugins/`, or install the ZIP from Plugins > Add New > Upload Plugin.
2. Activate **Ecommerce Audit Agent**.
3. Open **Ecommerce Audit** in the WordPress administrator menu.
4. Enter the SaaS license key issued to your customer account. The API base defaults to the hosted Ecommerce Audit Agent service and must use HTTPS.
5. Save and connect. The plugin registers this WordPress installation against the license.
6. Run a store audit or download one of the saved reports.

== Features ==

* License-authenticated site registration and connection status.
* Site identity bound to the authenticated SaaS license; one license can connect up to ten WordPress sites.
* WordPress and WooCommerce version metadata for support visibility.
* Live monthly quota, plan and entitlement information.
* Run a comprehensive audit and stream its PDF directly to the administrator browser.
* List and securely proxy-download saved reports belonging to the connected license.
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
