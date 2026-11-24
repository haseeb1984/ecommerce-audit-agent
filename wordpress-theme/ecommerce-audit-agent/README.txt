=== Ecommerce Audit Agent WordPress Theme ===

Contributors: ecommerceauditagent
Requires at least: 6.2
Tested up to: 6.8
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

== Overview ==

A responsive public marketing website theme for Ecommerce Audit Agent. It provides a homepage, feature and workflow pages, live pricing, contact form, FAQs, integration information, help content, legal-policy page templates and a custom 404 page.

The pricing display reads the active Starter / Pro / Business catalogue through the existing SaaS API. Checkout is created by the existing backend and is redirected only when the returned HTTPS destination is on the Paddle domain. The theme does not store payment credentials, license keys, customer sessions, audit results or PDF files.

== Installation ==

1. In WordPress, open Appearance > Themes > Add New > Upload Theme.
2. Upload the ecommerce-audit-agent.zip package and activate it.
3. On activation, the theme creates any missing public information pages and assigns the Home page as the static front page.
4. Review Appearance > Menus and Settings > Reading after activation.
5. Open Appearance > EAA Website Settings. Confirm the SaaS API base URL and public support email.
6. Set the Vercel contact API shared secret in WordPress and as `EAA_CONTACT_FORM_SECRET` in Vercel; set `EAA_CONTACT_TO_EMAIL` in Vercel. The Vercel API sends contact messages through the existing platform SMTP settings. Submit a controlled contact-form test.
7. Review every generated legal page and replace all bracketed placeholders before treating those pages as final policy statements.

Existing pages with matching slugs are preserved; the theme does not overwrite their content. The theme does not delete pages or user content when switched off.

== Pages created when missing ==

Home, Features, How It Works, Pricing, About, Contact, FAQ, Privacy Policy, Terms of Service, Cookie Policy, Refund & Cancellation Policy, Disclaimer, Security, Help Center and Integrations.

WordPress supplies the standard sitemap index and robots behavior. The theme enables the document title and emits a page description where a usable excerpt/content description is available.

== SaaS architecture boundary ==

The theme is a public WordPress presentation layer. It uses WordPress core pages/options for its own settings and proxies the public package catalogue and checkout request to the existing SaaS API.

Canonical ownership remains unchanged:
* Hostinger MySQL: operational SaaS/customer records.
* Supabase PostgreSQL: canonical licensing and audit-engine records.
* Hostinger private storage: customer reports and other private files.
* Vercel/FastAPI: API, application orchestration and provider integration.

No custom WordPress tables are created for SaaS operational, licensing or customer-file data. Duplicating those records in the marketing WordPress database would create a second source of truth and conflict with the repository architecture.

== Contact form ==

The contact form validates fields server-side, uses a WordPress nonce, a hidden honeypot and a short per-email submission cooldown. WordPress signs the request and sends it server-to-server to the FastAPI `/api/v1/public/contact` endpoint. Vercel verifies the shared HMAC secret and sends a branded HTML email through the existing platform SMTP configuration, with the visitor's address as Reply-To. The public contact email is display-only; leaving it blank hides it without disabling the form. No `wp_mail()` is used.

== Before launch ==

* Confirm the API base is the intended HTTPS deployment.
* Confirm live pricing is returned by the backend and the Paddle sandbox/live mode is intentional.
* Verify checkout end-to-end using a controlled account before enabling public purchases.
* Configure SMTP and verify delivery.
* Replace [LEGAL ENTITY NAME], [EFFECTIVE DATE], [PRIVACY CONTACT EMAIL], [POSTAL ADDRESS], [GOVERNING JURISDICTION], [SECURITY CONTACT EMAIL], refund terms and cookie inventory with approved details.
* Have legal pages reviewed for the actual business, provider list, data flows and applicable jurisdictions.
* Confirm privacy/cookie consent requirements and install/configure an appropriate consent manager if required.
* Confirm the WordPress host serves the site over HTTPS.

== Important limitations ==

This theme does not replace the official Ecommerce Audit Agent WordPress plugin. The plugin remains the customer-site integration installed on a store's WordPress/WooCommerce website. This theme is for the public marketing website only.

It does not deploy or modify the Vercel backend, run database migrations, create SaaS accounts, provision licenses, or configure Paddle/SMTP credentials.
