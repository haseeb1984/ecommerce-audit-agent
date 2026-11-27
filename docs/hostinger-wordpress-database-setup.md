# Hostinger WordPress database and site setup

This runbook describes the public marketing WordPress site at audit.juncsys.com. The theme source is wordpress-theme/ecommerce-audit-agent/; the separate customer-store integration is the plugin in wordpress-plugin/ecommerce-audit-agent/.

## Database ownership — do not combine these databases

There are three separate data stores in this application:

1. **WordPress site database (Hostinger):** only WordPress core content, pages, menus, users, theme settings and WordPress plugin options. WordPress creates its standard posts, postmeta, options, users, usermeta, taxonomy and comment tables during installation. The actual table prefix is whatever was selected in wp-config.php; do not assume it is wp_.
2. **Hostinger SaaS operational MySQL database:** customer operational records, queues, billing mirrors, WordPress integration records, report metadata and related operational tables. Its baseline is migrations/hostinger_operational_schema.sql. This is not the WordPress database.
3. **Supabase PostgreSQL:** canonical licenses, audit-engine data and licensing lifecycle records. Apply PostgreSQL migrations only to Supabase, never to either MySQL database.

The marketing theme deliberately creates no custom WordPress tables. On theme activation it creates missing public pages and the primary/footer menu using WordPress core APIs. Theme settings are stored in the WordPress options table. The customer plugin likewise stores its site-specific credential/settings in WordPress options and calls the SaaS API over HTTPS. Do not copy licenses, audit results, billing events, customer report PDFs or SaaS queue records into WordPress tables: doing so would create a conflicting source of truth.

## What is already in source

- Responsive marketing theme with homepage, features, how-it-works, pricing, about, contact, FAQ, legal, security, help and integrations pages.
- Theme activation creates missing pages and sets the Home page as the static front page; existing pages with matching slugs are preserved.
- Live pricing and checkout are served by the SaaS API.
- Contact form sends a signed server-to-server request to the SaaS API; SMTP delivery remains on the Vercel backend.
- Separate customer-store plugin supports license connection, identity linking, usage, audits and private report downloads.
- CI now produces separate installable ZIP artifacts for the marketing theme and customer plugin.

## WordPress database provisioning

For a new WordPress installation, create a dedicated MySQL database and a least-privilege database user in Hostinger hPanel (Databases → Management), assign that user to the database, and use those values in the Hostinger WordPress installer. WordPress will create its own core schema as part of installation. Use a unique table prefix, keep the database user scoped to this database, and require TLS where the Hostinger database endpoint supports it.

For an already-installed WordPress site, do not create a second WordPress database and do not import the SaaS MySQL or Supabase schema into it. The installed site's existing database is the WordPress database. Confirm its database name, prefix and connection through Hostinger's WordPress details / wp-config.php; never paste its password into chat or commit it.

## Activate the marketing site

1. In WordPress Admin, open Appearance → Themes and activate Ecommerce Audit Agent.
2. Check Pages → All Pages. The theme creates only missing pages; it does not overwrite existing content.
3. Check Settings → Reading and confirm Home is the static front page.
4. Check Appearance → Menus and confirm the Primary and Footer locations.
5. Open Appearance → EAA Website Settings and confirm the HTTPS SaaS API base.
6. Configure the shared contact-form secret in WordPress settings and as EAA_CONTACT_FORM_SECRET in Vercel; set EAA_CONTACT_TO_EMAIL in Vercel. The secret must be generated privately and must never be committed or sent in chat.
7. Replace legal-page placeholders with approved business/legal details before public launch.
8. Test pricing, checkout in the intended Paddle sandbox/live mode, contact form delivery, mobile navigation and all page links.

## Build artifacts

GitHub Actions uploads two independent artifacts after a successful CI build:

- wordpress-theme-package — upload this ZIP under Appearance → Themes → Add New → Upload Theme.
- wordpress-plugin-package — upload this ZIP under Plugins → Add New → Upload Plugin on a customer WordPress/WooCommerce store. Do not install the customer plugin on the marketing site unless that site itself is intended to be audited as a customer store.

The plugin is not a theme, and the theme is not the customer integration plugin. They must not be installed in each other's directories.

## Scope boundary

Source changes and CI packaging can be completed without Hostinger access. Actual creation of a new database, attaching it to an existing Hostinger WordPress installation, or replacing the active site's database is a hosting-account action and is intentionally not automated from this repository. Do not overwrite the existing audit.juncsys.com site or create a second database for it without a verified backup and explicit target. No database is created by importing the theme ZIP.
